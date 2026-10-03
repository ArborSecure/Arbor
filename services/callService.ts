/**
 * End-to-end encrypted voice calls (1:1 and small-group mesh).
 *
 * Security model — the same shape Signal uses:
 *  - ALL signaling (SDP offers/answers, ICE candidates) is encrypted through the
 *    existing pairwise Signal Double-Ratchet sessions before it touches the
 *    server. The server relays opaque blobs it cannot read or forge.
 *  - Media is WebRTC DTLS-SRTP. The DTLS certificate fingerprints ride inside
 *    the SDP — which the server never sees in plaintext — so a malicious server
 *    cannot man-in-the-middle the media keys. End-to-end, per pair.
 *  - Group calls are a FULL MESH of pairwise-encrypted connections (no SFU, so
 *    no server ever touches media). Practical up to ~5 participants.
 *
 * Honest limits: connectivity uses public STUN only; a small share of networks
 * (symmetric NAT on both ends) can't form a P2P path without a TURN relay. The
 * server learns call metadata (who signaled whom, when) — the same metadata it
 * already sees for messages.
 */
import * as signal from './signal';
import { sameKey } from './membership';
import { User } from '../types';

/**
 * v70 H3: who a call may be set up with, decided exactly as for messages
 * (api.ts callPeer → netTrust): the identity key a signed membership chain names
 * for this peer, `{ ik: null }` for a peer allowed without one (a personal-hub
 * contact, or an existing conversation during the transition window), or null
 * to refuse.
 */
export type PeerCheck = (peerId: string) => Promise<{ ik: string | null } | null>;
/** v72 B3: shown when a call can't start because the other person's key changed. */
export const KEY_CHANGED_CALL = 'This person’s security key changed. Compare your safety number with them and accept the new key before calling.';

export type CallPhase = 'idle' | 'outgoing' | 'incoming' | 'active';

export interface PeerState {
  id: string;
  name: string;
  status: 'ringing' | 'connecting' | 'connected' | 'left' | 'failed';
  stream?: MediaStream;
  ice?: string;   // last ICE connection state, for diagnostics in the UI
}

export interface CallUIState {
  phase: CallPhase;
  callId: string | null;
  peers: PeerState[];
  fromName?: string;      // who is calling (incoming)
  fromId?: string;
  participants?: { id: string; name: string }[]; // who's in the call (incoming ring metadata)
  muted: boolean;
  videoOn?: boolean;
  localStream?: MediaStream;
  startedAt?: number;
}

interface SignalSender { (toNodeId: string, callId: string, kind: string, kt?: number, kb?: string): Promise<void>; }

/** Emitted once when a call fully ends, so the app can drop a call-log entry
 *  into the relevant chat(s). One entry per remote peer that was in the call. */
export interface CallEndInfo {
  callId: string;
  direction: 'outgoing' | 'incoming';
  startedAt?: number;        // undefined = never connected (missed / declined / no-answer)
  endedAt: number;
  video: boolean;
  peers: { id: string; name: string; connected: boolean }[];
}

const FALLBACK_ICE = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
let iceServersPromise: Promise<RTCIceServer[]> | null = null;
let iceFetchedAt = 0;
// TURN credentials are short-lived (server mints them per request, ~2h TTL —
// security review V8 L-3), so the cached config is refreshed well before expiry.
const ICE_MAX_AGE_MS = 30 * 60 * 1000;
/** ICE config from the server (adds a TURN relay — STUN alone fails on most
 *  phone-carrier NATs). TURN forwards encrypted DTLS-SRTP only; E2E preserved. */
function getIceServers(): Promise<RTCIceServer[]> {
  if (!iceServersPromise || Date.now() - iceFetchedAt > ICE_MAX_AGE_MS) {
    iceFetchedAt = Date.now();
    iceServersPromise = fetch('/api/rtc/config', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then(j => (j && Array.isArray(j.iceServers) && j.iceServers.length ? j.iceServers : FALLBACK_ICE))
      .catch(() => FALLBACK_ICE);
  }
  return iceServersPromise;
}
const RING_TIMEOUT_MS = 35000;

const te = new TextEncoder();
const td = new TextDecoder();
const b64 = (buf: ArrayBuffer) => { const u = new Uint8Array(buf); let x = ''; const C = 0x8000; for (let i = 0; i < u.length; i += C) x += String.fromCharCode.apply(null, u.subarray(i, i + C) as unknown as number[]); return btoa(x); };

export class CallManager {
  private me: User | null = null;
  private send: SignalSender;
  private fetchBundle: (nodeId: string) => Promise<any>;
  private checkPeer: PeerCheck;
  // Lightweight diagnostics — visible in the browser console with the [call] tag,
  // AND kept in a ring buffer so it can be copied from inside the app (iPhones
  // have no easy console; "Copy call log" in the overlay reads this).
  private diag: string[] = [];
  private log(...args: any[]) {
    try { console.log('[call]', ...args); } catch {}
    try {
      const line = args.map(a => typeof a === 'string' ? a : (() => { try { return JSON.stringify(a); } catch { return String(a); } })()).join(' ');
      this.diag.push(`${new Date().toISOString().slice(11, 23)} ${line}`);
      if (this.diag.length > 200) this.diag.splice(0, this.diag.length - 200);
    } catch {}
  }
  /** Full [call] log for the current/most recent call, newline-joined. */
  getDiagnostics(): string { return this.diag.join('\n'); }
  private onChange: (s: CallUIState) => void;
  private onCallEnd?: (log: CallEndInfo) => void;
  private direction: 'outgoing' | 'incoming' = 'outgoing';
  private everConnected = false;   // did ANY peer connect during this call?
  private loggedCall = false;      // emit exactly one call-log per call

  private phase: CallPhase = 'idle';
  private callId: string | null = null;
  private muted = false;
  private videoOn = false;
  private facingMode: 'user' | 'environment' = 'environment';
  private startedAt?: number;
  private local: MediaStream | null = null;
  private pcs = new Map<string, RTCPeerConnection>();
  private peers = new Map<string, PeerState>();
  private pendingIce = new Map<string, RTCIceCandidateInit[]>();
  private ringTimer: ReturnType<typeof setTimeout> | null = null;
  private incoming: { callId: string; fromId: string; fromName: string; participants: { id: string; name: string }[] } | null = null;

  constructor(opts: { send: SignalSender; fetchBundle: (nodeId: string) => Promise<any>; checkPeer: PeerCheck; onChange: (s: CallUIState) => void; onCallEnd?: (log: CallEndInfo) => void }) {
    this.send = opts.send; this.fetchBundle = opts.fetchBundle; this.checkPeer = opts.checkPeer; this.onChange = opts.onChange;
    this.onCallEnd = opts.onCallEnd;
  }

  setSelf(me: User | null) { this.me = me; if (!me) this.teardown(); }

  private emit() {
    this.onChange({
      phase: this.phase, callId: this.callId, muted: this.muted, videoOn: this.videoOn, startedAt: this.startedAt,
      localStream: this.local || undefined,
      peers: [...this.peers.values()],
      fromName: this.incoming?.fromName, fromId: this.incoming?.fromId, participants: this.incoming?.participants,
    });
  }

  // ---- sealed signaling helpers -------------------------------------------
  /** Ratchet-encrypt a JSON payload to a peer, establishing a session from their
   *  published prekey bundle if we don't have one yet. v70 H3: only to a peer
   *  whose membership verifies, and only over a session bound to the identity key
   *  its certificate names — a prekey bundle the server swapped is refused, just
   *  as for messages (api.ts slotsFor). */
  private async seal(toId: string, payload: object): Promise<{ kt: number; kb: string }> {
    if (!this.me) throw new Error('no self');
    const peer = await this.checkPeer(toId);
    if (!peer) throw new Error('This person’s membership couldn’t be verified, so the call wasn’t set up.');
    if (!(await signal.hasSession(this.me.id, toId))) {
      const bundle = await this.fetchBundle(toId);
      if (peer.ik && !sameKey(bundle?.identityKey, peer.ik)) throw new Error('This person’s key doesn’t match their membership certificate.');
      await signal.establishSession(this.me.id, toId, bundle);
    } else if (peer.ik && !sameKey(await signal.remoteIdentity(this.me.id, toId), peer.ik)) {
      throw new Error('This person’s key doesn’t match their membership certificate.');
    }
    // v72 B3: no call to a peer whose security key changed until it is re-trusted.
    if (await signal.identityChanged(this.me.id, toId)) throw new Error(KEY_CHANGED_CALL);
    const slot = await signal.encryptKeyTo(this.me.id, toId, te.encode(JSON.stringify(payload)).buffer as ArrayBuffer);
    return { kt: slot.kt, kb: slot.kb };
  }
  /** Open a sealed signal. v70 H3: the sender must pass the same membership check,
   *  and the session that decrypted it must be bound to its certified key (a
   *  first message carries the sender's identity — checked after decryption). */
  private async open(fromId: string, kt: number, kb: string): Promise<any> {
    if (!this.me) throw new Error('no self');
    const peer = await this.checkPeer(fromId);
    if (!peer) throw new Error('unverified caller');
    if (peer.ik && (await signal.hasSession(this.me.id, fromId)) && kt !== 3 && !sameKey(await signal.remoteIdentity(this.me.id, fromId), peer.ik)) throw new Error('caller key mismatch');
    const buf = await signal.decryptKeyFrom(this.me.id, fromId, { kt, kb });
    if (peer.ik && !sameKey(await signal.remoteIdentity(this.me.id, fromId), peer.ik)) throw new Error('caller key mismatch');
    // v72 B3: a signal from a key that changed (flagged by this very decryption, or
    // earlier and not yet re-trusted) is dropped — no ringing from an unknown key.
    if (await signal.identityChanged(this.me.id, fromId)) throw new Error('caller key changed');
    return JSON.parse(td.decode(buf));
  }

  // ---- media ----------------------------------------------------------------
  private async ensureMic(): Promise<MediaStream> {
    if (this.local) return this.local;
    this.local = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true }, video: false });
    return this.local;
  }

  private async newPC(peerId: string, peerName: string): Promise<RTCPeerConnection> {
    // The mic MUST exist before the connection is built: if an accept arrives
    // while the caller is still on the permission dialog, a track-less PC would
    // produce a silently one-way "dead" call. Await both here, always.
    await this.ensureMic();
    const iceServers = await getIceServers();
    // iceCandidatePoolSize pre-gathers candidates for a faster first connection.
    const pc = new RTCPeerConnection({ iceServers, iceCandidatePoolSize: 4 });
    this.log('newPC', peerName, 'iceServers:', iceServers.map((s: any) => s.urls).flat().join(','));
    this.pcs.set(peerId, pc);
    this.peers.set(peerId, { id: peerId, name: peerName, status: 'connecting' });
    this.local?.getTracks().forEach(t => pc.addTrack(t, this.local!));
    pc.onicecandidate = async (e) => {
      if (!e.candidate || !this.callId) { if (!e.candidate) this.log('ICE gathering complete for', peerName); return; }
      try { const { kt, kb } = await this.seal(peerId, { ice: e.candidate.toJSON() }); await this.send(peerId, this.callId, 'ice', kt, kb); }
      catch (err) { this.log('failed to send ICE candidate:', err); }
    };
    pc.onicegatheringstatechange = () => this.log('iceGathering', peerName, pc.iceGatheringState);
    pc.ontrack = (e) => {
      const p = this.peers.get(peerId); if (!p) return;
      p.stream = e.streams[0] || new MediaStream([e.track]);
      p.status = 'connected';
      const w = this.watchdogs.get(peerId); if (w) { clearTimeout(w); this.watchdogs.delete(peerId); }
      if (!this.startedAt) this.startedAt = Date.now();
      this.everConnected = true;
      this.phase = 'active';
      this.emit();
    };
    pc.onconnectionstatechange = () => {
      const p = this.peers.get(peerId); if (!p) return;
      this.log('connectionState', peerName, '->', pc.connectionState);
      if (pc.connectionState === 'connected') p.status = 'connected';
      if (pc.connectionState === 'failed') p.status = 'failed';
      if (pc.connectionState === 'disconnected' || pc.connectionState === 'closed') p.status = 'left';
      this.emit();
      this.pruneIfEmpty();
    };
    // If ICE fails, try one automatic restart (common on flaky mobile networks)
    // before giving up — and never leave the peer stuck "connecting" silently.
    pc.oniceconnectionstatechange = async () => {
      const st = pc.iceConnectionState;
      const p = this.peers.get(peerId);
      if (!p) return;
      this.log('iceConnectionState', peerName, '->', st);
      p.ice = st;
      this.emit();
      if (st === 'failed') {
        if (!(pc as any)._restarted && this.me && this.me.id < peerId) {
          (pc as any)._restarted = true;
          try {
            const offer = await pc.createOffer({ iceRestart: true });
            await pc.setLocalDescription(offer);
            const { kt, kb } = await this.seal(peerId, { sdp: pc.localDescription });
            await this.send(peerId, this.callId!, 'offer', kt, kb);
          } catch { p.status = 'failed'; this.emit(); }
        } else {
          p.status = 'failed'; this.emit(); this.pruneIfEmpty();
        }
      }
    };
    return pc;
  }

  private async makeOffer(peerId: string, peerName: string) {
    const pc = this.pcs.get(peerId) || await this.newPC(peerId, peerName);
    // offerToReceiveVideo keeps a video m-line in EVERY offer, so the answering
    // side can attach a camera track in its answer (rollback path of glare
    // handling relies on this — see the 'offer' case in handleSignalSerial).
    const offer = await pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: true });
    await pc.setLocalDescription(offer);
    const { kt, kb } = await this.seal(peerId, { sdp: pc.localDescription });
    await this.send(peerId, this.callId!, 'offer', kt, kb);
    this.armWatchdog(peerId);
  }

  // If a peer never reaches "connected" within the window, stop showing an
  // endless "connecting" and report it — usually means no network path exists
  // (both ends behind restrictive NAT with no reachable TURN relay).
  private watchdogs = new Map<string, ReturnType<typeof setTimeout>>();
  private armWatchdog(peerId: string) {
    const existing = this.watchdogs.get(peerId);
    if (existing) clearTimeout(existing);
    this.watchdogs.set(peerId, setTimeout(() => {
      const p = this.peers.get(peerId);
      const pc = this.pcs.get(peerId);
      if (p && pc && pc.connectionState !== 'connected' && p.status !== 'connected') {
        p.status = 'failed';
        this.emit();
        this.pruneIfEmpty();
      }
    }, 25000));
  }

  private async flushIce(peerId: string) {
    const pc = this.pcs.get(peerId); const q = this.pendingIce.get(peerId);
    if (!pc || !q) return;
    for (const c of q) { try { await pc.addIceCandidate(c); } catch {} }
    this.pendingIce.delete(peerId);
  }

  // ---- public API -------------------------------------------------------------
  /** Start a call. `targets` = the other participants (1 for a direct call). */
  async startCall(targets: { id: string; name: string }[]): Promise<void> {
    if (!this.me || this.phase !== 'idle' || targets.length === 0) return;
    this.diag = [];
    this.direction = 'outgoing';
    this.everConnected = false;
    this.loggedCall = false;
    this.callId = crypto.randomUUID();
    this.phase = 'outgoing';
    // Names ride along with ids: a group participant who only knows the ringer
    // would otherwise have to display raw node ids (the "n_c9f18e" bug).
    const participantIds = [{ id: this.me.id, name: this.me.name }, ...targets.map(t => ({ id: t.id, name: t.name }))];
    // Ring FIRST so recipients get pinged immediately — the caller may sit on the
    // mic-permission dialog for a while, and the mic isn't needed until offers.
    let keyChangedOnly = true;
    for (const t of targets) {
      this.peers.set(t.id, { id: t.id, name: t.name, status: 'ringing' });
      // ring carries the participant list SEALED, so joiners know who to mesh with.
      try {
        const { kt, kb } = await this.seal(t.id, { participants: participantIds });
        await this.send(t.id, this.callId, 'ring', kt, kb);
        this.log('ring sent to', t.name);
      } catch (e: any) {
        if (e?.message !== KEY_CHANGED_CALL) keyChangedOnly = false;
        const p = this.peers.get(t.id); if (p) p.status = 'failed';
      }
    }
    // Nobody reachable (sealing/relay failed for every target): fail loudly
    // instead of ringing into the void.
    if (![...this.peers.values()].some(p => p.status === 'ringing')) {
      this.teardown();
      throw new Error(keyChangedOnly ? KEY_CHANGED_CALL : 'No participant could be reached');
    }
    this.emit();
    try { await this.ensureMic(); }
    catch { await this.hangup(); throw new Error('Microphone unavailable'); }
    this.ringTimer = setTimeout(() => { if (this.phase === 'outgoing') this.hangup(); }, RING_TIMEOUT_MS);
  }

  /** Accept the currently ringing incoming call. */
  async accept(): Promise<void> {
    if (!this.me || !this.incoming) return;
    const inc = this.incoming; this.incoming = null;
    await this.ensureMic();
    this.callId = inc.callId;
    this.phase = 'active';
    // Tell everyone in the participant list we've joined; mesh rule: the peer with
    // the LOWER node id makes the offer, so exactly one side initiates per pair.
    for (const part of inc.participants) {
      const pid = part.id;
      if (pid === this.me.id) continue;
      const name = part.name || (pid === inc.fromId ? inc.fromName : pid.slice(0, 8));
      this.peers.set(pid, { id: pid, name, status: 'connecting' });
      try {
        const { kt, kb } = await this.seal(pid, { joined: true });
        await this.send(pid, inc.callId, 'accept', kt, kb);
        this.log('accept sent to', name, '— I offer:', this.me.id < pid);
        if (this.me.id < pid) await this.makeOffer(pid, name);
        else this.armWatchdog(pid); // their offer is due; surface "no route" if it never comes
      } catch { const p = this.peers.get(pid); if (p) p.status = 'failed'; }
    }
    this.emit();
  }

  async decline(): Promise<void> {
    if (!this.incoming) return;
    const inc = this.incoming; this.incoming = null;
    try { await this.send(inc.fromId, inc.callId, 'decline'); } catch {}
    this.emitCallLog({
      callId: inc.callId, direction: 'incoming', startedAt: undefined, endedAt: Date.now(), video: false,
      peers: [{ id: inc.fromId, name: inc.fromName, connected: false }],
    });
    this.phase = 'idle'; this.emit();
  }

  async hangup(): Promise<void> {
    const cid = this.callId;
    if (cid) for (const pid of this.peers.keys()) { try { await this.send(pid, cid, 'hangup'); } catch {} }
    this.teardown();
  }

  toggleMute(): void {
    this.muted = !this.muted;
    this.local?.getAudioTracks().forEach(t => { t.enabled = !this.muted; });
    this.emit();
  }

  /** Turn the camera on/off mid-call. Adds or removes a video track on every
   *  peer connection and renegotiates (the offerer side drives the new offer).
   *  Full mesh: each pair stays end-to-end encrypted via its own DTLS-SRTP. */
  async toggleVideo(): Promise<void> {
    if (!this.me) return;
    if (!this.videoOn) {
      // Acquire a camera track and attach it to every peer connection.
      let camStream: MediaStream;
      try { camStream = await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 640 }, height: { ideal: 480 }, frameRate: { ideal: 24 }, facingMode: this.facingMode } }); }
      catch { throw new Error('Camera unavailable'); }
      const track = camStream.getVideoTracks()[0];
      if (!track) return;
      if (!this.local) this.local = new MediaStream();
      this.local.addTrack(track);
      this.videoOn = true;
      for (const [pid, pc] of this.pcs) {
        try {
          pc.addTrack(track, this.local);
          // Renegotiation rule: whoever CHANGED their tracks sends the new offer.
          // (The old "lower id offers" mesh rule is only for initial setup — using
          // it here meant a higher-id participant's camera was never negotiated
          // and their video silently went nowhere. Glare between two simultaneous
          // renegotiations is resolved in the 'offer' handler via polite rollback.)
          await this.makeOffer(pid, this.peers.get(pid)?.name || pid.slice(0, 8));
        } catch (e) { this.log('addVideo failed for', pid, e); }
      }
    } else {
      // Stop and remove the video track from every sender, then renegotiate.
      const vtracks = this.local?.getVideoTracks() || [];
      for (const [pid, pc] of this.pcs) {
        for (const sender of pc.getSenders()) {
          if (sender.track && sender.track.kind === 'video') {
            try { pc.removeTrack(sender); } catch {}
          }
        }
        try { await this.makeOffer(pid, this.peers.get(pid)?.name || pid.slice(0, 8)); } catch {}
      }
      vtracks.forEach(t => { t.stop(); this.local?.removeTrack(t); });
      this.videoOn = false;
    }
    this.emit();
  }

  /** Flip between the front ('user') and back ('environment') camera during a
   *  video call. Uses replaceTrack on each sender so no renegotiation is needed —
   *  the new camera feed swaps in seamlessly and stays end-to-end encrypted. */
  async switchCamera(): Promise<void> {
    if (!this.videoOn || !this.local) return;
    const next: 'user' | 'environment' = this.facingMode === 'user' ? 'environment' : 'user';
    let camStream: MediaStream;
    try { camStream = await navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 640 }, height: { ideal: 480 }, frameRate: { ideal: 24 }, facingMode: next } }); }
    catch { throw new Error('Could not switch camera'); }
    const newTrack = camStream.getVideoTracks()[0];
    if (!newTrack) return;
    // Swap the track into every peer connection without renegotiating.
    for (const [, pc] of this.pcs) {
      const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video');
      if (sender) { try { await sender.replaceTrack(newTrack); } catch (e) { this.log('replaceTrack failed', e); } }
    }
    // Swap it into the local preview stream too.
    const old = this.local.getVideoTracks()[0];
    if (old) { old.stop(); this.local.removeTrack(old); }
    this.local.addTrack(newTrack);
    this.facingMode = next;
    this.emit();
  }

  private pruneIfEmpty() {
    if (this.phase !== 'active' && this.phase !== 'outgoing') return;
    const alive = [...this.peers.values()].some(p => p.status === 'connected' || p.status === 'connecting' || p.status === 'ringing');
    if (!alive) this.teardown();
  }

  private emitCallLog(info: CallEndInfo) {
    if (this.loggedCall) return;
    this.loggedCall = true;
    try { this.onCallEnd?.(info); } catch {}
  }

  private teardown() {
    // Emit a call-log entry (once) for any call that actually started ringing or
    // connected. Remote peers only — a solo teardown (no peers) logs nothing.
    if (!this.loggedCall && this.callId && this.me) {
      const remote = [...this.peers.values()].filter(p => p.id !== this.me!.id);
      if (remote.length) {
        this.emitCallLog({
          callId: this.callId,
          direction: this.direction,
          startedAt: this.everConnected ? this.startedAt : undefined,
          endedAt: Date.now(),
          video: this.videoOn,
          peers: remote.map(p => ({ id: p.id, name: p.name, connected: p.status === 'connected' || (this.everConnected && p.status === 'left') })),
        });
      }
    }
    if (this.ringTimer) { clearTimeout(this.ringTimer); this.ringTimer = null; }
    this.watchdogs.forEach(w => clearTimeout(w)); this.watchdogs.clear();
    this.signalChains.clear();
    this.pcs.forEach(pc => { try { pc.close(); } catch {} });
    this.pcs.clear(); this.peers.clear(); this.pendingIce.clear();
    this.local?.getTracks().forEach(t => t.stop());
    this.local = null;
    this.phase = 'idle'; this.callId = null; this.incoming = null;
    this.muted = false; this.videoOn = false; this.startedAt = undefined;
    this.emit();
  }

  // ---- inbound signaling (from the SSE stream) ---------------------------------
  // Signals from a given peer MUST be processed strictly in order. SSE delivers
  // offer/answer/ICE back-to-back, and because each handler awaits crypto + WebRTC
  // calls, two concurrent invocations could (a) build two PeerConnections for the
  // same peer, or (b) run flushIce before a racing candidate was queued — leaving
  // the connection stuck "connecting" forever. We chain each peer's signals.
  private signalChains = new Map<string, Promise<void>>();
  async handleSignal(ev: { callId: string; kind: string; from: string; fromName: string; kt: number | null; kb: string | null }): Promise<void> {
    if (!this.me) return;
    const prev = this.signalChains.get(ev.from) || Promise.resolve();
    const next = prev.then(() => this.handleSignalSerial(ev)).catch(() => {});
    this.signalChains.set(ev.from, next);
    return next;
  }

  private async handleSignalSerial(ev: { callId: string; kind: string; from: string; fromName: string; kt: number | null; kb: string | null }): Promise<void> {
    if (!this.me) return;
    try {
      switch (ev.kind) {
        case 'ring': {
          // duplicate of the call we're already showing (pending-ring replay): ignore
          if (this.phase === 'incoming' && this.incoming?.callId === ev.callId) return;
          if (this.callId === ev.callId) return;
          // v70 H3: a ring must be SEALED by the caller (every Arbor client seals the
          // participant list into it) and open under the caller's certified key. A
          // bare or unopenable ring is the server — or an unverified node — speaking
          // for someone: it never rings this device.
          if (ev.kt === null || !ev.kb) { this.log('drop unsealed ring from', ev.fromName); return; }
          let p: any;
          try { p = await this.open(ev.from, ev.kt, ev.kb); }
          catch (e: any) { this.log('drop ring from', ev.fromName, ':', String(e?.message || e)); return; }
          if (this.phase !== 'idle') { try { await this.send(ev.from, ev.callId, 'decline'); } catch {} return; } // busy
          let participants: { id: string; name: string }[] = [{ id: ev.from, name: ev.fromName }, { id: this.me.id, name: this.me.name }];
          if (Array.isArray(p?.participants)) {
            participants = p.participants.map((x: any) => typeof x === 'string' ? { id: x, name: x === ev.from ? ev.fromName : x.slice(0, 10) } : x)
              .filter((x: any) => x && typeof x.id === 'string');
          }
          this.incoming = { callId: ev.callId, fromId: ev.from, fromName: ev.fromName, participants };
          this.direction = 'incoming';
          this.everConnected = false;
          this.loggedCall = false;
          this.phase = 'incoming'; this.emit();
          this.log('incoming ring from', ev.fromName);
          setTimeout(() => {
            if (this.phase === 'incoming' && this.incoming?.callId === ev.callId) {
              // Rang out unanswered — record a missed call from the caller.
              const inc = this.incoming;
              this.emitCallLog({
                callId: inc.callId, direction: 'incoming', startedAt: undefined, endedAt: Date.now(), video: false,
                peers: [{ id: inc.fromId, name: inc.fromName, connected: false }],
              });
              this.incoming = null; this.phase = 'idle'; this.emit();
            }
          }, RING_TIMEOUT_MS);
          return;
        }
        case 'accept': {
          if (ev.callId !== this.callId) { this.log('drop accept from', ev.fromName, '(callId mismatch)'); return; }
          // v70 H3: an accept is sealed ({ joined: true }); one that doesn't open
          // under this peer's certified key didn't come from them.
          if (ev.kt === null || !ev.kb) { this.log('drop unsealed accept from', ev.fromName); return; }
          await this.open(ev.from, ev.kt, ev.kb);
          if (this.ringTimer) { clearTimeout(this.ringTimer); this.ringTimer = null; }
          const p = this.peers.get(ev.from) || { id: ev.from, name: ev.fromName, status: 'connecting' as const };
          p.status = 'connecting'; this.peers.set(ev.from, p);
          if (this.phase === 'outgoing') this.phase = 'active';
          // mesh rule: lower id offers
          this.log('accept received from', ev.fromName, '— I offer:', this.me.id < ev.from);
          if (this.me.id < ev.from) await this.makeOffer(ev.from, ev.fromName);
          else this.armWatchdog(ev.from); // we expect THEIR offer; don't wait silently
          this.emit();
          return;
        }
        case 'offer': {
          if (ev.callId !== this.callId || ev.kt === null || !ev.kb) { this.log('drop offer from', ev.fromName, ev.callId !== this.callId ? '(callId mismatch)' : '(no sealed payload)'); return; }
          const payload = await this.open(ev.from, ev.kt, ev.kb);
          this.log('offer received from', ev.fromName);
          const pc = this.pcs.get(ev.from) || await this.newPC(ev.from, ev.fromName);
          // Glare (both sides offered at once, e.g. simultaneous camera toggles):
          // the HIGHER-id peer is polite — it rolls back its own pending offer and
          // answers instead (its already-attached tracks ride in the answer, since
          // every offer carries audio+video m-lines). The lower-id peer ignores
          // the colliding offer and waits for the answer to its own.
          if (pc.signalingState === 'have-local-offer') {
            const polite = this.me.id > ev.from;
            if (!polite) { this.log('offer glare with', ev.fromName, '— ignoring (impolite side)'); return; }
            this.log('offer glare with', ev.fromName, '— rolling back (polite side)');
            try { await pc.setLocalDescription({ type: 'rollback' } as RTCSessionDescriptionInit); } catch (e) { this.log('rollback failed:', e); }
          }
          await pc.setRemoteDescription(payload.sdp);
          await this.flushIce(ev.from);
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          const { kt, kb } = await this.seal(ev.from, { sdp: pc.localDescription });
          await this.send(ev.from, ev.callId, 'answer', kt, kb);
          this.armWatchdog(ev.from);
          return;
        }
        case 'answer': {
          if (ev.callId !== this.callId || ev.kt === null || !ev.kb) return;
          const payload = await this.open(ev.from, ev.kt, ev.kb);
          this.log('answer received from', ev.fromName);
          const pc = this.pcs.get(ev.from); if (!pc) return;
          // A stale answer can arrive after a glare rollback (we no longer have a
          // local offer outstanding) — applying it would throw and kill the chain.
          if (pc.signalingState !== 'have-local-offer') { this.log('drop answer from', ev.fromName, '(no local offer outstanding)'); return; }
          await pc.setRemoteDescription(payload.sdp);
          await this.flushIce(ev.from);
          return;
        }
        case 'ice': {
          if (ev.callId !== this.callId || ev.kt === null || !ev.kb) return;
          const payload = await this.open(ev.from, ev.kt, ev.kb);
          const pc = this.pcs.get(ev.from);
          if (pc && pc.remoteDescription) { try { await pc.addIceCandidate(payload.ice); } catch {} }
          else { const q = this.pendingIce.get(ev.from) || []; q.push(payload.ice); this.pendingIce.set(ev.from, q); }
          return;
        }
        case 'decline': {
          if (ev.callId !== this.callId) return;
          const p = this.peers.get(ev.from); if (p) p.status = 'left';
          this.emit(); this.pruneIfEmpty();
          return;
        }
        case 'hangup': {
          if (this.incoming?.callId === ev.callId && this.incoming.fromId === ev.from) { this.incoming = null; this.phase = 'idle'; this.emit(); return; }
          if (ev.callId !== this.callId) return;
          const pc = this.pcs.get(ev.from); try { pc?.close(); } catch {}
          const p = this.peers.get(ev.from); if (p) p.status = 'left';
          this.emit(); this.pruneIfEmpty();
          return;
        }
      }
    } catch (e: any) {
      // Never crash the call on one bad signal — but never hide it either.
      this.log('signal handler ERROR on', ev.kind, 'from', ev.fromName, ':', String(e?.message || e));
    }
  }
}

export const callDigest = b64; // (exported for potential future fingerprint UI)
