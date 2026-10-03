/**
 * V8 phase 2 — the client side of signed membership (H-2) and end-to-end
 * encrypted profiles (M-8).
 *
 * Per node this keeps: the pinned identity of its network's root (the trust
 * anchor), the verified member set derived from signed certificates, the network
 * keys it has been given (key boxes), and the decrypted names of everyone it can
 * see. It also does the chores only a client can do: the root's one-time
 * migration and key rotation, filling in key boxes for members who lack the
 * current key, and re-encrypting this node's own profile.
 *
 * Nothing here trusts the server's word about WHO is a member: a recipient is
 * encrypted to only when a chain of signatures from the pinned root names both
 * its id and its identity key (see decideRecipients).
 */
import type { User } from '../types';
import * as m from './membership';
import * as pr from './profiles';
import * as signal from './signal';
import * as keyStore from './keyStore';

type Post = (endpoint: string, body: any) => Promise<any>;
type Get = (endpoint: string) => Promise<any>;
type Pin = { tree: string; anchor: string | null; tofu: boolean };
/** Where this device's knowledge of its network owner stands (v70 H2):
 *  ok — pinned from an invite link / the owner itself; first-sight — trusted the
 *  oldest owner certificate once (pre-signed-membership members only);
 *  missing — a pin existed but can't be read, or none may be taken: nothing verifies. */
export type PinState = 'ok' | 'first-sight' | 'missing';
/** Device-local storage for sealed root pins (IndexedDB by default; swappable in tests). */
export interface PinStore { get(nodeId: string): Promise<string | null>; put(nodeId: string, sealed: string): Promise<void> }
const idbPins: PinStore = { get: keyStore.getRootPinSealed, put: keyStore.putRootPinSealed };

const te = new TextEncoder(), td = new TextDecoder();
const wrapJson = (o: any) => keyStore.wrapBytes(te.encode(JSON.stringify(o)).buffer as ArrayBuffer);
const unwrapJson = async (s: string) => JSON.parse(td.decode(await keyStore.unwrapBytes(s)));
const CHORE_INTERVAL_MS = 15000;
/** Label for a member whose profile this device can't decrypt (yet). */
export const UNKNOWN_NAME = 'Member';
/** v72 B2: shown when a join/contact request can't be verified (and so can't be accepted). */
export const UNVERIFIED_REQUEST = 'Arbor can’t verify this request came from the person it names, so it can’t be accepted. Decline it and ask them to join again with a fresh invite link.';
const emptyTrust = (tree = ''): m.Trust => ({ tree, rootIk: null, anchored: false, members: new Map(), bound: new Map(), legacy: new Set(), epoch: null, hasRoot: false, conflicts: new Set() });

export interface RecipientDecision { id: string; ik: string | null; verified: boolean }
export interface JoinPrep {
  code: string; secret: m.InviteSecret; tree: string; hub: boolean;
  inviteCert: string; inviteId: string; invitePriv: Uint8Array; rootIk: string; aa: boolean;
}

export class NetTrust {
  private keyring = new Map<string, Uint8Array>();            // `${tree}|${kid}` → network key
  private curKid = new Map<string, string>();                  // tree → newest key id known to be current
  private pins = new Map<string, Pin>();                       // nodeId → pinned root
  private trusts = new Map<string, m.Trust>();                 // nodeId → verified view of its tree
  private ids = new Map<string, { ik: string; priv: Uint8Array }>();
  private names = new Map<string, string>();                  // pid → display name
  private profiles = new Map<string, pr.ProfileData>();       // pid → decrypted profile
  private selfLabels = new Map<string, { n?: string; t?: string }>(); // nodeId → selfCt contents
  private joinReqs = new Map<string, any[]>();                // nodeId → last join requests
  private serverIk = new Map<string, string>();               // pid → identity key the server reported
  private lastChores = new Map<string, number>();
  private pinStates = new Map<string, PinState>();            // nodeId → how its owner is known
  private healed = new Set<string>();                         // nodeIds whose server pin copy was re-sent
  private hubActive = new Map<string, Set<string>>();         // hub nodeId → its ACTIVE contacts (v72 B3)

  constructor(private post: Post, private get: Get, private pinStore: PinStore = idbPins) {}

  /** Drop everything decrypted (logout, app re-lock). Reloaded from sealed stores. */
  reset(): void {
    for (const k of this.keyring.values()) k.fill(0);
    for (const v of this.ids.values()) v.priv.fill(0);
    [this.keyring, this.curKid, this.pins, this.trusts, this.ids, this.names, this.profiles, this.selfLabels, this.joinReqs, this.serverIk, this.lastChores, this.pinStates, this.healed, this.hubActive].forEach(x => x.clear());
  }

  keyFor = (tree: string, kid: string): Uint8Array | null => this.keyring.get(`${tree}|${kid}`) || null;
  nameOf(pid: string | null | undefined): string | null { return (pid && this.names.get(pid)) || null; }
  trustOf(nodeId: string): m.Trust | null { return this.trusts.get(nodeId) || null; }
  isVerified(nodeId: string, pid: string): boolean {
    const t = this.trusts.get(nodeId);
    return !!t && (t.members.has(pid) || (pid === t.tree && !!t.rootIk));
  }
  ownProfile(nodeId: string): pr.ProfileData | null { return this.profiles.get(nodeId) || null; }
  selfLabelOf(nodeId: string): { n?: string; t?: string } | null { return this.selfLabels.get(nodeId) || null; }
  photoKeyOf(pid: string): string | null { return this.profiles.get(pid)?.av?.k || null; }

  private remember(tree: string, kid: string, key: Uint8Array) { this.keyring.set(`${tree}|${kid}`, key); }
  private current(tree: string, t?: m.Trust | null): { kid: string; key: Uint8Array } | null {
    const kid = t?.epoch?.kid || this.curKid.get(tree);
    const key = kid ? this.keyFor(tree, kid) : null;
    return kid && key ? { kid, key } : null;
  }

  async identity(nodeId: string): Promise<{ ik: string; priv: Uint8Array }> {
    const hit = this.ids.get(nodeId);
    if (hit) return hit;
    const r = await signal.exportIdentityRaw(nodeId);
    const v = { ik: m.b64(new Uint8Array(r.pub)), priv: new Uint8Array(r.priv) };
    this.ids.set(nodeId, v);
    return v;
  }

  // ------------------------------------------------------------------ pins ---
  /**
   * The pinned owner of `tree` for this node (v70 H2). Sources, in order:
   *   1. memory; 2. this DEVICE's sealed pin (IndexedDB — survives reloads and
   *   logout; restored from the encrypted state backup on a new device);
   *   3. the server's copy (anchorCt, sealed under the account key: the server
   *   can withhold it but not forge it).
   * Only a node that has NEVER had a pin on this device may trust the oldest
   * owner certificate on first sight — and only during the pre-signed-membership
   * transition window, and never from the send path. Everyone else gets
   * 'missing': no pin, so nothing verifies and the UI says so.
   */
  private async pinFor(node: User, tree: string, anchorCt: string | undefined, certs: string[], allowFirstSight = true): Promise<Pin> {
    if (node.id === tree) { this.pinStates.set(node.id, 'ok'); return { tree, anchor: await m.anchorOf((await this.identity(node.id)).ik), tofu: false }; }
    const mem = this.pins.get(node.id);
    if (mem && mem.tree === tree && mem.anchor) return mem;
    const dev = await this.devicePin(node.id);
    if (dev && dev !== 'unreadable' && dev.tree === tree) {
      this.use(node.id, dev);
      // The server lost (or withheld) its copy: send it again, once per session.
      if (allowFirstSight && !anchorCt && !this.healed.has(node.id)) {
        this.healed.add(node.id);
        try { await this.post('/profile/set', { nodeId: node.id, anchorCt: await wrapJson(dev) }); } catch {}
      }
      return dev;
    }
    if (anchorCt) {
      try {
        const o = await unwrapJson(anchorCt);
        if (o && o.tree === tree && typeof o.anchor === 'string') {
          const v = { tree, anchor: o.anchor, tofu: !!o.tofu };
          this.use(node.id, v);
          await this.saveDevicePin(node.id, v);
          return v;
        }
      } catch { /* unreadable: fall through */ }
    }
    // A pin existed on this device (sealed under a key we don't hold now, or for
    // another network): never fall back to first sight.
    if (dev || !allowFirstSight || Date.now() >= m.LEGACY_GRACE_END) {
      this.pinStates.set(node.id, 'missing');
      return { tree, anchor: null, tofu: false };
    }
    // First sight, for a member from before signed membership (new joiners always
    // bring the pin in their invite link): trust the oldest well-signed root cert.
    const t = await m.verifyTree(tree, null, certs);
    if (!t.rootIk) { this.pinStates.set(node.id, 'missing'); return { tree, anchor: null, tofu: false }; }
    const anchor = await m.anchorOf(t.rootIk);
    await this.pin(node.id, tree, anchor, true);
    return { tree, anchor, tofu: true };
  }
  /** Verify a tree against a pin. No pin → nothing is verified (never first sight here). */
  private async verified(tree: string, pin: Pin, certs: string[]): Promise<m.Trust> {
    return pin.anchor ? m.verifyTree(tree, pin.anchor, certs) : emptyTrust(tree);
  }
  private use(nodeId: string, p: Pin) { this.pins.set(nodeId, p); this.pinStates.set(nodeId, p.tofu ? 'first-sight' : 'ok'); }
  private async devicePin(nodeId: string): Promise<Pin | 'unreadable' | null> {
    let raw: string | null = null;
    try { raw = await this.pinStore.get(nodeId); } catch { return null; }
    if (!raw) return null;
    try {
      const o = await unwrapJson(raw);
      if (o && typeof o.tree === 'string' && typeof o.anchor === 'string') return { tree: o.tree, anchor: o.anchor, tofu: !!o.tofu };
    } catch { /* locked, or sealed under another key */ }
    return 'unreadable';
  }
  private async saveDevicePin(nodeId: string, p: Pin): Promise<void> {
    try { await this.pinStore.put(nodeId, await wrapJson({ tree: p.tree, anchor: p.anchor, tofu: p.tofu })); } catch { /* locked: kept in memory + on the server */ }
  }
  /** Pin `tree`'s owner for this node: memory, this device, and the server's copy. */
  async pin(nodeId: string, tree: string, anchor: string, tofu: boolean): Promise<void> {
    const p = { tree, anchor, tofu };
    this.use(nodeId, p);
    await this.saveDevicePin(nodeId, p);
    try { await this.post('/profile/set', { nodeId, anchorCt: await wrapJson(p) }); } catch { /* retried next sync */ }
  }
  hasPin(nodeId: string, tree: string): boolean {
    const p = this.pins.get(nodeId);
    return nodeId === tree || !!(p && p.tree === tree && p.anchor);
  }
  pinStatus(nodeId: string): PinState | null { return this.pinStates.get(nodeId) || null; }
  /** For the encrypted state backup (so a new device starts with the pin). */
  async exportPin(nodeId: string): Promise<Pin | null> {
    const mem = this.pins.get(nodeId);
    if (mem && mem.anchor) return mem;
    const dev = await this.devicePin(nodeId);
    return dev && dev !== 'unreadable' ? dev : null;
  }
  /** From a restored backup: adopt the pin unless this device already has a readable one. */
  async importPin(nodeId: string, p: any): Promise<void> {
    if (!p || typeof p.tree !== 'string' || typeof p.anchor !== 'string') return;
    const dev = await this.devicePin(nodeId);
    if (dev && dev !== 'unreadable') return;
    const v = { tree: p.tree, anchor: p.anchor, tofu: !!p.tofu };
    await this.saveDevicePin(nodeId, v);
    if (!this.pins.get(nodeId)?.anchor) this.use(nodeId, v);
  }
  /** Re-seal this node's device pin and server pin copy under the current account
   *  key (after the password-hashing upgrade changed it). */
  async resealPin(nodeId: string, anchorCt?: string): Promise<void> {
    let p: Pin | null = this.pins.get(nodeId) || null;
    if (!p?.anchor) { const dev = await this.devicePin(nodeId); p = dev && dev !== 'unreadable' ? dev : null; }
    if (!p?.anchor && anchorCt) { try { const o = await unwrapJson(anchorCt); if (o && typeof o.tree === 'string' && typeof o.anchor === 'string') p = { tree: o.tree, anchor: o.anchor, tofu: !!o.tofu }; } catch {} }
    if (!p?.anchor) return;
    await this.saveDevicePin(nodeId, p);
    try { await this.post('/profile/set', { nodeId, anchorCt: await wrapJson(p), replaceAnchor: true }); } catch {}
  }

  // ------------------------------------------------------------ key boxes ---
  private async openBoxes(node: User, tree: string, t: m.Trust, boxes: m.Box[], hub: boolean, users: any[]) {
    const me = await this.identity(node.id);
    for (const b of boxes || []) {
      if (!b || b.to !== node.id || this.keyFor(b.tree, b.kid)) continue;
      let fromIk: string | null = null;
      if (b.from === node.id) fromIk = me.ik;                                   // my own self-box
      else if (b.tree === tree) fromIk = b.from === tree ? t.rootIk : (t.members.get(b.from)?.ik || null); // a VERIFIED member of my network
      else if (hub && b.from === b.tree) {                                        // a contact's own hub key, from that contact
        // v71 M3: vouched contact → its certified key; otherwise the key this
        // device's session with them is pinned to (server's claim only before one).
        fromIk = t.members.get(b.from)?.ik || await this.contactIk(node.id, b.from, users.find(u => u.id === b.from)?.ik) || null;
      }
      if (!fromIk) continue;
      const k = await m.openBox(b, me.priv, fromIk);
      if (k) this.remember(b.tree, b.kid, k);
    }
  }
  private async boxTo(from: User, tree: string, kid: string, key: Uint8Array, to: string, toIk: string): Promise<m.Box> {
    const me = await this.identity(from.id);
    return m.sealBox(key, { tree, kid, from: from.id, to }, me.priv, toIk);
  }
  private async submitBoxes(nodeId: string, boxes: m.Box[]) {
    for (let i = 0; i < boxes.length; i += 400) await this.post('/netkeys/box', { nodeId, boxes: boxes.slice(i, i + 400) });
  }
  private async submitCerts(nodeId: string, certs: string[]) {
    for (let i = 0; i < certs.length; i += 400) await this.post('/certs/submit', { nodeId, certs: certs.slice(i, i + 400) });
  }

  // ------------------------------------------------------------ profiles ---
  /**
   * v71 M3: the identity key to check a NON-certified peer's signatures with
   * (personal-hub contacts added by id, pre-membership legacy members). The key
   * this device's Signal session is pinned to wins; the server's claim is used only
   * before any session exists (first contact — the same trust-on-first-use step
   * the session itself takes). v70 always used the server's claim, so a malicious
   * server could sign a fake name/photo for such a contact under a key of its own.
   */
  private async contactIk(nodeId: string, pid: string, serverIk: string | null | undefined): Promise<string | null> {
    const pinned = await signal.remoteIdentity(nodeId, pid).catch(() => null);
    return pinned || serverIk || null;
  }

  /**
   * v71: open a profile and ENFORCE its owner's signature whenever this device
   * knows the owner's identity key. v70 computed `signed` but never used it, so a
   * profile the owner never signed (any member holds the network key and can seal
   * one for someone else's id; the server decides whose it is) was still shown
   * under that member's name. With no key known yet there is nothing to check
   * against, and the result is shown as before.
   */
  private async openProfileChecked(ct: string, pid: string, ik: string | null): Promise<Awaited<ReturnType<typeof pr.openProfile>>> {
    const op = await pr.openProfile(ct, pid, this.keyFor, ik);
    if (!op) return null;
    if (ik && !op.signed) { try { console.warn('[trust] ignored a profile not signed by its owner:', pid); } catch {} return null; }
    return op;
  }

  private async openUser(u: any, t: m.Trust | null, nodeId?: string): Promise<void> {
    const certIk = t ? (u.id === t.tree ? t.rootIk : t.members.get(u.id)?.ik || null) : null;
    u.memberVerified = !!certIk;
    if (u.ik) this.serverIk.set(u.id, u.ik);
    if (u.profileCt) {
      const ik = certIk || (nodeId && !u.isMe ? await this.contactIk(nodeId, u.id, u.ik) : u.ik) || null;
      const op = await this.openProfileChecked(u.profileCt, u.id, ik);
      if (op) {
        u.name = op.p.n; u.bio = op.p.b || ''; u.nameHistory = op.p.h || [];
        u.profileSigned = op.signed; u.profileLocked = false;
        this.profiles.set(u.id, op.p);
        this.names.set(u.id, op.p.n);
      } else {
        u.profileLocked = true;
        u.name = this.names.get(u.id) || (u.isMe && this.selfLabels.get(u.id)?.n) || UNKNOWN_NAME;
      }
    } else if (typeof u.name === 'string' && u.name) {
      u.legacyProfile = true;                          // owner hasn't opened an updated app yet
      this.names.set(u.id, u.name);
    } else {
      u.name = this.names.get(u.id) || (u.isMe && this.selfLabels.get(u.id)?.n) || UNKNOWN_NAME;
    }
  }

  /** Seal and upload this node's profile under the current network key. */
  async writeProfile(node: User, tree: string, p: pr.ProfileData, opts: { avatarDataUrl?: string | null; kid?: string; key?: Uint8Array } = {}): Promise<{ avatarAt: number }> {
    const cur = opts.kid && opts.key ? { kid: opts.kid, key: opts.key } : this.current(tree, this.trusts.get(node.id));
    if (!cur) throw new Error('This network’s encryption key hasn’t reached this device yet. Try again in a moment.');
    const clean = pr.cleanName(p.n, 64);
    if (!clean) throw new Error('Name must be 1–64 visible characters (no control, invisible, or text-direction characters).');
    const me = await this.identity(node.id);
    const body: any = { nodeId: node.id };
    const next: pr.ProfileData = { ...p, n: clean, ts: Date.now() };
    if (opts.avatarDataUrl) {
      const a = await pr.sealAvatar(opts.avatarDataUrl, node.id);
      body.avatarCt = a.blob;
      next.av = { k: a.key, at: Date.now() };
    } else if (opts.avatarDataUrl === null) {
      body.removeAvatar = true;
      next.av = null;
    }
    body.profileCt = await pr.sealProfile(next, { tree, pid: node.id, kid: cur.kid, netKey: cur.key, identityPriv: me.priv });
    const r = await this.post('/profile/set', body);
    this.profiles.set(node.id, next);
    this.names.set(node.id, next.n);
    await this.writeSelf(node.id, { n: next.n });
    return { avatarAt: r?.avatarAt || 0 };
  }

  /** The owner-only label (name + network name) the network picker shows. */
  async writeSelf(nodeId: string, patch: { n?: string; t?: string }): Promise<void> {
    const cur = this.selfLabels.get(nodeId) || {};
    const next = { ...cur, ...patch };
    if (cur.n === next.n && cur.t === next.t) return;
    this.selfLabels.set(nodeId, next);
    try { await this.post('/profile/set', { nodeId, selfCt: await wrapJson(next) }); } catch { /* next sync retries */ }
  }
  async readSelf(n: any): Promise<{ n?: string; t?: string } | null> {
    if (!n?.selfCt) return null;
    try {
      const o = await unwrapJson(n.selfCt);
      const v = { n: pr.cleanName(o?.n, 64) || undefined, t: pr.cleanName(o?.t, 80) || undefined };
      this.selfLabels.set(n.id, v);
      return v;
    } catch { return null; }
  }

  /** Root: seal the network name. */
  async writeTreeName(node: User, tree: string, name: string): Promise<void> {
    const clean = pr.cleanName(name, 80);
    if (!clean) throw new Error('Name must be 1–80 visible characters.');
    const cur = this.current(tree, null) || this.current(tree, this.trusts.get(node.id));
    if (!cur) throw new Error('This network’s encryption key hasn’t reached this device yet.');
    const me = await this.identity(node.id);
    const treeNameCt = await pr.sealTreeName(clean, { tree, kid: cur.kid, netKey: cur.key, rootPriv: me.priv });
    await this.post('/profile/set', { nodeId: node.id, treeNameCt });
    await this.writeSelf(node.id, { t: clean });
  }

  // ------------------------------------------------------- the sync pass ---
  /**
   * Run on every tree-context fetch, BEFORE messages are ingested: verify the
   * certificates, open key boxes, decrypt every visible profile in place (so
   * the UI keeps reading user.name), then run the owner/root chores.
   */
  async sync(node: User, data: any): Promise<void> {
    const users: any[] = Array.isArray(data.users) ? data.users : [];
    const self = users.find(u => u.isMe) || users.find(u => u.id === node.id);
    if (self?.selfCt) await this.readSelf(self);

    // A requester awaiting approval: only its own self-box, and the inviter's name.
    if (data.pendingApproval) {
      await this.openBoxes(node, '', emptyTrust(), data.boxes, false, users);
      for (const u of users) await this.openUser(u, null);
      if (data.inviterProfileCt && data.inviterId) {
        const op = await this.openProfileChecked(data.inviterProfileCt, data.inviterId, data.inviterIk || null);
        if (op) { data.inviterName = op.p.n; this.names.set(data.inviterId, op.p.n); }
      }
      return;
    }

    const tree: string = data.treeRoot || self?.treeRoot || node.id;
    const hub = (self?.treeMode || node.treeMode) === 'HUB';
    const pin = await this.pinFor(node, tree, self?.anchorCt, data.certs || []);
    const t = await this.verified(tree, pin, data.certs || []);
    this.trusts.set(node.id, t);
    if (t.epoch) this.curKid.set(tree, t.epoch.kid);
    if (self) self.ownerPin = this.pinStatus(node.id) || undefined;
    if (t.conflicts.size) { try { console.warn('[trust] ignored certificates that tried to re-key members:', [...t.conflicts]); } catch {} }

    await this.openBoxes(node, tree, t, data.boxes, hub, users);
    for (const u of users) await this.openUser(u, t, node.id);
    if (hub) this.hubActive.set(node.id, new Set(users.filter(u => !u.isMe && u.id !== node.id && !u.pending).map(u => u.id)));
    // Network name: the root's entry (visibility-gated by the server) for the header…
    // v72 (L): ONLY the root's own entry names the network. v71 also opened a name
    // on any other entry, unsigned, and the header fell back to it — so a member (or
    // the server) could show everyone a network name the root never set.
    for (const u of users) {
      if (u.id !== tree) { delete u.treeName; continue; }
      if (!u.treeNameCt) continue;
      const tn = await pr.openTreeName(u.treeNameCt, this.keyFor, t.rootIk);
      if (tn && (tn.signed || !t.rootIk)) u.treeName = tn.name; else delete u.treeName;   // v71: the root's signature is enforced
    }
    // …and the picker label (always, for members).
    let myTreeName: string | undefined;
    if (data.treeNameCt) { const tn = await pr.openTreeName(data.treeNameCt, this.keyFor, t.rootIk); if (tn && (tn.signed || !t.rootIk)) myTreeName = tn.name; }

    // Join / contact requests (v72 B2). A request can be accepted only when its
    // key is VERIFIED — never on the server's word alone:
    //   'link'    — the joiner's key is the one its invite LINK bound (signed join
    //               cert), or a certificate already names it;
    //   'network' — personal hub, "Add to my hub": the requester's certified key in
    //               a network this node's account shares signed for its hub's key.
    // Anything else is shown as unverified and can't be accepted.
    const jrs: any[] = Array.isArray(data.joinRequests) ? data.joinRequests : [];
    for (const jr of jrs) {
      let vik: string | null = t.bound.get(jr.id) || t.members.get(jr.id)?.ik || null;
      let via: 'link' | 'network' | null = vik ? 'link' : null;
      if (!vik && hub && jr.attest) { vik = await this.checkHubAttest(jr).catch(() => null); if (vik) via = 'network'; }
      jr.verifiedIk = vik; jr.verified = via;
      jr.linkVerified = !!vik;
      const bound = vik;
      if (jr.ik) this.serverIk.set(jr.id, jr.ik);
      if (jr.profileCt) {
        const op = await this.openProfileChecked(jr.profileCt, jr.id, bound || jr.ik || null);
        jr.name = op ? op.p.n : UNKNOWN_NAME;
        if (op) this.names.set(jr.id, op.p.n);
      } else if (!jr.name) jr.name = UNKNOWN_NAME;
      if (jr.referredBy && jr.referredByProfileCt) {
        const op = await this.openProfileChecked(jr.referredByProfileCt, jr.referredBy, t.members.get(jr.referredBy)?.ik || jr.referredByIk || null);
        if (op) jr.referredByName = op.p.n;
      }
    }
    this.joinReqs.set(node.id, jrs);

    // Look-alike names (V8 L-8) — only the viewer can compare decrypted names now.
    const counts = new Map<string, number>();
    const sk = (u: any) => (u.name && u.name !== UNKNOWN_NAME ? pr.nameSkeleton(u.name) : '');
    for (const u of users) { const k = sk(u); if (k) counts.set(k, (counts.get(k) || 0) + 1); }
    for (const u of users) { const k = sk(u); u.nameClash = !!k && (counts.get(k) || 0) > 1; }

    // Names on acks / reactions (the server keeps ids only).
    const nm = (id: string) => this.names.get(id) || UNKNOWN_NAME;
    if (data.acks && typeof data.acks === 'object') for (const mid of Object.keys(data.acks)) data.acks[mid] = (data.acks[mid] || []).map((a: any) => ({ ...a, name: nm(a.id) }));
    if (data.reactions && typeof data.reactions === 'object') for (const mid of Object.keys(data.reactions)) {
      const r = data.reactions[mid];
      for (const e of Object.keys(r || {})) r[e] = (r[e] || []).map((x: any) => ({ ...x, name: nm(x.id) }));
    }
    if (self && Array.isArray(self.visiting)) for (const v of self.visiting) v.ownerName = this.names.get(v.o) || undefined;

    // Chores (writes). Throttled; a root without its certificates goes right away.
    const due = (Date.now() - (this.lastChores.get(node.id) || 0)) > CHORE_INTERVAL_MS
      || (node.id === tree && !t.rootIk) || !!self?.rotateNeeded;
    if (due) {
      this.lastChores.set(node.id, Date.now());
      try { await this.chores(node, data, t, tree, hub, self, myTreeName); }
      catch (e) { try { console.warn('[trust] chores deferred:', (e as any)?.message || e); } catch {} }
    }
  }

  private async chores(node: User, data: any, t: m.Trust, tree: string, hub: boolean, self: any, myTreeName?: string) {
    const users: any[] = data.users || [];
    const me = await this.identity(node.id);
    const isRoot = node.id === tree;
    const ts = Date.now();
    const certs: string[] = [];
    const boxes: m.Box[] = [];
    const present = (pid: string) => users.find(u => u.id === pid && !u.pending);
    const everyone = users.filter(u => u.id !== node.id && !u.pending);
    const withKeys = everyone.filter(u => typeof u.ik === 'string' && u.ik);

    if (isRoot) {
      let rotate = false;
      if (!t.rootIk) {
        // One-time upgrade of this network: root certificate, first network key,
        // and a SIGNED list of the members that exist right now, vouched on the
        // keys the server reports at this moment (the migration's one TOFU step).
        certs.push(await m.makeCert({ k: 'root', v: 1, tree, pid: tree, ik: me.ik, ts }, me.priv));
        const roster = everyone.map(u => u.id);
        for (let i = 0; i < roster.length; i += m.LEGACY_CHUNK) {
          certs.push(await m.makeCert({ k: 'legacy', v: 1, tree, by: tree, pids: roster.slice(i, i + m.LEGACY_CHUNK), ts }, me.priv));
        }
        for (const u of withKeys) certs.push(await m.makeCert({ k: 'vouch', v: 1, tree, by: tree, pid: u.id, ik: u.ik, ts }, me.priv));
        rotate = true;
      } else {
        // Members on the signed legacy roster who only now have an identity key
        // get vouched (the server can't add names to that signed list).
        for (const pid of t.legacy) {
          if (t.members.has(pid)) continue;
          const u = present(pid);
          if (u && u.ik) certs.push(await m.makeCert({ k: 'vouch', v: 1, tree, by: tree, pid, ik: u.ik, ts }, me.priv));
        }
        if (self?.rotateNeeded || !this.current(tree, t)) rotate = true; // someone left, or the key never reached this device
      }
      if (rotate) {
        const kid = m.newKid(), key = m.newNetKey();
        certs.push(await m.makeCert({ k: 'epoch', v: 1, tree, by: tree, kid, ts: ts + 1 }, me.priv));
        this.remember(tree, kid, key);
        this.curKid.set(tree, kid);
        boxes.push(await this.boxTo(node, tree, kid, key, node.id, me.ik));
        // Everyone still here gets the new key: verified members by their
        // certified key; at the one-time upgrade, the members just vouched; for a
        // personal hub, contacts by the key their contact edge carries.
        const recipients = new Map<string, string>();
        for (const [pid, mi] of t.members) recipients.set(pid, mi.ik);
        if (!t.rootIk || hub) for (const u of withKeys) if (!recipients.has(u.id)) recipients.set(u.id, u.ik);
        for (const [pid, ik] of recipients) if (pid !== node.id && present(pid)) boxes.push(await this.boxTo(node, tree, kid, key, pid, ik));
      }
      if (certs.length) await this.submitCerts(node.id, certs);
      if (boxes.length) await this.submitBoxes(node.id, boxes);
      certs.length = 0; boxes.length = 0;
    }

    // Fill in the current key for members who lack it (any holder may do this).
    const cur = isRoot ? this.current(tree, null) : this.current(tree, t);
    if (cur && Array.isArray(data.netNeed)) {
      for (const pid of data.netNeed.slice(0, 100)) {
        if (pid === node.id) { boxes.push(await this.boxTo(node, tree, cur.kid, cur.key, pid, me.ik)); continue; }
        const ik = (pid === tree ? t.rootIk : t.members.get(pid)?.ik) || (hub ? present(pid)?.ik : null);
        if (ik) boxes.push(await this.boxTo(node, tree, cur.kid, cur.key, pid, ik));
      }
      if (boxes.length) await this.submitBoxes(node.id, boxes);
    }

    // My own profile: migrate a legacy plaintext one, or re-seal after rotation.
    const label = this.selfLabels.get(node.id);
    if (cur && self) {
      const hdr = pr.profileHeader(self.profileCt);
      const mine = this.profiles.get(node.id);
      // (self.name is a placeholder unless the server sent a legacy plaintext one.)
      const legacyName = self.profileCt ? null : ((self.legacyProfile && pr.cleanName(self.name, 64)) || label?.n || null);
      if (legacyName) {
        const p: pr.ProfileData = { n: legacyName, ts };
        if (typeof self.bio === 'string' && self.bio) p.b = self.bio.slice(0, 500);
        if (Array.isArray(self.nameHistory)) p.h = self.nameHistory.slice(-50);
        let avatar: string | undefined;
        if (self.avatarAt) {
          try {
            const r = await this.get(`/users/${encodeURIComponent(node.id)}/avatar?viewerNodeId=${encodeURIComponent(node.id)}`);
            if (typeof r?.avatar === 'string' && r.avatar.startsWith('data:')) avatar = r.avatar;
          } catch {}
        }
        await this.writeProfile(node, tree, p, { ...(avatar ? { avatarDataUrl: avatar } : {}), kid: cur.kid, key: cur.key });
      } else if (mine && hdr && hdr.kid !== cur.kid) {
        await this.writeProfile(node, tree, mine, { kid: cur.kid, key: cur.key });
      }
    }
    // Root: the network name follows the same path.
    if (isRoot && cur && self) {
      const hdr = pr.profileHeader(self.treeNameCt);
      const plain = typeof self.treeName === 'string' ? pr.cleanName(self.treeName, 80) : null;
      const who = (self.name && self.name !== UNKNOWN_NAME ? self.name : label?.n) || null;
      const name = (!self.treeNameCt && plain) || (hdr && hdr.kid !== cur.kid ? plain : null)
        || (!self.treeNameCt && !plain && who ? (hub ? `${who}'s Chats` : `${who}'s Network`) : null);
      if (name) await this.writeTreeName(node, tree, name).catch(() => {});
    }
    if (self) {
      const n = self.name && self.name !== UNKNOWN_NAME ? self.name : undefined;
      const tn = myTreeName || (isRoot && typeof self.treeName === 'string' ? self.treeName : undefined);
      await this.writeSelf(node.id, { ...(n ? { n } : {}), ...(tn ? { t: tn } : {}) });
    }
  }

  // ------------------------------------------------------- recipients ---
  /**
   * Which of the server-listed recipients this device will actually encrypt to.
   * Verified: a certificate chain from the pinned root names the id AND identity
   * key (the caller then checks the Signal session is bound to that same key).
   * Unverified but allowed: the one contact picked for a personal-hub chat, or —
   * until LEGACY_GRACE_END — someone this device already had a session with.
   * Everyone else is refused.
   */
  async decideRecipients(node: User, r: any, ids: string[], o: { oneToOne: boolean; hub: boolean }): Promise<{ ok: RecipientDecision[]; refused: string[] }> {
    const tree: string = r.treeRoot;
    const pin = await this.pinFor(node, tree, undefined, r.certs || [], false);
    const t = await this.verified(tree, pin, r.certs || []);
    const ok: RecipientDecision[] = [], refused: string[] = [];
    for (const id of ids) {
      const mem = id === tree && t.rootIk ? { ik: t.rootIk } : t.members.get(id);
      if (mem) { ok.push({ id, ik: mem.ik, verified: true }); continue; }
      if (o.hub && o.oneToOne) { ok.push({ id, ik: null, verified: false }); continue; }
      if (Date.now() < m.LEGACY_GRACE_END && await signal.hasSession(node.id, id)) { ok.push({ id, ik: null, verified: false }); continue; }
      refused.push(id);
    }
    return { ok, refused };
  }

  // ------------------------------------------------------------ invites ---
  /**
   * The #fragment for an invite link: the link key (whose public half this
   * member signs into an invite certificate), the current network key, and the
   * root pin. Only this device and whoever gets the link ever see it.
   */
  async inviteFragment(signer: User, code: string, o: { aa: boolean; groupId?: string }): Promise<string> {
    const tree = signer.treeRoot || signer.id;
    const t = this.trusts.get(signer.id);
    if (!t || !t.rootIk) throw new Error('This network is still upgrading its security — try again once its owner has opened Arbor.');
    if (signer.id !== tree && !t.members.has(signer.id)) throw new Error('Your membership isn’t verified yet, so you can’t share invite links. Ask the network owner to open Arbor.');
    const cur = signer.id === tree ? this.current(tree, null) || this.current(tree, t) : this.current(tree, t);
    if (!cur) throw new Error('This network’s encryption key hasn’t reached this device yet. Try again in a moment.');
    const me = await this.identity(signer.id);
    const seed = await m.inviteSeed(me.priv, tree, code);
    const kp = await m.inviteKeys(seed);
    const ip = m.b64(kp.pub);
    const info = await this.post('/invites/info', { code, ip }).catch(() => null);
    let ok = false;
    if (info?.cert) {
      const c: any = await m.parseCert(info.cert);
      ok = !!c && c.b.k === 'inv' && c.b.by === signer.id && c.b.aa === o.aa && (c.b.g || undefined) === (o.groupId || undefined);
    }
    if (!ok) {
      const cert = await m.makeCert({ k: 'inv', v: 1, tree, by: signer.id, ip, aa: o.aa, ...(o.groupId ? { g: o.groupId } : {}), ts: Date.now() }, me.priv);
      await this.submitCerts(signer.id, [cert]);
    }
    const anchor = signer.id === tree ? await m.anchorOf(me.ik) : this.pins.get(signer.id)?.anchor;
    if (!anchor) throw new Error('This network’s owner isn’t pinned on this device yet.');
    return m.encodeFragment({ seed, kid: cur.kid, key: cur.key, anchor });
  }

  /** Joiner, before registering: check the link against the server's copy. */
  async prepareJoin(code: string, fragment: string): Promise<JoinPrep> {
    const secret = m.decodeFragment(fragment);
    if (!secret) throw new Error('This invite link is from an older version of Arbor or is incomplete. Ask for a new link (the full link, not just the code).');
    const kp = await m.inviteKeys(secret.seed);
    const ip = m.b64(kp.pub);
    const info = await this.post('/invites/info', { code, ip });
    const c: any = await m.parseCert(info.cert);
    if (!c || c.b.k !== 'inv' || c.b.ip !== ip || c.b.tree !== info.tree) throw new Error('This invite link doesn’t match the network it points to.');
    const rt = await m.verifyTree(info.tree, secret.anchor, info.rootCerts || []);
    if (!rt.rootIk) throw new Error('This invite link doesn’t match the network it points to.');
    return { code, secret, tree: info.tree, hub: !!info.hub, inviteCert: info.cert, inviteId: c.id, invitePriv: kp.priv, rootIk: rt.rootIk, aa: !!c.b.aa };
  }

  /** Joiner, right after registering: join cert, keys, pin, encrypted profile. */
  async completeJoin(node: User, j: JoinPrep, profile: pr.ProfileData, avatarDataUrl?: string): Promise<void> {
    const me = await this.identity(node.id);
    const ts = Date.now();
    const join = await m.makeCert({ k: 'join', v: 1, tree: j.tree, pid: node.id, ik: me.ik, inv: j.inviteId, ts }, j.invitePriv);
    await this.submitCerts(node.id, [join]);
    this.remember(j.tree, j.secret.kid, j.secret.key);
    // Keep the key across devices: box it to myself.
    await this.submitBoxes(node.id, [await this.boxTo(node, j.tree, j.secret.kid, j.secret.key, node.id, me.ik)]);
    if (!j.hub) {
      this.curKid.set(j.tree, j.secret.kid);
      await this.pin(node.id, j.tree, j.secret.anchor, false);
      await this.writeProfile(node, j.tree, profile, { kid: j.secret.kid, key: j.secret.key, ...(avatarDataUrl ? { avatarDataUrl } : {}) });
      return;
    }
    // Personal-hub link: I become a contact, not a member. My own hub is its own
    // tree; vouch the inviter (checked against the link's pin) into it and give
    // them my hub's key so they can read my name on the request.
    const myTree = node.id;
    await this.bootstrapRoot(node, myTree, profile, `${profile.n}'s Chats`, avatarDataUrl);
    await this.submitCerts(node.id, [await m.makeCert({ k: 'vouch', v: 1, tree: myTree, by: myTree, pid: j.tree, ik: j.rootIk, ts }, me.priv)]);
    const cur = this.current(myTree, null);
    if (cur) await this.submitBoxes(node.id, [await this.boxTo(node, myTree, cur.kid, cur.key, j.tree, j.rootIk)]);
  }

  /**
   * A network root (or a personal hub) gets its root certificate + first key if
   * it has none, then its profile and network name. For an EXISTING root this
   * only writes what's asked (its certificates already exist).
   */
  async bootstrapRoot(node: User, tree: string, profile: pr.ProfileData | null, treeName: string | null, avatarDataUrl?: string): Promise<void> {
    const me = await this.identity(node.id);
    let cur = this.current(tree, null);
    if (!cur) {
      const r = await this.post('/tree-context', { nodeId: node.id }).catch(() => null);
      if (r && !r.pendingApproval) {
        await this.sync(node, r);                       // an existing root: load (or create) its keys
        cur = this.current(tree, null);
        if (cur && r.users?.find((u: any) => u.isMe)?.profileCt) return; // already has a profile: nothing to redo
      }
    }
    if (!cur) {
      const ts = Date.now(), kid = m.newKid(), key = m.newNetKey();
      await this.submitCerts(node.id, [
        await m.makeCert({ k: 'root', v: 1, tree, pid: tree, ik: me.ik, ts }, me.priv),
        await m.makeCert({ k: 'epoch', v: 1, tree, by: tree, kid, ts }, me.priv),
      ]);
      this.remember(tree, kid, key);
      this.curKid.set(tree, kid);
      await this.submitBoxes(node.id, [await this.boxTo(node, tree, kid, key, node.id, me.ik)]);
      this.lastChores.set(node.id, Date.now());
      cur = { kid, key };
    }
    if (profile) await this.writeProfile(node, tree, profile, { kid: cur.kid, key: cur.key, ...(avatarDataUrl ? { avatarDataUrl } : {}) });
    if (treeName) await this.writeTreeName(node, tree, treeName);
  }

  // ------------------------------------------------------------ approvals ---
  /**
   * v72 B2: check an "Add to my hub" request's attestation. The requester's node
   * `by` in network `tree` signed that hub `jr.id` has key `ik` and addressed it to
   * `to` — this account's own node in that network. `by` must be a VERIFIED member
   * of that network under THIS device's pin for `to` (device pin or the sealed
   * server copy — never first sight), and the signature must be `by`'s certified
   * key. Returns the hub key to vouch for, or null.
   */
  private async checkHubAttest(jr: any): Promise<string | null> {
    const c = await m.parseCert(jr.attest);
    if (!c || c.b.k !== 'hubreq') return null;
    const b = c.b as Extract<m.CertBody, { k: 'hubreq' }>;
    if (b.hub !== jr.id || b.ts > Date.now() + m.FUTURE_SKEW_MS) return null;
    const certs: string[] = Array.isArray(jr.attestCerts) ? jr.attestCerts : [];
    const pin = await this.pinFor({ id: b.to } as User, b.tree, typeof jr.attestAnchorCt === 'string' ? jr.attestAnchorCt : undefined, certs, false);
    const t = await this.verified(b.tree, pin, certs);
    if (!t.rootIk) return null;
    const signerIk = b.by === b.tree ? t.rootIk : t.members.get(b.by)?.ik;
    if (!signerIk || !(await m.certSignedBy(c, signerIk))) return null;
    return b.ik;
  }

  /** v72 B3: is pid an accepted (not pending) contact of this personal hub, as of the last sync? */
  isActiveHubContact(nodeId: string, pid: string): boolean { return !!this.hubActive.get(nodeId)?.has(pid); }

  /** v72 B2: the verified key of a pending request, or null when it can't be verified. */
  verifiedRequestIk(approverId: string, targetId: string): string | null {
    const jr = (this.joinReqs.get(approverId) || []).find(x => x.id === targetId);
    if (jr && typeof jr.verifiedIk === 'string' && jr.verifiedIk) return jr.verifiedIk;
    // Not (yet) in the listed requests: the verified tree alone can still vouch for
    // it — the key its link bound, or a certificate already naming it. Never the
    // server's claim.
    const t = this.trusts.get(approverId);
    return (t && (t.bound.get(targetId) || t.members.get(targetId)?.ik)) || null;
  }

  /** v72 B2 (requester): sign an "Add to my hub" request with my certified key in
   *  the network I share with the target (`via` is my node there). */
  async hubRequestAttest(via: User, hubId: string, targetPid: string): Promise<string> {
    const tree = via.treeRoot || via.id;
    const me = await this.identity(via.id);
    const hubIk = (await this.identity(hubId)).ik;
    return m.makeCert({ k: 'hubreq', v: 1, tree, by: via.id, to: targetPid, hub: hubId, ik: hubIk, ts: Date.now() }, me.priv);
  }

  /** Approver (after the server accepted): vouch for the requester, give them the key.
   *  v72 B2: ONLY on a verified key (see sync); v71 fell back to the key the server
   *  reported, so a server could slip in a key of its own. */
  async approve(approver: User, targetId: string): Promise<void> {
    const tree = approver.treeRoot || approver.id;
    const t = this.trusts.get(approver.id);
    const ik = this.verifiedRequestIk(approver.id, targetId);
    if (!ik) throw new Error(UNVERIFIED_REQUEST);
    const me = await this.identity(approver.id);
    await this.submitCerts(approver.id, [await m.makeCert({ k: 'vouch', v: 1, tree, by: approver.id, pid: targetId, ik, ts: Date.now() }, me.priv)]);
    const cur = approver.id === tree ? this.current(tree, null) : this.current(tree, t);
    if (cur) await this.submitBoxes(approver.id, [await this.boxTo(approver, tree, cur.kid, cur.key, targetId, ik)]).catch(() => {});
  }

  /** Vouch for an active member with no certificate (e.g. joined through an old link). */
  async vouch(voucher: User, targetId: string, ik: string): Promise<void> {
    const tree = voucher.treeRoot || voucher.id;
    const me = await this.identity(voucher.id);
    await this.submitCerts(voucher.id, [await m.makeCert({ k: 'vouch', v: 1, tree, by: voucher.id, pid: targetId, ik, ts: Date.now() }, me.priv)]);
    this.lastChores.delete(voucher.id);
  }

  /** Can this (verified) node vouch for pid, which no certificate names yet? */
  canVouch(viewerId: string, pid: string): boolean {
    const t = this.trusts.get(viewerId);
    if (!t || !t.rootIk || pid === viewerId || t.members.has(pid)) return false;
    return (viewerId === t.tree || t.members.has(viewerId)) && !!this.serverIk.get(pid);
  }
  async vouchById(viewerId: string, pid: string): Promise<void> {
    const t = this.trusts.get(viewerId);
    const ik = this.serverIk.get(pid);
    if (!t || !ik) throw new Error('Nothing to confirm yet — this person needs to open Arbor once.');
    await this.vouch({ id: viewerId, treeRoot: t.tree } as User, pid, ik);
  }

  // ------------------------------------------------------------ profile view ---
  async openProfileFor(viewer: User, r: any): Promise<{ name: string; bio: string; nameHistory: { name: string; at: number }[]; signed: boolean; verified: boolean }> {
    const t = this.trusts.get(viewer.id) || null;
    const certIk = t ? (r.id === t.tree ? t.rootIk : t.members.get(r.id)?.ik || null) : null;
    if (r.profileCt) {
      const ik = certIk || (r.id !== viewer.id ? await this.contactIk(viewer.id, r.id, r.ik) : r.ik) || null;
      const op = await this.openProfileChecked(r.profileCt, r.id, ik);
      if (op) {
        this.profiles.set(r.id, op.p); this.names.set(r.id, op.p.n);
        return { name: op.p.n, bio: op.p.b || '', nameHistory: op.p.h || [], signed: op.signed, verified: !!certIk };
      }
      return { name: this.names.get(r.id) || UNKNOWN_NAME, bio: '', nameHistory: [], signed: false, verified: !!certIk };
    }
    return { name: r.name || UNKNOWN_NAME, bio: r.bio || '', nameHistory: Array.isArray(r.nameHistory) ? r.nameHistory : [], signed: false, verified: !!certIk };
  }
}
