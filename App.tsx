import React, { useState, useEffect, useCallback, useRef, lazy, Suspense } from 'react';
import { User, Message, AppState, Account } from './types';
import { api } from './services/api';
import * as keyStore from './services/keyStore';
import * as appLock from './services/appLock';
import * as sealedLocal from './services/sealedLocal';
import { CallManager, CallUIState } from './services/callService';
import AuthScreen from './components/AuthScreen';
import AccountAuth from './components/AccountAuth';
import UnlockScreen from './components/UnlockScreen';
// Dashboard is by far the heaviest part of the app (tree, chat, media, calls). It's
// only needed AFTER you pick a network, so load it lazily: the auth/identity-hub
// screens become interactive without paying its parse cost first — the single
// biggest lever on cold-start "snappiness". Its chunk is cached by the SW after the
// first load, so entering a network stays instant on every reopen.
const Dashboard = lazy(() => import('./components/Dashboard'));
import InstallPrompt from './components/InstallPrompt';

const loadJSON = (key: string) => { try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch { return null; } };

const App: React.FC = () => {
  const [state, setState] = useState<AppState>({
    account: loadJSON('arbor_account'),
    // Deliberately NOT resumed from storage: after sign-in the default page is
    // the network chooser (unless the account has no networks, where the same
    // screen offers create/join).
    currentUser: null,
    users: [],
    messages: [],
    invites: [],
    isLoading: false
  });

  const [myNodes, setMyNodes] = useState<User[]>([]);
  const [nodesLoaded, setNodesLoaded] = useState(false);
  // Set true right after a fresh signup so the node-load effect seeds a personal
  // hub for the new user (existing users never trip this).
  const [autoHubPending, setAutoHubPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const stateRef = useRef(state);
  const refreshDataRef = useRef<((showLoading?: boolean) => void) | null>(null);
  useEffect(() => { stateRef.current = state; }, [state]);
  // Bumped on every OPTIMISTIC local mutation (group/link edits). A tree-context
  // fetch records this value when it STARTS; if it changed by the time the fetch
  // resolves, a local edit committed mid-flight and that snapshot is now stale —
  // so we discard it rather than let it revert the edit. This is what stops a
  // slow 8s-poll response (issued just before an unlink) from clobbering the
  // change and making it "not stick until reload".
  const writeSeq = useRef(0);
  // Optimistic group/link edits, held per node id until a server read confirms
  // them (or the TTL lapses). Overlaid onto every tree-context snapshot so a
  // transient stale read can't revert a just-made edit. See applyPending below.
  const pendingGroups = useRef<Map<string, { g: any; until: number }>>(new Map());
  // Same idea for root network-settings flags (auto-accept, referral, global chat,
  // monitoring, name visibility): hold the just-written values on the session node
  // and overlay them onto every tree-context snapshot until a read confirms them or
  // the TTL lapses, so an in-flight stale read can't snap a freshly-toggled switch
  // back to its old state.
  const pendingSelf = useRef<{ vals: Record<string, any>; until: number } | null>(null);
  // Optimistic sent messages, held by id and overlaid onto every tree-context
  // snapshot until the encrypted copy actually lands in the local cache (or TTL) —
  // so a background poll that fires mid-send can't blink the just-sent bubble away.
  const pendingSends = useRef<Map<string, { m: Message; until: number }>>(new Map());
  // v70 H5: the account wrap key is never stored in the clear, so a signed-in
  // cold start opens LOCKED: unlock with biometrics (the key sealed under the
  // authenticator's PRF secret, appLock.ts) or the password. With App Lock on,
  // the app also re-locks after inactivity and forgets the key until unlocked.
  const [lockState, setLockState] = useState<'locked' | 'open'>(() => (loadJSON('arbor_account') && !keyStore.hasWrapKey()) ? 'locked' : 'open');
  const lockStateRef = useRef(lockState);
  useEffect(() => { lockStateRef.current = lockState; }, [lockState]);
  // v71 M6: sign-in found biometric unlock sealing a key from before a password
  // change — it was switched off (api.login); tell the person once.
  useEffect(() => {
    if (!state.account || lockState !== 'open') return;
    try {
      if (localStorage.getItem('arbor-biometric-reset')) {
        localStorage.removeItem('arbor-biometric-reset');
        setTimeout(() => alert('Your password was changed, so biometric unlock was turned off on this device. Turn App Lock on again in the sidebar if you want it.'), 300);
      }
    } catch {}
  }, [state.account, lockState]);
  // V8 M-11: the lock used to gate only the FIRST open — an unlocked session
  // stayed unlocked forever, so anyone picking up the device later walked in.
  // Re-lock after the app has been in the background for LOCK_HIDDEN_MS or idle
  // (no input) for LOCK_IDLE_MS, and drop decrypted material held in memory
  // (message/attachment caches, unwrapped node keys) until biometrics pass again.
  useEffect(() => {
    if (lockState !== 'open') return;
    const LOCK_HIDDEN_MS = 30 * 1000, LOCK_IDLE_MS = 5 * 60 * 1000;
    let hiddenAt = 0, lastActive = Date.now();
    const lock = () => {
      if (!appLock.isEnabled()) return;           // lock toggled off in Settings: nothing to do
      api.dropSensitiveMemory();
      keyStore.lockWrapKey();                     // v70 H5: the key goes too — unlocking needs biometrics or the password
      setLockState('locked');
    };
    const onVis = () => {
      if (document.visibilityState === 'hidden') hiddenAt = Date.now();
      else if (hiddenAt && Date.now() - hiddenAt >= LOCK_HIDDEN_MS) lock();
    };
    const bump = () => { lastActive = Date.now(); };
    const idle = setInterval(() => { if (Date.now() - lastActive >= LOCK_IDLE_MS) lock(); }, 10 * 1000);
    const evs = ['pointerdown', 'keydown', 'touchstart', 'wheel'] as const;
    document.addEventListener('visibilitychange', onVis);
    evs.forEach(e => window.addEventListener(e, bump, { passive: true }));
    return () => {
      clearInterval(idle);
      document.removeEventListener('visibilitychange', onVis);
      evs.forEach(e => window.removeEventListener(e, bump));
    };
  }, [lockState]);
  const [notifPermission, setNotifPermission] = useState<NotificationPermission>(
    typeof Notification !== 'undefined' ? Notification.permission : 'denied');
  // Push is only "on" when permission is granted AND the person hasn't turned
  // it off in-app (permission itself can't be revoked from page script).
  const [billingAlert, setBillingAlert] = useState(false);
  // Live typing indicators keyed by the peer's public node id.
  const [typingPeers, setTypingPeers] = useState<Record<string, { name: string; at: number }>>({});
  // Expire stale typing states (a 'stop' can be missed if the sender drops).
  useEffect(() => {
    const iv = setInterval(() => {
      setTypingPeers(prev => {
        const now = Date.now();
        let changed = false;
        const next: typeof prev = {};
        for (const [k, v] of Object.entries(prev)) { if (now - v.at < 6000) next[k] = v; else changed = true; }
        return changed ? next : prev;
      });
    }, 2000);
    return () => clearInterval(iv);
  }, []);
  // Clear a peer's "typing…" the instant a message from them arrives, so it flows
  // straight into the message instead of blinking off early then popping back.
  const seenMsgIds = useRef<Set<string>>(new Set());
  useEffect(() => {
    const newSenders = new Set<string>();
    for (const m of state.messages) if (!seenMsgIds.current.has(m.id)) { seenMsgIds.current.add(m.id); if (m.senderId) newSenders.add(m.senderId); }
    if (seenMsgIds.current.size > 4000) seenMsgIds.current = new Set(state.messages.map(m => m.id));
    if (newSenders.size) setTypingPeers(prev => {
      let changed = false; const next = { ...prev };
      for (const s of newSenders) if (next[s]) { delete next[s]; changed = true; }
      return changed ? next : prev;
    });
  }, [state.messages]);
  const [pushEnabled, setPushEnabled] = useState<boolean>(() =>
    localStorage.getItem('arbor_push_on') !== '0' &&
    typeof Notification !== 'undefined' && Notification.permission === 'granted');
  // Encrypted calls: one manager per app instance; UI mirrors its state.
  const [callState, setCallState] = useState<CallUIState>({ phase: 'idle', callId: null, peers: [], muted: false });
  const callMgr = useRef<CallManager | null>(null);
  if (!callMgr.current) {
    callMgr.current = new CallManager({
      send: (to, callId, kind, kt, kb) => api.sendRtcSignal(stateRef.current.currentUser?.id || '', to, callId, kind, kt, kb),
      fetchBundle: (id) => api.fetchPrekeyBundle(id),
      // v70 H3: calls use the same membership check as messages.
      checkPeer: (id) => { const me = stateRef.current.currentUser; return me ? api.callPeer(me, id) : Promise.resolve(null); },
      onChange: setCallState,
      onCallEnd: async (info) => {
        const me = stateRef.current.currentUser;
        if (!me) return;
        const durationSec = info.startedAt ? Math.max(1, Math.round((info.endedAt - info.startedAt) / 1000)) : undefined;
        // Who started the call, and everyone who was in it (me + all peers).
        const callerName = info.direction === 'outgoing' ? me.name : (info.peers[0]?.name || 'Unknown');
        const participants = [{ name: me.name }, ...info.peers.map(p => ({ name: p.name }))];
        const outcome: NonNullable<import('./types').Message['callLog']>['outcome'] =
          info.startedAt ? 'completed'
          : info.direction === 'incoming' ? 'missed'
          : 'no_answer';
        // Group call (2+ peers): write ONE consolidated record listing everyone,
        // not one per invitee. 1:1 call: the single peer is the target as before.
        const targets = info.peers.length > 1 ? info.peers.slice(0, 1) : info.peers;
        for (const p of targets) {
          try {
            await api.recordCallLog(me, p.id, {
              direction: info.direction,
              outcome: (!info.startedAt && info.direction === 'incoming' && p.connected === false) ? 'missed' : outcome,
              durationSec,
              video: info.video,
              callerName,
              participants,
            }, info.endedAt);
          } catch {}
        }
        refreshDataRef.current?.(false);
      },
    });
  }
  // Calls can arrive while no network is selected (the chooser is the default
  // screen) or while a DIFFERENT node is active — the sealed payload can only be
  // decrypted by the target node's store. Queue such events and flush them once
  // the right node is selected; surface a banner so the person knows to switch.
  const pendingRtc = useRef<{ ev: any; at: number }[]>([]);
  const [callBanner, setCallBanner] = useState<{ fromName: string; to: string } | null>(null);
  const seenRings = useRef<Set<string>>(new Set()); // dedupe live-SSE vs pending-replay
  const seenSids = useRef<Set<number>>(new Set());  // per-event dedupe (SSE + poll paths)
  const routeRtc = (raw: any) => {
    // V8 phase 2: the server no longer relays the caller's display name (profiles
    // are end-to-end encrypted); label it from this device's decrypted roster.
    const data = { ...raw, fromName: api.nameOf(raw?.from) || 'Someone' };
    if (typeof data.sid === 'number') {
      if (seenSids.current.has(data.sid)) return;
      seenSids.current.add(data.sid);
      if (seenSids.current.size > 500) seenSids.current.clear();
    }
    if (data.kind === 'ring') {
      const key = `${data.callId}|${data.from}`;
      if (seenRings.current.has(key)) return;
      seenRings.current.add(key);
      if (seenRings.current.size > 50) seenRings.current.clear();
    }
    const cur = stateRef.current.currentUser;
    if (cur && cur.id === data.to) { callMgr.current?.handleSignal(data); }
    else {
      const now = Date.now();
      pendingRtc.current = [...pendingRtc.current.filter(p => now - p.at < 40000), { ev: data, at: now }];
      if (data.kind === 'ring') setCallBanner({ fromName: data.fromName || 'Someone', to: data.to });
      if (data.kind === 'hangup' || data.kind === 'decline') setCallBanner(null);
    }
  };
  // Rings buffered server-side while this device was closed/asleep (e.g. the
  // person opened the app by tapping the call notification).
  const checkPendingCalls = () => { api.fetchPendingCalls().then(rings => rings.forEach(routeRtc)).catch(() => {}); };
  // The service worker pings us when a call notification is tapped; a cold open
  // arrives as ?call=1. Both funnel to the pending-ring fetch.
  useEffect(() => {
    const onSwMsg = (e: MessageEvent) => { if (e.data?.type === 'OPEN_CALL') checkPendingCalls(); };
    navigator.serviceWorker?.addEventListener?.('message', onSwMsg);
    try {
      const u = new URL(window.location.href);
      if (u.searchParams.get('call') === '1') { checkPendingCalls(); u.searchParams.delete('call'); window.history.replaceState({}, '', u.pathname + (u.search || '')); }
    } catch {}
    return () => navigator.serviceWorker?.removeEventListener?.('message', onSwMsg);
    // eslint-disable-next-line
  }, []);
  const lastMessageCount = useRef(0);
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const failCount = useRef(0);

  const urlBase64ToUint8Array = (base64String: string) => {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/\-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
    return outputArray;
  };

  // Mobile browsers only grant notification permission from a user gesture, so
  // the Dashboard offers an explicit "Enable notifications" action that calls this.
  // While a call is ringing/connecting/active, poll the server's signal buffer as
  // a fallback transport. SSE through proxies (Cloudflare) can silently drop —
  // losing one accept/offer/answer used to strand calls at "connecting" forever.
  useEffect(() => {
    if (callState.phase === 'idle' && !callBanner) return;
    const iv = setInterval(() => checkPendingCalls(), 2500);
    return () => clearInterval(iv);
    // eslint-disable-next-line
  }, [callState.phase, !!callBanner]);

  // Audible + haptic ringtone while a call is incoming (WebAudio needs no asset).
  useEffect(() => {
    if (callState.phase !== 'incoming') return;
    let ctx: AudioContext | null = null;
    let stopped = false;
    let vib: ReturnType<typeof setInterval> | null = null;
    try {
      const AC: typeof AudioContext = (window as any).AudioContext || (window as any).webkitAudioContext;
      ctx = new AC();
      const ring = () => {
        if (!ctx || stopped) return;
        const t0 = ctx.currentTime;
        [0, 0.4].forEach(off => {
          const o = ctx!.createOscillator(); const g = ctx!.createGain();
          o.type = 'sine'; o.frequency.value = 440;
          o.connect(g); g.connect(ctx!.destination);
          g.gain.setValueAtTime(0.0001, t0 + off);
          g.gain.exponentialRampToValueAtTime(0.18, t0 + off + 0.05);
          g.gain.exponentialRampToValueAtTime(0.0001, t0 + off + 0.35);
          o.start(t0 + off); o.stop(t0 + off + 0.36);
        });
      };
      ring();
      const iv = setInterval(ring, 2000);
      if (navigator.vibrate) { navigator.vibrate([400, 200, 400]); vib = setInterval(() => navigator.vibrate?.([400, 200, 400]), 2000); }
      return () => { stopped = true; clearInterval(iv); if (vib) clearInterval(vib); navigator.vibrate?.(0); ctx?.close().catch(() => {}); };
    } catch { return () => { if (vib) clearInterval(vib); }; }
  }, [callState.phase]);

    // Call manager follows the active node; leaving a network ends any call.
  // Flush any queued signaling that was waiting for this node to become active.
  useEffect(() => {
    callMgr.current?.setSelf(state.currentUser);
    const cur = state.currentUser;
    if (!cur) return;
    const now = Date.now();
    const mine = pendingRtc.current.filter(p => p.ev.to === cur.id && now - p.at < 40000);
    pendingRtc.current = pendingRtc.current.filter(p => p.ev.to !== cur.id && now - p.at < 40000);
    if (mine.length) setCallBanner(null);
    (async () => { for (const p of mine) { try { await callMgr.current?.handleSignal(p.ev); } catch {} } })();
  }, [state.currentUser]);

  const requestNotifications = async (): Promise<NotificationPermission> => {
    if (typeof Notification === 'undefined') return 'denied';
    let perm = Notification.permission;
    if (perm === 'default') { try { perm = await Notification.requestPermission(); } catch {} }
    setNotifPermission(perm);
    if (perm === 'granted') await setupPushNotifications();
    return perm;
  };

  const setupPushNotifications = async () => {
    if (localStorage.getItem('arbor_push_on') === '0') return; // turned off in-app
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
    if (typeof Notification !== 'undefined' && Notification.permission !== 'granted') return;
    try {
      const registration = await navigator.serviceWorker.ready;
      const existing = await registration.pushManager.getSubscription();
      if (existing) { await api.subscribeToPush(existing); setPushEnabled(true); return; }
      const publicKey = await api.getVapidPublicKey();
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey)
      });
      await api.subscribeToPush(subscription);
      setPushEnabled(true);
    } catch (e) {
      console.error("Push setup failed:", e);
    }
  };

  // Toggle: ON runs the permission+subscribe flow; OFF unsubscribes this
  // device's push endpoint locally AND removes it server-side.
  const toggleNotifications = async (): Promise<NotificationPermission> => {
    if (pushEnabled) {
      try {
        const reg = await navigator.serviceWorker.ready;
        const sub = await reg.pushManager.getSubscription();
        if (sub) {
          try { await api.unsubscribeFromPush(sub.endpoint); } catch {}
          await sub.unsubscribe().catch(() => {});
        } else {
          try { await api.unsubscribeFromPush(); } catch {}
        }
      } catch {}
      localStorage.setItem('arbor_push_on', '0');
      setPushEnabled(false);
      return notifPermission;
    }
    localStorage.setItem('arbor_push_on', '1');
    const p = await requestNotifications();
    return p;
  };

  // Force re-authentication (used when the session key is locked, e.g. after a
  // refresh on a device that has never unlocked this node).
  const forceReauth = useCallback((msg?: string) => {
    localStorage.removeItem('arbor_account');
    setLockState('open');
    setState({ account: null, currentUser: null, users: [], messages: [], invites: [], isLoading: false });
    if (msg) setError(msg);
  }, []);

  // When any authenticated request gets a 401 (expired/dropped session), bounce
  // to the login screen instead of sitting on a dead dashboard.
  useEffect(() => {
    api.onAuthError = () => forceReauth('Your session expired — please sign in again.');
    return () => { api.onAuthError = null; };
  }, [forceReauth]);

  // The starter hub being created for a new signup, shared by every run of the
  // loader below (the effect can re-run while it is still being created).
  const starterHubRef = useRef<Promise<User | null> | null>(null);
  useEffect(() => {
    let live = true;   // a newer run supersedes this one: never apply stale results
    if (state.account && lockState === 'open') {
      api.fetchMyNodes()
        .then(async n => {
          // New signup: seed a personal hub so the user starts with a place to
          // chat instead of an empty Identity Hub. Do it BEFORE marking nodes
          // loaded, so AuthScreen only ever mounts with the hub already present —
          // otherwise it briefly shows its network-creation form (the post-signup
          // "flash"). The server allows one hub per account, so this is idempotent.
          if (autoHubPending && !starterHubRef.current && !n.some(x => x.treeMode === 'HUB')) {
            const hubName = state.account?.username || 'Me';
            starterHubRef.current = (async () => {
              try { await keyStore.ensureWrapKey(); return await api.registerUser(hubName, undefined, undefined, 'HUB'); }
              catch (err) { console.error('Could not create starter hub', err); return null; }
            })();
          }
          if (autoHubPending) setAutoHubPending(false);
          // A run that started while the hub was still being created waits for it
          // too (v71: that run used to show an empty list — the "sometimes" flash).
          if (starterHubRef.current) {
            const hub = await starterHubRef.current;
            if (hub && !n.some(p => p.id === hub.id)) n = [...n, hub];
          }
          if (!live) return;
          setMyNodes(n);
          setNodesLoaded(true);
        })
        .catch(err => { console.error(err); if (!live) return; setAutoHubPending(false); setNodesLoaded(true); });
      setupPushNotifications();
    } else {
      starterHubRef.current = null;
      setMyNodes([]);
      setNodesLoaded(false);
    }
    return () => { live = false; };
  }, [state.account, lockState]);

  // Pre-warm the on-device cache for each network WHILE the picker is showing, so the
  // FIRST entry into a network is a cache hit too (not just re-entry). Runs once per
  // picker visit, only when no network is active, and warms sequentially (each fetch
  // saves its sealed snapshot + messages locally) so it never bursts the tunnel. It
  // bails the instant a network is entered — that entry's own hydrate/refresh takes over.
  const warmedRef = useRef(false);
  useEffect(() => {
    if (state.currentUser || !myNodes.length) { warmedRef.current = false; return; }
    if (warmedRef.current) return;
    warmedRef.current = true;
    let cancelled = false;
    (async () => {
      for (const n of myNodes) {
        if (cancelled || stateRef.current.currentUser) break; // a network was entered — stop
        await api.warmSnapshot(n);
      }
    })();
    return () => { cancelled = true; };
  }, [state.currentUser, myNodes]);

  const refreshData = useCallback(async (showLoading = false) => {
    // Read the session from a ref, NOT from the closure, so this callback keeps a
    // STABLE identity across refreshes. Depending on `state.currentUser` (a new
    // object every refresh) made refreshData change identity every time, which
    // re-ran the SSE/poll effect below, which called refreshData again — a ~15
    // req/s feedback loop that also let stale snapshots win. Keeping it stable
    // breaks that loop.
    const cur = stateRef.current;
    if (!cur.currentUser || !cur.account) return;
    if (lockStateRef.current === 'locked') return;   // v70 H5: no key until unlocked
    const basisSeq = writeSeq.current;
    if (showLoading) setState(prev => ({ ...prev, isLoading: true }));
    try {
      const data = await api.fetchTreeContext(cur.currentUser);
      // A local edit committed while this fetch was in flight → its snapshot
      // predates the edit. Discard it so we don't revert the just-made change.
      if (writeSeq.current !== basisSeq) return;
      const { users, messages, invites } = data;
      // Sticky optimistic groups: after a local group/link edit we hold the
      // written values (pendingGroups) and overlay them onto every server
      // snapshot until a read actually CONFIRMS them (server caught up) or a
      // short TTL elapses. This defends the edit against a transient stale read
      // (the flaky tunnel occasionally replays a pre-edit tree-context), which is
      // what made link edits appear to "not stick until reload".
      const applyPending = (u: any) => {
        if (!u) return u;
        const pend = pendingGroups.current.get(u.id);
        if (!pend) return u;
        const eq = (a: any, b: any) => JSON.stringify(a || {}) === JSON.stringify(b || {});
        const confirmed = eq(u.groupLinks, pend.g.groupLinks) && eq(u.groupLabels, pend.g.groupLabels)
          && eq(u.groupParents, pend.g.groupParents) && eq(u.inviteeGroups, pend.g.inviteeGroups)
          && eq(u.groupVisitors, pend.g.groupVisitors); // else a stale read that lacks the new visitor drops the overlay early
        if (confirmed || Date.now() > pend.until) { pendingGroups.current.delete(u.id); return u; }
        return { ...u, ...pend.g };
      };
      // Normalize a settings value for comparing the server snapshot against the
      // optimistic overlay: treeName is a string, monitorEnabled defaults to true
      // when absent, everything else is a boolean flag.
      const norm = (v: any, k: string) =>
        (k === 'treeName' || k === 'name' || k === 'bio') ? (v || '')
        : k === 'avatarAt' ? (v || 0)
        : k === 'monitorEnabled' ? (v !== false)
        : !!v;
      setState(prev => {
        let updatedUser = prev.currentUser;
        const freshSelf = users.find(u => u.id === prev.currentUser?.id);
        if (freshSelf) {
          // Preserve locally-held key material reference fields on the session node.
          const s: any = applyPending(freshSelf);
          // Sticky root-settings overlay: keep the just-toggled flag values until a
          // read confirms them (or TTL), so a stale in-flight snapshot can't revert.
          const ps = pendingSelf.current;
          if (ps) {
            const confirmed = Object.keys(ps.vals).every(k => norm(s[k], k) === norm(ps.vals[k], k));
            if (confirmed || Date.now() > ps.until) pendingSelf.current = null;
            else Object.assign(s, ps.vals);
          }
          updatedUser = { ...s, wrappedKeys: prev.currentUser?.wrappedKeys,
            inviteeGroups: s.inviteeGroups ?? prev.currentUser?.inviteeGroups,
            groupLabels: s.groupLabels ?? prev.currentUser?.groupLabels,
            groupParents: s.groupParents ?? prev.currentUser?.groupParents,
            groupLinks: s.groupLinks ?? prev.currentUser?.groupLinks,
            groupVisitors: s.groupVisitors ?? prev.currentUser?.groupVisitors,
            visiting: s.visiting ?? prev.currentUser?.visiting,
            // Cross-level channels I'm in (root-owned, spanning compartments).
            crossLinks: (data as any).crossLinks ?? prev.currentUser?.crossLinks };
        }
        // Overlay any still-unconfirmed optimistic sends so a poll that landed
        // mid-send doesn't drop the just-sent bubble. Drop ones now in the snapshot
        // (confirmed) or past their TTL.
        let mergedMessages = messages;
        if (pendingSends.current.size) {
          const present = new Set(messages.map((m: Message) => m.id));
          const extra: Message[] = [];
          const nowT = Date.now();
          for (const [id, p] of pendingSends.current) {
            if (present.has(id) || nowT > p.until) { pendingSends.current.delete(id); continue; }
            extra.push(p.m);
          }
          if (extra.length) mergedMessages = [...messages, ...extra].sort((a, b) => a.timestamp - b.timestamp);
        }
        if (mergedMessages.length > lastMessageCount.current && document.visibilityState === 'visible') { /* in-app alert hook */ }
        lastMessageCount.current = mergedMessages.length;
        return { ...prev, currentUser: updatedUser, users: users.map(u => applyPending(u)), messages: mergedMessages, invites, joinRequests: (data as any).joinRequests || [], acks: (data as any).acks || {}, reactions: (data as any).reactions || {}, isLoading: false };
      });
      failCount.current = 0;
      setError(null);
    } catch (e: any) {
      const m = e?.message || '';
      // A pending join that was DECLINED: our node no longer exists, so the very
      // next refresh is denied. Return to the network chooser with a clear note.
      if (cur.currentUser?.pending && /denied|access/i.test(m)) {
        setState(prev => ({ ...prev, currentUser: null, users: [], messages: [], invites: [], joinRequests: [] }));
        setError('Your join request was declined.');
        return;
      }
      if (/locked|key material|Session locked|log in again|unauthenticated/i.test(m)) {
        forceReauth('Your session expired — please sign in again.');
        return;
      }
      // Only surface a banner after repeated failures so a single tunnel blip
      // (common with SSE over Cloudflare) doesn't flash "Connection lost".
      failCount.current += 1;
      console.warn("Sync failed:", m);
      if (failCount.current >= 2) setError("Connection lost — retrying…");
      setState(prev => ({ ...prev, isLoading: false }));
    }
  }, [forceReauth]);
  refreshDataRef.current = refreshData;

  // Coalesce bursts of stream events into a single refresh.
  const scheduleRefresh = useCallback(() => {
    if (refreshTimer.current) return;
    refreshTimer.current = setTimeout(() => { refreshTimer.current = null; refreshData(false); }, 300);
  }, [refreshData]);

  useEffect(() => {
    if (!state.currentUser) return;
    refreshData(true);

    let es: EventSource | null = null;
    let closed = false;
    let backoff = 1000;

    const connect = () => {
      if (closed) return;
      // Session travels as a HttpOnly cookie, sent automatically on same-origin SSE.
      es = new EventSource('/api/events');
      es.onopen = () => { backoff = 1000; checkPendingCalls(); };
      es.onmessage = (ev) => {
        // Payload events (calls / typing) are routed; anything else = refresh cue.
        try {
          const data = JSON.parse(ev.data);
          if (data?.type === 'RTC') { routeRtc(data); return; }
          if (data?.type === 'RETRACT') {
            // v70: the server's notice is only a cue to sync. The deletion itself
            // arrives as a sealed message from the sender (api.ts), so the server
            // can't erase messages on this device.
            scheduleRefresh();
            return;
          }
          if (data?.type === 'BILLING') {
            setBillingAlert(true);
            scheduleRefresh();
            return;
          }
          if (data?.type === 'RECEIPT') {
            const cur = stateRef.current.currentUser;
            if (cur && cur.id === data.to && Array.isArray(data.mids)) {
              if (typeof data.from === 'string' && data.from) api.markMessagesRead(cur.id, data.mids, data.from).then(() => scheduleRefresh()).catch(() => {});
            }
            return;
          }
          if (data?.type === 'REACTION') {
            // Reaction persisted server-side; a light refresh pulls the new map.
            scheduleRefresh();
            return;
          }
          if (data?.type === 'TYPING') {
            const cur = stateRef.current.currentUser;
            if (cur && data.from) {
              setTypingPeers(prev => {
                const next = { ...prev };
                if (data.state === 'start') next[data.from] = { name: api.nameOf(data.from) || 'Someone', at: Date.now() };
                else delete next[data.from];
                return next;
              });
            }
            return;
          }
        } catch {}
        scheduleRefresh();
      };
      es.onerror = () => {
        if (es) es.close();
        if (closed) return;
        // Exponential backoff so a dropped stream doesn't hammer the tunnel/edge.
        setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, 30000);
      };
    };
    connect();

    // Mobile OSes kill background SSE streams. When the app comes back to the
    // foreground (notification tap, task switch, screen unlock), reconnect the
    // stream IMMEDIATELY and refresh — this is what makes messages appear right
    // away instead of waiting out a poll/backoff window.
    const wake = () => {
      if (document.visibilityState !== 'visible') return;
      refreshData(false);
      checkPendingCalls(); // e.g. opened via a call notification
      try { if (es && es.readyState === EventSource.CLOSED) { backoff = 1000; connect(); } } catch {}
    };
    document.addEventListener('visibilitychange', wake);
    window.addEventListener('focus', wake);
    window.addEventListener('online', wake);

    // Safety-net poll: covers the case where the tunnel buffers SSE and events
    // never arrive. 8s keeps worst-case delivery latency low (Monitor Hub included).
    const poll = setInterval(() => { if (document.visibilityState === 'visible') refreshData(false); }, 8000);

    return () => {
      closed = true; if (es) es.close(); clearInterval(poll);
      document.removeEventListener('visibilitychange', wake);
      window.removeEventListener('focus', wake);
      window.removeEventListener('online', wake);
    };
    // Key on the session NODE ID, not the currentUser OBJECT: the object is
    // replaced on every refresh, but the id only changes on login/logout — so
    // this effect (which opens the SSE stream + 8s poll) sets up ONCE per session
    // instead of tearing down and re-running ~15×/s. refreshData/scheduleRefresh
    // are now stable, so they don't retrigger it either.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.currentUser?.id, refreshData, scheduleRefresh]);

  const handleAccountLogin = (account: Account, isNew = false) => {
    localStorage.setItem('arbor_account', JSON.stringify(account));
    setError(null);
    setLockState('open');
    // Brand-new accounts get a personal hub created for them once their (empty)
    // node list loads — see the fetchMyNodes effect. Existing users are untouched.
    if (isNew) setAutoHubPending(true);
    setState(prev => ({ ...prev, account, currentUser: null }));
  };

  const handleLogoutAccount = async () => {
    try { await api.logout(); } catch {}
    localStorage.removeItem('arbor_account');
    setState({ account: null, currentUser: null, users: [], messages: [], invites: [], isLoading: false });
  };

  const handleNodeLogin = async (user: User) => {
    try {
      await api.unlockNode(user); // ensure key material is available before entering
      // Drafts + scheduled-message text live in the sealed local store (V8 M-12);
      // unseal it now so the composer can restore drafts synchronously.
      sealedLocal.init().catch(() => {});
    } catch (e: any) {
      setError('Could not unlock this identity on this device. Log in again to sync keys.');
      return;
    }
    // Local-first: read the on-device SEALED snapshot + messages BEFORE mounting the
    // new network, so Dashboard mounts already-populated in a SINGLE render. This kills
    // two entry artifacts at once: (1) the empty first frame ("split-second blank"),
    // because there's never an empty mount; and (2) the top-of-history media flash,
    // because the first paint is a genuine chat-entry that pins to the newest message
    // instantly (an empty pre-mount used to poison that into a top→bottom smooth glide).
    // The read is fast (IndexedDB + unseal); the /tree-context refresh reconciles a beat
    // later. Replacing users/messages atomically also means the PREVIOUS network never
    // flashes in the new one. First-ever entry to a node (nothing cached) mounts empty
    // as before and fills on the network response.
    const local = await api.hydrateLocal(user).catch(() => null);
    const self = local?.self;
    const mergedUser = self
      ? { ...user, ...self, wrappedKeys: user.wrappedKeys, encPub: user.encPub, sigPub: user.sigPub }
      : user;
    setState(prev => ({
      ...prev,
      currentUser: mergedUser as any,
      users: local?.users || [],
      messages: local?.messages || [],
      invites: local?.invites || [],
      joinRequests: [], acks: {}, reactions: {},
    }));
  };

  const handleNodeLogout = () => {
    setState(prev => ({ ...prev, currentUser: null, messages: [], invites: [] }));
    if (state.account) api.fetchMyNodes().then(setMyNodes).catch(console.error);
  };

  const handleSwitchIdentity = (userId: string) => {
    const target = myNodes.find(n => n.id === userId);
    if (target) handleNodeLogin(target);
  };

  const handleSendMessage = async (payload: { text?: string, imageUrl?: string, audioUrl?: string, videoUrl?: string, expiresAt?: number, replyTo?: { mid: string; name: string; text: string }, editsMid?: string, audioPeaks?: number[], audioDurMs?: number }, type: Message['type'], _targetBranchId?: string, targets?: string[], targetCircle?: 'UP' | 'DOWN', targetUserId?: string, ackRequested?: boolean, targetGroup?: string, mentions?: { users?: string[]; viaGroup?: string[] }) => {
    if (!state.currentUser) return;
    const me = state.currentUser;
    // Bump writeSeq so a stale in-flight read can't drop the message being sent.
    writeSeq.current++;
    // INSTANT optimistic bubble: render the plaintext you just typed on your OWN
    // screen immediately, under the same id the encrypted send will use. This is a
    // local-only display of your own text — NOTHING is transmitted here. The real
    // send below still does the full /recipients + seal + per-recipient ratchet
    // encryption before anything leaves the device; only then does it POST.
    const mid = api.newMid();
    const optimistic: Message = {
      id: mid, senderId: me.id, timestamp: Date.now(), type,
      targetCircle, targetGroup, peerId: targetUserId,
      text: payload.text, imageUrl: payload.imageUrl, audioUrl: payload.audioUrl, videoUrl: payload.videoUrl,
      replyTo: payload.replyTo, verified: true, sending: true,
    } as Message;
    pendingSends.current.set(mid, { m: optimistic, until: Date.now() + 30000 });
    setState(prev => prev.currentUser ? { ...prev, messages: [...prev.messages, optimistic] } : prev);
    // When the encrypted copy lands in the local cache, drop the overlay and
    // reconcile to it (same id → the same bubble is confirmed in place, no flicker).
    const echo = () => { pendingSends.current.delete(mid); setState(prev => prev.currentUser ? { ...prev, messages: api.messagesNow() } : prev); };
    try {
      await api.sendMessage(me, payload, type, targets, targetCircle, targetUserId, ackRequested, targetGroup, mentions, echo, mid);
      refreshData(false);
    } catch (e: any) {
      // WebCrypto errors carry an empty message; show their name instead of a blank.
      alert("Transmission failed: " + (e?.message || e?.name || 'unknown error'));
      refreshData(false); // reconcile to the local cache (drops the bubble if it never actually stored)
    }
  };

  const handleAcknowledge = async (mid: string) => {
    if (!state.currentUser) return;
    try { await api.acknowledgeMessage(state.currentUser.id, mid); refreshData(false); }
    catch (e: any) { alert("Couldn't acknowledge: " + e.message); }
  };

  const handleReact = async (mid: string, emoji: string) => {
    if (!state.currentUser) return;
    try {
      const { reactions } = await api.reactMessage(state.currentUser.id, mid, emoji);
      // Optimistic: patch just this mid's reactions so the UI is instant.
      setState(prev => ({ ...prev, reactions: { ...(prev.reactions || {}), [mid]: reactions } }));
    } catch (e: any) { /* silent — reaction is non-critical */ }
  };

  const handleTyping = (toNodeId: string, typingState: 'start' | 'stop') => {
    if (!state.currentUser || !toNodeId) return;
    api.sendTyping(state.currentUser.id, toNodeId, typingState);
  };

  const handlePrune = async (userId: string) => {
    if (!state.currentUser) return;
    try { await api.deleteNode(userId, state.currentUser.id); refreshData(false); }
    catch (e: any) { alert("Pruning failed: " + e.message); }
  };

  const handleTogglePermissions = async (userId: string, permissions: any) => {
    if (!state.currentUser) return;
    try { await api.updatePermissions(userId, permissions, state.currentUser.id); refreshData(false); }
    catch (e: any) { alert("Permission update failed: " + e.message); }
  };


  const handleUpdateTreeSettings = async (changes: { treeName?: string; treeNameVisible?: boolean; monitorEnabled?: boolean; referralOpen?: boolean; globalChat?: boolean; autoAcceptInvites?: boolean }) => {
    if (!state.currentUser) return;
    const nodeId = state.currentUser.id;
    // Apply the change to the session node IMMEDIATELY (before the network round
    // trip) so the switch flips on tap, bump writeSeq so any tree-context read
    // already in flight is discarded, and stash the values as a sticky overlay so a
    // stale snapshot that lands right after can't revert them. Mirrors the group/
    // link edit path — the fix for "doesn't stick until reload".
    writeSeq.current++;
    pendingSelf.current = { vals: { ...(pendingSelf.current?.vals || {}), ...changes }, until: Date.now() + 60000 };
    setState(prev => prev.currentUser ? { ...prev, currentUser: { ...prev.currentUser, ...changes } } : prev);
    try {
      const res = await api.updateTreeSettings(nodeId, changes);
      // Reconcile to the server's authoritative echo (and refresh the overlay TTL).
      const vals: Record<string, any> = { treeName: res.treeName, treeNameVisible: res.treeNameVisible };
      if (res.monitorEnabled !== undefined) vals.monitorEnabled = res.monitorEnabled;
      if (res.referralOpen !== undefined) vals.referralOpen = res.referralOpen;
      if (res.globalChat !== undefined) vals.globalChat = res.globalChat;
      if ((res as any).autoAcceptInvites !== undefined) vals.autoAcceptInvites = (res as any).autoAcceptInvites;
      pendingSelf.current = { vals: { ...(pendingSelf.current?.vals || {}), ...vals }, until: Date.now() + 60000 };
      setState(prev => prev.currentUser ? { ...prev, currentUser: { ...prev.currentUser, ...vals } } : prev);
    } catch (e: any) {
      pendingSelf.current = null; // let the next read restore the true server state
      alert(e?.message || 'Could not update network settings.');
      refreshData(false);
      return;
    }
    refreshData(false);
  };

  const handleUpdateColor = async (color: string) => {
    if (!state.currentUser) return;
    const res = await api.setMyColor(state.currentUser.id, color);
    // Optimistic paint; the share() signature now includes color, so the
    // follow-up refresh confirms rather than clobbers this.
    setState(prev => prev.currentUser ? {
      ...prev,
      currentUser: { ...prev.currentUser, color: res.color },
      users: prev.users.map(u => u.isMe ? { ...u, color: res.color } : u),
    } : prev);
    refreshData(false);
  };

  // Network Profile — change my display name in THIS network (server keeps the
  // full, server-stamped change history and returns it).
  const handleUpdateName = async (name: string) => {
    if (!state.currentUser) return;
    const myId = state.currentUser.id;
    const clean = name.trim();
    // Optimistic FIRST (instant), bump writeSeq so an in-flight tree-context read
    // can't clobber it, and stick the value until a read confirms it — the
    // client-update-stale-read pattern (a plain post-await setState reverts on the
    // next poll because the fetch that was already in flight carries the old name).
    writeSeq.current++;
    pendingSelf.current = { vals: { ...(pendingSelf.current?.vals || {}), name: clean }, until: Date.now() + 60000 };
    setState(prev => prev.currentUser ? {
      ...prev,
      currentUser: { ...prev.currentUser, name: clean },
      users: prev.users.map(u => u.isMe ? { ...u, name: clean } : u),
    } : prev);
    setMyNodes(prev => prev.map(n => n.id === myId ? { ...n, name: clean } : n));
    try {
      const res = await api.setMyName(myId, clean);
      writeSeq.current++;
      pendingSelf.current = { vals: { ...(pendingSelf.current?.vals || {}), name: res.name }, until: Date.now() + 60000 };
      setState(prev => prev.currentUser ? {
        ...prev,
        currentUser: { ...prev.currentUser, name: res.name, nameHistory: res.nameHistory },
        users: prev.users.map(u => u.isMe ? { ...u, name: res.name, nameHistory: res.nameHistory } : u),
      } : prev);
    } catch (e) {
      pendingSelf.current = null; refreshData(false); throw e;
    }
    refreshData(false);
  };

  // Set/clear my bio and/or profile photo. The avatar is scrubbed (canvas
  // re-encode) by the caller before it reaches here.
  const handleUpdateProfile = async (changes: { bio?: string | null; avatar?: string; removeAvatar?: boolean }) => {
    if (!state.currentUser) return;
    const myId = state.currentUser.id;
    // Optimistic values we can know before the round trip (bio, avatar removal).
    // A set-avatar's version is server-stamped, so its avatarAt lands post-await;
    // the caller (pickAvatar) has already seeded the image cache so it shows at once.
    const optimistic: any = {};
    if (changes.bio !== undefined) optimistic.bio = changes.bio || '';
    if (changes.removeAvatar) optimistic.avatarAt = 0;
    writeSeq.current++;
    pendingSelf.current = { vals: { ...(pendingSelf.current?.vals || {}), ...optimistic }, until: Date.now() + 60000 };
    if (Object.keys(optimistic).length) {
      setState(prev => prev.currentUser ? {
        ...prev,
        currentUser: { ...prev.currentUser, ...optimistic },
        users: prev.users.map(u => u.isMe ? { ...u, ...optimistic } : u),
      } : prev);
    }
    try {
      const res = await api.updateProfile(myId, changes);
      const confirmed = { bio: res.bio, avatarAt: res.avatarAt };
      writeSeq.current++;
      pendingSelf.current = { vals: { ...(pendingSelf.current?.vals || {}), ...confirmed }, until: Date.now() + 60000 };
      setState(prev => prev.currentUser ? {
        ...prev,
        currentUser: { ...prev.currentUser, ...confirmed },
        users: prev.users.map(u => u.isMe ? { ...u, ...confirmed } : u),
      } : prev);
      refreshData(false);
      return res;
    } catch (e) {
      pendingSelf.current = null; refreshData(false); throw e;
    }
  };

  // "Add to my hub" from a profile info view. Ensures this account has a personal
  // hub (create-or-reuse — does NOT switch the network I'm viewing), then sends a
  // symmetric contact request. Returns the server status for the UI to report.
  const handleHubConnect = async (targetPublicId: string): Promise<string> => {
    let hub = myNodes.find(n => (n.treeMode === 'HUB') && !n.invitedBy);
    if (!hub) {
      const myName = state.currentUser?.name || state.account?.username || 'Me';
      hub = await api.registerUser(myName, undefined, undefined, 'HUB');
      const created = hub;
      setMyNodes(prev => prev.some(n => n.id === created.id) ? prev : [...prev, created]);
    }
    if (!state.currentUser) throw new Error('Open the network you share with them first.');
    const res = await api.hubConnect(hub.id, targetPublicId, state.currentUser);
    refreshData(false);
    return res.status;
  };

  const handleRegisterNode = async (name: string, inviteCode?: string, treeName?: string, treeMode?: 'HIERARCHICAL' | 'DM' | 'HUB', treeNameVisible?: boolean, color?: string, monitorEnabled?: boolean, referralOpen?: boolean, globalChat?: boolean, useDefaultProfile?: boolean, inviteFragment?: string) => {
    if (!state.account) return;
    try {
      const newUser = await api.registerUser(name, inviteCode, treeName, treeMode, treeNameVisible, color, monitorEnabled, referralOpen, globalChat, useDefaultProfile, inviteFragment);
      // Personal-hub links reuse the account's existing hub — don't list it twice.
      setMyNodes(prev => prev.some(n => n.id === newUser.id) ? prev : [...prev, newUser]);
      await handleNodeLogin(newUser);
    } catch (e: any) {
      const m = e?.message || '';
      // A locked session can't be fixed by retrying — route straight back to
      // the sign-in screen instead of leaving the person on a dead form.
      if (/locked|Session locked|log in again/i.test(m)) {
        forceReauth('Your session needs a fresh sign-in before creating a new identity.');
        return;
      }
      alert(m || 'Could not create the identity.');
    }
  };

  // v70 H5: locked = the account key isn't in memory (cold start, or an App
  // Lock re-lock). Nothing renders until biometrics or the password bring it back.
  if (lockState === 'locked' && state.account) {
    return (
      <UnlockScreen
        username={state.account.username}
        onUnlocked={() => setLockState('open')}
        onSignOut={() => { setLockState('open'); handleLogoutAccount(); }}
      />
    );
  }

  if (!state.account) {
    return (
      <>
        {error && (
          <div className="fixed top-0 left-0 right-0 z-[100] bg-amber-500/90 text-black text-[10px] font-bold py-1 text-center uppercase tracking-widest backdrop-blur-sm">{error}</div>
        )}
        <AccountAuth onAccountLogin={handleAccountLogin} />
        <InstallPrompt />
      </>
    );
  }

  if (!state.currentUser) {
    // Until the account's nodes have loaded once, show a neutral loader — never
    // AuthScreen, whose empty state is the network-creation screen (that flash
    // on login was the "blip").
    if (!nodesLoaded) {
      return (
        <div className="min-h-[100dvh] w-full flex items-center justify-center bg-[#0a0a0a]">
          <div className="w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
        </div>
      );
    }
    return (
      <>
        {callBanner && (
          <button
            onClick={() => {
              const target = myNodes.find(n => n.id === callBanner.to);
              if (target) handleNodeLogin(target); else setCallBanner(null);
            }}
            className="fixed top-0 left-0 right-0 z-[200] bg-emerald-500 text-black text-xs font-black py-3 text-center uppercase tracking-widest animate-pulse"
            style={{ paddingTop: 'calc(env(safe-area-inset-top, 0px) + 12px)' }}>
            Incoming encrypted call from {callBanner.fromName} — tap to answer
          </button>
        )}
        <AuthScreen
          onLogin={handleNodeLogin}
          onRegister={handleRegisterNode}
          myNodes={myNodes}
          onLogoutAccount={handleLogoutAccount}
        />
        <InstallPrompt />
      </>
    );
  }

  // v70 H2: say so when this device can't confirm who owns the network (the pin
  // is unreadable / was withheld), or when it trusted the owner on first sight.
  const ownerPin = (state.users.find(u => u.isMe) as any)?.ownerPin as string | undefined;
  const pinNoteKey = state.currentUser ? 'arbor_pinnote_' + state.currentUser.id : '';
  const showPinNote = !!state.currentUser && !state.currentUser.pending && (ownerPin === 'missing'
    || (ownerPin === 'first-sight' && (() => { try { return !localStorage.getItem(pinNoteKey); } catch { return true; } })()));

  return (
    <>
      {showPinNote && (
        <div className={`fixed left-0 right-0 z-[90] px-4 py-2 text-[11px] leading-snug text-center ${ownerPin === 'missing' ? 'bg-red-600/95 text-white' : 'bg-amber-500/95 text-black'}`}
          style={{ top: 'env(safe-area-inset-top, 0px)' }} role="alert">
          {ownerPin === 'missing'
            ? 'This device can’t confirm who owns this network, so no member can be verified and your messages to them may be withheld. Open an invite link from the owner on this device, or sign in on a device you used here before.'
            : 'This device trusted this network’s owner the first time it saw them (you joined before signed membership). Compare safety numbers with the owner to be sure.'}
          {ownerPin === 'first-sight' && (
            <button className="ml-3 underline font-bold" onClick={() => { try { localStorage.setItem(pinNoteKey, '1'); } catch {} setState(prev => ({ ...prev })); }}>Dismiss</button>
          )}
        </div>
      )}
      {state.currentUser?.pending && (
        <div className="fixed inset-0 z-[150] bg-[#0a0a0a] flex flex-col items-center justify-center p-8 text-center" style={{ paddingTop: 'calc(env(safe-area-inset-top, 0px) + 2rem)' }}>
          <div className="w-16 h-16 rounded-3xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center mb-6">
            <div className="w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
          </div>
          <div className="text-lg font-black text-white tracking-tight mb-2">Request sent</div>
          <p className="text-xs text-zinc-400 leading-relaxed max-w-xs">
            You asked to join as <span className="text-emerald-400 font-bold">{state.currentUser.name}</span>. Your inviter has to accept before you're connected — this screen updates the moment they do.
          </p>
          <button
            onClick={() => setState(prev => ({ ...prev, currentUser: null, users: [], messages: [], invites: [], joinRequests: [] }))}
            className="mt-8 text-[10px] font-black uppercase tracking-widest text-zinc-500 hover:text-white transition-colors">
            Back to networks
          </button>
        </div>
      )}
      {callBanner && (
        <button
          onClick={() => {
            const target = myNodes.find(n => n.id === callBanner.to);
            if (target) handleNodeLogin(target); else setCallBanner(null);
          }}
          className="fixed top-0 left-0 right-0 z-[200] bg-emerald-500 text-black text-xs font-black py-3 text-center uppercase tracking-widest animate-pulse"
          style={{ paddingTop: 'calc(env(safe-area-inset-top, 0px) + 12px)' }}>
          Incoming call on another network from {callBanner.fromName} — tap to switch
        </button>
      )}
      {error && (
        <div className="fixed top-0 left-0 right-0 z-[100] bg-amber-500/90 text-black text-[10px] font-bold py-1 text-center uppercase tracking-widest backdrop-blur-sm">{error}</div>
      )}
      <Suspense fallback={<div className="min-h-[100dvh] bg-[#0a0a0a] flex items-center justify-center"><div className="w-6 h-6 rounded-full border-2 border-emerald-500/30 border-t-emerald-500 animate-spin" /></div>}>
      <Dashboard
        key={state.currentUser.id}
        state={state}
        onLogout={handleNodeLogout}
        onSwitchIdentity={handleSwitchIdentity}
        onSendMessage={handleSendMessage}
        onPrune={handlePrune}
        onTogglePermissions={handleTogglePermissions}
        onUpdateTreeSettings={handleUpdateTreeSettings}
        onUpdateColor={handleUpdateColor}
        onUpdateName={handleUpdateName}
        onUpdateProfile={handleUpdateProfile}
        onHubConnect={handleHubConnect}
        typingPeers={typingPeers}
        onReact={handleReact}
        onTyping={handleTyping}
        notifPermission={notifPermission}
        onEnableNotifications={toggleNotifications}
        pushEnabled={pushEnabled}
        billingAlert={billingAlert}
        onDismissBillingAlert={() => setBillingAlert(false)}
        callState={callState}
        callActions={{
          start: (targets) => callMgr.current!.startCall(targets),
          accept: () => callMgr.current!.accept(),
          decline: () => callMgr.current!.decline(),
          hangup: () => callMgr.current!.hangup(),
          toggleMute: () => callMgr.current!.toggleMute(),
          toggleVideo: () => callMgr.current!.toggleVideo(),
          switchCamera: () => callMgr.current!.switchCamera(),
          getDiag: () => callMgr.current?.getDiagnostics() || '',
        }}
        onPanicWipe={async () => { await api.panicWipe(state.currentUser?.id || null); window.location.reload(); }}
        onAcknowledge={handleAcknowledge}
        joinRequests={state.joinRequests || []}
        onRespondJoin={async (targetUserId, accept) => {
          if (!state.currentUser) return;
          await api.respondJoinRequest(state.currentUser.id, targetUserId, accept);
          refreshData(false);
        }}
        onDeleteForMe={async (mids) => {
          if (!state.currentUser) return;
          await api.deleteMessagesLocal(state.currentUser.id, mids);
          refreshData(false);
        }}
        onDeleteForAll={async (mids) => {
          if (!state.currentUser) return;
          await api.deleteMessagesForAll(state.currentUser, mids);
          refreshData(false);
        }}
        onSetGroups={async (ownerNodeId, assignments, labels, parents, links, visitors) => {
          if (!state.currentUser) return;
          const target = ownerNodeId || state.currentUser.id;
          const res = await api.setInviteeGroups(target, assignments, labels, parents, links, visitors as any);
          // Build the optimistic group maps by applying THIS operation to the
          // owner's CURRENT maps — NOT by trusting res wholesale. A flaky tunnel
          // can hand back a malformed/empty response, and blindly adopting it was
          // what wiped every link ("deleting one deletes all"). We start from what
          // we know, apply the exact edit, and prefer the server's value per-field
          // only when it's a well-formed object. The next confirmed read reconciles.
          const ownerNode: any = target === (stateRef.current.currentUser as any)?.id
            ? stateRef.current.currentUser
            : stateRef.current.users.find(u => u.id === target);
          const ownerLabels: any = (ownerNode?.groupLabels) || {};
          const optLinks: any = { ...((ownerNode?.groupLinks) || {}) };
          if (links) for (const [lid, spec] of Object.entries(links as any)) {
            if (spec === null) { delete optLinks[lid]; continue; }
            if (spec && typeof (spec as any).archived === 'boolean' && (spec as any).groups === undefined) {
              if (optLinks[lid]) optLinks[lid] = { ...optLinks[lid], archived: (spec as any).archived };
              continue;
            }
            if (spec && Array.isArray((spec as any).refs)) {
              // Cross-level link: keep the client-supplied name (owner labels span
              // multiple nodes, so we trust the name the caller derived).
              optLinks[lid] = { refs: (spec as any).refs, name: (spec as any).name || optLinks[lid]?.name || 'Cross-level chat', crossLevel: true };
            } else if (spec && Array.isArray((spec as any).groups)) {
              const gs: string[] = (spec as any).groups;
              // Derive the same default name the server uses ("A × B") so a new
              // link shows its name IMMEDIATELY instead of a blank tab for minutes.
              const nm = (spec as any).name || optLinks[lid]?.name || gs.map((g: string) => ownerLabels[g] || g).join(' × ');
              optLinks[lid] = { groups: gs, name: nm };
            }
          }
          const optAssign: any = { ...((ownerNode?.inviteeGroups) || {}) };
          if (assignments) for (const [cid, gid] of Object.entries(assignments as any)) { if (gid == null || gid === '') delete optAssign[cid]; else optAssign[cid] = gid; }
          const optLabels: any = { ...((ownerNode?.groupLabels) || {}) };
          if (labels) for (const [gid, nm] of Object.entries(labels as any)) { if (nm == null || nm === '') delete optLabels[gid]; else optLabels[gid] = nm; }
          const optParents: any = { ...((ownerNode?.groupParents) || {}) };
          if (parents) for (const [gid, pid] of Object.entries(parents as any)) { if (pid == null || pid === '') delete optParents[gid]; else optParents[gid] = pid; }
          const optVisitors: any = { ...((ownerNode?.groupVisitors) || {}) };
          if (visitors) for (const [gid, arr] of Object.entries(visitors as any)) { if (arr == null || (Array.isArray(arr) && (arr as any).length === 0)) delete optVisitors[gid]; else optVisitors[gid] = arr; }
          const wellFormed = (v: any) => v && typeof v === 'object' && !Array.isArray(v);
          const g = {
            inviteeGroups: wellFormed((res as any).inviteeGroups) ? (res as any).inviteeGroups : optAssign,
            groupLabels: wellFormed((res as any).groupLabels) ? (res as any).groupLabels : optLabels,
            groupParents: wellFormed((res as any).groupParents) ? (res as any).groupParents : optParents,
            // Links carry the reported failure mode, so trust our computed result
            // over the response body (they agree on a healthy connection anyway).
            groupLinks: optLinks,
            groupVisitors: wellFormed((res as any).groupVisitors) ? (res as any).groupVisitors : optVisitors,
          };
          // Mark a local edit and hold the written group fields so any tree-context
          // read (in-flight or a later stale replay) can't revert them until the
          // server CONFIRMS them. Held up to 60s to outlast a flaky-tunnel spell.
          writeSeq.current++;
          pendingGroups.current.set(target, { g, until: Date.now() + 60000 });
          // Optimistic paint on the OWNER node (which may be a descendant, not me).
          setState(prev => prev.currentUser ? ({
            ...prev,
            currentUser: prev.currentUser.id === target ? { ...prev.currentUser, ...g } : prev.currentUser,
            users: prev.users.map(u => u.id === target ? { ...u, ...g } : u),
          }) : prev);
          // Then reconcile from the server. tree-context returns the same group
          // data, so this confirms rather than clobbers — and it picks up the
          // group-scoped message tabs. Awaited so any SSE-triggered refresh that
          // fires in parallel can't leave us on stale data.
          await refreshData(false);
        }}
        onMoveNode={async (nodeId, targetOwnerId, targetGroupId) => {
          if (!state.currentUser) return;
          await api.moveNode(state.currentUser.id, nodeId, targetOwnerId, targetGroupId);
          // A move re-parents a whole subtree (paths/levels change) — just pull a
          // fresh tree rather than trying to optimistically splice the structure.
          await refreshData(false);
        }}
        onDeleteTree={async () => {
          if (!state.currentUser) return;
          await api.deleteTree(state.currentUser.id);
          localStorage.removeItem('arbor_account');
          window.location.reload();
        }}
      />
      </Suspense>
    </>
  );
};

export default App;
