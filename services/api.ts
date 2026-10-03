import { User, Message, Invite, Account, AttachmentRef } from '../types';
import {
  deriveAuthMaterial, generateNodeKeys, exportPublicBundle,
  sealContent, openContent, newMessageId, isSafeMediaDataUrl,
  assessPassphrase, Envelope, NodePrivateKeys, ContentMeta, KdfVersion, CURRENT_KDF,
  bindCekToEnvelope, unbindCek, rewrapBlob,
  buildRecoveryBlob, recoveryIdFor, openRecoveryBlob, generateSeedPhrase, solvePow,
} from './cryptoService';
import * as keyStore from './keyStore';
import * as appLock from './appLock';
import * as signal from './signal';
import * as msgStore from './messageStore';
import * as snapshotStore from './snapshotStore';
import * as sealedLocal from './sealedLocal';
import { resealAllSignal, hasRecordsUnderOtherKey } from './signalStore';
import { encryptAttachment, decryptAttachment, bytesToB64 } from './mediaService';
import { NetTrust, UNKNOWN_NAME, UNVERIFIED_REQUEST } from './netTrust';
import { sameKey, LEGACY_GRACE_END } from './membership';

// v72 M6: shown when the server asks for a weaker password check than this device has used before.
export const KDF_DOWNGRADE = 'This server asked for an older, weaker password check than this device has used for your account before, so Arbor stopped to protect your password. Try again later — if it keeps happening, the server may have been tampered with; contact its operator.';
import { cleanName, openAvatar } from './profiles';
import * as x from './xeddsa';

// v72 (L): newest encrypted-state backup this device made or restored, per identity
// (a restore never goes back before it — see ensureSignalReady).
const backupHwKey = (nodeId: string) => 'arbor-backup-hw|' + nodeId;
const backupHighWater = (nodeId: string): number => { try { return Number(localStorage.getItem(backupHwKey(nodeId))) || 0; } catch { return 0; } };
const noteBackupHighWater = (nodeId: string, at: number) => {
  try { if (at > backupHighWater(nodeId)) localStorage.setItem(backupHwKey(nodeId), String(at)); } catch {}
};

// Session repair. When a verified member's messages stop decrypting for good, our
// ratchet session with them has diverged (e.g. one side resumed from an older
// backup on another device). The peer is flagged; the next send to them starts a
// fresh session through the same verified-bundle path as first contact, and their
// device adopts it on receipt. At most one re-key per peer per REKEY_MIN_MS.
const REKEY_MIN_MS = 10 * 60 * 1000;
const rekeyKey = (nodeId: string, peerId: string) => 'arbor-rekey|' + nodeId + '|' + peerId;
const readRekey = (nodeId: string, peerId: string): { due?: boolean; at?: number } => {
  try { return JSON.parse(localStorage.getItem(rekeyKey(nodeId, peerId)) || '{}') || {}; } catch { return {}; }
};
const flagRekey = (nodeId: string, peerId: string) => {
  const r = readRekey(nodeId, peerId);
  if (r.due || (r.at && Date.now() - r.at < REKEY_MIN_MS)) return;
  try { localStorage.setItem(rekeyKey(nodeId, peerId), JSON.stringify({ due: true, at: r.at || 0 })); } catch {}
};
const noteRekeyed = (nodeId: string, peerId: string) => {
  try { localStorage.setItem(rekeyKey(nodeId, peerId), JSON.stringify({ at: Date.now() })); } catch {}
};

/** V8 phase 2: this build speaks the encrypted-profile / signed-membership
 *  protocol. The server refuses profile and messaging routes from older builds. */
const ARBOR_PROTO = '2';

// Every IndexedDB database this app creates. Panic Wipe deletes ALL of them
// (V8 M-12: the avatar cache and the key/pin store used to be left behind).
const ALL_LOCAL_DBS = ['arbor-signal-v1', 'arbor-messages-v1', 'arbor-snapshots-v1', 'arbor-keys-v4', 'arbor-avatars'];
const deleteDb = (name: string) => new Promise<void>(res => {
  try { const r = indexedDB.deleteDatabase(name); r.onsuccess = r.onerror = r.onblocked = () => res(); }
  catch { res(); }
});

const API_BASE = '/api';

const readCookie = (name: string): string | null => {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
};

// CSRF token: held in memory only (never in a JS-readable cookie). Set from the
// login/signup response, or fetched from GET /api/csrf after a page reload.
let csrfToken: string | null = null;
export const setCsrfToken = (t: string | null) => { csrfToken = t; };

class BackendAPI {
  // Render-perf: reuse previous array references when nothing changed, so React
  // never re-renders a chat full of multi-MB base64 images for a no-op refresh.
  private lastMsgs: { sig: string; arr: Message[] } | null = null;
  // Message-store read cache (see fetchTreeContext PERF note).
  private msgCache: (msgStore.StoredMessage & { mid: string })[] | null = null;
  private msgCacheNode: string | null = null;
  /** Any code path that writes to the message store must call this. */
  invalidateMsgCache() { this.msgCache = null; }
  // Decrypt attempts per message id: a session-mismatch failure (e.g. both sides
  // established Signal sessions simultaneously) fails FOREVER but used to fail
  // INVISIBLY — the message simply never appeared ("j1 can't see j3's messages").
  // After a few retries we persist a visible placeholder instead.
  private decryptAttempts = new Map<string, number>();
  /** Incrementally add one message to the in-memory render cache instead of
   *  invalidating it. Invalidation forced the next poll to re-read EVERY message
   *  (with multi-MB media bodies) out of IndexedDB — that read was the "sending
   *  a message lags the whole chat" cost on phones. */
  private appendToMsgCache(nodeId: string, mid: string, rec: any) {
    if (this.msgCacheNode !== nodeId || !this.msgCache) return; // cache will lazy-build later
    const row = { ...rec, mid };
    // UPSERT: an existing mid means the stored record was patched in place
    // (message edit, read-marker, hidden flag). Replace the row where it sits —
    // its timestamp doesn't change — instead of silently dropping the update
    // (which left the OLD text on screen until a full reload).
    const existingIdx = this.msgCache.findIndex(m => m.mid === mid);
    if (existingIdx >= 0) { this.msgCache[existingIdx] = row; return; }
    const arr = this.msgCache;
    if (!arr.length || arr[arr.length - 1].timestamp <= rec.timestamp) arr.push(row);
    else {
      const i = arr.findIndex(m => m.timestamp > rec.timestamp);
      arr.splice(i < 0 ? arr.length : i, 0, row);
    }
  }
  private dropFromMsgCache(nodeId: string, mids: string[]) {
    if (this.msgCacheNode !== nodeId || !this.msgCache) return;
    const dead = new Set(mids);
    this.msgCache = this.msgCache.filter(m => !dead.has(m.mid));
  }
  // Map the in-memory message cache to the wire Message[] the UI renders, with the
  // same expiry filter + structural sharing fetchTreeContext uses. Pulled out so a
  // fresh send can echo the message to the UI INSTANTLY (before the network round
  // trip) rather than waiting for the next tree-context fetch.
  private mapMsgCache(): Message[] {
    const now = Date.now();
    const msgs = (this.msgCache || [])
      .filter(s => !(typeof s.expiresAt === 'number' && s.expiresAt <= now))
      .filter(s => !(s as any).hidden)
      .map(s => ({
        id: s.mid, senderId: s.senderId, timestamp: s.timestamp, type: s.type,
        targetCircle: s.targetCircle, targetGroup: (s as any).targetGroup, peerId: (s as any).peerId,
        expiresAt: s.expiresAt, text: s.text, imageUrl: s.imageUrl, audioUrl: s.audioUrl, videoUrl: s.videoUrl,
        attachments: s.attachments, replyTo: s.replyTo, ackRequested: s.ackRequested, senderLevel: s.senderLevel,
        callLog: s.callLog, edited: (s as any).edited, editedAt: (s as any).editedAt,
        verified: s.verified, keyChanged: s.keyChanged, readAt: s.readAt, sentTo: s.sentTo, withheld: s.withheld, keyChangedWithheld: s.keyChangedWithheld,
        verifiedIfKeyOk: s.verifiedIfKeyOk, editRefused: s.editRefused,
      } as Message))
      .sort((a, b) => a.timestamp - b.timestamp);
    return this.share('m', msgs,
      msgs.map(m => `${m.id}:${m.expiresAt || 0}:${m.keyChanged ? 1 : 0}:${m.verified ? 1 : 0}:${m.readAt ? 1 : 0}:${m.editedAt || 0}`).join('|'));
  }
  /** The current chat's messages straight from the local cache (no network) — used
   *  for the instant optimistic echo on send. Empty if the cache isn't built yet. */
  messagesNow(): Message[] { return this.msgCache ? this.mapMsgCache() : []; }
  /** A fresh message id, so the UI can render an instant local bubble under the
   *  SAME id the encrypted send will use — the confirm is then seamless. */
  newMid(): string { return newMessageId(); }
  private lastUsers: { sig: string; arr: User[] } | null = null;
  private share<T>(kind: 'm' | 'u', arr: T[], sig: string): T[] {
    const slot = kind === 'm' ? this.lastMsgs : this.lastUsers;
    if (slot && slot.sig === sig) return slot.arr as unknown as T[];
    if (kind === 'm') this.lastMsgs = { sig, arr: arr as unknown as Message[] };
    else this.lastUsers = { sig, arr: arr as unknown as User[] };
    return arr;
  }

  onAuthError: (() => void) | null = null;
  /** V8 phase 2: signed membership + encrypted profiles (see netTrust.ts). */
  readonly trust = new NetTrust(
    (endpoint, body) => this.request(endpoint, { method: 'POST', body: JSON.stringify(body) }),
    (endpoint) => this.request(endpoint),
  );
  /** Decrypted display name for a public id this device has seen (null if none). */
  nameOf(pid: string | null | undefined): string | null { return this.trust.nameOf(pid); }
  // Nodes whose Signal prekeys we've already ensured/published this session.
  private prepared = new Set<string>();

  isAuthed(): boolean { return !!csrfToken; }

  // Ensure we have a CSRF token before a state-changing request. After a page
  // reload the token isn't in memory yet, so fetch it (the httpOnly session
  // cookie authenticates this GET). Returns null if not authenticated.
  private async ensureCsrf(): Promise<string | null> {
    if (csrfToken) return csrfToken;
    try {
      const r = await fetch(`${API_BASE}/csrf`, { credentials: 'same-origin' });
      if (r.ok) { csrfToken = (await r.json()).csrf || null; }
    } catch {}
    return csrfToken;
  }

  private async request(endpoint: string, options: RequestInit = {}) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-Arbor-Proto': ARBOR_PROTO, ...(options.headers as any) };
    const method = (options.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      const csrf = await this.ensureCsrf();
      if (csrf) headers['X-CSRF-Token'] = csrf;
    }
    const response = await fetch(`${API_BASE}${endpoint}`, { ...options, headers, credentials: 'same-origin' });
    const ct = response.headers.get('content-type') || '';
    if (!response.ok) {
      let msg = `Server error: ${response.status}`;
      let body: any = null;
      if (ct.includes('application/json')) { try { body = await response.json(); msg = body?.error || msg; } catch {} }
      if (response.status === 401 && !endpoint.startsWith('/auth/')) { csrfToken = null; this.onAuthError?.(); }
      // The server moved to a newer protocol than this page: reload once to pick
      // up the current app (the service worker is network-first).
      if (response.status === 426) {
        try { if (!sessionStorage.getItem('arbor-426')) { sessionStorage.setItem('arbor-426', '1'); location.reload(); } } catch {}
      }
      // Attach the structured error body + status so callers can branch on it
      // (e.g. a link that collides with an archived one carries { code, linkId }).
      const err: any = new Error(msg); err.status = response.status; err.body = body;
      throw err;
    }
    return ct.includes('application/json') ? response.json() : null;
  }

  // ---- v72 M6: no password-KDF downgrade -------------------------------------
  // The KDF version comes from the server (/auth/salt). A compromised or impersonated
  // server could answer 'kdf 1' (the old, much cheaper PBKDF2) for an account that is
  // on the memory-hard KDF, to obtain an easy-to-crack password verifier. This device
  // remembers the strongest version it has used for each username (under a hash, not
  // the name) and refuses to derive with a weaker one.
  private async kdfFloorKey(username: string): Promise<string> {
    const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('arbor-kdf-floor|' + username.trim().toLowerCase()));
    return 'arbor-kdf-floor:' + Array.from(new Uint8Array(d).slice(0, 16), b => b.toString(16).padStart(2, '0')).join('');
  }
  private async noteKdf(username: string, version: number): Promise<void> {
    try { const k = await this.kdfFloorKey(username); if (version > Number(localStorage.getItem(k) || 0)) localStorage.setItem(k, String(version)); } catch {}
  }
  private async saltFor(username: string): Promise<{ salt: string; kdf: number }> {
    const r = await this.request('/auth/salt', { method: 'POST', body: JSON.stringify({ username }) });
    let floor = 0;
    try { floor = Number(localStorage.getItem(await this.kdfFloorKey(username)) || 0); } catch {}
    if ((r.kdf === 1 ? 1 : 2) < floor) throw new Error(KDF_DOWNGRADE);
    return r;
  }

  // ---- Account auth ----
  async login(username: string, password: string): Promise<Account> {
    const { salt, kdf } = await this.saltFor(username);   // v72 M6: refuses a KDF downgrade
    const version: KdfVersion = kdf === 1 ? 1 : 2;
    const { authHash, wrapKey } = await deriveAuthMaterial(username, password, salt, version);
    const acc = await this.request('/auth/login', { method: 'POST', body: JSON.stringify({ username, authHash }) });
    csrfToken = acc.csrf || csrfToken;
    keyStore.setWrapKey(wrapKey);
    await this.noteKdf(username, version);
    // v71 M6: biometric unlock sealed a key from before a password change (here or
    // on another device) — it would unlock the wrong key, so it is switched off.
    try { if (await appLock.isStaleFor(wrapKey)) { await appLock.disable(); try { localStorage.setItem('arbor-biometric-reset', '1'); } catch {} } } catch {}
    // v71 M6: the password was changed: this device's local data may still be
    // sealed under an earlier key. The server keeps the earlier key(s) sealed under
    // the current one; open them and re-seal everything local.
    if (Array.isArray(acc.prevWraps) && acc.prevWraps.length) {
      const olds: CryptoKey[] = [];
      for (const pw of acc.prevWraps) {
        try {
          const raw = new Uint8Array(await keyStore.unwrapBytes(pw));
          try { olds.push(await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])); } finally { raw.fill(0); }
        } catch { /* not ours / unreadable */ }
      }
      if (olds.length) {
        keyStore.addLegacyWrapKeys(olds);
        try { localStorage.setItem(keyStore.RESEAL_PENDING, '1'); } catch {}
        this.fetchMyNodes().then(nodes => this.finishReseal(nodes)).catch(() => this.finishReseal([]));
        return { id: acc.id, username: acc.username };
      }
    }
    // V8 H-3: a legacy (PBKDF2) account is migrated to the memory-hard KDF right
    // after a successful login. Best-effort: on any failure the account simply
    // stays on kdf 1 (fully working) and the migration retries next login.
    if (version === 1) {
      try { await this.upgradeKdf(username, password, salt, authHash, wrapKey); }
      catch (e) { try { console.warn('[kdf] upgrade deferred:', (e as any)?.message || e); } catch {} }
    } else if (localStorage.getItem(keyStore.RESEAL_PENDING) || await hasRecordsUnderOtherKey().catch(() => false)) {
      // v70 H5: the pre-upgrade key is no longer kept on disk. If this device's
      // re-seal was interrupted (reload) — or local records were written under the
      // pre-upgrade key after the upgrade (an older app version) — re-derive it
      // from the password as a read-only key and re-seal everything.
      try {
        const old = await deriveAuthMaterial(username, password, salt, 1);
        await keyStore.setLegacyWrapKey(old.wrapKey);
        this.finishReseal([]);
      } catch {}
    }
    return { id: acc.id, username: acc.username };
  }

  /**
   * v70 H5: turn on biometric unlock for this device. The password is needed to
   * re-derive the wrap key's raw bytes (the in-memory key can't be exported); it
   * is checked against the key this session already holds before anything is
   * sealed under the authenticator's PRF secret (appLock.enable).
   */
  async enableBiometricUnlock(username: string, password: string): Promise<void> {
    const { salt, kdf } = await this.saltFor(username);   // v72 M6: refuses a KDF downgrade
    const d = await deriveAuthMaterial(username, password, salt, kdf === 1 ? 1 : 2, true);
    const raw = d.wrapRaw!;
    try {
      const probe = await keyStore.wrapBytes(new TextEncoder().encode('arbor-applock-probe').buffer as ArrayBuffer);
      const { iv, ct } = JSON.parse(probe);
      const u = (x: string) => Uint8Array.from(atob(x), c => c.charCodeAt(0));
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u(iv) }, d.wrapKey, u(ct));
    } catch { raw.fill(0); throw new Error('That password doesn’t match this account.'); }
    await appLock.enable(username, raw);
  }

  /**
   * V8 H-3 — move an account from the PBKDF2 derivation to scrypt. Every blob the
   * SERVER holds under the old wrap key (node private keys, wrapped Signal
   * identity, encrypted state backups) is re-encrypted under the new key and
   * uploaded FIRST; only then is the new auth value committed (which needs the
   * old one — a password-change-strength operation). If interrupted, the account
   * stays on kdf 1 and the next login repeats the process; rewrapBlob accepts
   * either key, so partially-migrated blobs are handled. Local sealed stores are
   * re-sealed in the background, with the old key kept as a read-only fallback
   * until that finishes.
   */
  private async upgradeKdf(username: string, password: string, salt: string, oldAuthHash: string, oldWrapKey: CryptoKey): Promise<void> {
    const { authHash: newAuthHash, wrapKey: newWrapKey } = await deriveAuthMaterial(username, password, salt, CURRENT_KDF);
    const from = [oldWrapKey, newWrapKey];
    const nodes: User[] = await this.fetchMyNodes();
    // A blob that opens with NEITHER key is already unreadable garbage (nothing to
    // protect), so it is skipped rather than blocking the upgrade forever.
    const tryRewrap = async (blob: string) => { try { return await rewrapBlob(blob, from, newWrapKey); } catch { return null; } };
    for (const n of nodes) {
      const body: Record<string, string> = { nodeId: n.id };
      const wk = n.wrappedKeys ? await tryRewrap(n.wrappedKeys) : null;
      if (wk) body.wrappedKeys = wk;
      const got = await this.request('/signal-identity/get', { method: 'POST', body: JSON.stringify({ nodeId: n.id }) }).catch(() => null);
      const iw = got?.identity?.wrapped ? await tryRewrap(got.identity.wrapped) : null;
      if (iw) body.identityWrapped = iw;
      if (wk || iw) await this.request('/nodes/rewrap', { method: 'POST', body: JSON.stringify({ ...body, authHash: oldAuthHash }) }); // v71 L4: re-auth
      const bk = await this.request('/state-backup/get', { method: 'POST', body: JSON.stringify({ nodeId: n.id }) }).catch(() => null);
      const bw = bk?.backup?.wrapped ? await tryRewrap(bk.backup.wrapped) : null;
      if (bw) await this.request('/state-backup/set', { method: 'POST', body: JSON.stringify({ nodeId: n.id, wrapped: bw, ts: bk.backup.ts }) });
      // v70 H2: the owner pin and picker label are sealed under the account key too;
      // left behind, they'd stop opening once the old key is gone.
      const ac = (n as any).anchorCt ? await tryRewrap((n as any).anchorCt) : null;
      const sc = (n as any).selfCt ? await tryRewrap((n as any).selfCt) : null;
      if (ac || sc) await this.request('/profile/set', { method: 'POST', body: JSON.stringify({ nodeId: n.id, ...(ac ? { anchorCt: ac, replaceAnchor: true } : {}), ...(sc ? { selfCt: sc } : {}) }) }).catch(() => {});
    }
    await this.request('/auth/kdf-upgrade', { method: 'POST', body: JSON.stringify({ oldAuthHash, newAuthHash, kdf: CURRENT_KDF }) });
    await this.noteKdf(username, CURRENT_KDF);                         // v72 M6
    // Committed. Switch this device to the new key; keep the old one for READING
    // local records until the background re-seal has converted them.
    try { localStorage.setItem(keyStore.RESEAL_PENDING, '1'); } catch {}
    await keyStore.setLegacyWrapKey(oldWrapKey);
    keyStore.setWrapKey(newWrapKey);
    this.lastBackupHash.clear();
    this.finishReseal(nodes);
  }
  /** Re-seal local stores still under the pre-upgrade key, then forget that key. */
  private finishReseal(nodes: User[]): void {
    (async () => {
      try {
        await msgStore.resealAll();
        await snapshotStore.resealAll();
        await resealAllSignal();
        await sealedLocal.resealNow().catch(() => {});       // v71: drafts + scheduled sends
        for (const n of nodes) await this.trust.resealPin(n.id, (n as any).anchorCt).catch(() => {}); // v70 H2
        await keyStore.setLegacyWrapKey(null);
        try { localStorage.removeItem(keyStore.RESEAL_PENDING); } catch {}
      } catch { /* legacy key stays in memory; the next password login retries */ }
    })();
  }

  async signup(username: string, password: string, onPow?: (tried: number) => void): Promise<Account> {
    const strength = assessPassphrase(password);
    if (!strength.ok) throw new Error(strength.reason || 'Choose a stronger passphrase.');
    const wrapSalt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
    const { authHash, wrapKey } = await deriveAuthMaterial(username, password, wrapSalt, CURRENT_KDF);
    // Anti-spam proof-of-work: fetch a challenge and solve it before signing up.
    // The server may report it disabled, in which case we skip straight through.
    let pow: { powToken?: string; powNonce?: string } = {};
    try {
      const ch = await this.request('/auth/pow-challenge', { method: 'GET' });
      if (ch && ch.token && !ch.disabled) {
        const powNonce = await solvePow(ch.token, ch.difficulty, onPow);
        pow = { powToken: ch.token, powNonce };
      }
    } catch { /* if the challenge fetch fails, let the server decide (it will reject if PoW is required) */ }
    const acc = await this.request('/auth/signup', { method: 'POST', body: JSON.stringify({ username, authHash, wrapSalt, kdf: CURRENT_KDF, ...pow }) });
    csrfToken = acc.csrf || csrfToken;
    keyStore.setWrapKey(wrapKey);
    await this.noteKdf(username, CURRENT_KDF);                         // v72 M6
    return { id: acc.id, username: acc.username };
  }

  async logout(): Promise<void> {
    try { await this.request('/auth/logout', { method: 'POST' }); } catch {}
    csrfToken = null;
    // V8 M-12: drafts / scheduled-message text and the cached faces of contacts
    // are device-local data that must not outlive the login.
    sealedLocal.clearAll();
    await deleteDb('arbor-avatars');
    await keyStore.clearAllKeys();
    await appLock.disable().catch(() => {});   // the sealed biometric key dies with the login (v70 H5)
    this.trust.reset();
    this.prepared.clear();
    this.attachmentCache.clear();
    this.invalidateMsgCache();
  }

  /** V8 M-11: app-lock re-lock — drop decrypted material held in memory. Keys
   *  reload from their non-extractable IndexedDB handles after unlock. */
  dropSensitiveMemory(): void {
    this.attachmentCache.clear();
    this.invalidateMsgCache();
    this.lastMsgs = null;
    this.trust.reset();
    keyStore.dropMemoryKeys();
  }

  /**
   * V8 M-7 — permanently delete this account on the server (requires the
   * password). If the account owns networks other people are in, the server
   * refuses unless deleteOwnedNetworks is true; the error carries
   * { code: 'owns-networks', networks }. On success every local store is wiped.
   */
  async deleteAccount(username: string, password: string, deleteOwnedNetworks = false): Promise<void> {
    const { salt, kdf } = await this.saltFor(username);   // v72 M6: refuses a KDF downgrade
    const { authHash } = await deriveAuthMaterial(username, password, salt, kdf === 1 ? 1 : 2);
    await this.request('/account/delete', { method: 'POST', body: JSON.stringify({ authHash, deleteOwnedNetworks }) });
    await this.panicWipe(null);
  }

  /**
   * v71 M6 — change the account password.
   * Every blob the server holds under the current wrap key is re-encrypted under
   * the new one HERE, then all of it is committed together with the new auth value
   * in ONE request (the server applies all or nothing). v72 M7: the state backups
   * too — too large for that request, they are staged first and swapped in by it. The old key is sent along
   * sealed under the new key (plus any earlier ones still pending), so every device
   * of this account can re-seal its local data at its next login. Afterwards this
   * device re-seals its own local stores. Other sessions are ended, the recovery
   * phrase is cleared (it holds the old password), and biometric unlock is reset.
   */
  async changePassword(username: string, oldPassword: string, newPassword: string): Promise<{ recoveryCleared: boolean; sessionsEnded: number }> {
    const strength = assessPassphrase(newPassword);
    if (!strength.ok) throw new Error(strength.reason || 'Choose a stronger passphrase.');
    if (oldPassword === newPassword) throw new Error('The new password must be different.');
    const { salt, kdf } = await this.saltFor(username);   // v72 M6: refuses a KDF downgrade
    if (kdf === 1) throw new Error('Sign out and back in once to finish a security upgrade, then try again.');
    const old = await deriveAuthMaterial(username, oldPassword, salt, 2, true);
    const next = await deriveAuthMaterial(username, newPassword, salt, 2);
    const oldRaw = old.wrapRaw!;
    try {
      // The current password must be the one this session's key came from.
      const cur = keyStore.currentWrapKey();
      if (cur) {
        const probe = await keyStore.wrapBytes(new TextEncoder().encode('arbor-pw-probe').buffer as ArrayBuffer);
        try { const { iv, ct } = JSON.parse(probe); await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Uint8Array.from(atob(iv), c => c.charCodeAt(0)) }, old.wrapKey, Uint8Array.from(atob(ct), c => c.charCodeAt(0))); }
        catch { throw new Error('Your current password is incorrect.'); }
      }
      const from = [old.wrapKey, ...keyStore.legacyWrapKeys()];
      const re = async (blob: string) => rewrapBlob(blob, from, next.wrapKey);
      const nodes: User[] = await this.fetchMyNodes();
      const payloadNodes: any[] = [];
      // v72 M7: the encrypted state backups are staged re-encrypted first and swapped
      // in by the change request itself (v71 re-wrapped them afterwards, best
      // effort, so a failure left them under the old password). This device's own
      // backup uploads pause meanwhile — a new one would void the staged copy.
      this.pwChangeActive = true;
      const backupStage = Array.from(crypto.getRandomValues(new Uint8Array(18)), b => b.toString(16).padStart(2, '0')).join('');
      for (const n of nodes) {
        const entry: any = { nodeId: n.id };
        if (n.wrappedKeys) entry.wrappedKeys = await re(n.wrappedKeys).catch(() => { throw new Error('Some of your keys could not be re-encrypted. Nothing was changed.'); });
        const got = await this.request('/signal-identity/get', { method: 'POST', body: JSON.stringify({ nodeId: n.id }) }).catch(() => null);
        if (got?.identity?.wrapped) entry.identityWrapped = await re(got.identity.wrapped).catch(() => { throw new Error('Some of your keys could not be re-encrypted. Nothing was changed.'); });
        // Owner pin + picker label: best effort (unreadable ones were already lost).
        if ((n as any).anchorCt) { const v = await re((n as any).anchorCt).catch(() => null); if (v) entry.anchorCt = v; }
        if ((n as any).selfCt) { const v = await re((n as any).selfCt).catch(() => null); if (v) entry.selfCt = v; }
        const bk = await this.request('/state-backup/get', { method: 'POST', body: JSON.stringify({ nodeId: n.id }) })
          .catch(() => { throw new Error('Your backups could not be re-encrypted. Nothing was changed.'); });
        if (bk?.backup?.wrapped) {
          const bw = await re(bk.backup.wrapped).catch(() => null);
          if (bw) {
            await this.request('/auth/change-password/stage-backup', { method: 'POST', body: JSON.stringify({ nodeId: n.id, stage: backupStage, wrapped: bw, ts: bk.backup.ts }) });
            entry.backup = { ts: bk.backup.ts, staged: true };
          } else {
            // Opens with none of this device's keys (it was already unreadable here): left as it is.
            entry.backup = { ts: bk.backup.ts, staged: false };
          }
        }
        payloadNodes.push(entry);
      }
      const dp = await this.request('/account/profile').catch(() => null);
      const defaultProfileCt = dp?.ct ? await re(dp.ct).catch(() => undefined) : undefined;
      // The old key (and any earlier keys still pending re-seal), sealed under the new one.
      const sealRaw = async (raw: Uint8Array) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, next.wrapKey, raw.slice().buffer as ArrayBuffer));
        const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
        return JSON.stringify({ iv: b64(iv), ct: b64(ct) });
      };
      const prevWraps = [await sealRaw(oldRaw)];
      const pending = await this.request('/auth/prev-wraps', { method: 'POST', body: '{}' }).catch(() => null);
      // Earlier keys still pending (sealed under the CURRENT key): carry them over,
      // re-sealed under the new key, so a device several changes behind can catch up.
      const ub = (x: string) => Uint8Array.from(atob(x), c => c.charCodeAt(0));
      for (const pw of (pending?.prevWraps || []).slice(0, 2)) {
        try {
          const { iv, ct } = JSON.parse(pw);
          const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub(iv) }, old.wrapKey, ub(ct)));
          prevWraps.push(await sealRaw(raw));
          raw.fill(0);
        } catch { /* expired / unreadable */ }
      }
      const r = await this.request('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ oldAuthHash: old.authHash, newAuthHash: next.authHash, nodes: payloadNodes, prevWraps, backupStage, ...(defaultProfileCt !== undefined ? { defaultProfileCt } : {}) }),
      });
      // Committed (backups included). This device now uses the new key, reading
      // local records with the old one until the re-seal below has converted them.
      try { localStorage.setItem(keyStore.RESEAL_PENDING, '1'); } catch {}
      keyStore.setWrapKey(next.wrapKey);
      keyStore.addLegacyWrapKeys([old.wrapKey]);
      await appLock.disable().catch(() => {});           // it sealed the old key
      this.lastBackupHash.clear();                        // next refresh uploads a fresh one
      this.finishReseal(nodes);
      return { recoveryCleared: !!r?.recoveryCleared, sessionsEnded: r?.sessionsEnded || 0 };
    } finally { oldRaw.fill(0); this.pwChangeActive = false; }
  }

  /** v71 M6 — end every other session of this account (needs the password). */
  async revokeOtherSessions(username: string, password: string): Promise<number> {
    const { salt, kdf } = await this.saltFor(username);   // v72 M6: refuses a KDF downgrade
    const { authHash } = await deriveAuthMaterial(username, password, salt, kdf === 1 ? 1 : 2);
    const r = await this.request('/auth/sessions/revoke-others', { method: 'POST', body: JSON.stringify({ authHash }) });
    return r?.ended || 0;
  }

  /** V8 M-8 — erase this node's server-side name history. */
  async clearNameHistory(nodeId: string): Promise<void> {
    // V8 phase 2: the history lives inside the encrypted profile — re-seal without it.
    const cur = this.ownProfileOrThrow(nodeId);
    const ref = this.nodeRef(nodeId);
    await this.trust.writeProfile(ref, ref.treeRoot!, { ...cur, h: [] });
    // Also drop any legacy plaintext copy still on the server.
    await this.request('/users/name/history/clear', { method: 'POST', body: JSON.stringify({ nodeId }) }).catch(() => {});
  }

  // ---- Donations (one-time; public endpoints) ----
  async donateConfig(): Promise<{ card: boolean; crypto: boolean }> { return this.request('/donate/config'); }
  async donateStripe(amount: number): Promise<{ url: string }> { return this.request('/donate/stripe', { method: 'POST', body: JSON.stringify({ amount }) }); }
  async donateCrypto(amount: number): Promise<{ url: string }> { return this.request('/donate/crypto', { method: 'POST', body: JSON.stringify({ amount }) }); }

  async fetchMyNodes(): Promise<User[]> {
    const nodes: User[] = await this.request('/my-nodes', { method: 'POST', body: '{}' });
    // V8 phase 2: each identity's own name + network name are sealed under the
    // ACCOUNT key (selfCt) so the picker can label them without network keys.
    for (const n of nodes as any[]) {
      const lbl = await this.trust.readSelf(n);
      if (lbl?.n) n.name = lbl.n;
      if (lbl?.t) n.treeName = lbl.t;
      if (!n.name) n.name = UNKNOWN_NAME;
    }
    return nodes;
  }

  async unlockNode(node: User): Promise<NodePrivateKeys> {
    const have = await keyStore.getNodeKeys(node.id);
    if (have) return have;
    if (!node.wrappedKeys) throw new Error('No key material for this node.');
    return keyStore.unlockNode(node.id, node.wrappedKeys);
  }

  /**
   * Make sure this node has a published Signal prekey bundle so others can start
   * sessions with it. A device that lacks the local identity (fresh device / cleared
   * storage) regenerates one and republishes — counterparties then see an identity
   * change, exactly as Signal does.
   */
  private async ensureSignalReady(node: User): Promise<void> {
    if (this.prepared.has(node.id)) return;
    this.prepared.add(node.id);
    try {
      // 0) State restore: if this device has NO local Signal state for this node
      //    (fresh device, or iOS evicted IndexedDB — a routine event for PWAs),
      //    pull the client-encrypted backup and rehydrate ratchet sessions, prekey
      //    private keys, remote identities, and text message history. Without this,
      //    a device that lost its store can never decrypt messages that were
      //    ratcheted to its old sessions — the "notification arrived but no message
      //    shows up" failure.
      if (await signal.stateIsEmpty(node.id)) {
        const got = await this.request('/state-backup/get', { method: 'POST', body: JSON.stringify({ nodeId: node.id }) }).catch(() => null);
        if (got?.backup?.wrapped) {
          try {
            const raw = await keyStore.unwrapBytes(got.backup.wrapped);
            const snap = JSON.parse(new TextDecoder().decode(raw));
            // v71 L5: every backup is sealed under the same account key, so the
            // server could hand one node's backup to another — refuse that.
            if (snap?.node && snap.node !== node.id) throw new Error('backup belongs to another identity');
            // v72 (L): never roll back to a backup older than one this device made
            // (restoring old ratchet state could re-use message keys). The time is
            // inside the encrypted backup, so the server can't fake it. Limit: this
            // only helps while this device's localStorage survived.
            const hw = backupHighWater(node.id);
            if (hw && !(typeof snap?.at === 'number' && snap.at >= hw)) throw new Error('backup is older than one this device made');
            if (snap?.signal) await signal.importState(node.id, snap.signal);
            if (Array.isArray(snap?.messages)) { await msgStore.importFromBackup(node.id, snap.messages); this.invalidateMsgCache(); }
            if (snap?.pin) await this.trust.importPin(node.id, snap.pin);    // v70 H2: the owner pin moves with the backup
            if (typeof snap?.at === 'number') noteBackupHighWater(node.id, snap.at);
          } catch { /* corrupt/old backup: continue with fresh state */ }
        }
      }

      // 1) Stable identity: restore the node's persisted Signal identity if this
      //    device doesn't have it yet; otherwise make sure the server has a copy.
      //    This stops a re-login / new device from regenerating the identity (which
      //    a peer would otherwise see as "identity changed").
      const haveLocal = await signal.hasLocalIdentity(node.id);
      if (!haveLocal) {
        const got = await this.request('/signal-identity/get', { method: 'POST', body: JSON.stringify({ nodeId: node.id }) }).catch(() => null);
        if (got?.identity?.wrapped) {
          try {
            const priv = await keyStore.unwrapBytes(got.identity.wrapped);
            // v71 L5: the public key arrives in the clear next to the sealed private
            // key — prove they belong together before adopting them.
            const pubAb = signal.b642ab(got.identity.pub);
            const probe = new TextEncoder().encode('arbor-identity-check-v1');
            if (!(await x.verify(new Uint8Array(pubAb), probe, await x.sign(new Uint8Array(priv), probe)))) {
              throw new Error('stored identity public key does not match its private key');
            }
            await signal.importIdentity(node.id, pubAb, priv, got.identity.regId);
          } catch { /* fall through to generate */ }
        }
      }
      if (!(await signal.hasLocalIdentity(node.id))) {
        const idr = await signal.exportIdentityRaw(node.id); // generates + stores locally
        try {
          const wrapped = await keyStore.wrapBytes(idr.priv);
          await this.request('/signal-identity/set', { method: 'POST', body: JSON.stringify({ nodeId: node.id, signalIdentity: { pub: signal.ab2b64(idr.pub), regId: idr.regId, wrapped } }) });
        } catch {}
      } else {
        // Ensure the server has our identity persisted (idempotent first-write-wins).
        const got = await this.request('/signal-identity/get', { method: 'POST', body: JSON.stringify({ nodeId: node.id }) }).catch(() => null);
        if (!got?.identity) {
          const idr = await signal.exportIdentityRaw(node.id);
          try {
            const wrapped = await keyStore.wrapBytes(idr.priv);
            await this.request('/signal-identity/set', { method: 'POST', body: JSON.stringify({ nodeId: node.id, signalIdentity: { pub: signal.ab2b64(idr.pub), regId: idr.regId, wrapped } }) });
          } catch {}
        }
      }

      // 2) Prekeys: publish/replenish so others can open sessions with us.
      const status = await this.request('/prekeys/status', { method: 'POST', body: JSON.stringify({ nodeId: node.id }) });
      if (!status.published || (status.remaining ?? 0) < 5) {
        const bundle = await signal.buildPublishBundle(node.id);
        await this.request('/prekeys/publish', { method: 'POST', body: JSON.stringify({ nodeId: node.id, bundle }) });
      }
    } catch (e) {
      this.prepared.delete(node.id); // allow a retry on the next call
      throw e;
    }
  }

  async getVapidPublicKey(): Promise<string> {
    return (await this.request('/vapid-public-key')).publicKey;
  }
  async subscribeToPush(subscription: PushSubscription): Promise<void> {
    await this.request('/push/subscribe', { method: 'POST', body: JSON.stringify({ subscription }) });
  }
  async unsubscribeFromPush(endpoint?: string): Promise<void> {
    await this.request('/push/unsubscribe', { method: 'POST', body: JSON.stringify({ endpoint }) });
  }

  // ---- Seed-phrase recovery -------------------------------------------------
  /** Store an encrypted recovery blob for the CURRENT account (auth required). */
  async setRecovery(seed: string, username: string, password: string): Promise<void> {
    const { recoveryId, blob } = await buildRecoveryBlob(seed, username, password);
    // v72: the server checks the password before replacing a recovery phrase.
    const { salt, kdf } = await this.saltFor(username);
    const { authHash } = await deriveAuthMaterial(username, password, salt, kdf === 1 ? 1 : 2);
    await this.request('/auth/recovery/set', { method: 'POST', body: JSON.stringify({ recoveryId, blob, authHash }) });
  }
  async recoveryStatus(): Promise<{ hasRecovery: boolean }> {
    return this.request('/auth/recovery/status', { method: 'POST', body: JSON.stringify({}) });
  }
  /** Set up a recovery phrase AFTER signup (from Settings). The blob must contain
   *  the real credentials, so the password is verified by re-authenticating first
   *  — storing a blob with a mistyped password would produce a recovery phrase
   *  that "works" but hands back credentials that can't log in. */
  async setupRecovery(username: string, password: string): Promise<string> {
    const acc = await this.login(username, password); // throws on wrong password
    if (acc.username.toLowerCase() !== username.toLowerCase()) throw new Error('Account mismatch.');
    const phrase = generateSeedPhrase(12);
    await this.setRecovery(phrase, username, password);
    return phrase;
  }
  /** Pre-auth: given a seed phrase, fetch + decrypt the stored credentials. */
  async recoverCredentials(seed: string, username: string): Promise<{ username: string; password: string }> {
    for (const version of [2, 1] as const) {
      const recoveryId = await recoveryIdFor(seed, username, version);
      const { blob } = await this.request('/auth/recovery/fetch', { method: 'POST', body: JSON.stringify({ recoveryId }) });
    // Unknown seeds yield a decoy blob that fails to decrypt — surfaced as a
    // generic "not found" so real vs. fake is indistinguishable to the caller.
      try { return await openRecoveryBlob(seed, username, blob); }
      catch { /* wrong scheme or decoy - try the next */ }
    }
    throw new Error('That recovery phrase did not match any account.');
  }

  // ---- Settings -------------------------------------------------------------
  async getSettings(): Promise<{ readReceipts: boolean; notifyPref?: 'all' | 'mentions' | 'alias' }> {
    return this.request('/settings/get', { method: 'POST', body: JSON.stringify({}) });
  }
  async updateSettings(s: { readReceipts?: boolean; notifyPref?: 'all' | 'mentions' | 'alias' }): Promise<void> {
    await this.request('/settings/update', { method: 'POST', body: JSON.stringify(s) });
  }

  // ---- Broadcast acknowledgments --------------------------------------------
  async acknowledgeMessage(nodeId: string, mid: string): Promise<{ count: number }> {
    return this.request('/messages/ack', { method: 'POST', body: JSON.stringify({ nodeId, mid }) });
  }

  /** Toggle an emoji reaction on a message. Returns the updated reaction map. */
  async reactMessage(nodeId: string, mid: string, emoji: string): Promise<{ reactions: Record<string, { id: string; name: string }[]> }> {
    return this.request('/messages/react', { method: 'POST', body: JSON.stringify({ nodeId, mid, emoji }) });
  }

  /** Ephemeral typing signal to a single contact ('start' heartbeat / 'stop'). */
  async sendTyping(nodeId: string, toNodeId: string, state: 'start' | 'stop'): Promise<void> {
    try { await this.request('/typing', { method: 'POST', body: JSON.stringify({ nodeId, toNodeId, state }) }); } catch { /* best-effort */ }
  }

  /**
   * Schedule a text message for server-side release at fireAt. The envelope is
   * sealed NOW, exactly like a live send — the server stores ciphertext only and
   * relays it at the fire time, so delivery happens even with this device off.
   * Returns the server entry id + the message mid (for the sender's own copy).
   */
  async scheduleMessage(
    node: User, text: string, fireAt: number,
    type: Message['type'], targetCircle?: 'UP' | 'DOWN', targetUserId?: string, ackRequested?: boolean, targetGroup?: string,
  ): Promise<{ id: string; mid: string }> {
    await this.unlockNode(node);
    await this.ensureSignalReady(node);
    const r = await this.request('/recipients', {
      method: 'POST', body: JSON.stringify({ nodeId: node.id, type, targetCircle, targetGroup }),
    });
    if (!(r.recipients || []).some((x: any) => x.id !== node.id && (!targetUserId || x.id === targetUserId))) throw new Error('No recipients available for this message.');

    const mid = newMessageId();
    // The authenticated timestamp is the INTENDED delivery time (V8 M-9: recipients
    // display the sealed ts, never the server's clock).
    const ts = fireAt;
    const meta: ContentMeta = { t: type as ContentMeta['t'], c: targetCircle || null, g: targetGroup || null, a: !!ackRequested, l: typeof node.level === 'number' ? node.level : null };
    const content = { meta, text, imageUrl: null, audioUrl: null, videoUrl: null, attachments: null, replyTo: null, editsMid: null };
    const { cek, iv, ct } = await sealContent(content, node.id, mid, ts, null);
    const slotPlain = await bindCekToEnvelope(cek, { sigBy: node.id, mid, ts, exp: null, iv, ct }); // V8 H-1
    const { recips, others, withheld, unreachable, changed } = await this.slotsFor(node, r, targetUserId, slotPlain); // V8 phase 2: verified members only
    if (!recips.length) throw this.noRecipientsError(others, withheld, unreachable, changed);
    const envelope = { v: 5, mid, ts, exp: null, iv, ct, recips, sigBy: node.id, ...(targetGroup ? { targetGroup } : {}) };
    const resp = await this.request('/messages/schedule', {
      method: 'POST',
      body: JSON.stringify({ nodeId: node.id, envelope, type, targetCircle, targetGroup: targetGroup || undefined, ackRequested: ackRequested || undefined, fireAt }),
    });
    return { id: resp.id, mid };
  }

  async listScheduledServer(nodeId: string): Promise<{ scheduled: { id: string; fireAt: number; mid: string }[] }> {
    return this.request('/messages/scheduled/list', { method: 'POST', body: JSON.stringify({ nodeId }) });
  }

  async cancelScheduledServer(nodeId: string, id: string): Promise<void> {
    await this.request('/messages/scheduled/cancel', { method: 'POST', body: JSON.stringify({ nodeId, id }) });
  }

  /** Sender's own local copy for a scheduled message that has fired. */
  async recordFiredScheduled(node: User, s: { mid: string; text: string; fireAt: number; tab: string; targetUserId?: string }): Promise<void> {
    const rec: msgStore.StoredMessage = {
      senderId: node.id, timestamp: s.fireAt,
      type: s.tab === 'BROADCAST' ? 'BROADCAST' : 'PEER',
      targetCircle: s.tab === 'ANCESTORS' ? 'UP' : s.tab === 'DESCENDANTS' ? 'DOWN' : undefined,
      peerId: s.targetUserId || undefined,
      verified: true, text: s.text,
    };
    await msgStore.put(node.id, s.mid, rec);
    this.appendToMsgCache(node.id, s.mid, rec);
  }

  /** Store a local-only call-log entry in a chat. Never leaves the device — it's
   *  a system record of a call, scoped to the peer's conversation via peerId. */
  async recordCallLog(node: User, peerId: string, log: NonNullable<Message['callLog']>, timestamp = Date.now()): Promise<void> {
    const mid = newMessageId();
    const rec: msgStore.StoredMessage = {
      senderId: node.id,       // local system entry authored "by" this node
      timestamp,
      type: 'PEER',
      peerId,
      verified: true,
      callLog: log,
    };
    await msgStore.put(node.id, mid, rec);
    this.appendToMsgCache(node.id, mid, rec);
  }

  // ---- Network deletion (root only) -----------------------------------------
  async deleteTree(nodeId: string): Promise<void> {
    await this.withReauth('Deleting the network removes it and everything in it for everyone.',
      () => this.request('/tree/delete', { method: 'POST', body: JSON.stringify({ nodeId }) }));
  }

  // ---- Billing --------------------------------------------------------------
  async billingStatus(nodeId: string): Promise<{ treeSize: number; limit: number; premiumLimit?: number; relayCalls?: boolean; priceUsd: number; premium: boolean; premiumUntil: number | null; isRoot: boolean; archived: boolean; graceUntil: number | null; cardConfigured: boolean; moneroConfigured: boolean; cardSubscription?: { renews: boolean } | null; media?: { used: number; quota: number }; historyDays?: number; limits?: { freeMediaBytes: number; premiumMediaBytes: number; freeHistoryDays: number; premiumHistoryDays: number; attachmentBytes: number; premiumAttachmentBytes?: number }; attachMax?: number }> {
    return this.request('/billing/status', { method: 'POST', body: JSON.stringify({ nodeId }) });
  }
  /** Back from a card checkout (see PENDING_CHECKOUT): confirm the session with the
   *  server, which checks it with Stripe and credits it once. True when Premium was
   *  credited. The id is kept for a retry if the server couldn't be reached. */
  async billingConfirmPending(): Promise<boolean> {
    let sid: string | null = null;
    try { sid = sessionStorage.getItem(PENDING_CHECKOUT); } catch {}
    if (!sid) return false;
    try {
      const r = await this.request('/billing/stripe/confirm', { method: 'POST', body: JSON.stringify({ sessionId: sid }) });
      try { sessionStorage.removeItem(PENDING_CHECKOUT); } catch {}
      return !!r?.paid;
    } catch (e: any) {
      if (e?.status && e.status < 500) { try { sessionStorage.removeItem(PENDING_CHECKOUT); } catch {} }
      return false;
    }
  }
  /** Undo a cancellation: the card subscription renews again. */
  async billingResume(nodeId: string): Promise<{ ok: boolean }> {
    return this.request('/billing/stripe/resume', { method: 'POST', body: JSON.stringify({ nodeId }) });
  }
  /** Stop the card subscription renewing; the time already paid for stays. */
  async billingCancel(nodeId: string): Promise<{ ok: boolean; premiumUntil: number | null }> {
    return this.request('/billing/stripe/cancel', { method: 'POST', body: JSON.stringify({ nodeId }) });
  }
  async billingCheckout(nodeId: string): Promise<{ url: string }> {
    return this.request('/billing/stripe/checkout', { method: 'POST', body: JSON.stringify({ nodeId }) });
  }
  async moneroCreate(nodeId: string): Promise<{ requestId: string; address: string; amountXmr: number; usd: number }> {
    return this.request('/billing/monero/create', { method: 'POST', body: JSON.stringify({ nodeId }) });
  }
  async moneroCheck(requestId: string): Promise<{ status: 'paid' | 'pending'; receivedXmr?: number; confirmedXmr?: number; neededXmr?: number; requiredConfirmations?: number }> {
    return this.request('/billing/monero/check', { method: 'POST', body: JSON.stringify({ requestId }) });
  }

  // ---- Encrypted state backup (push side) ----------------------------------
  private backupTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private lastBackupHash = new Map<string, string>();
  private pwChangeActive = false;                        // v72 M7: uploads wait during a password change

  /** Debounced: snapshot signal state + text history, encrypt under the session
   *  key, upload if changed. Server sees only an opaque blob. */
  private scheduleBackup(node: User): void {
    if (this.backupTimers.has(node.id)) return;
    this.backupTimers.set(node.id, setTimeout(async () => {
      this.backupTimers.delete(node.id);
      try {
        if (!keyStore.hasWrapKey() || this.pwChangeActive) return;   // (next refresh schedules it again)
        const snap = {
          v: 1,
          node: node.id,                                            // v71 L5: bound to this node
          at: Date.now(),                                           // v72: freshness (see restore)
          signal: await signal.exportState(node.id),
          messages: await msgStore.exportForBackup(node.id),
          pin: await this.trust.exportPin(node.id),                 // v70 H2
        };
        let json = JSON.stringify(snap);
        // Size guard: if text history alone pushes past the server cap, keep the
        // ratchet state (the part that MUST survive) and drop oldest messages.
        if (json.length > 2_000_000) {
          snap.messages = snap.messages
            .sort((a: any, b: any) => (b.timestamp || 0) - (a.timestamp || 0))
            .slice(0, 500);
          json = JSON.stringify(snap);
          if (json.length > 2_000_000) { snap.messages = []; json = JSON.stringify(snap); }
        }
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(json));
        const hash = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
        if (this.lastBackupHash.get(node.id) === hash) return;   // unchanged since last push
        const wrapped = await keyStore.wrapBytes(new TextEncoder().encode(json).buffer);
        await this.request('/state-backup/set', { method: 'POST', body: JSON.stringify({ nodeId: node.id, wrapped, ts: Date.now() }) });
        this.lastBackupHash.set(node.id, hash);
        noteBackupHighWater(node.id, snap.at);
      } catch { /* backup is best-effort; never disrupt the app */ }
    }, 4000));
  }

  /** v71 H1: pages a refresh may follow before yielding (the rest come next refresh). */
  private static readonly MAX_SYNC_PAGES = 10;

  /**
   * Decrypt + store a batch of relayed messages (decrypt-once). Returns whether
   * anything was stored and the mids that failed TRANSIENTLY (to retry: the
   * delivery cursor must not move past them).
   */
  private async ingestMessages(node: User, messages: any[], senderOk: (sender: string) => Promise<boolean>, keyMismatch: (sender: string) => Promise<boolean>): Promise<{ ingested: boolean; unresolved: Set<string> }> {
    let ingested = false;
    const unresolved = new Set<string>();
    for (const m of messages) {
      const env = m.envelope as Envelope | undefined;
      if (!env || !env.mid) continue;
      if (await msgStore.has(node.id, env.mid)) continue;       // already decoded & stored
      const slot = Array.isArray(env.recips) ? env.recips.find((r: any) => r.id === node.id) : undefined;

      const rec: msgStore.StoredMessage = {
        senderId: m.senderId,
        timestamp: m.timestamp,
        type: m.type,
        targetCircle: m.targetCircle,
        // Carry the group-chat tag so grouped members filter their view too.
        targetGroup: (env as any).targetGroup || undefined,
        expiresAt: typeof env.exp === 'number' ? env.exp : m.expiresAt,
        verified: false,
        ackRequested: (m as any).ackRequested || undefined,
        senderLevel: typeof (m as any).senderLevel === 'number' ? (m as any).senderLevel : undefined,
      };
      if (!slot) {
        // Not addressed to this device; record it so we don't reprocess endlessly.
        rec.text = '🔒 [Sent to another device/session]';
        await msgStore.put(node.id, env.mid, rec);
        ingested = true;
        continue;
      }
      // V8 M-9: the envelope's claimed author must be the node whose ratchet
      // session delivers the key slot (the server labels m.senderId; the slot
      // is only decryptable if that label is true). A mismatch is tampering.
      if (env.sigBy !== m.senderId) {
        rec.text = '⚠️ A message failed its integrity check and was discarded.';
        await msgStore.put(node.id, env.mid, rec);
        this.appendToMsgCache(node.id, env.mid, rec);
        ingested = true;
        continue;
      }
      let slotPlain: ArrayBuffer | null = null;
      try {
        slotPlain = await signal.decryptKeyFrom(node.id, m.senderId, slot);
        // V8 H-1: verify the sender bound THIS ciphertext into the slot. Throws on
        // mismatch (a co-recipient + server swapped the content). A 32-byte slot is
        // a pre-V8 sender: readable, but never marked verified.
        const { cek, bound } = await unbindCek(slotPlain, env);
        const content = await openContent(env, cek);
        const changed = await signal.identityChanged(node.id, m.senderId);
        const okMember = bound && await senderOk(m.senderId);
        rec.verified = okMember && !changed;
        rec.verifiedIfKeyOk = okMember;       // v71: what re-trusting the key may restore
        rec.keyChanged = changed;
        // V8 M-9: display metadata comes from the AUTHENTICATED sealed content,
        // never from the server's plaintext copy (which could re-time, re-file
        // or relabel a genuine message). Legacy senders keep the server hints.
        if (bound) {
          rec.timestamp = env.ts;
          const meta = content.meta;
          if (meta && typeof meta === 'object') {
            rec.type = (['PEER', 'BROADCAST', 'GLOBAL'].includes(meta.t) ? meta.t : rec.type) as any;
            rec.targetCircle = meta.c === 'UP' || meta.c === 'DOWN' ? meta.c : undefined;
            rec.targetGroup = typeof meta.g === 'string' && meta.g ? meta.g : undefined;
            rec.ackRequested = meta.a === true ? true : undefined;
            rec.senderLevel = meta.t === 'BROADCAST' && typeof meta.l === 'number' ? meta.l : undefined;
          }
        }
        // Always surface the content (Signal delivers + warns rather than hiding);
        // the UI flags key changes with a warning style.
        rec.text = content.text || undefined;
        // v70: delete-for-everyone. Honoured only when it arrives SEALED from the
        // original sender through the ratchet, bound to this exact ciphertext (so
        // a co-recipient can't forge one): each named message this device holds
        // FROM THAT SENDER — never someone else's, never my own — is replaced
        // by a hidden tombstone, so a server replaying the original can't bring
        // it back. The server's own "retracted" list no longer deletes anything.
        // v71 M1: a control message (edit / delete-for-everyone) changes messages
        // this device ALREADY TRUSTS, so it must meet a higher bar than a new
        // message: content-bound AND from the sender's unchanged, already-trusted
        // identity. A session whose key changed (possibly an interceptor) can still
        // deliver new, flagged messages — but can't rewrite or erase earlier ones.
        // Also refused when the sender HAS a certified key and this session isn't it
        // (defence in depth: that session can't be the member the certificate names).
        const trustedControl = bound && !changed && !(await keyMismatch(m.senderId));
        const retracts = (content as any).retracts;
        if (Array.isArray(retracts)) {
          if (trustedControl) {
            const dropped: string[] = [];
            for (const rm of retracts.slice(0, 200)) {
              if (typeof rm !== 'string' || !rm || rm === env.mid) continue;
              // Only a message this device already holds (a retraction naming one it
              // hasn't seen could otherwise pre-empt a co-recipient's message id).
              const orig = await msgStore.get(node.id, rm).catch(() => null);
              if (!orig || orig.senderId !== m.senderId || orig.senderId === node.id) continue;
              const tomb = { senderId: m.senderId, timestamp: orig.timestamp, type: orig.type, verified: false, hidden: true, retracted: true } as any;
              await msgStore.put(node.id, rm, tomb);
              dropped.push(rm);
            }
            if (dropped.length) this.dropFromMsgCache(node.id, dropped);
          }
          rec.text = undefined;
          (rec as any).hidden = true;
          await msgStore.put(node.id, env.mid, rec);
          this.decryptAttempts.delete(env.mid);
          ingested = true;
          continue;
        }
        // Edit: this message is an edit of an earlier one from the same sender.
        // Apply it in place and DON'T surface the edit as a separate message.
        const editsMid = (content as any).editsMid;
        if (typeof editsMid === 'string' && editsMid) {
          let orig: msgStore.StoredMessage | null = null;
          try { orig = await msgStore.get(node.id, editsMid); } catch {}
          // Only the original sender may edit their own message, and only through a
          // trusted control message (M1). The edited text keeps the verified mark
          // only if BOTH the original and this edit are verified — an edit from a
          // sender that no longer passes the membership check can't vouch for it.
          if (orig && orig.senderId === m.senderId && !(orig as any).hidden && trustedControl) {
            const patched = { ...orig, text: content.text || undefined, edited: true, editedAt: env.ts, verified: !!orig.verified && rec.verified };
            await msgStore.put(node.id, editsMid, patched);
            this.appendToMsgCache(node.id, editsMid, patched);
            // Record the edit envelope as processed so we don't reprocess it, but
            // keep it out of the visible thread.
            rec.text = undefined;
            (rec as any).hidden = true;
            await msgStore.put(node.id, env.mid, rec);
            this.decryptAttempts.delete(env.mid);
            ingested = true;
            continue;
          }
          if (orig && orig.senderId === m.senderId && !trustedControl) {
            // Refused: the original stays as it was. The attempted text is shown as
            // its own (unverified, flagged) message — nothing is silently dropped.
            rec.verified = false;
            rec.editRefused = true;
          } else {
            // Not an edit of anything this device holds from that sender: keep it
            // out of the visible thread, as before.
            rec.text = undefined;
            (rec as any).hidden = true;
            await msgStore.put(node.id, env.mid, rec);
            this.decryptAttempts.delete(env.mid);
            ingested = true;
            continue;
          }
        }
        if ((content as any).replyTo && typeof (content as any).replyTo === 'object') {
          const rt = (content as any).replyTo;
          if (typeof rt.mid === 'string' && typeof rt.name === 'string' && typeof rt.text === 'string') {
            // v71 L7: the quoted author and text are the SENDER's claim — anyone could
            // "quote" words someone never wrote. When this device holds the quoted
            // message, show its real author and text; otherwise mark the quote.
            const q = rt.mid.length <= 64 ? await msgStore.get(node.id, rt.mid).catch(() => null) : null;
            // Anything taken from the sender's claim (an author this device can't
            // name, a quoted message without text) keeps the "unverified" mark.
            const qn = q && !q.hidden ? this.nameOf(q.senderId) : null;
            if (q && !q.hidden) rec.replyTo = { mid: rt.mid, name: (qn || rt.name).slice(0, 60), text: (q.text || rt.text).slice(0, 240), ...(qn && q.text ? {} : { unverified: true }) };
            else rec.replyTo = { mid: rt.mid, name: rt.name.slice(0, 60), text: rt.text.slice(0, 240), unverified: true };
          }
        }
        // Signal-style attachments (validated pointers, fetched lazily at render).
        if (Array.isArray(content.attachments) && content.attachments.length) {
          rec.attachments = content.attachments.filter((a: any) =>
            a && typeof a.id === 'string' && typeof a.key === 'string' && typeof a.iv === 'string' &&
            typeof a.mime === 'string' && ['image', 'audio', 'video'].includes(a.kind));
        }
        // Legacy inline media (messages sent before the blob pipeline) still decode.
        rec.imageUrl = isSafeMediaDataUrl(content.imageUrl, 'image') ? content.imageUrl! : undefined;
        rec.audioUrl = isSafeMediaDataUrl(content.audioUrl, 'audio') ? content.audioUrl! : undefined;
        rec.videoUrl = isSafeMediaDataUrl(content.videoUrl, 'video') ? content.videoUrl! : undefined;
        await msgStore.put(node.id, env.mid, rec); // success -> persist (decrypt-once)
        this.appendToMsgCache(node.id, env.mid, rec);
        this.decryptAttempts.delete(env.mid);
        ingested = true;
      } catch (e: any) {
        // The key slot decrypted (so the ratchet message key is now CONSUMED) but
        // the content failed its binding / integrity check: this is tampering, not
        // a transient error — record it visibly right away, never retry.
        if (slotPlain) {
          rec.text = '⚠️ A message failed its integrity check and was discarded.';
          rec.verified = false;
          await msgStore.put(node.id, env.mid, rec);
          this.appendToMsgCache(node.id, env.mid, rec);
          this.decryptAttempts.delete(env.mid);
          ingested = true;
          continue;
        }
        // Transient (e.g. session not formed yet): retry on the next refresh.
        // But a session MISMATCH never heals — after several attempts, surface
        // a visible placeholder instead of silently losing the message forever.
        const n = (this.decryptAttempts.get(env.mid) || 0) + 1;
        this.decryptAttempts.set(env.mid, n);
        try { console.warn(`[msg] decrypt failed (attempt ${n}) mid=${env.mid} from=${m.senderId}:`, e?.message || e); } catch {}
        if (n < 4) unresolved.add(env.mid);
        if (n >= 4) {
          rec.text = '🔒 Couldn\'t unlock this message — your secure session with this person got out of sync. It resets the next time you send them a message; ask them to resend this one.';
          rec.verified = false;
          await msgStore.put(node.id, env.mid, rec);
          this.appendToMsgCache(node.id, env.mid, rec);
          this.decryptAttempts.delete(env.mid);
          ingested = true;
          // Only a verified member can trigger a re-key (see flagRekey).
          if (await senderOk(m.senderId).catch(() => false)) flagRekey(node.id, m.senderId);
        }
      }

    }
    return { ingested, unresolved };
  }

  async fetchTreeContext(node: User): Promise<{ users: User[]; messages: Message[]; invites: Invite[]; crossLinks?: Record<string, { name: string; archived?: boolean }> }> {
    await this.unlockNode(node);
    await this.ensureSignalReady(node).catch(() => {});
    const cursor = await msgStore.getCursor(node.id).catch(() => null);
    const data = await this.request('/tree-context', { method: 'POST', body: JSON.stringify({ nodeId: node.id, since: cursor ?? 0 }) });

    // V8 phase 2: verify membership certificates, open network-key boxes and
    // decrypt every visible profile IN PLACE before anything below reads names.
    // Never fatal — a failure leaves names as placeholders for this refresh.
    try { await this.trust.sync(node, data); }
    catch (e) { try { console.warn('[trust] sync failed:', (e as any)?.message || e); } catch {} }
    const hubNode = (node as any).treeMode === 'HUB';
    // A sender counts as a verified member only when a signed certificate names
    // it AND the key its ratchet session is bound to (personal-hub contacts are
    // 1:1 people this person accepted, so they don't need a certificate).
    const senderOk = async (sender: string): Promise<boolean> => {
      const t = this.trust.trustOf(node.id);
      const ik = t ? (sender === t.tree ? t.rootIk : t.members.get(sender)?.ik) : null;
      // v72 (L): in a hub, only an ACTIVE contact (v71: any sender at all).
      if (!ik) return hubNode && this.trust.isActiveHubContact(node.id, sender);
      return sameKey(await signal.remoteIdentity(node.id, sender), ik);
    };
    // v71: a certified member whose session key isn't the certified one.
    const keyMismatch = async (sender: string): Promise<boolean> => {
      const t = this.trust.trustOf(node.id);
      const ik = t ? (sender === t.tree ? t.rootIk : t.members.get(sender)?.ik) : null;
      return !!ik && !sameKey(await signal.remoteIdentity(node.id, sender), ik);
    };

    // Tag each visible identity with whether its Signal identity key has changed.
    if (Array.isArray(data.users)) {
      for (const u of data.users as User[]) {
        if (!u.isMe) {
          try { u.keyStatus = (await signal.identityChanged(node.id, u.id)) ? 'changed' : 'match'; }
          catch { u.keyStatus = 'match'; }
        }
      }
    }

    // Decrypt any server-relayed messages we haven't seen yet — EXACTLY ONCE —
    // then persist the plaintext locally (a ratchet message key cannot be reused).
    // v71 H1: the server delivers bounded PAGES after this device's cursor; follow
    // `msgMore` with /messages/sync (a few pages per refresh — the rest continue on
    // the next one). The cursor only moves past messages that are fully processed,
    // so one that failed transiently is delivered again and retried.
    let ingested = false;
    if (Array.isArray(data.messages)) {
      let page: { messages: any[]; next?: number; more?: boolean } = { messages: data.messages, next: data.msgNext, more: !!data.msgMore };
      let cur = cursor ?? 0;
      for (let pages = 1; ; pages++) {
        const r = await this.ingestMessages(node, page.messages, senderOk, keyMismatch);
        ingested = ingested || r.ingested;
        if (typeof page.next !== 'number') break;                 // a pre-v71 server: no cursor
        const ordered = page.messages.filter((m: any) => typeof m.seq === 'number').sort((x: any, y: any) => x.seq - y.seq);
        let upto = page.next;
        for (let i = 0; i < ordered.length; i++) {
          const mid = ordered[i].envelope?.mid;
          if (mid && r.unresolved.has(mid)) { upto = i > 0 ? ordered[i - 1].seq : cur; break; }
        }
        if (upto > cur) { await msgStore.setCursor(node.id, upto).catch(() => {}); cur = upto; }
        if (!page.more || r.unresolved.size || pages >= BackendAPI.MAX_SYNC_PAGES) break;
        page = await this.request('/messages/sync', { method: 'POST', body: JSON.stringify({ nodeId: node.id, since: cur }) });
        if (!Array.isArray(page?.messages)) break;
      }
    }

    // v70: the server's "retracted" list is NOT applied — it's the server's word,
    // and it used to let a server erase any message (even my own) from this
    // device. Deletions arrive as sealed messages from their sender (above).

    // Render the conversation from the LOCAL store (own sent + received), filtering
    // out anything whose disappearing-message TTL has elapsed.
    //
    // PERF: re-reading every message (with multi-MB media strings) out of
    // IndexedDB on every 8-second poll was the main source of chat lag on phones.
    // The store only changes when we ingest/send/import — cache the mapped list
    // and rebuild ONLY then; expiry is handled with a cheap in-memory filter.
    const now = Date.now();
    // Ingest and retraction now update the cache in place; a full IndexedDB
    // re-read only happens on node switch or first load.
    void ingested;
    if (this.msgCacheNode !== node.id || !this.msgCache) {
      this.msgCache = await msgStore.listForNode(node.id);
      this.msgCacheNode = node.id;
    }
    data.messages = this.mapMsgCache();
    // Stable (key-order-independent) serialization of a small map. Used to fold
    // invitee-group state into the user signature below. Sorting the keys means
    // the SAME group data always yields the SAME string, so unchanged polls still
    // hit the cache — only a real edit produces a new signature.
    const mapSig = (o: any): string =>
      o && typeof o === 'object' ? Object.keys(o).sort().map(k => `${k}=${o[k]}`).join(',') : '';
    data.users = this.share('u', data.users,
      // NOTE: invitee group fields (inviteeGroups / groupLabels / myGroupUnder) are
      // part of a user's rendered state but change WITHOUT touching name/level/etc.
      // Omitting them here meant a groups-only edit produced an identical signature,
      // so share() handed back the STALE cached array and the just-saved assignments
      // were clobbered on the next refresh — they only reappeared after a full reload
      // (which starts with an empty cache). Include them so group edits bust the cache.
      data.users.map((u: User) => `${u.id}:${u.name}:${u.invitedBy || ''}:${(u as any).prunedAt || 0}:${(u as any).permissions?.viewTrueLevel ? 1 : 0}:${u.level ?? ''}:${u.pending ? 1 : 0}:${(u as any).pendingDirection || ''}:${u.treeName || ''}:${(u as any).treeNameVisible ? 1 : 0}:${(u as any).color || ''}:${(u as any).monitorEnabled === false ? 0 : 1}:${(u as any).referralOpen ? 1 : 0}:${(u as any).globalChat ? 1 : 0}:${(u as any).referredBy || ''}:${mapSig((u as any).inviteeGroups)}:${mapSig((u as any).groupLabels)}:${mapSig((u as any).groupParents)}:${mapSig((u as any).groupLinks)}:${mapSig((u as any).myLinks)}:${mapSig((u as any).myGroupLabels)}:${(u as any).myGroupUnder ?? ''}:${(u as any).avatarAt || 0}:${u.memberVerified ? 1 : 0}:${u.nameClash ? 1 : 0}:${u.profileLocked ? 1 : 0}:${u.profileAt || 0}:${u.bio || ''}:${(u as any).ownerPin || ''}`).join('|')); // V8 phase 2: verification + decrypted-profile state must bust the cache too

    // Ratchet state advanced (new sessions / consumed message keys) — snapshot it.
    this.scheduleBackup(node);

    // Cache this tree snapshot (sealed, on-device) so RE-ENTERING this network
    // paints the chat instantly from local state next time, instead of blanking
    // for a full round trip. Messages already live in msgStore; this covers the
    // roster/group metadata. Best-effort — a failure just means no fast path.
    snapshotStore.save(node.id, { users: data.users, invites: data.invites, crossLinks: (data as any).crossLinks }).catch(() => {});

    return data;
  }

  /** Local-first hydrate: read the on-device SEALED snapshot + messages for a node
   *  with NO network, so entering a previously-opened network paints instantly and
   *  the network refresh then reconciles in the background (stale-while-revalidate).
   *  Returns null when nothing is cached yet (first-ever entry on this device) or
   *  the store can't be unlocked; the caller then just waits for the normal refresh. */
  async hydrateLocal(node: User): Promise<{ self?: User; users: User[]; invites: Invite[]; crossLinks?: Record<string, { name: string; archived?: boolean }>; messages: Message[] } | null> {
    try { await this.unlockNode(node); } catch { return null; }
    // Local messages (sealed store) — the same read fetchTreeContext does on a node switch.
    try {
      this.msgCache = await msgStore.listForNode(node.id);
      this.msgCacheNode = node.id;
    } catch { return null; }
    const messages = this.mapMsgCache();
    const snap = await snapshotStore.load(node.id).catch(() => null);
    if (!snap) return { self: undefined, users: [], invites: [], crossLinks: undefined, messages };
    const users = (snap.users || []) as User[];
    return {
      self: users.find(u => (u as any).isMe),
      users,
      invites: (snap.invites || []) as Invite[],
      crossLinks: snap.crossLinks,
      messages,
    };
  }

  /** Background pre-warm: run a full tree-context fetch for a node so its SEALED
   *  snapshot + messages land on-device ahead of time — making the FIRST entry into
   *  a network instant too, not just re-entry. Used while the network picker is shown.
   *  The live in-memory message cache is saved and RESTORED around the call, so warming
   *  network B can never corrupt the cache of a network you're actively viewing; only
   *  the persistent stores (msgStore + snapshotStore) are updated. Best-effort. */
  async warmSnapshot(node: User): Promise<void> {
    const savedCache = this.msgCache, savedNode = this.msgCacheNode;
    try { await this.fetchTreeContext(node); }
    catch { /* offline / locked — skip; a real entry will just do a live fetch */ }
    finally { this.msgCache = savedCache; this.msgCacheNode = savedNode; }
  }

  /**
   * V8 phase 2 (H-2): encrypt a message's key slot ONLY to recipients whose
   * membership this device can verify. /recipients is the server's claim; each
   * listed node must be named — with its identity key — by a certificate chain
   * from the pinned network root, and the Signal session used must be bound to
   * that same key (a swapped prekey bundle is refused). Returns the slots plus an
   * audit trail for Message Info.
   */
  private async slotsFor(node: User, r: any, targetUserId: string | undefined, slotPlain: ArrayBuffer) {
    let ids: string[] = (r.recipients || []).map((x: any) => x.id);
    if (targetUserId) ids = ids.filter(id => id === node.id || id === targetUserId);
    const others = ids.filter(id => id !== node.id);
    if (r.treeRoot && !this.trust.hasPin(node.id, r.treeRoot)) { try { await this.fetchTreeContext(node); } catch {} }
    const { ok, refused } = await this.trust.decideRecipients(node, r, others, { oneToOne: !!targetUserId, hub: (node as any).treeMode === 'HUB' });
    const recips: { id: string; kt: number; kb: string }[] = [];
    const sentTo: { id: string; name: string; verified: boolean }[] = [];
    const changed: string[] = [];
    let withheld = refused.length, unreachable = 0;
    if (refused.length) { try { console.warn('[trust] refused unverified recipients:', refused); } catch {} }
    for (const d of ok) {
      try {
        const hadSession = await signal.hasSession(node.id, d.id);
        const rekey = hadSession && !!readRekey(node.id, d.id).due;   // session repair (flagRekey)
        if (!hadSession || rekey) {
          const bundle = await this.request('/prekeys/fetch', { method: 'POST', body: JSON.stringify({ forNodeId: d.id }) }).catch(() => null);
          if (!bundle) {
            if (!hadSession) { unreachable++; continue; }                  // hasn't published prekeys yet
            // Re-key couldn't fetch a bundle: keep the existing session for now, retry next send.
          } else {
            if (d.ik && !sameKey(bundle.identityKey, d.ik)) { withheld++; continue; } // server-swapped key: refuse
            await signal.establishSession(node.id, d.id, bundle);           // an existing session is archived, not deleted
            if (rekey) noteRekeyed(node.id, d.id);
          }
        }
        if (hadSession && d.ik && !sameKey(await signal.remoteIdentity(node.id, d.id), d.ik)) { withheld++; continue; }
        // v72 B3: nothing is encrypted to a peer whose security key CHANGED until the
        // user compares the safety number and accepts it (acceptKeyChange). v71 kept
        // encrypting to the new key and only flagged messages coming FROM it.
        if (await signal.identityChanged(node.id, d.id)) { changed.push(d.id); continue; }
        recips.push(await signal.encryptKeyTo(node.id, d.id, slotPlain));
        sentTo.push({ id: d.id, name: this.trust.nameOf(d.id) || UNKNOWN_NAME, verified: d.verified });
      } catch { unreachable++; }
    }
    return { recips, sentTo, others: others.length, withheld, unreachable, changed };
  }

  private noRecipientsError(others: number, withheld: number, unreachable: number, changed: string[] = []): Error {
    if (changed.length && changed.length + withheld >= others) {
      const who = changed.length === 1 ? (this.trust.nameOf(changed[0]) || UNKNOWN_NAME) + '’s' : 'These recipients’';
      return new Error(`Not sent: ${who} security key changed. Compare your safety number with them and accept the new key before sending.`);
    }
    if (withheld && withheld >= others) return new Error('Nothing was sent: this app couldn’t verify that the recipients are members of this network. They may need to open the updated app, or be confirmed by whoever invited them.');
    return new Error(unreachable
      ? 'Recipients can’t receive yet — they need to sign in once so their secure keys publish.'
      : 'No recipients available for this message.');
  }

  async sendMessage(
    node: User,
    payload: { text?: string; imageUrl?: string; audioUrl?: string; videoUrl?: string; expiresAt?: number; replyTo?: { mid: string; name: string; text: string }; editsMid?: string; retracts?: string[]; audioPeaks?: number[]; audioDurMs?: number },
    type: Message['type'],
    targets?: string[],           // announcement branch targets (node ids); undefined = everyone
    targetCircle?: 'UP' | 'DOWN',
    targetUserId?: string,
    ackRequested?: boolean,
    targetGroup?: string,          // descendants group chat scope (inviter only); undefined = default/ungrouped
    mentions?: { users?: string[]; viaGroup?: string[] }, // @-mention targets (public ids) for push routing
    onEcho?: () => void,           // fired the moment the message is in the local cache, before the network POST — lets the UI show it instantly
    presetMid?: string,            // reuse the id the UI already rendered an optimistic bubble under (seamless confirm)
  ): Promise<void> {
    await this.unlockNode(node);
    await this.ensureSignalReady(node);

    const r = await this.request('/recipients', {
      method: 'POST', body: JSON.stringify({ nodeId: node.id, type, targetCircle, targets, targetGroup }),
    });
    // The sender is not a ciphertext recipient (no self-session); we keep our own
    // copy locally instead. Everyone else gets the CEK via their ratchet session —
    // but only those whose membership is verified (slotsFor, V8 phase 2).

    const mid = presetMid || newMessageId();
    const ts = Date.now();
    const exp = typeof payload.expiresAt === 'number' ? payload.expiresAt : null;

    // Signal-style media: upload each media file as its own encrypted blob and
    // replace the multi-MB inline data URL with a tiny pointer. The message that
    // gets sealed + relayed is now small, so send latency no longer scales with
    // media size, and recipients fetch each blob lazily.
    const attachments: AttachmentRef[] = [];
    const uploadIfMedia = async (url: string | undefined, kind: 'image' | 'audio' | 'video') => {
      if (!url || !url.startsWith('data:')) return;
      // Global chat and the main Descendants/Ancestors chat let the channel's other
      // members fetch the blob (the key stays inside the sealed message).
      const scope = type === 'GLOBAL' ? 'global' : (type === 'PEER' && targetCircle && !targetGroup && !targetUserId ? 'main' : undefined);
      try { attachments.push(await this.uploadAttachment(node.id, url, kind, exp ?? undefined, scope)); }
      catch (e) { throw new Error(`Couldn't upload ${kind}: ${(e as any)?.message || e}`); }
    };
    await uploadIfMedia(payload.imageUrl, 'image');
    await uploadIfMedia(payload.audioUrl, 'audio');
    await uploadIfMedia(payload.videoUrl, 'video');
    // Attach the amplitude envelope captured during recording to the voice note,
    // so the sent/received bubble always renders the real waveform (independent of
    // whether the recipient can re-decode the audio for peaks).
    if ((payload.audioPeaks && payload.audioPeaks.length) || payload.audioDurMs) {
      const a = attachments.find(x => x.kind === 'audio');
      if (a) {
        if (payload.audioPeaks && payload.audioPeaks.length) a.peaks = payload.audioPeaks.slice(0, 64).map(v => Math.max(0, Math.min(1, v)));
        if (payload.audioDurMs && isFinite(payload.audioDurMs)) a.durMs = Math.round(payload.audioDurMs);
      }
    }

    // V8 M-9: the conversation metadata recipients DISPLAY is sealed inside the
    // content (authenticated by this sender), not taken from the server's copy.
    const meta: ContentMeta = {
      t: type as ContentMeta['t'], c: targetCircle || null, g: targetGroup || null,
      a: !!ackRequested, l: typeof node.level === 'number' ? node.level : null,
    };
    const content = {
      meta,
      text: payload.text || null,
      // Inline fields stay null now — media travels as attachment pointers.
      imageUrl: null, audioUrl: null, videoUrl: null,
      attachments: attachments.length ? attachments : null,
      replyTo: payload.replyTo || null,
      editsMid: payload.editsMid || null,
      // v70: delete-for-everyone travels sealed through the ratchet, like an edit.
      ...(payload.retracts && payload.retracts.length ? { retracts: payload.retracts.slice(0, 200) } : {}),
    };
    const { cek, iv, ct } = await sealContent(content, node.id, mid, ts, exp);
    // V8 H-1: every ratchet slot carries CEK ‖ digest(this exact ciphertext), so a
    // co-recipient who knows the CEK still cannot substitute different content.
    const slotPlain = await bindCekToEnvelope(cek, { sigBy: node.id, mid, ts, exp, iv, ct });

    // V8 H-2: remember exactly who this was encrypted to (monitors included) and
    // whether each was a verified member, for Message Info.
    const { recips, sentTo, others, withheld, unreachable, changed } = await this.slotsFor(node, r, targetUserId, slotPlain);
    // v72 B3: refuse BEFORE keeping our own copy, so a message nobody can receive
    // (e.g. the only recipient's key changed) never shows as sent.
    if (!recips.length && others && !payload.retracts) throw this.noRecipientsError(others, withheld, unreachable, changed);

    // Edit: instead of creating a new visible message, patch the original's text
    // in our own store and relay the edit so recipients do the same.
    if (payload.editsMid) {
      try {
        const existing = await msgStore.get(node.id, payload.editsMid);
        if (existing) {
          const patched = { ...existing, text: payload.text || undefined, edited: true, editedAt: ts };
          await msgStore.put(node.id, payload.editsMid, patched);
          this.appendToMsgCache(node.id, payload.editsMid, patched);
        }
      } catch {}
    } else if (payload.retracts) {
      // A retraction is a control message: nothing to show or keep.
    } else {
    // Store our own copy so the sender sees their message (survives reload).
    // We keep the attachment POINTERS (not the multi-MB data URLs) — the sender
    // re-fetches its own blobs on demand exactly like recipients do.
    const ownRec = {
      senderId: node.id, timestamp: ts, type, targetCircle: targetCircle,
      // Which single contact this was sent to (DM / personal-hub chats) — lets
      // the per-contact chat view show only the messages that belong to it.
      peerId: targetUserId || undefined,
      // Which invitee-group chat this belongs to (inviter's descendants groups).
      targetGroup: targetGroup || undefined,
      expiresAt: exp ?? undefined, verified: true,
      text: payload.text || undefined,
      attachments: attachments.length ? attachments : undefined,
      replyTo: payload.replyTo || undefined,
      ackRequested: ackRequested || undefined,
      sentTo: sentTo.length ? sentTo : undefined,
      withheld: withheld || undefined,
      keyChangedWithheld: changed.length || undefined,   // v72 B3: shown in Message Info
    };
    await msgStore.put(node.id, mid, ownRec);
    this.appendToMsgCache(node.id, mid, ownRec); // no full-IDB reload on send
    try { onEcho?.(); } catch {} // surface it to the UI now; the POST below happens after
    }

    if (!recips.length) {
      if (payload.retracts) return;                  // nobody else holds it
      if (others) throw this.noRecipientsError(others, withheld, unreachable, changed);
      return; // note-to-self only: stored locally, nothing to relay
    }

    const envelope: Envelope = { v: 5, mid, ts, exp, iv, ct, recips, sigBy: node.id, targetGroup: targetGroup || undefined };
    await this.request('/messages', {
      method: 'POST',
      body: JSON.stringify({ nodeId: node.id, envelope, type, targets, targetCircle, ackRequested: ackRequested || undefined, targetGroup, mentions: (mentions && ((mentions.users && mentions.users.length) || (mentions.viaGroup && mentions.viaGroup.length))) ? mentions : undefined }),
    });
    this.scheduleBackup(node); // sending advanced our ratchet sessions too
  }

  async registerUser(name: string, inviteCode?: string, treeName?: string, treeMode?: 'HIERARCHICAL' | 'DM' | 'HUB', treeNameVisible?: boolean, color?: string, monitorEnabled?: boolean, referralOpen?: boolean, globalChat?: boolean, useDefaultProfile?: boolean, inviteFragment?: string): Promise<User> {
    // The wrap key may only be missing from memory after a page reload — try
    // restoring the persisted (non-extractable) copy before giving up.
    if (!keyStore.hasWrapKey()) await keyStore.ensureWrapKey();
    if (!keyStore.hasWrapKey()) throw new Error('Session locked. Please log in again.');
    // V8 phase 2: names are validated here (the server can no longer see them).
    const cleanNm = cleanName(name, 64);
    if (!cleanNm) throw new Error('Name must be 1–64 visible characters (no control, invisible, or text-direction characters).');
    if (treeName && !cleanName(treeName, 80)) throw new Error('Network name must be 1–80 visible characters.');
    // Joining: the link's #fragment carries the invite key, the network key and
    // the root pin. Check it against the server's invite certificate BEFORE
    // creating anything.
    const join = inviteCode ? await this.trust.prepareJoin(inviteCode, inviteFragment || '') : null;
    // Account default photo/bio, applied only when the person opts in (V8 M-8).
    const defaults = useDefaultProfile ? await this.getAccountProfile().catch(() => null) : null;
    const profile = { n: cleanNm, ts: Date.now(), ...(defaults?.bio ? { b: defaults.bio.slice(0, 500) } : {}) };
    const avatar = defaults?.avatar || undefined;

    const keys = await generateNodeKeys();
    const pub = await exportPublicBundle(keys);
    const wrappedKeys = await keyStore.wrapWithSessionKey(keys);
    const user = await this.request('/register', {
      method: 'POST',
      body: JSON.stringify({ inviteCode, treeMode, treeNameVisible, color, monitorEnabled, referralOpen, globalChat, encPub: pub.encPub, sigPub: pub.sigPub, wrappedKeys }),
    });
    if ((user as any).existing) {
      // Personal hub reuse: the account already has its hub identity (one per
      // account — a hub link connects hubs, it doesn't mint new members). The
      // keys we just generated are throwaways; unlock the REAL identity from
      // the server's wrapped blob instead of overwriting it.
      const node = user as User;
      try { await this.unlockNode(node); } catch { /* surfaces on node login */ }
      try { await this.ensureSignalReady(node); } catch {}
      if (join) {
        try { await this.fetchTreeContext(node); } catch {}   // load my hub's keys first
        await this.trust.completeJoin(node, join, this.trust.ownProfile(node.id) || profile);
      }
      return node;
    }
    await keyStore.storeFreshNode(user.id, { encPriv: keys.enc.privateKey, sigPriv: keys.sig.privateKey });
    try { await keyStore.repin(user.id, pub); } catch {}
    // Publish this new node's Signal prekey bundle so it can be messaged immediately
    // (and so its identity key exists to sign with).
    await this.ensureSignalReady(user);
    const node = user as User;
    if (join) await this.trust.completeJoin(node, join, profile, avatar);
    else {
      const label = treeName ? cleanName(treeName, 80)! : (treeMode === 'HUB' ? `${cleanNm}'s Chats` : `${cleanNm}'s Network`);
      await this.trust.bootstrapRoot(node, node.id, profile, label, avatar);
      (node as any).treeName = label;
    }
    node.name = cleanNm;
    return node;
  }


  async deleteNode(userId: string, initiatorId: string): Promise<void> {
    await this.withReauth('Pruning removes this person and everyone below them from the network.',
      () => this.request('/users/delete', { method: 'POST', body: JSON.stringify({ targetUserId: userId, initiatorId }) }));
  }

  // ---- v72 M4: password confirmation for destructive actions -----------------
  /** Set by the UI: asks for the password (explaining `reason`) and confirms it
   *  with confirmPassword(); resolves false if the person cancels. */
  onReauthNeeded: ((reason: string) => Promise<boolean>) | null = null;
  /** Confirm the password for this session (valid ~10 minutes on the server). */
  async confirmPassword(username: string, password: string): Promise<void> {
    const { salt, kdf } = await this.saltFor(username);   // v72 M6: refuses a KDF downgrade
    const { authHash } = await deriveAuthMaterial(username, password, salt, kdf === 1 ? 1 : 2);
    await this.request('/auth/reauth', { method: 'POST', body: JSON.stringify({ authHash }) });
  }
  /** Run `fn`; if the server wants the password first, ask for it once and retry. */
  private async withReauth<T>(reason: string, fn: () => Promise<T>): Promise<T> {
    try { return await fn(); }
    catch (e: any) {
      if (e?.body?.code !== 'reauth-required' || !this.onReauthNeeded) throw e;
      if (!(await this.onReauthNeeded(reason))) throw new Error('Cancelled — nothing was changed.');
      return await fn();
    }
  }

  async updatePermissions(targetUserId: string, permissions: any, initiatorId: string): Promise<void> {
    await this.request('/users/permissions', { method: 'POST', body: JSON.stringify({ targetUserId, permissions, initiatorId }) });
  }

  /** Inviter-only: partition your own direct invitees into groups that can't
   *  see or message each other. assignments maps invitee publicId -> group id,
   *  or an ARRAY of ids for a member in several groups (null to ungroup); labels
   *  maps groupId -> display name (null to delete). */
  async setInviteeGroups(initiatorId: string, assignments?: Record<string, string | string[] | null>, labels?: Record<string, string | null>, parents?: Record<string, string | null>, links?: Record<string, { groups?: string[]; name?: string; archived?: boolean; refs?: { o: string; g: string }[] } | null>, visitors?: Record<string, string[] | null>): Promise<{ inviteeGroups: Record<string, string | string[]>; groupLabels: Record<string, string>; groupParents?: Record<string, string>; groupLinks?: Record<string, { groups?: string[]; name: string; archived?: boolean; refs?: { o: string; g: string }[]; crossLevel?: boolean }>; groupVisitors?: Record<string, string[]> }> {
    return this.request('/users/groups', { method: 'POST', body: JSON.stringify({ initiatorId, assignments, labels, parents, links, visitors }) });
  }

  /** Move a member (and its whole subtree) into another node's group — re-parents it. */
  async moveNode(initiatorId: string, nodeId: string, targetOwnerId: string, targetGroupId: string | null): Promise<{ ok: boolean }> {
    return this.request('/nodes/move', { method: 'POST', body: JSON.stringify({ initiatorId, nodeId, targetOwnerId, targetGroupId }) });
  }

  /** Change this node's own icon color (as it appears to everyone who can see it). */
  async setMyColor(nodeId: string, color: string): Promise<{ color: string }> {
    return this.request('/users/color', { method: 'POST', body: JSON.stringify({ nodeId, color }) });
  }

  // ---- Network Profile (V8 phase 2: end-to-end encrypted) ----
  /** A node reference for trust operations (its network root comes from the last sync). */
  private nodeRef(nodeId: string): User {
    return { id: nodeId, treeRoot: this.trust.trustOf(nodeId)?.tree || nodeId } as User;
  }
  private ownProfileOrThrow(nodeId: string) {
    const p = this.trust.ownProfile(nodeId);
    if (!p) throw new Error('Your profile is still loading on this device — try again in a moment.');
    return p;
  }
  /** Change my display name in THIS network. The name history lives inside the
   *  encrypted profile (owner-maintained; the server can't read or stamp it). */
  async setMyName(nodeId: string, name: string): Promise<{ name: string; nameHistory: { name: string; at: number }[] }> {
    const clean = cleanName(name, 64);
    if (!clean) throw new Error('Name must be 1–64 visible characters (no control, invisible, or text-direction characters).');
    const cur = this.ownProfileOrThrow(nodeId);
    const h = [...(cur.h || [])];
    if (cur.n && cur.n !== clean) h.push({ name: cur.n, at: Date.now() });
    const ref = this.nodeRef(nodeId);
    const next = { ...cur, n: clean, h: h.slice(-50) };
    await this.trust.writeProfile(ref, ref.treeRoot!, next);
    return { name: clean, nameHistory: next.h };
  }
  /** Set/clear my bio and/or profile photo. `avatar` is an ALREADY-scrubbed data
   *  URL (caller runs it through mediaService first); it is encrypted here under
   *  a fresh per-photo key. removeAvatar clears it. */
  async updateProfile(nodeId: string, changes: { bio?: string | null; avatar?: string; removeAvatar?: boolean }): Promise<{ bio: string; avatarAt: number }> {
    if (changes.bio && changes.bio.length > 500) throw new Error('Bio must be 500 characters or fewer');
    const cur = this.ownProfileOrThrow(nodeId);
    const next = { ...cur };
    if (changes.bio !== undefined) { if (changes.bio) next.b = changes.bio; else delete next.b; }
    const ref = this.nodeRef(nodeId);
    const r = await this.trust.writeProfile(ref, ref.treeRoot!, next, changes.removeAvatar ? { avatarDataUrl: null } : changes.avatar ? { avatarDataUrl: changes.avatar } : {});
    return { bio: next.b || '', avatarAt: changes.removeAvatar ? 0 : r.avatarAt };
  }
  /** Profile info-view data for a node I can see (decrypted here). `verified`:
   *  a signed membership certificate names this node and its key. */
  async fetchProfile(viewerNodeId: string, targetPublicId: string): Promise<{ id: string; name: string; color: string; bio: string; avatarAt: number; nameHistory: { name: string; at: number }[]; verified?: boolean }> {
    const r = await this.request(`/users/${encodeURIComponent(targetPublicId)}/profile?viewerNodeId=${encodeURIComponent(viewerNodeId)}`);
    const o = await this.trust.openProfileFor(this.nodeRef(viewerNodeId), { ...r, id: targetPublicId });
    return { id: targetPublicId, name: o.name, color: r.color, bio: o.bio, avatarAt: r.avatarAt || 0, nameHistory: o.nameHistory, verified: o.verified };
  }
  /** Lazy avatar (data URL) for a visible node, decrypted with the photo key from
   *  its encrypted profile. Returns null on 404/no photo/no key. */
  async fetchAvatar(viewerNodeId: string, targetPublicId: string): Promise<string | null> {
    try {
      const r = await this.request(`/users/${encodeURIComponent(targetPublicId)}/avatar?viewerNodeId=${encodeURIComponent(viewerNodeId)}`);
      const blob: string | undefined = r?.avatar;
      if (!blob) return null;
      if (!blob.startsWith('enc1:')) return isSafeMediaDataUrl(blob, 'image') ? blob : null; // legacy, until its owner migrates
      let k = this.trust.photoKeyOf(targetPublicId);
      let url = k ? await openAvatar(blob, targetPublicId, k) : null;
      if (!url) {                        // photo changed since we last read the profile
        await this.fetchProfile(viewerNodeId, targetPublicId).catch(() => null);
        k = this.trust.photoKeyOf(targetPublicId);
        url = k ? await openAvatar(blob, targetPublicId, k) : null;
      }
      return url;
    } catch { return null; }
  }
  /** Add a visible user to my personal hub (symmetric contact request). Returns the
   *  resulting status: requested/pending/connected/invited. */
  async hubConnect(fromHubNodeId: string, targetPublicId: string, viaNode: User): Promise<{ ok: boolean; status: string }> {
    // v72 B2: `viaNode` is my node in the network where I saw them; it signs my
    // hub's key so they can verify the request against my membership there.
    const attest = await this.trust.hubRequestAttest(viaNode, fromHubNodeId, targetPublicId);
    return this.request('/hub/connect', { method: 'POST', body: JSON.stringify({ fromHubNodeId, targetPublicId, attest }) });
  }

  // ---- Account-level DEFAULT profile (V8 phase 2: sealed under the account key) ----
  async getAccountProfile(): Promise<{ name: string; bio: string; avatar: string; avatarAt: number }> {
    const r = await this.request('/account/profile');
    if (r?.ct) {
      try {
        const o = JSON.parse(new TextDecoder().decode(await keyStore.unwrapBytes(r.ct)));
        return { name: cleanName(o?.name, 64) || '', bio: typeof o?.bio === 'string' ? o.bio : '', avatar: isSafeMediaDataUrl(o?.avatar, 'image') ? o.avatar : '', avatarAt: o?.avatarAt || 0 };
      } catch { /* unreadable: treat as empty */ }
    }
    if (r?.legacy) {
      // One-time move of a plaintext default profile into the sealed form.
      const v = { name: r.legacy.name || '', bio: r.legacy.bio || '', avatar: r.legacy.avatar || '', avatarAt: r.legacy.avatar ? Date.now() : 0 };
      await this.saveAccountProfile(v).catch(() => {});
      return v;
    }
    return { name: '', bio: '', avatar: '', avatarAt: 0 };
  }
  private async saveAccountProfile(v: { name: string; bio: string; avatar: string; avatarAt: number }): Promise<void> {
    const ct = await keyStore.wrapBytes(new TextEncoder().encode(JSON.stringify(v)).buffer as ArrayBuffer);
    await this.request('/account/profile', { method: 'POST', body: JSON.stringify({ ct }) });
  }
  async setAccountProfile(changes: { name?: string | null; bio?: string | null; avatar?: string; removeAvatar?: boolean }): Promise<{ name: string; bio: string; avatar: string; avatarAt: number }> {
    const next = await this.getAccountProfile();
    if (changes.name !== undefined) {
      if (changes.name) { const c = cleanName(changes.name, 64); if (!c) throw new Error('Name must be 1–64 visible characters'); next.name = c; }
      else next.name = '';
    }
    if (changes.bio !== undefined) {
      if (changes.bio && changes.bio.length > 500) throw new Error('Bio must be 500 characters or fewer');
      next.bio = changes.bio || '';
    }
    if (changes.removeAvatar) { next.avatar = ''; next.avatarAt = 0; }
    else if (changes.avatar) {
      if (!isSafeMediaDataUrl(changes.avatar, 'image')) throw new Error('Invalid image');
      next.avatar = changes.avatar; next.avatarAt = Date.now();
    }
    await this.saveAccountProfile(next);
    return next;
  }

  /** Root-only: rename the network / 1:1 and/or toggle network-name visibility.
   *  The name itself is sealed client-side (V8 phase 2) and never sent in clear. */
  async updateTreeSettings(nodeId: string, changes: { treeName?: string; treeNameVisible?: boolean; monitorEnabled?: boolean; referralOpen?: boolean; globalChat?: boolean; autoAcceptInvites?: boolean }): Promise<{ treeName: string; treeNameVisible: boolean; monitorEnabled?: boolean; referralOpen?: boolean; globalChat?: boolean; autoAcceptInvites?: boolean }> {
    const { treeName, ...rest } = changes;
    let named: string | undefined;
    if (treeName !== undefined) {
      const ref = this.nodeRef(nodeId);
      await this.trust.writeTreeName(ref, ref.treeRoot!, treeName);
      named = cleanName(treeName, 80) || undefined;
    }
    const res = await this.request('/tree/settings', { method: 'POST', body: JSON.stringify({ nodeId, ...rest }) }); // echoes the current switches
    return { ...res, treeName: named ?? this.trust.selfLabelOf(nodeId)?.t ?? '' };
  }

  // ---- Encrypted calls: sealed-signaling relay ------------------------------
  async sendRtcSignal(fromNodeId: string, toNodeId: string, callId: string, kind: string, kt?: number, kb?: string): Promise<void> {
    await this.request('/rtc/signal', { method: 'POST', body: JSON.stringify({ fromNodeId, toNodeId, callId, kind, kt, kb }) });
  }
  /** Rings that arrived while the app was closed/asleep (see server buffer). */
  async fetchPendingCalls(): Promise<any[]> {
    const r = await this.request('/rtc/pending').catch(() => null);
    return Array.isArray(r?.signals) ? r.signals : (Array.isArray(r?.rings) ? r.rings : []);
  }
  /** Prekey bundle for on-demand session establishment (call signaling). */
  // ---- Attachments (Signal-style out-of-band encrypted media) -----------------
  /** Encrypt one media data URL, upload the ciphertext, return a small pointer
   *  (the key stays here and rides the E2E message envelope). */
  /** `global`: the blob belongs to a global-chat message — v72 M2: only then may
   *  network members walled apart from the sender download it (they still need the
   *  key, which travels only inside that message). */
  async uploadAttachment(nodeId: string, dataUrl: string, kind: 'image' | 'audio' | 'video', expiresAt?: number, scope?: 'global' | 'main'): Promise<AttachmentRef> {
    const enc = await encryptAttachment(dataUrl);
    const { id } = await this.request('/attachments', {
      method: 'POST',
      body: JSON.stringify({ nodeId, data: bytesToB64(enc.cipher), expiresAt: expiresAt ?? undefined, ...(scope ? { scope } : {}) }),
    });
    return { id, key: enc.key, iv: enc.iv, mime: enc.mime, kind };
  }

  private attachmentCache = new Map<string, string>(); // blobId -> decrypted data URL

  /** Fetch + decrypt one attachment into a data URL, memoized per blob id. */
  async fetchAttachment(ref: AttachmentRef): Promise<string> {
    const hit = this.attachmentCache.get(ref.id);
    if (hit) return hit;
    const resp = await fetch(`${API_BASE}/attachments/${encodeURIComponent(ref.id)}`, { credentials: 'same-origin' });
    if (!resp.ok) throw new Error(`attachment ${resp.status}`);
    const buf = await resp.arrayBuffer();
    const dataUrl = await decryptAttachment(buf, ref.key, ref.iv, ref.mime);
    if (this.attachmentCache.size > 60) this.attachmentCache.clear(); // bounded
    this.attachmentCache.set(ref.id, dataUrl);
    return dataUrl;
  }

    /**
     * v70 H3: may this node set up a call with peerId, and on which identity key?
     * The same rule messages follow (decideRecipients): a peer a signed membership
     * chain names → its certified key; otherwise only a personal-hub contact, or
     * — during the transition window — someone this device already has a session
     * with, and then without a key to check; anyone else is refused.
     */
    async callPeer(node: User, peerId: string): Promise<{ ik: string | null } | null> {
      if (!this.trust.trustOf(node.id)) { try { await this.fetchTreeContext(node); } catch {} }
      const t = this.trust.trustOf(node.id);
      const ik = t ? (peerId === t.tree ? t.rootIk : t.members.get(peerId)?.ik || null) : null;
      if (ik) return { ik };
      // v72 B3: in a personal hub only an ACTIVE contact (v71: any id at all).
      if ((node as any).treeMode === 'HUB') return this.trust.isActiveHubContact(node.id, peerId) ? { ik: null } : null;
      if (Date.now() < LEGACY_GRACE_END && await signal.hasSession(node.id, peerId)) return { ik: null };
      return null;
    }
    async fetchPrekeyBundle(forNodeId: string): Promise<any> {
    return this.request('/prekeys/fetch', { method: 'POST', body: JSON.stringify({ forNodeId }) });
  }

  // ---- Read receipts (optional, content-free) -------------------------------
  /** Batch-send read receipts to a message's sender. Fire-and-forget. */
  async sendReadReceipts(fromNodeId: string, toNodeId: string, mids: string[]): Promise<void> {
    if (!mids.length) return;
    await this.request('/receipt', { method: 'POST', body: JSON.stringify({ nodeId: fromNodeId, toNodeId, mids }) }).catch(() => {});
  }
  /** A receipt arrived for our own messages: persist read state locally. */
  async markMessagesRead(nodeId: string, mids: string[], from?: string): Promise<number> {
    // v71 L6: a receipt counts only for MY messages that were sent to its author.
    if (from) {
      const ok: string[] = [];
      for (const mid of mids.slice(0, 100)) {
        const r = await msgStore.get(nodeId, mid).catch(() => null);
        if (!r || r.senderId !== nodeId) continue;
        const sentTo = Array.isArray(r.sentTo) ? r.sentTo : null;
        if (sentTo ? sentTo.some(t => t.id === from) : (!r.peerId || r.peerId === from)) ok.push(mid);
      }
      mids = ok;
      if (!mids.length) return 0;
    }
    const n = await msgStore.markRead(nodeId, mids);
    if (n > 0 && this.msgCacheNode === nodeId && this.msgCache) {
      // In-place readAt update: a read receipt shouldn't trigger a full
      // IndexedDB reload of every media-bearing message.
      const set = new Set(mids);
      const now = Date.now();
      this.msgCache = this.msgCache.map(m => set.has(m.mid) && !(m as any).readAt ? { ...m, readAt: now } : m);
    }
    return n;
  }

  // ---- Message deletion ---------------------------------------------------------
  /** Delete for me only: drop from THIS device's local store. */
  async deleteMessagesLocal(nodeId: string, mids: string[]): Promise<void> {
    for (const mid of mids) { await msgStore.remove(nodeId, mid).catch(() => {}); }
    this.dropFromMsgCache(nodeId, mids);
  }
  /** Delete for everyone (own messages only). v70: recipients delete only on a
   *  SEALED retraction from me, sent to each message's original audience through
   *  the ratchet (like an edit); the server call then drops the stored ciphertext
   *  so nobody who hasn't fetched it yet ever does. */
  async deleteMessagesForAll(node: User, mids: string[]): Promise<string[]> {
    const groups = new Map<string, { type: Message['type']; circle?: 'UP' | 'DOWN'; group?: string; peer?: string; mids: string[] }>();
    for (const mid of mids) {
      const r: any = await msgStore.get(node.id, mid).catch(() => null);
      if (!r || r.senderId !== node.id || r.hidden) continue;
      const key = [r.type, r.targetCircle || '', r.targetGroup || '', r.peerId || ''].join('|');
      if (!groups.has(key)) groups.set(key, { type: r.type, circle: r.type === 'PEER' ? r.targetCircle : undefined, group: r.targetGroup || undefined, peer: r.peerId || undefined, mids: [] });
      groups.get(key)!.mids.push(mid);
    }
    for (const g of groups.values()) {
      for (let i = 0; i < g.mids.length; i += 200) {
        try { await this.sendMessage(node, { retracts: g.mids.slice(i, i + 200) }, g.type, undefined, g.circle, g.peer, undefined, g.group); }
        catch (e) { try { console.warn('[delete] sealed retraction not sent:', (e as any)?.message || e); } catch {} }
      }
    }
    const r = await this.request('/messages/delete', { method: 'POST', body: JSON.stringify({ nodeId: node.id, mids }) });
    const removed: string[] = Array.isArray(r?.removed) ? r.removed : [];
    for (const mid of mids) { await msgStore.remove(node.id, mid).catch(() => {}); }
    this.dropFromMsgCache(node.id, mids);
    return removed;
  }

  // ---- Join-request review ------------------------------------------------------
  async respondJoinRequest(inviterId: string, targetUserId: string, accept: boolean): Promise<void> {
    // v72 B2: an unverified request is refused HERE, before the server is told to
    // accept it (v71 accepted first and vouched the server's claimed key after).
    if (accept && !this.trust.verifiedRequestIk(inviterId, targetUserId)) throw new Error(UNVERIFIED_REQUEST);
    await this.request('/join-requests/respond', { method: 'POST', body: JSON.stringify({ inviterId, targetUserId, accept }) });
    // V8 phase 2: accepting = vouching. Sign the requester (with its verified key)
    // into the network and hand it the network key.
    if (accept) {
      try { await this.trust.approve(this.nodeRef(inviterId), targetUserId); }
      catch (e) { try { console.warn('[trust] vouch after accept failed:', (e as any)?.message || e); } catch {} }
    }
  }

  /** Confirm an active member who has no membership certificate yet (e.g. one who
   *  joined through an old-style link) — shown as unverified until someone vouches. */
  async vouchMember(voucher: User, targetUserId: string, ik: string): Promise<void> {
    await this.trust.vouch(voucher, targetUserId, ik);
  }

  // ---- Permanent invite (QR) --------------------------------------------------
  /**
   * Get (or rotate) a permanent invite code and build its LINK. V8 phase 2: the
   * link's #fragment (never sent to the server) carries a per-link key whose
   * public half `signer` signs into an invite certificate, plus the network key
   * and the root pin — so a joiner can prove it came through this link, and the
   * server can't invent members. `signer` is the node the viewer is acting as.
   */
  async getPermanentInvite(inviterId: string, rotate = false, groupId?: string, signer?: User): Promise<{ code: string; groupId?: string; link: string }> {
    const r = await this.request('/invites/permanent', { method: 'POST', body: JSON.stringify({ inviterId, rotate, groupId }) });
    const s: any = signer || { ...this.nodeRef(inviterId), id: inviterId };
    const hubMode = s.treeMode === 'HUB';
    const isRoot = s.role === 'ROOT' || s.id === (s.treeRoot || '');
    // Mirrors the server's auto-accept rule (/api/register): the link says, under
    // the inviter's signature, whether joiners are members on arrival or need an
    // approval (a vouch) first.
    const aa = !hubMode && (!!s.autoAcceptInvites || (s.treeMode === 'DM' && !!s.referralOpen && isRoot));
    // Signing needs this network's verified state; on a fresh entry the first
    // sync may still be in flight, so load it here rather than fail.
    if (!this.trust.trustOf(s.id)?.rootIk && signer) { try { await this.fetchTreeContext(signer); } catch { /* inviteFragment reports it */ } }
    const frag = await this.trust.inviteFragment(s, r.code, { aa, ...(groupId ? { groupId } : {}) });
    return { code: r.code, ...(r.groupId ? { groupId: r.groupId } : {}), link: `${window.location.origin}/launch?invite=${r.code}#${frag}` };
  }

  // ---- Panic wipe ------------------------------------------------------------
  /** Destroy local crypto/message stores, the server-side encrypted backup, and
   *  the session. Irreversible by design. */
  async panicWipe(nodeId: string | null): Promise<void> {
    this.invalidateMsgCache();
    // v71 L10: every identity's encrypted server backup, not just the open one.
    const ids = new Set<string>(nodeId ? [nodeId] : []);
    try { for (const n of await this.request('/my-nodes', { method: 'POST', body: '{}' }) || []) if (n && typeof n.id === 'string') ids.add(n.id); } catch {}
    for (const id of ids) await this.request('/state-backup/delete', { method: 'POST', body: JSON.stringify({ nodeId: id }) }).catch(() => {});
    await this.logout().catch(() => {});
    sealedLocal.clearAll();
    try { localStorage.clear(); } catch {}
    try { sessionStorage.clear(); } catch {}
    // V8 M-12: EVERY local database — including the avatar cache (contacts' faces)
    // and the key/pin store, which the old hard-coded list left behind.
    await Promise.all(ALL_LOCAL_DBS.map(deleteDb));
    // v72: the offline cache and the service worker too (the cache could hold pages
    // opened from invite / payment links).
    try { if (typeof caches !== 'undefined') await Promise.all((await caches.keys()).map(k => caches.delete(k))); } catch {}
    try { if (navigator.serviceWorker) for (const r of await navigator.serviceWorker.getRegistrations()) await r.unregister(); } catch {}
  }

  // ---- Safety-number support (out-of-band verification via Signal fingerprints) ----
  // v71 M2: the exact key each safety number was computed from, so accepting pins
  // THAT key (and refuses if it changed again after it was shown).
  private shownKeys = new Map<string, string>();
  async safetyNumberWith(me: User, other: User): Promise<string | null> {
    try {
      const key = await signal.remoteIdentity(me.id, other.id);
      const num = await signal.safetyNumber(me.id, other.id);
      if (!key || !num || (await signal.remoteIdentity(me.id, other.id)) !== key) return null;
      this.shownKeys.set(me.id + '|' + other.id, key);
      return num;
    } catch { return null; }
  }
  async acceptKeyChange(me: User, other: User): Promise<void> {
    const shown = this.shownKeys.get(me.id + '|' + other.id);
    if (!shown) throw new Error('Open the safety number first, then compare it before trusting the new key.');
    // Pin exactly the key whose number was compared (v70 deleted the pin instead,
    // so whatever key arrived next was trusted on first sight).
    if (!(await signal.acceptIdentity(me.id, other.id, shown))) {
      this.shownKeys.delete(me.id + '|' + other.id);
      throw new Error('Their security key changed again after the safety number was shown. Compare the new number before trusting it.');
    }
    this.shownKeys.delete(me.id + '|' + other.id);
    try { await msgStore.clearKeyChangedFrom(me.id, other.id); } catch {}
    this.invalidateMsgCache();                         // repaint from the corrected store
  }
}

export const api = new BackendAPI();

// Returning from a card checkout: /launch?billing=success&session_id=cs_… — keep
// the session id for the plan panel to confirm, and clean the address bar.
const PENDING_CHECKOUT = 'arbor-pending-checkout';
try {
  const u = new URL(location.href);
  const billing = u.searchParams.get('billing');
  if (billing) {
    const sid = u.searchParams.get('session_id');
    if (billing === 'success' && sid && /^cs_[A-Za-z0-9_]+$/.test(sid)) sessionStorage.setItem(PENDING_CHECKOUT, sid);
    u.searchParams.delete('billing'); u.searchParams.delete('session_id');
    history.replaceState(history.state, '', u.pathname + (u.search || '') + u.hash);
  }
} catch { /* not in a browser page */ }
