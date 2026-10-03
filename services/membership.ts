/**
 * Signed membership (V8 phase 2, H-2) and network-key boxes (M-8).
 *
 * Every membership step is a small certificate signed with a Signal identity key
 * (XEdDSA). The server stores and relays them but cannot mint them, so a client
 * can tell a real member from one the server merely claims exists:
 *
 *   root   — self-signed by the network root: {tree, pid, ik}
 *   inv    — signed by a verified member when an invite link is made; carries the
 *            PUBLIC half of a one-link key whose private half travels only in the
 *            link's #fragment (never sent to the server)
 *   join   — signed with that link key by the joiner's app: {pid, ik, inv}
 *   vouch  — a verified member vouches for {pid, ik} (manual approval, migration)
 *   epoch  — root announces the current network-key id
 *   legacy — root lists the members that existed when the network first upgraded
 *   hubreq — (v72, not a tree certificate) a member of network `tree` signs, with its
 *            certified key there, that its personal hub `hub` has identity `ik` and
 *            asks `to` (a member of the same network) to connect. It rides on an
 *            "Add to my hub" request so the person accepting can check the hub's key
 *            against a membership they already verify.
 *
 * A node is a VERIFIED member of a tree iff a chain of valid signatures leads from
 * the pinned root identity to a cert naming that node's pid AND identity key.
 *
 * Network-key boxes carry the per-network symmetric key from one member to
 * another, sealed with static X25519 between their identity keys (authenticated
 * both ways; only the named recipient can open one).
 */
import * as x from './xeddsa';

// ---------------------------------------------------------------- encoding ----
const te = new TextEncoder();
export const utf8 = (s: string) => te.encode(s);
export function b64(u: Uint8Array): string { let s = ''; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
export function unb64(s: string): Uint8Array { const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
export const b64url = (u: Uint8Array) => b64(u).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export function unb64url(s: string): Uint8Array {
  const t = s.replace(/-/g, '+').replace(/_/g, '/');
  return unb64(t + '='.repeat((4 - (t.length % 4)) % 4));
}
const ab = (u: Uint8Array): ArrayBuffer => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

/** Deterministic JSON: sorted keys, no undefined members. Signed bytes are canon(body). */
export function canon(v: any): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  return '{' + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
}
export async function sha256(u: Uint8Array): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest('SHA-256', ab(u))); }
async function hkdf(ikm: Uint8Array, salt: string, info: string, len = 32): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', ab(ikm), 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: ab(utf8(salt)), info: ab(utf8(info)) }, k, len * 8));
}
const eqBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
/** Two identity keys (33- or 32-byte, base64) name the same Curve25519 key. */
export function sameKey(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false;
  try { return eqBytes(x.rawPub(unb64(a)), x.rawPub(unb64(b))); } catch { return false; }
}
/** Pin value for a root identity: SHA-256 of its raw 32-byte key, base64url. */
export async function anchorOf(ikB64: string): Promise<string> { return b64url(await sha256(x.rawPub(unb64(ikB64)))); }

// ---------------------------------------------------------------- certs -------
export type CertBody =
  | { k: 'root'; v: 1; tree: string; pid: string; ik: string; ts: number }
  | { k: 'inv'; v: 1; tree: string; by: string; ip: string; aa: boolean; g?: string; ts: number }
  | { k: 'join'; v: 1; tree: string; pid: string; ik: string; inv: string; ts: number }
  | { k: 'vouch'; v: 1; tree: string; by: string; pid: string; ik: string; ts: number }
  | { k: 'epoch'; v: 1; tree: string; by: string; kid: string; ts: number }
  | { k: 'legacy'; v: 1; tree: string; by: string; pids: string[]; ts: number }
  | { k: 'hubreq'; v: 1; tree: string; by: string; to: string; hub: string; ik: string; ts: number };
export interface Cert { b: CertBody; s: string; id: string; raw: string }

const CERT_DOMAIN = 'arbor-cert-v1\n';
const isStr = (v: any, max = 200) => typeof v === 'string' && v.length > 0 && v.length <= max;
const isTs = (v: any) => typeof v === 'number' && isFinite(v) && v > 0;
/** A legacy roster is split into certificates of at most this many pids (v70). */
export const LEGACY_CHUNK = 500;
/** Certificates dated further ahead than this are ignored (v70 H1). */
export const FUTURE_SKEW_MS = 24 * 60 * 60 * 1000;
// Exact field sets: a certificate can't carry padding or fields nobody checks (v70 H4).
const FIELDS: Record<string, string[]> = {
  root: ['k', 'v', 'tree', 'pid', 'ik', 'ts'],
  inv: ['k', 'v', 'tree', 'by', 'ip', 'aa', 'g', 'ts'],
  join: ['k', 'v', 'tree', 'pid', 'ik', 'inv', 'ts'],
  vouch: ['k', 'v', 'tree', 'by', 'pid', 'ik', 'ts'],
  epoch: ['k', 'v', 'tree', 'by', 'kid', 'ts'],
  legacy: ['k', 'v', 'tree', 'by', 'pids', 'ts'],
  hubreq: ['k', 'v', 'tree', 'by', 'to', 'hub', 'ik', 'ts'],
};

function wellFormed(b: any): b is CertBody {
  if (!b || typeof b !== 'object' || Array.isArray(b) || b.v !== 1 || !isStr(b.tree, 128) || !isTs(b.ts)) return false;
  const allowed = FIELDS[b.k];
  if (!allowed || Object.keys(b).some(k => b[k] !== undefined && !allowed.includes(k))) return false;
  switch (b.k) {
    case 'root': return isStr(b.pid, 128) && isStr(b.ik, 64);
    case 'inv': return isStr(b.by, 128) && isStr(b.ip, 64) && typeof b.aa === 'boolean' && (b.g === undefined || isStr(b.g, 64));
    case 'join': return isStr(b.pid, 128) && isStr(b.ik, 64) && isStr(b.inv, 64);
    case 'vouch': return isStr(b.by, 128) && isStr(b.pid, 128) && isStr(b.ik, 64);
    case 'epoch': return isStr(b.by, 128) && isStr(b.kid, 64);
    case 'legacy': return isStr(b.by, 128) && Array.isArray(b.pids) && b.pids.length <= 20000 && b.pids.every((p: any) => isStr(p, 128));
    case 'hubreq': return isStr(b.by, 128) && isStr(b.to, 128) && isStr(b.hub, 128) && isStr(b.ik, 64);
    default: return false;
  }
}

async function idOf(body: CertBody, s: string): Promise<string> { return b64url(await sha256(utf8(canon(body) + '|' + s))); }

export async function makeCert(body: CertBody, priv: Uint8Array): Promise<string> {
  if (!wellFormed(body) || (body.k === 'legacy' && body.pids.length > LEGACY_CHUNK)) throw new Error('Malformed certificate');
  const s = b64(await x.sign(priv, utf8(CERT_DOMAIN + canon(body))));
  return JSON.stringify({ b: body, s });
}

export async function parseCert(raw: string): Promise<Cert | null> {
  try {
    if (typeof raw !== 'string' || raw.length > 600000) return null;
    const o = JSON.parse(raw);
    if (!o || typeof o !== 'object' || Object.keys(o).some(k => k !== 'b' && k !== 's') || !wellFormed(o.b) || !isStr(o.s, 200)) return null;
    return { b: o.b, s: o.s, id: await idOf(o.b, o.s), raw };
  } catch { return null; }
}

// Signature results are pure functions of (cert, key): memoise across refreshes.
const sigMemo = new Map<string, boolean>();
async function sigOk(c: Cert, pubB64: string): Promise<boolean> {
  const k = c.id + '|' + pubB64;
  const hit = sigMemo.get(k);
  if (hit !== undefined) return hit;
  let ok = false;
  try { ok = await x.verify(unb64(pubB64), utf8(CERT_DOMAIN + canon(c.b)), unb64(c.s)); } catch { ok = false; }
  if (sigMemo.size > 20000) sigMemo.clear();
  sigMemo.set(k, ok);
  return ok;
}
/** Is `c` signed by the identity key `ikB64`? */
export const certSignedBy = (c: Cert, ikB64: string): Promise<boolean> => sigOk(c, ikB64);

/** Who authorised a binding: the root, the member's own previous key, or another member. */
export type BindAuth = 'root' | 'self' | 'member';
export interface MemberInfo { ik: string; ts: number; via: 'root' | 'join' | 'vouch'; auth: BindAuth }
export interface Trust {
  tree: string;
  /** Root identity (base64), or null when no root cert matched the pin. */
  rootIk: string | null;
  /** True when rootIk came from the caller's pin (not first-sight). */
  anchored: boolean;
  members: Map<string, MemberInfo>;
  /** Joins through links that need an approval (aa=false): pid → bound identity key. */
  bound: Map<string, string>;
  /** Pids the root listed as pre-existing when the network upgraded. */
  legacy: Set<string>;
  epoch: { kid: string; ts: number } | null;
  hasRoot: boolean;
  /** Pids some certificate tried to re-bind to a different key without the
   *  authority to (ignored; surfaced to the user as a warning). */
  conflicts: Set<string>;
}

/**
 * Evaluate a tree's certificates. `anchor` is the pinned root identity hash
 * (anchorOf); with no anchor the oldest well-signed root cert is taken on first
 * sight and `anchored` is false (the caller should pin it).
 *
 * Key bindings (v70 H1). A member's identity key is the FIRST one bound to its
 * pid (certificates are evaluated in the order the server received them). After
 * that the binding changes only through
 *   - a vouch by the root (the network owner re-keys a member), or
 *   - a vouch the member signs itself with its CURRENT key, dated later.
 * Any other member's vouch naming a different key is ignored and recorded in
 * `conflicts`, so one member can't re-key (or cut out) another. Someone waiting
 * on an approval can only be confirmed on the key its invite link bound.
 * Certificates dated more than FUTURE_SKEW_MS ahead are ignored.
 */
export async function verifyTree(tree: string, anchor: string | null, raws: string[], now: number = Date.now()): Promise<Trust> {
  const certs: Cert[] = [];
  const seen = new Set<string>();
  for (const r of raws || []) {
    const c = await parseCert(r);
    if (c && c.b.tree === tree && c.b.ts <= now + FUTURE_SKEW_MS && !seen.has(c.id)) { seen.add(c.id); certs.push(c); }
  }
  const t: Trust = { tree, rootIk: null, anchored: false, members: new Map(), bound: new Map(), legacy: new Set(), epoch: null, hasRoot: false, conflicts: new Set() };

  // 1) Root: self-signed, pid === tree, identity matches the pin (if any).
  const roots = certs.filter(c => c.b.k === 'root' && (c.b as any).pid === tree).sort((a, b) => a.b.ts - b.b.ts);
  t.hasRoot = roots.length > 0;
  for (const c of roots) {
    const ik = (c.b as any).ik as string;
    if (!(await sigOk(c, ik))) continue;
    if (anchor) { if ((await anchorOf(ik)) !== anchor) continue; t.anchored = true; }
    t.rootIk = ik;
    t.members.set(tree, { ik, ts: c.b.ts, via: 'root', auth: 'root' });
    break;
  }
  if (!t.rootIk) return t;

  // 2) Fixpoint over the rest: a cert counts once its signer is verified.
  const invites = new Map<string, { ip: string; aa: boolean }>();
  const done = new Set<string>();
  const put = (pid: string, ik: string, ts: number, via: MemberInfo['via'], auth: BindAuth) => {
    if (pid === tree) return;                         // the root's key comes only from the pin
    const cur = t.members.get(pid);
    if (!cur) {
      const linked = t.bound.get(pid);
      if (linked && auth !== 'root' && !sameKey(linked, ik)) { t.conflicts.add(pid); return; }
      t.members.set(pid, { ik, ts, via, auth });
      return;
    }
    if (sameKey(cur.ik, ik)) return;                  // a re-confirmation of the same key
    if ((auth === 'root' && !(cur.auth === 'root' && cur.ts >= ts)) || (auth === 'self' && ts > cur.ts)) {
      t.members.set(pid, { ik, ts, via, auth });
      return;
    }
    t.conflicts.add(pid);
  };
  const bind = (pid: string, ik: string) => {         // aa=false join: the first binding wins
    const cur = t.bound.get(pid);
    if (!cur) t.bound.set(pid, ik);
    else if (!sameKey(cur, ik)) t.conflicts.add(pid);
  };
  for (let round = 0; round < 64; round++) {
    let progress = false;
    for (const c of certs) {
      if (done.has(c.id)) continue;
      const b: any = c.b;
      switch (b.k) {
        case 'inv': case 'vouch': case 'epoch': case 'legacy': {
          const signer = t.members.get(b.by);
          if (!signer) break;
          if (b.k !== 'inv' && b.k !== 'vouch' && b.by !== tree) { done.add(c.id); break; } // epoch/legacy: root only
          done.add(c.id); progress = true;
          if (!(await sigOk(c, signer.ik))) break;
          if (b.k === 'inv') invites.set(c.id, { ip: b.ip, aa: b.aa });
          else if (b.k === 'vouch') put(b.pid, b.ik, b.ts, 'vouch', b.by === tree ? 'root' : b.by === b.pid ? 'self' : 'member');
          else if (b.k === 'epoch') { if (!t.epoch || t.epoch.ts < b.ts) t.epoch = { kid: b.kid, ts: b.ts }; }
          else for (const p of b.pids) t.legacy.add(p);
          break;
        }
        case 'join': {
          const inv = invites.get(b.inv);
          if (!inv) break;
          done.add(c.id); progress = true;
          if (!(await sigOk(c, inv.ip))) break;
          if (inv.aa) put(b.pid, b.ik, b.ts, 'join', 'member');
          else bind(b.pid, b.ik);
          break;
        }
        default: done.add(c.id);
      }
    }
    if (!progress) break;
  }
  return t;
}

// ---------------------------------------------------------------- invites -----
/** Per-link key seed, derived from the signer's identity key so the same link can
 *  be re-shown later without storing anything. */
export async function inviteSeed(identityPriv: Uint8Array, tree: string, code: string): Promise<Uint8Array> {
  return hkdf(identityPriv, 'arbor-invite-v1', `${tree}|${code}`);
}
export async function inviteKeys(seed: Uint8Array) { return x.keyPairFromSeed(seed); }

export interface InviteSecret { seed: Uint8Array; kid: string; key: Uint8Array; anchor: string }
/** The #fragment of an invite link. Never sent to the server. */
export function encodeFragment(s: InviteSecret): string {
  return ['s1', b64url(s.seed), s.kid, b64url(s.key), s.anchor].join('.');
}
export function decodeFragment(frag: string): InviteSecret | null {
  try {
    const m = String(frag || '').match(/s1\.([A-Za-z0-9_-]{43})\.([0-9a-f]{16})\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})/);
    if (!m) return null;
    const s = { seed: unb64url(m[1]), kid: m[2], key: unb64url(m[3]), anchor: m[4] };
    return s.seed.length === 32 && s.key.length === 32 ? s : null;
  } catch { return null; }
}

// ---------------------------------------------------------------- key boxes ---
export interface Box { v: 1; tree: string; kid: string; from: string; to: string; iv: string; ct: string }
const boxHeader = (b: { tree: string; kid: string; from: string; to: string }) => canon({ tree: b.tree, kid: b.kid, from: b.from, to: b.to });
async function boxKey(myPriv: Uint8Array, theirIk: string, header: string): Promise<CryptoKey> {
  const shared = await x.agree(unb64(theirIk), myPriv);
  const raw = await hkdf(shared, 'arbor-netbox-v1', header);
  return crypto.subtle.importKey('raw', ab(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function sealBox(netKey: Uint8Array, h: { tree: string; kid: string; from: string; to: string }, myPriv: Uint8Array, theirIk: string): Promise<Box> {
  const header = boxHeader(h);
  const k = await boxKey(myPriv, theirIk, header);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: ab(utf8(header)) }, k, ab(netKey)));
  return { v: 1, tree: h.tree, kid: h.kid, from: h.from, to: h.to, iv: b64(iv), ct: b64(ct) };
}
export async function openBox(box: Box, myPriv: Uint8Array, fromIk: string): Promise<Uint8Array | null> {
  try {
    const header = boxHeader(box);
    const k = await boxKey(myPriv, fromIk, header);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ab(unb64(box.iv)), additionalData: ab(utf8(header)) }, k, ab(unb64(box.ct))));
    return pt.length === 32 ? pt : null;
  } catch { return null; }
}

export const newKid = () => Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');
export const newNetKey = () => crypto.getRandomValues(new Uint8Array(32));

// ---------------------------------------------------------------- policy ------
/**
 * Transition window for members that existed before signed membership. Until
 * this instant, an UNVERIFIED recipient is still encrypted to — but only one this
 * device already has a Signal session with (someone it was talking to before the
 * update), and it is shown as unverified. A server-invented member has no such
 * session, so it is refused even during the window. Fixed in the client build:
 * the server cannot extend it.
 */
export const LEGACY_GRACE_END = Date.parse('2026-10-27T00:00:00Z');
