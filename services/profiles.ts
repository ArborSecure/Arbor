/**
 * End-to-end encrypted profiles (V8 phase 2, M-8).
 *
 * A member's display name, bio, name history and photo key live in ONE blob,
 * signed with the member's Signal identity key and encrypted under the network
 * key (AES-256-GCM, bound to tree + member + key id). The server stores only
 * ciphertext. Photos are encrypted separately under a per-photo key that rides
 * inside the profile, so rotating the network key never re-uploads images.
 * The network name is encrypted the same way, signed by the root.
 */
import * as x from './xeddsa';
import { b64, unb64, canon, utf8 } from './membership';

const ab = (u: Uint8Array): ArrayBuffer => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
const td = new TextDecoder();

export interface ProfileData {
  n: string;                                   // display name
  b?: string;                                  // bio
  h?: { name: string; at: number }[];          // earlier names (owner-maintained)
  av?: { k: string; at: number } | null;       // photo key + version
  ts: number;
}
export interface OpenedProfile { p: ProfileData; kid: string; tree: string; signed: boolean }

// ---- names (the server can no longer vet them, so every client does) ----
const INVISIBLE_FILLERS = /[͏ᅟᅠ឴឵⠀ㅤﾠ]/u;
export function cleanName(raw: unknown, max = 64): string | null {
  if (typeof raw !== 'string') return null;
  const s = raw.normalize('NFKC').replace(/\s+/gu, ' ').trim();
  if (!s || s.length > max) return null;
  if (/[\p{Cc}\p{Cs}\p{Co}\p{Cn}]/u.test(s)) return null;
  if (/(?!‍)\p{Cf}/u.test(s)) return null;           // bidi, zero-width, tags…
  if (INVISIBLE_FILLERS.test(s)) return null;
  if (s.includes('‍') && /(?<!\p{Extended_Pictographic}️?)‍|‍(?!\p{Extended_Pictographic})/u.test(s)) return null;
  if (!/[\p{L}\p{N}\p{Extended_Pictographic}]/u.test(s)) return null;
  return s;
}
const CONFUSABLE: Record<string, string> = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ӏ': 'l', 'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', '0': 'o', '1': 'l', '|': 'l', '3': 'e', '5': 's', '$': 's', '@': 'a' };
/** Look-alike skeleton (V8 L-8), now computed on the client over decrypted names. */
export const nameSkeleton = (n: string) => String(n || '').normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase()
  .replace(/./gsu, ch => CONFUSABLE[ch] || ch).replace(/rn/g, 'm').replace(/[^\p{L}\p{N}\p{Extended_Pictographic}]/gu, '');

// ---- AES-GCM helpers ----
async function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', ab(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function seal(raw: Uint8Array, plain: Uint8Array, aad: string): Promise<{ iv: string; ct: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: ab(utf8(aad)) }, await aesKey(raw), ab(plain)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function open(raw: Uint8Array, iv: string, ct: string, aad: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ab(unb64(iv)), additionalData: ab(utf8(aad)) }, await aesKey(raw), ab(unb64(ct))));
}

const PROFILE_DOMAIN = 'arbor-profile-v1\n';
const profileAad = (tree: string, pid: string, kid: string) => canon({ t: 'profile', tree, pid, kid });

/** Validate what a peer put in their profile; anything malformed is dropped. */
function tidy(p: any): ProfileData | null {
  if (!p || typeof p !== 'object') return null;
  const n = cleanName(p.n, 64);
  if (!n) return null;
  const out: ProfileData = { n, ts: typeof p.ts === 'number' ? p.ts : 0 };
  if (typeof p.b === 'string' && p.b.length <= 500) out.b = p.b;
  if (Array.isArray(p.h)) out.h = p.h.filter((e: any) => e && typeof e.at === 'number' && cleanName(e.name, 64)).slice(-50).map((e: any) => ({ name: cleanName(e.name, 64)!, at: e.at }));
  if (p.av && typeof p.av.k === 'string' && p.av.k.length <= 64 && typeof p.av.at === 'number') out.av = { k: p.av.k, at: p.av.at };
  return out;
}

export async function sealProfile(p: ProfileData, o: { tree: string; pid: string; kid: string; netKey: Uint8Array; identityPriv: Uint8Array }): Promise<string> {
  const sig = await x.sign(o.identityPriv, utf8(PROFILE_DOMAIN + canon({ tree: o.tree, pid: o.pid, kid: o.kid, p })));
  const plain = utf8(JSON.stringify({ p, s: b64(sig) }));
  const { iv, ct } = await seal(o.netKey, plain, profileAad(o.tree, o.pid, o.kid));
  return JSON.stringify({ v: 1, tree: o.tree, kid: o.kid, iv, ct });
}

export function profileHeader(ct: string | undefined | null): { tree: string; kid: string } | null {
  try { const o = JSON.parse(String(ct)); return o && o.v === 1 && typeof o.tree === 'string' && typeof o.kid === 'string' ? { tree: o.tree, kid: o.kid } : null; }
  catch { return null; }
}

/**
 * Decrypt a member's profile. `ik` is the identity key the viewer holds for that
 * member (from a verified cert, or the server's claim for a legacy member); the
 * result says whether the owner's signature checked out against it.
 */
export async function openProfile(ctStr: string, pid: string, keyFor: (tree: string, kid: string) => Uint8Array | null, ik: string | null): Promise<OpenedProfile | null> {
  try {
    const o = JSON.parse(ctStr);
    if (!o || o.v !== 1) return null;
    const key = keyFor(o.tree, o.kid);
    if (!key) return null;
    const inner = JSON.parse(td.decode(await open(key, o.iv, o.ct, profileAad(o.tree, pid, o.kid))));
    const p = tidy(inner && inner.p);
    if (!p) return null;
    let signed = false;
    if (ik && typeof inner.s === 'string') {
      signed = await x.verify(unb64(ik), utf8(PROFILE_DOMAIN + canon({ tree: o.tree, pid, kid: o.kid, p: inner.p })), unb64(inner.s));
    }
    return { p, kid: o.kid, tree: o.tree, signed };
  } catch { return null; }
}

// ---- network name (root-signed) ----
const TREENAME_DOMAIN = 'arbor-treename-v1\n';
export async function sealTreeName(name: string, o: { tree: string; kid: string; netKey: Uint8Array; rootPriv: Uint8Array }): Promise<string> {
  const sig = await x.sign(o.rootPriv, utf8(TREENAME_DOMAIN + canon({ tree: o.tree, kid: o.kid, name })));
  const { iv, ct } = await seal(o.netKey, utf8(JSON.stringify({ name, s: b64(sig) })), canon({ t: 'treename', tree: o.tree, kid: o.kid }));
  return JSON.stringify({ v: 1, tree: o.tree, kid: o.kid, iv, ct });
}
export async function openTreeName(ctStr: string, keyFor: (tree: string, kid: string) => Uint8Array | null, rootIk: string | null): Promise<{ name: string; kid: string; signed: boolean } | null> {
  try {
    const o = JSON.parse(ctStr);
    const key = o && o.v === 1 ? keyFor(o.tree, o.kid) : null;
    if (!key) return null;
    const inner = JSON.parse(td.decode(await open(key, o.iv, o.ct, canon({ t: 'treename', tree: o.tree, kid: o.kid }))));
    const name = cleanName(inner && inner.name, 80);
    if (!name) return null;
    const signed = !!rootIk && await x.verify(unb64(rootIk), utf8(TREENAME_DOMAIN + canon({ tree: o.tree, kid: o.kid, name: inner.name })), unb64(inner.s || ''));
    return { name, kid: o.kid, signed };
  } catch { return null; }
}

// ---- photos: per-photo key, carried inside the (encrypted) profile ----
export async function sealAvatar(dataUrl: string, pid: string): Promise<{ blob: string; key: string }> {
  const k = crypto.getRandomValues(new Uint8Array(32));
  const { iv, ct } = await seal(k, utf8(dataUrl), `arbor-avatar-v1|${pid}`);
  return { blob: `enc1:${iv}:${ct}`, key: b64(k) };
}
export async function openAvatar(blob: string, pid: string, keyB64: string): Promise<string | null> {
  try {
    const m = /^enc1:([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$/.exec(blob);
    if (!m) return null;
    const url = td.decode(await open(unb64(keyB64), m[1], m[2], `arbor-avatar-v1|${pid}`));
    return /^data:image\/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(url) ? url : null;
  } catch { return null; }
}
