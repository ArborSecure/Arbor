/**
 * Biometric app lock (Face ID / Touch ID / Android biometrics / Windows Hello)
 * via WebAuthn — v70 H5: a CRYPTOGRAPHIC lock, not just a screen.
 *
 * The account wrap key (which seals identity keys, sessions and history on this
 * device) is never stored in the clear any more (keyStore.ts). With the lock on,
 * this device keeps the wrap key SEALED under a secret that only the platform
 * authenticator can produce, and only after it verifies the user: the WebAuthn
 * PRF extension (hmac-secret) evaluated on a per-device salt. Unlocking = a
 * successful biometric check that yields that secret, which opens the sealed key.
 * Without the authenticator — a copied browser profile, a deleted localStorage
 * flag — there is nothing to open: Arbor asks for the password instead.
 *
 * Authenticators without PRF can't do this; enabling the lock then fails with
 * PrfUnsupported and the app keeps asking for the password on a cold start.
 */
import * as keyStore from './keyStore';

const FLAG = 'arbor_applock';
const HKDF_SALT = 'arbor-applock-v1';

export class PrfUnsupported extends Error {
  constructor() { super('This device’s biometrics can’t protect Arbor’s key (no WebAuthn PRF support). Arbor will ask for your password when it starts instead.'); }
}

// v71 M6: `kc` = a key-check value (a constant sealed under the wrap key itself),
// so a password login can tell the sealed key is from before a password change.
interface PrfRecord { v: 1; credId: string; salt: string; iv: string; ct: string; kc?: { iv: string; ct: string } }
const KC_PLAIN = 'arbor-applock-keycheck-v1';

const b64u = (buf: ArrayBuffer | Uint8Array) => {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = ''; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const bs = (u: Uint8Array) => u as unknown as BufferSource;
const b64uToBytes = (s: string) => {
  const t = s.replace(/-/g, '+').replace(/_/g, '/');
  const b = atob(t + '='.repeat((4 - (t.length % 4)) % 4));
  const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
};

export function isSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

export async function platformAuthenticatorAvailable(): Promise<boolean> {
  if (!isSupported()) return false;
  try { return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); }
  catch { return false; }
}

/** The lock is on for this device (UI hint only — the sealed record is what unlocks). */
export function isEnabled(): boolean {
  try { return !!localStorage.getItem(FLAG); } catch { return false; }
}
/** Is there a sealed key this device's biometrics can open? */
export async function hasKeyUnlock(): Promise<boolean> { return !!(await keyStore.getPrfRecord<PrfRecord>()); }

async function prfSecret(credId: Uint8Array, salt: Uint8Array): Promise<Uint8Array | null> {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: location.hostname,
      allowCredentials: [{ type: 'public-key', id: bs(credId) }],
      userVerification: 'required',
      timeout: 60000,
      extensions: { prf: { eval: { first: bs(salt) } } } as any,
    },
  }) as PublicKeyCredential | null;
  const out = (assertion?.getClientExtensionResults() as any)?.prf?.results?.first;
  return out ? new Uint8Array(out) : null;
}
async function sealingKey(secret: Uint8Array, credId: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', bs(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(HKDF_SALT), info: bs(credId) },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * Register a platform credential and seal the wrap key under its PRF secret.
 * `wrapRaw` is the account wrap key's raw bytes (re-derived from the password —
 * api.enableBiometricUnlock); zeroed here. Must run from a user gesture.
 */
export async function enable(accountName: string, wrapRaw: Uint8Array): Promise<void> {
  try {
    const cred = (await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: 'Arbor', id: location.hostname },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: accountName || 'arbor-user', displayName: accountName || 'Arbor user' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
        timeout: 60000,
        attestation: 'none',
        extensions: { prf: {} } as any,
      },
    })) as PublicKeyCredential | null;
    if (!cred) throw new Error('Biometric registration was cancelled.');
    const credId = new Uint8Array(cred.rawId);
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const secret = await prfSecret(credId, salt);
    if (!secret) throw new PrfUnsupported();
    const k = await sealingKey(secret, credId);
    secret.fill(0);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: bs(iv), additionalData: bs(credId) }, k, bs(wrapRaw)));
    const wk = await crypto.subtle.importKey('raw', bs(wrapRaw), { name: 'AES-GCM' }, false, ['encrypt']);
    const kiv = crypto.getRandomValues(new Uint8Array(12));
    const kct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: bs(kiv) }, wk, new TextEncoder().encode(KC_PLAIN)));
    const rec: PrfRecord = { v: 1, credId: b64u(credId), salt: b64u(salt), iv: b64u(iv), ct: b64u(ct), kc: { iv: b64u(kiv), ct: b64u(kct) } };
    await keyStore.putPrfRecord(rec);
    localStorage.setItem(FLAG, JSON.stringify({ credId: rec.credId }));
  } finally { wrapRaw.fill(0); }
}

/**
 * Biometric check → the account wrap key (non-extractable, for memory only), or
 * null when there's no sealed key, the check failed / was cancelled, or the
 * authenticator gave no PRF secret. The caller installs it (keyStore.setWrapKey).
 */
export async function unlock(): Promise<CryptoKey | null> {
  const rec = await keyStore.getPrfRecord<PrfRecord>();
  if (!rec || rec.v !== 1) return null;
  try {
    const credId = b64uToBytes(rec.credId);
    const secret = await prfSecret(credId, b64uToBytes(rec.salt));
    if (!secret) return null;
    const k = await sealingKey(secret, credId);
    secret.fill(0);
    const raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bs(b64uToBytes(rec.iv)), additionalData: bs(credId) }, k, bs(b64uToBytes(rec.ct))));
    try { return await crypto.subtle.importKey('raw', bs(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']); }
    finally { raw.fill(0); }
  } catch {
    return null;
  }
}

/**
 * v71 M6: after a password login — is the biometric record sealing a key that is
 * no longer the account's (the password was changed, here or on another device)?
 * Records made before v71 carry no check value and are reported as not stale.
 */
export async function isStaleFor(wrapKey: CryptoKey): Promise<boolean> {
  const rec = await keyStore.getPrfRecord<PrfRecord>();
  if (!rec || !rec.kc) return false;
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bs(b64uToBytes(rec.kc.iv)) }, wrapKey, bs(b64uToBytes(rec.kc.ct)));
    return new TextDecoder().decode(pt) !== KC_PLAIN;
  } catch { return true; }
}

/** Turn the lock off on this device (the sealed key is deleted). */
export async function disable(): Promise<void> {
  try { localStorage.removeItem(FLAG); } catch {}
  await keyStore.deletePrfRecord();
}
