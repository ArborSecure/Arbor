/**
 * Key storage for Arbor V4.
 *
 * - The password-derived wrapKey is held in MEMORY ONLY (v70 H5 — see
 *   setWrapKey). A reload needs the password, or the biometric unlock whose
 *   record here is the key sealed under a WebAuthn-PRF secret.
 * - Each node's private keys are persisted as NON-EXTRACTABLE CryptoKey objects in
 *   IndexedDB (opaque handles; raw bytes cannot be exported, even by page script).
 * - PINNED public keys (Trust On First Use): the first time we see a contact's
 *   identity we record their public keys; if the server later serves different keys
 *   for the same node we surface a "safety number changed" warning instead of
 *   silently trusting the new key. This is the anti-MITM anchor.
 */

import { unwrapPrivateKeys, wrapPrivateKeys, NodePrivateKeys, NodeKeyPair, PublicBundle } from './cryptoService';

const DB_NAME = 'arbor-keys-v4';
const PRIV_STORE = 'nodeKeys';
const PIN_STORE = 'pins';
const WRAP_STORE = 'wrapKey';
const WRAP_KEY_ID = 'session';

let wrapKeyMem: CryptoKey | null = null;
// V8 H-3 migration: the PREVIOUS (PBKDF2-derived) wrap key, kept as a READ-ONLY
// fallback while this device's sealed local data is re-sealed under the new
// scrypt-derived key. Never used to encrypt. Non-extractable, persisted like the
// main key, and dropped once the re-seal completes (or on logout).
// v71 M6: a LIST — after a password change a device may hold records sealed under
// one or more earlier keys (a device can be several changes behind).
let legacyKeysMem: CryptoKey[] = [];
const LEGACY_KEY_ID = 'legacy';
const memCache = new Map<string, NodePrivateKeys>();

export interface PinRecord { encPub: JsonWebKey; sigPub: JsonWebKey; firstSeen: number }

/**
 * v70 H5: the wrap key lives in MEMORY ONLY. It used to be mirrored into
 * IndexedDB (as a "non-extractable" CryptoKey — but the key material itself is
 * written into the browser profile), so a copy of the profile — a seized or
 * imaged device — opened identity keys, sessions and the whole history with no
 * password. Now a cold start needs the password again, or the biometric unlock
 * (appLock.ts), which keeps the key sealed under a secret only the device's
 * authenticator can produce (WebAuthn PRF). Any copy an older build persisted
 * is deleted.
 */
export function setWrapKey(k: CryptoKey | null) {
  wrapKeyMem = k;
  purgePersistedKeys();
  if (!k) legacyKeysMem = [];
}
/** Forget the key in memory (app-lock re-lock) without touching anything stored. */
export function lockWrapKey(): void { wrapKeyMem = null; legacyKeysMem = []; }
export function hasWrapKey(): boolean { return !!wrapKeyMem; }
let purged = false;
function purgePersistedKeys(): void {
  if (purged) return;
  purged = true;
  idbDelete(WRAP_STORE, WRAP_KEY_ID).catch(() => {});
  idbDelete(WRAP_STORE, LEGACY_KEY_ID).catch(() => {});
}

/** Install / clear the read-only legacy wrap key (V8 H-3 migration). Memory
 *  only (v70 H5); a reload mid-migration re-derives it from the password —
 *  see RESEAL_PENDING and api.login. */
export async function setLegacyWrapKey(k: CryptoKey | null): Promise<void> {
  legacyKeysMem = k ? [k] : [];
  purgePersistedKeys();
}
/** v71 M6: add read-only earlier keys (after a password change). Memory only. */
export function addLegacyWrapKeys(keys: CryptoKey[]): void {
  for (const k of keys) if (k && !legacyKeysMem.includes(k)) legacyKeysMem.push(k);
}
export async function getLegacyWrapKey(): Promise<CryptoKey | null> { return legacyKeysMem[0] || null; }
export function legacyWrapKeys(): CryptoKey[] { return [...legacyKeysMem]; }
/** Set while local records may still be sealed under the pre-upgrade key. */
export const RESEAL_PENDING = 'arbor_reseal_pending';

/** The biometric unlock record: the wrap key sealed under a WebAuthn-PRF secret
 *  (appLock.ts). Useless without the authenticator. */
const PRF_KEY_ID = 'prf';
export async function getPrfRecord<T>(): Promise<T | null> { try { return (await idbGet<T>(WRAP_STORE, PRF_KEY_ID)) || null; } catch { return null; } }
export async function putPrfRecord(rec: any): Promise<void> { await idbPut(WRAP_STORE, PRF_KEY_ID, rec); }
export async function deletePrfRecord(): Promise<void> { try { await idbDelete(WRAP_STORE, PRF_KEY_ID); } catch {} }
/** Current key first, then the legacy fallback (if any) — the order to try when OPENING. */
export async function readKeys(): Promise<CryptoKey[]> {
  if (!wrapKeyMem) await ensureWrapKey();
  const out: CryptoKey[] = [];
  if (wrapKeyMem) out.push(wrapKeyMem);
  out.push(...legacyKeysMem);
  return out;
}
export function currentWrapKey(): CryptoKey | null { return wrapKeyMem; }

/** Is a wrap key available? v70 H5: nothing is restored from disk any more —
 *  after a cold start the app must be unlocked (password or biometric PRF). */
export async function ensureWrapKey(): Promise<boolean> {
  purgePersistedKeys();
  return !!wrapKeyMem;
}

export async function wrapWithSessionKey(keys: NodeKeyPair): Promise<string> {
  if (!wrapKeyMem) await ensureWrapKey();
  if (!wrapKeyMem) throw new Error('Session locked: no wrap key in memory.');
  return wrapPrivateKeys(keys, wrapKeyMem);
}

// Wrap/unwrap raw bytes (used for the device-independent Signal identity private
// key, so a node keeps the SAME identity across logins/devices instead of
// regenerating one — which peers would otherwise see as an identity change).
const _b64 = (b: ArrayBuffer) => { const u = new Uint8Array(b); let s = ''; const C = 0x8000; for (let i = 0; i < u.length; i += C) s += String.fromCharCode.apply(null, u.subarray(i, i + C) as unknown as number[]); return btoa(s); };
const _ub64 = (s: string) => { const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };

export async function wrapBytes(bytes: ArrayBuffer): Promise<string> {
  if (!wrapKeyMem) await ensureWrapKey();
  if (!wrapKeyMem) throw new Error('Session locked: no wrap key in memory.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKeyMem, bytes);
  return JSON.stringify({ iv: _b64(iv.buffer), ct: _b64(ct) });
}
export async function unwrapBytes(blob: string): Promise<ArrayBuffer> {
  if (!wrapKeyMem) await ensureWrapKey();
  if (!wrapKeyMem) throw new Error('locked');
  const { iv, ct } = JSON.parse(blob);
  try {
    return await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _ub64(iv) }, wrapKeyMem, _ub64(ct));
  } catch (e) {
    // A record sealed before this device's KDF upgrade (V8 H-3) or a password
    // change (v71 M6) opens with an earlier key until the re-seal reaches it.
    for (const legacy of legacyKeysMem) {
      try { return await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _ub64(iv) }, legacy, _ub64(ct)); } catch { /* next */ }
    }
    throw e;
  }
}
/** Is this sealed blob still under the LEGACY key? (Used by the re-seal pass.) */
export async function needsReseal(blob: string): Promise<boolean> {
  if (!wrapKeyMem) await ensureWrapKey();
  if (!wrapKeyMem) return false;
  try { const { iv, ct } = JSON.parse(blob); await crypto.subtle.decrypt({ name: 'AES-GCM', iv: _ub64(iv) }, wrapKeyMem, _ub64(ct)); return false; }
  catch { return true; }
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 2);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(PRIV_STORE)) db.createObjectStore(PRIV_STORE);
      if (!db.objectStoreNames.contains(PIN_STORE)) db.createObjectStore(PIN_STORE);
      if (!db.objectStoreNames.contains(WRAP_STORE)) db.createObjectStore(WRAP_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet<T>(store: string, key: string): Promise<T | undefined> {
  return openDB().then(db => new Promise<T | undefined>((resolve, reject) => {
    const tx = db.transaction(store, 'readonly').objectStore(store).get(key);
    tx.onsuccess = () => resolve(tx.result as T | undefined);
    tx.onerror = () => reject(tx.error);
  }));
}

function idbDelete(store: string, key: string): Promise<void> {
  return openDB().then(db => new Promise<void>((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite').objectStore(store).delete(key);
    tx.onsuccess = () => resolve();
    tx.onerror = () => reject(tx.error);
  }));
}

function idbPut(store: string, key: string, val: any): Promise<void> {
  return openDB().then(db => new Promise<void>((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite').objectStore(store).put(val, key);
    tx.onsuccess = () => resolve();
    tx.onerror = () => reject(tx.error);
  }));
}

async function idbClearStore(store: string): Promise<void> {
  try {
    const db = await openDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(store, 'readwrite').objectStore(store).clear();
      tx.onsuccess = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch { /* ignore */ }
}

// ---- Private keys ----
export async function getNodeKeys(nodeId: string): Promise<NodePrivateKeys | null> {
  if (memCache.has(nodeId)) return memCache.get(nodeId)!;
  try {
    const stored = await idbGet<NodePrivateKeys>(PRIV_STORE, nodeId);
    if (stored) { memCache.set(nodeId, stored); return stored; }
  } catch { /* ignore */ }
  return null;
}

export async function unlockNode(nodeId: string, wrappedBlob: string): Promise<NodePrivateKeys> {
  const existing = await getNodeKeys(nodeId);
  if (existing) return existing;
  if (!wrapKeyMem) await ensureWrapKey();
  if (!wrapKeyMem) throw new Error('locked');
  const keys = await unwrapPrivateKeys(wrappedBlob, await readKeys());
  memCache.set(nodeId, keys);
  try { await idbPut(PRIV_STORE, nodeId, keys); } catch { /* non-fatal */ }
  return keys;
}

export async function storeFreshNode(nodeId: string, priv: NodePrivateKeys): Promise<void> {
  memCache.set(nodeId, priv);
  try { await idbPut(PRIV_STORE, nodeId, priv); } catch { /* non-fatal */ }
}

// ---- TOFU public-key pins ----
export async function getPin(nodeId: string): Promise<PinRecord | null> {
  try { return (await idbGet<PinRecord>(PIN_STORE, nodeId)) || null; } catch { return null; }
}

/**
 * Reconcile a server-presented identity with what we have pinned.
 * Returns 'new' (first sight, now pinned), 'match' (unchanged), or 'changed'
 * (server is presenting a DIFFERENT key for a known node — possible MITM).
 */
export async function reconcilePin(nodeId: string, bundle: PublicBundle): Promise<'new' | 'match' | 'changed'> {
  const same = (a: JsonWebKey, b: JsonWebKey) =>
    (a as any).x === (b as any).x && (a as any).y === (b as any).y && a.kty === b.kty && (a as any).crv === (b as any).crv;
  const existing = await getPin(nodeId);
  if (!existing) {
    await idbPut(PIN_STORE, nodeId, { encPub: bundle.encPub, sigPub: bundle.sigPub, firstSeen: Date.now() } as PinRecord);
    return 'new';
  }
  if (same(existing.encPub, bundle.encPub) && same(existing.sigPub, bundle.sigPub)) return 'match';
  return 'changed';
}

// ---- Network-owner (root) pins, v70 H2 ----
// One sealed record per node: which network owner this node trusts. Kept in the
// pin store so it survives page reloads and logout (like the TOFU pins above) —
// a missing server copy can then never make the app re-trust on first sight.
const ROOT_PIN_PREFIX = 'root|';
export async function getRootPinSealed(nodeId: string): Promise<string | null> {
  try { return (await idbGet<string>(PIN_STORE, ROOT_PIN_PREFIX + nodeId)) || null; } catch { return null; }
}
export async function putRootPinSealed(nodeId: string, sealed: string): Promise<void> {
  await idbPut(PIN_STORE, ROOT_PIN_PREFIX + nodeId, sealed);
}

/** Explicitly accept a changed key (after the user re-verifies the safety number). */
export async function repin(nodeId: string, bundle: PublicBundle): Promise<void> {
  await idbPut(PIN_STORE, nodeId, { encPub: bundle.encPub, sigPub: bundle.sigPub, firstSeen: Date.now() } as PinRecord);
}

export async function clearAllKeys(): Promise<void> {
  // Wipe private keys + session wrap key on logout. PINS ARE KEPT on purpose:
  // they are public trust anchors, and discarding them would mean silently
  // re-trusting whatever the server presents next time.
  wrapKeyMem = null;
  legacyKeysMem = [];
  memCache.clear();
  await idbClearStore(PRIV_STORE);
  await idbClearStore(WRAP_STORE); // the persisted session wrap key (and any legacy key) dies with the login
}

/** Drop decrypted node keys from memory (app-lock re-lock, V8 M-11). They reload
 *  from their non-extractable IndexedDB handles after the user unlocks again. */
export function dropMemoryKeys(): void { memCache.clear(); }
