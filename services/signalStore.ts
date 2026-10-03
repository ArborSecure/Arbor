/**
 * IndexedDB-backed Signal protocol store (one logical namespace per local node).
 *
 * Implements the libsignal `StorageType` interface: identity keypair, registration
 * id, one-time + signed prekeys, sessions, and remote identity keys. Trust is
 * Trust-On-First-Use: an unseen identity is accepted and pinned. If a peer later
 * presents a DIFFERENT identity key, this store accepts it at the protocol level
 * (so the message can be decrypted and shown with a warning) but records a sticky
 * "changed" flag. The app acts on that flag (v72 B3): messages from the new key are
 * shown flagged, and nothing is SENT to that peer — no message slot, no call — until
 * the user compares the safety number and accepts the key (acceptIdentity).
 *
 * NOTE: like the reference libsignal-js store, private key material is held in
 * IndexedDB as raw bytes. Ratchet state is device-local by design (forward secrecy
 * means it cannot be safely shared across devices).
 */

import type { StorageType, KeyPairType, Direction } from '@privacyresearch/libsignal-protocol-typescript';
import { wrapBytes, unwrapBytes, hasWrapKey, ensureWrapKey, needsReseal } from './keyStore';

const DB_NAME = 'arbor-signal-v1';
const STORE = 'kv';

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => { const db = req.result; if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE); };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
function idbGetRaw<T>(key: string): Promise<T | undefined> {
  return openDB().then(db => new Promise<T | undefined>((res, rej) => {
    const r = db.transaction(STORE, 'readonly').objectStore(STORE).get(key);
    r.onsuccess = () => res(r.result as T | undefined); r.onerror = () => rej(r.error);
  }));
}
function idbPutRaw(key: string, val: any): Promise<void> {
  return openDB().then(db => new Promise<void>((res, rej) => {
    const r = db.transaction(STORE, 'readwrite').objectStore(STORE).put(val, key);
    r.onsuccess = () => res(); r.onerror = () => rej(r.error);
  }));
}
// At-rest encryption wrappers. Every value is sealed with the account wrap key
// (the same non-extractable key that already protects node private keys and the
// server-side Signal identity backup) before it touches disk. Reads transparently
// handle BOTH sealed records and legacy plaintext ones, so existing installs keep
// working and migrate lazily; migrateAtRest() re-seals whatever is left.
async function idbGet<T>(key: string): Promise<T | undefined> {
  return (await decField(await idbGetRaw<any>(key))) as T | undefined;
}
async function idbPut(key: string, val: any): Promise<void> {
  await idbPutRaw(key, await encField(val));
}
function idbDel(key: string): Promise<void> {
  return openDB().then(db => new Promise<void>((res, rej) => {
    const r = db.transaction(STORE, 'readwrite').objectStore(STORE).delete(key);
    r.onsuccess = () => res(); r.onerror = () => rej(r.error);
  }));
}
function idbAllKeys(): Promise<string[]> {
  return openDB().then(db => new Promise<string[]>((res, rej) => {
    const r = db.transaction(STORE, 'readonly').objectStore(STORE).getAllKeys();
    r.onsuccess = () => res((r.result as IDBValidKey[]).map(String)); r.onerror = () => rej(r.error);
  }));
}

// JSON-safe deep encoding for stored values (ArrayBuffers <-> tagged base64).
const abToB64 = (b: ArrayBuffer) => { const u = new Uint8Array(b); let x = ''; const C = 0x8000; for (let i = 0; i < u.length; i += C) x += String.fromCharCode.apply(null, u.subarray(i, i + C) as unknown as number[]); return btoa(x); };
const b64ToAb = (x: string) => { const bin = atob(x); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u.buffer; };
function encodeVal(v: any): any {
  if (v instanceof ArrayBuffer) return { __ab: abToB64(v) };
  if (ArrayBuffer.isView(v)) return { __ab: abToB64((v as any).buffer.slice((v as any).byteOffset, (v as any).byteOffset + (v as any).byteLength)) };
  if (Array.isArray(v)) return v.map(encodeVal);
  if (v && typeof v === 'object') { const o: any = {}; for (const k of Object.keys(v)) o[k] = encodeVal(v[k]); return o; }
  return v;
}
function decodeVal(v: any): any {
  if (v && typeof v === 'object') {
    if (typeof v.__ab === 'string' && Object.keys(v).length === 1) return b64ToAb(v.__ab);
    if (Array.isArray(v)) return v.map(decodeVal);
    const o: any = {}; for (const k of Object.keys(v)) o[k] = decodeVal(v[k]); return o;
  }
  return v;
}

// ---- At-rest sealing (see idbGet/idbPut) ----------------------------------
// A sealed record is exactly { __enc: "<{iv,ct} json>" }; wrapBytes/unwrapBytes
// do AES-GCM under the account wrap key. Values are first run through
// encodeVal/decodeVal so ArrayBuffers survive the JSON round-trip.
const ENC_MARK = '__enc';
async function encField(val: any): Promise<any> {
  // v70 H5: a locked session (no wrap key in memory — every cold start until the
  // app is unlocked) REFUSES the write. It used to fall back to plaintext, which
  // put ratchet state and identity keys on disk in the clear.
  if (!hasWrapKey()) await ensureWrapKey();
  if (!hasWrapKey()) throw new Error('Session locked: unlock Arbor first.');
  const json = JSON.stringify(encodeVal(val));
  const sealed = await wrapBytes(new TextEncoder().encode(json).buffer as ArrayBuffer);
  return { [ENC_MARK]: sealed };
}
async function decField(raw: any): Promise<any> {
  if (raw && typeof raw === 'object' && typeof raw[ENC_MARK] === 'string') {
    const buf = await unwrapBytes(raw[ENC_MARK]);
    return decodeVal(JSON.parse(new TextDecoder().decode(buf)));
  }
  return raw; // legacy plaintext (or undefined)
}

const eqAB = (a?: ArrayBuffer, b?: ArrayBuffer) => {
  if (!a || !b || a.byteLength !== b.byteLength) return false;
  const x = new Uint8Array(a), y = new Uint8Array(b);
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
};

/** V8 H-3: after a password-KDF upgrade, re-seal every Signal record (all node
 *  namespaces) still under the legacy wrap key. Idempotent. */
export async function resealAllSignal(): Promise<number> {
  let n = 0;
  for (const k of await idbAllKeys()) {
    const raw = await idbGetRaw<any>(k);
    if (!raw || typeof raw !== 'object' || typeof raw[ENC_MARK] !== 'string') continue;
    if (!(await needsReseal(raw[ENC_MARK]))) continue;
    try { await idbPutRaw(k, await encField(await decField(raw))); n++; } catch { /* leave it */ }
  }
  return n;
}

/** True when a sealed Signal record here doesn't open with the current wrap key —
 *  it was written under an earlier one (e.g. by an older app version that used
 *  the pre-upgrade KDF while the account was temporarily back on it). */
export async function hasRecordsUnderOtherKey(): Promise<boolean> {
  for (const k of await idbAllKeys()) {
    const raw = await idbGetRaw<any>(k);
    if (raw && typeof raw === 'object' && typeof raw[ENC_MARK] === 'string' && await needsReseal(raw[ENC_MARK])) return true;
  }
  return false;
}

export class ArborSignalStore implements StorageType {
  constructor(private ns: string) {}
  private k(suffix: string) { return `${this.ns}:${suffix}`; }

  async getIdentityKeyPair(): Promise<KeyPairType | undefined> { return idbGet<KeyPairType>(this.k('idkeypair')); }
  async getLocalRegistrationId(): Promise<number | undefined> { return idbGet<number>(this.k('regid')); }

  async setLocalIdentity(kp: KeyPairType, regId: number): Promise<void> {
    await idbPut(this.k('idkeypair'), kp);
    await idbPut(this.k('regid'), regId);
  }
  async hasLocalIdentity(): Promise<boolean> { return !!(await this.getIdentityKeyPair()); }

  async isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, _dir: Direction): Promise<boolean> {
    const id = identifier.split('.')[0];
    const existing = await idbGet<ArrayBuffer>(this.k('remoteid:' + id));
    if (!existing) return true;                          // TOFU: first sight is trusted (and saved)
    if (eqAB(existing, identityKey)) return true;
    await idbPut(this.k('changed:' + id), true);          // changed -> FLAG it...
    return true;                                          // ...but do NOT block (Signal delivers + warns)
  }
  // v71: the "changed" flag is STICKY — only acceptIdentity (the user compared the
  // safety number) clears it. v70 cleared it whenever a message matched the stored
  // key; since saveIdentity stores the NEW key, the second message under a changed
  // key already "matched", so only the first message was ever flagged and the rest
  // (edits and deletes included) were treated as coming from a trusted key.
  async saveIdentity(encodedAddress: string, publicKey: ArrayBuffer): Promise<boolean> {
    const id = encodedAddress.split('.')[0];
    const prev = await idbGet<ArrayBuffer>(this.k('remoteid:' + id));
    await idbPut(this.k('remoteid:' + id), publicKey);
    if (prev && !eqAB(prev, publicKey)) { await idbPut(this.k('changed:' + id), true); return true; }
    return false;
  }
  async loadRemoteIdentity(identifier: string): Promise<ArrayBuffer | undefined> { return idbGet<ArrayBuffer>(this.k('remoteid:' + identifier)); }
  async identityChanged(identifier: string): Promise<boolean> { return !!(await idbGet<boolean>(this.k('changed:' + identifier))); }
  /**
   * v71 M2: the user compared the safety number for `expected` (the key this
   * store holds right now) and accepts it. The key STAYS PINNED — only the
   * "changed" flag clears. (v70 deleted the pin, which re-armed trust-on-first-use:
   * whatever key arrived next was then accepted silently.) If the stored key is no
   * longer the one that was shown, nothing is accepted.
   */
  async acceptIdentity(identifier: string, expected: ArrayBuffer): Promise<boolean> {
    const cur = await idbGet<ArrayBuffer>(this.k('remoteid:' + identifier));
    if (!cur || !eqAB(cur, expected)) return false;
    await idbDel(this.k('changed:' + identifier));
    return true;
  }

  async loadPreKey(keyId: string | number): Promise<KeyPairType | undefined> { return idbGet<KeyPairType>(this.k('prekey:' + keyId)); }
  async storePreKey(keyId: string | number, keyPair: KeyPairType): Promise<void> { await idbPut(this.k('prekey:' + keyId), keyPair); }
  async removePreKey(keyId: string | number): Promise<void> { await idbDel(this.k('prekey:' + keyId)); }

  async loadSignedPreKey(keyId: string | number): Promise<KeyPairType | undefined> { return idbGet<KeyPairType>(this.k('spk:' + keyId)); }
  async storeSignedPreKey(keyId: string | number, keyPair: KeyPairType): Promise<void> { await idbPut(this.k('spk:' + keyId), keyPair); }
  async removeSignedPreKey(keyId: string | number): Promise<void> { await idbDel(this.k('spk:' + keyId)); }

  async loadSession(encodedAddress: string): Promise<string | undefined> { return idbGet<string>(this.k('session:' + encodedAddress)); }
  async storeSession(encodedAddress: string, record: string): Promise<void> { await idbPut(this.k('session:' + encodedAddress), record); }
  async hasSession(encodedAddress: string): Promise<boolean> { return !!(await idbGet<string>(this.k('session:' + encodedAddress))); }

  // Monotonic prekey-id allocation so generated prekeys never collide.
  async nextPreKeyId(count: number): Promise<number> {
    const cur = (await idbGet<number>(this.k('pkcounter'))) || 1;
    await idbPut(this.k('pkcounter'), cur + count);
    return cur;
  }

  // ---- Namespace snapshot (for the client-encrypted server backup) ----------
  /** Serialize every record in this node's namespace to a JSON-safe object. */
  async exportNamespace(): Promise<Record<string, any>> {
    const prefix = this.ns + ':';
    const keys = (await idbAllKeys()).filter(k => k.startsWith(prefix));
    const out: Record<string, any> = {};
    for (const k of keys) out[k.slice(prefix.length)] = encodeVal(await idbGet(k));
    return out;
  }
  /** Restore a namespace snapshot. Only fills keys, never deletes existing ones. */
  async importNamespace(data: Record<string, any>): Promise<void> {
    for (const suffix of Object.keys(data)) await idbPut(this.k(suffix), decodeVal(data[suffix]));
  }

  /** Re-seal any legacy plaintext records in this namespace at rest. Idempotent
   *  (already-sealed records are skipped) and a no-op while the session is locked,
   *  so it is safe to fire-and-forget whenever the store is first used. */
  async migrateAtRest(): Promise<void> {
    if (!hasWrapKey()) { await ensureWrapKey(); if (!hasWrapKey()) return; }
    const prefix = this.ns + ':';
    const keys = (await idbAllKeys()).filter(k => k.startsWith(prefix));
    for (const k of keys) {
      const raw = await idbGetRaw<any>(k);
      if (raw === undefined) continue;
      if (raw && typeof raw === 'object' && typeof (raw as any)[ENC_MARK] === 'string') continue;
      await idbPutRaw(k, await encField(raw));
    }
  }
  async isEmpty(): Promise<boolean> {
    const prefix = this.ns + ':';
    return !(await idbAllKeys()).some(k => k.startsWith(prefix));
  }
}
