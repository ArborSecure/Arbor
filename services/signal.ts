/**
 * High-level Signal protocol wrapper for Arbor (X3DH + Double Ratchet).
 *
 * Message confidentiality model in V5:
 *   - Content is sealed ONCE per message with a random Content Encryption Key (CEK).
 *   - The CEK is delivered to each authorised recipient through that recipient's
 *     pairwise Double Ratchet session (established via X3DH from their published
 *     prekey bundle on first contact). This gives Signal-grade forward secrecy and
 *     post-compromise security on the key-delivery channel, while keeping a single
 *     content ciphertext for efficient multi-recipient (tree / broadcast) fan-out.
 *
 * Sessions and identities are device-local (forward secrecy precludes sharing
 * ratchet state across devices); the sender keeps a local plaintext copy of what it
 * sent (see api.ts outbox), exactly as a real Signal client does.
 */

import {
  KeyHelper, SignalProtocolAddress, SessionBuilder, SessionCipher, FingerprintGenerator,
  type DeviceType, type KeyPairType,
} from '@privacyresearch/libsignal-protocol-typescript';
import { ArborSignalStore } from './signalStore';

const DEVICE_ID = 1;
const ONE_TIME_COUNT = 30;

const stores = new Map<string, ArborSignalStore>();
function store(localNodeId: string): ArborSignalStore {
  let s = stores.get(localNodeId);
  if (!s) {
    s = new ArborSignalStore(localNodeId);
    stores.set(localNodeId, s);
    // One-time-per-session: seal any pre-existing plaintext ratchet/identity
    // state at rest. Fire-and-forget — reads already handle unsealed records.
    s.migrateAtRest().catch(() => {});
  }
  return s;
}

// ---- base64 helpers (chunked; safe for multi-MB and binary strings) ----
export const ab2b64 = (buf: ArrayBuffer): string => {
  const bytes = new Uint8Array(buf); let out = ''; const C = 0x8000;
  for (let i = 0; i < bytes.length; i += C) out += String.fromCharCode.apply(null, bytes.subarray(i, i + C) as unknown as number[]);
  return btoa(out);
};
export const b642ab = (s: string): ArrayBuffer => {
  const bin = atob(s); const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u.buffer;
};

export interface PublishBundle {
  identityKey: string;             // b64
  registrationId: number;
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  oneTimePreKeys: { keyId: number; publicKey: string }[];
}
export interface FetchedBundle {
  identityKey: string;
  registrationId: number;
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  preKey?: { keyId: number; publicKey: string };
}
export interface KeySlot { id: string; kt: number; kb: string } // kt=signal msg type, kb=b64 body

const addr = (id: string) => new SignalProtocolAddress(id, DEVICE_ID);

/** Ensure this local node has a Signal identity + registration id. */
export async function ensureIdentity(localNodeId: string): Promise<void> {
  const s = store(localNodeId);
  if (await s.hasLocalIdentity()) return;
  const idKp = await KeyHelper.generateIdentityKeyPair();
  const regId = KeyHelper.generateRegistrationId();
  await s.setLocalIdentity(idKp, regId);
}

export async function hasLocalIdentity(localNodeId: string): Promise<boolean> {
  return store(localNodeId).hasLocalIdentity();
}

/** Export this node's Signal identity (generating it if absent) so it can be
 *  wrapped and persisted server-side for stable cross-device/login identity. */
export async function exportIdentityRaw(localNodeId: string): Promise<{ pub: ArrayBuffer; priv: ArrayBuffer; regId: number }> {
  await ensureIdentity(localNodeId);
  const s = store(localNodeId);
  const kp = (await s.getIdentityKeyPair())!;
  const regId = (await s.getLocalRegistrationId())!;
  return { pub: kp.pubKey, priv: kp.privKey, regId };
}

/** Restore a previously-persisted Signal identity into this device's local store. */
export async function importIdentity(localNodeId: string, pub: ArrayBuffer, priv: ArrayBuffer, regId: number): Promise<void> {
  await store(localNodeId).setLocalIdentity({ pubKey: pub, privKey: priv }, regId);
}

// ---- Whole-state snapshot (identity + prekeys + sessions + remote identities),
// used for the client-encrypted server backup so an evicted/new device can resume.
export async function exportState(localNodeId: string): Promise<Record<string, any>> {
  return store(localNodeId).exportNamespace();
}
export async function importState(localNodeId: string, data: Record<string, any>): Promise<void> {
  await store(localNodeId).importNamespace(data);
}
export async function stateIsEmpty(localNodeId: string): Promise<boolean> {
  return store(localNodeId).isEmpty();
}

/** Generate a fresh signed prekey + a batch of one-time prekeys and return the
 *  PUBLIC bundle to publish to the server. */
export async function buildPublishBundle(localNodeId: string): Promise<PublishBundle> {
  await ensureIdentity(localNodeId);
  const s = store(localNodeId);
  const idKp = (await s.getIdentityKeyPair())!;
  const regId = (await s.getLocalRegistrationId())!;

  const spkId = await s.nextPreKeyId(1);
  const spk = await KeyHelper.generateSignedPreKey(idKp, spkId);
  await s.storeSignedPreKey(spkId, spk.keyPair);

  const baseId = await s.nextPreKeyId(ONE_TIME_COUNT);
  const oneTimePreKeys: { keyId: number; publicKey: string }[] = [];
  for (let i = 0; i < ONE_TIME_COUNT; i++) {
    const id = baseId + i;
    const pk = await KeyHelper.generatePreKey(id);
    await s.storePreKey(id, pk.keyPair);
    oneTimePreKeys.push({ keyId: id, publicKey: ab2b64(pk.keyPair.pubKey) });
  }
  return {
    identityKey: ab2b64(idKp.pubKey),
    registrationId: regId,
    signedPreKey: { keyId: spkId, publicKey: ab2b64(spk.keyPair.pubKey), signature: ab2b64(spk.signature) },
    oneTimePreKeys,
  };
}

export async function hasSession(localNodeId: string, remoteId: string): Promise<boolean> {
  return store(localNodeId).hasSession(addr(remoteId).toString());
}

/** Establish a session to a remote node from its fetched prekey bundle (X3DH). */
export async function establishSession(localNodeId: string, remoteId: string, b: FetchedBundle): Promise<void> {
  const device: DeviceType = {
    identityKey: b642ab(b.identityKey),
    registrationId: b.registrationId,
    signedPreKey: { keyId: b.signedPreKey.keyId, publicKey: b642ab(b.signedPreKey.publicKey), signature: b642ab(b.signedPreKey.signature) },
    preKey: b.preKey ? { keyId: b.preKey.keyId, publicKey: b642ab(b.preKey.publicKey) } : undefined,
  };
  await new SessionBuilder(store(localNodeId), addr(remoteId)).processPreKey(device);
}

/** Ratchet-encrypt the CEK to a recipient (requires an existing session). */
export async function encryptKeyTo(localNodeId: string, remoteId: string, cek: ArrayBuffer): Promise<KeySlot> {
  const cipher = new SessionCipher(store(localNodeId), addr(remoteId));
  const msg = await cipher.encrypt(cek);
  return { id: remoteId, kt: msg.type, kb: btoa(msg.body || '') };
}

/** Ratchet-decrypt the CEK from a sender's slot. Throws if not decryptable. */
export async function decryptKeyFrom(localNodeId: string, senderId: string, slot: { kt: number; kb: string }): Promise<ArrayBuffer> {
  const cipher = new SessionCipher(store(localNodeId), addr(senderId));
  const body = atob(slot.kb);
  return slot.kt === 3
    ? cipher.decryptPreKeyWhisperMessage(body, 'binary')
    : cipher.decryptWhisperMessage(body, 'binary');
}

/** The identity key (base64, 33-byte Signal form) this device's session with a
 *  remote node is bound to, or null when there is no session yet. V8 phase 2
 *  compares it with the key the remote's membership certificate names. */
export async function remoteIdentity(localNodeId: string, remoteId: string): Promise<string | null> {
  const k = await store(localNodeId).loadRemoteIdentity(remoteId);
  return k ? ab2b64(k) : null;
}

export async function identityChanged(localNodeId: string, remoteId: string): Promise<boolean> {
  return store(localNodeId).identityChanged(remoteId);
}
/** v71 M2: accept the remote's CURRENT key, but only if it is still `expectedB64`
 *  (the key the user compared). The key stays pinned; only the warning clears. */
export async function acceptIdentity(localNodeId: string, remoteId: string, expectedB64: string): Promise<boolean> {
  return store(localNodeId).acceptIdentity(remoteId, b642ab(expectedB64));
}

/** Signal safety number between this local node and a remote node (if we have its identity). */
export async function safetyNumber(localNodeId: string, remoteId: string): Promise<string | null> {
  const s = store(localNodeId);
  const me = await s.getIdentityKeyPair();
  const them = await s.loadRemoteIdentity(remoteId);
  if (!me || !them) return null;
  const fp = new FingerprintGenerator(1024);
  const num = await fp.createFor(localNodeId, me.pubKey, remoteId, them);
  return num.match(/.{1,5}/g)?.join(' ') || num;
}
