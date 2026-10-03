/**
 * XEdDSA signatures and X25519 agreement over Signal identity keys (V8 phase 2).
 *
 * Uses the same curve25519 build libsignal uses, so a node's existing Signal
 * identity key — the key behind its safety number — can sign membership
 * certificates and seal network-key boxes. Public keys may be given in Signal's
 * 33-byte form (0x05 prefix) or raw 32 bytes.
 *
 * NOTE: the underlying `verify()` returns TRUE FOR AN INVALID signature; only the
 * explicit `signatureIsValid()` is used here.
 */
import { Curve25519Wrapper } from '@privacyresearch/curve25519-typescript';

let curveP: Promise<Curve25519Wrapper> | null = null;
const curve = () => (curveP ||= Curve25519Wrapper.create());

const ab = (u: Uint8Array): ArrayBuffer => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

/** Signal (33-byte, 0x05-prefixed) or raw 32-byte public key → raw 32 bytes. */
export function rawPub(pub: Uint8Array): Uint8Array {
  if (pub.length === 33 && pub[0] === 5) return pub.slice(1);
  if (pub.length === 32) return pub;
  throw new Error('Invalid public key');
}

/** Clamp a 32-byte seed into a key pair; pub is returned in Signal's 33-byte form. */
export async function keyPairFromSeed(seed: Uint8Array): Promise<{ pub: Uint8Array; priv: Uint8Array }> {
  if (seed.length !== 32) throw new Error('Invalid seed');
  const kp = (await curve()).keyPair(ab(seed.slice()));
  const pub = new Uint8Array(33); pub[0] = 5; pub.set(new Uint8Array(kp.pubKey), 1);
  return { pub, priv: new Uint8Array(kp.privKey) };
}

export async function sign(priv: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  if (priv.length !== 32) throw new Error('Invalid private key');
  return new Uint8Array((await curve()).sign(ab(priv), ab(msg)));
}

export async function verify(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean> {
  try {
    if (sig.length !== 64) return false;
    return (await curve()).signatureIsValid(ab(rawPub(pub)), ab(msg), ab(sig)) === true;
  } catch { return false; }
}

export async function agree(theirPub: Uint8Array, myPriv: Uint8Array): Promise<Uint8Array> {
  if (myPriv.length !== 32) throw new Error('Invalid private key');
  return new Uint8Array((await curve()).sharedSecret(ab(rawPub(theirPub)), ab(myPriv)));
}
