/**
 * Local tree-snapshot store (per node), IndexedDB-backed.
 *
 * Entering a network used to blank the screen for a full /tree-context round trip
 * (~0.5-0.7s over the tunnel) before ANY chat could render, because the messages
 * live on-device (see messageStore) but the tree/roster/group metadata did not.
 * This store caches the last good tree snapshot (users, invites, cross-links) for a
 * node so the UI can paint the chat INSTANTLY from local state on entry, then
 * reconcile in the background from the network — stale-while-revalidate, exactly the
 * pattern messengers use.
 *
 * AT REST the snapshot is ENCRYPTED, not plaintext: the whole blob is sealed with
 * AES-GCM under the account's password-derived session wrap key — the SAME
 * non-extractable key that protects private keys and the message store. A copy of
 * the IndexedDB files off the device yields only ciphertext. Nothing here is content
 * the server does not already hold (it manages the tree), and panic-wipe clears it.
 */

import { wrapBytes, unwrapBytes, needsReseal } from './keyStore';

const DB_NAME = 'arbor-snapshots-v1';
const STORE = 'snap';

export interface TreeSnapshot {
  users: any[];
  invites: any[];
  crossLinks?: Record<string, { name: string; archived?: boolean }>;
  savedAt: number;
}

type SealedRow = { e: string };

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => { const db = req.result; if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE); };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

const _enc = new TextEncoder();
const _dec = new TextDecoder();

/** Seal + persist the latest tree snapshot for a node. Best-effort. */
export async function save(nodeId: string, snap: Omit<TreeSnapshot, 'savedAt'>): Promise<void> {
  const body: TreeSnapshot = { ...snap, savedAt: Date.now() };
  const e = await wrapBytes(_enc.encode(JSON.stringify(body)).buffer as ArrayBuffer);
  const row: SealedRow = { e };
  const db = await openDB();
  return new Promise((res, rej) => {
    const r = db.transaction(STORE, 'readwrite').objectStore(STORE).put(row, nodeId);
    r.onsuccess = () => res(); r.onerror = () => rej(r.error);
  });
}

/** Load + unseal the cached snapshot for a node, or null if none / not unlockable. */
export async function load(nodeId: string): Promise<TreeSnapshot | null> {
  const db = await openDB();
  const row: any = await new Promise((res, rej) => {
    const r = db.transaction(STORE, 'readonly').objectStore(STORE).get(nodeId);
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
  if (!row || typeof row.e !== 'string') return null;
  try {
    const buf = await unwrapBytes(row.e);
    return JSON.parse(_dec.decode(buf)) as TreeSnapshot;
  } catch { return null; } // wrap key not loaded, or corrupt — caller falls back to network
}

/** V8 H-3: re-seal every snapshot still under the legacy wrap key. */
export async function resealAll(): Promise<number> {
  const db = await openDB();
  const rows: { k: IDBValidKey; v: any }[] = await new Promise((res, rej) => {
    const out: { k: IDBValidKey; v: any }[] = [];
    const cur = db.transaction(STORE, 'readonly').objectStore(STORE).openCursor();
    cur.onsuccess = () => { const c = cur.result; if (c) { out.push({ k: c.key, v: c.value }); c.continue(); } else res(out); };
    cur.onerror = () => rej(cur.error);
  });
  let n = 0;
  for (const { k, v } of rows) {
    if (!v || typeof v.e !== 'string' || !(await needsReseal(v.e))) continue;
    try {
      const e = await wrapBytes(await unwrapBytes(v.e));
      await new Promise<void>((res, rej) => { const r = db.transaction(STORE, 'readwrite').objectStore(STORE).put({ e }, k); r.onsuccess = () => res(); r.onerror = () => rej(r.error); });
      n++;
    } catch { /* leave it */ }
  }
  return n;
}

/** Remove a node's cached snapshot (panic wipe). */
export async function remove(nodeId: string): Promise<void> {
  const db = await openDB();
  return new Promise((res, rej) => {
    const r = db.transaction(STORE, 'readwrite').objectStore(STORE).delete(nodeId);
    r.onsuccess = () => res(); r.onerror = () => rej(r.error);
  });
}
