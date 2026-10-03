/**
 * Local decrypted-message store (per node), IndexedDB-backed.
 *
 * With a Double Ratchet, a message key is consumed on first decryption and cannot
 * be re-derived (that is what forward secrecy means). So each received message is
 * decrypted exactly ONCE and the plaintext is persisted here; the sender's own
 * messages are stored here too (the sender is not a ciphertext recipient). The chat
 * view is rendered from this local store, exactly as a real Signal client does.
 *
 * AT REST the message body is ENCRYPTED, not plaintext. Every record's content
 * (text, media data URLs, attachment keys, quoted text, call metadata, routing
 * fields) is sealed with AES-GCM under the account's password-derived session wrap
 * key — the SAME non-extractable key that already protects private keys (see
 * keyStore). This means a copy of the browser profile / IndexedDB files off the
 * device (a stolen laptop, a synced backup, forensic disk access) yields only
 * ciphertext, not readable chats. It is NOT a defence against an attacker who can
 * already drive the unlocked app in this browser origin — that is what the app
 * lock gate is for, exactly as in Signal/WhatsApp.
 *
 * Only two fields stay in the clear on each row: `mid` (the IndexedDB key, needed
 * for lookup/range scans) and `readAt` (a receipt timestamp, kept outside the
 * sealed blob so marking-read never needs to decrypt). Neither is message content
 * and both are already known to the server.
 */

import { Message } from '../types';
import { wrapBytes, unwrapBytes, needsReseal } from './keyStore';

const DB_NAME = 'arbor-messages-v1';
const STORE = 'msgs';

export type StoredMessage = Pick<Message,
  'senderId' | 'timestamp' | 'type' | 'targetCircle' | 'peerId' | 'targetGroup' | 'expiresAt' |
  'text' | 'imageUrl' | 'audioUrl' | 'videoUrl' | 'attachments' | 'verified' | 'keyChanged' |
  'replyTo' | 'ackRequested' | 'senderLevel' | 'callLog' | 'edited' | 'editedAt' | 'sentTo' | 'withheld' | 'keyChangedWithheld' | 'verifiedIfKeyOk' | 'editRefused'> & { readAt?: number; hidden?: boolean };

// Physical row shape. `e` present => sealed (v1). A row WITHOUT `e` is a legacy
// plaintext record from before at-rest encryption; it is read transparently and
// re-sealed opportunistically the next time its node's chat is listed.
type SealedRow = { mid: string; readAt?: number; e: string };

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => { const db = req.result; if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE); };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
const key = (nodeId: string, mid: string) => `${nodeId}|${mid}`;

const _enc = new TextEncoder();
const _dec = new TextDecoder();

// Seal everything EXCEPT readAt (which rides the row in the clear so markRead is
// cheap and never needs the wrap key). Returns the sealed blob string.
async function seal(rec: StoredMessage): Promise<string> {
  const { readAt: _drop, ...body } = rec;
  return wrapBytes(_enc.encode(JSON.stringify(body)).buffer as ArrayBuffer);
}
// Reconstruct a StoredMessage from a physical row (sealed or legacy plaintext).
// Returns null if a sealed row cannot be opened (e.g. wrap key not loaded yet).
async function fromRow(row: any): Promise<StoredMessage | null> {
  if (row && typeof row.e === 'string') {
    try {
      const buf = await unwrapBytes(row.e);
      const body = JSON.parse(_dec.decode(buf)) as StoredMessage;
      if (row.readAt != null) body.readAt = row.readAt;
      return body;
    } catch { return null; }
  }
  // Legacy plaintext row: shape is { mid, ...StoredMessage }.
  if (!row) return null;
  const { mid: _m, ...rest } = row;
  return rest as StoredMessage;
}

export async function has(nodeId: string, mid: string): Promise<boolean> {
  const db = await openDB();
  return new Promise((res, rej) => {
    const r = db.transaction(STORE, 'readonly').objectStore(STORE).getKey(key(nodeId, mid));
    r.onsuccess = () => res(r.result !== undefined); r.onerror = () => rej(r.error);
  });
}
export async function get(nodeId: string, mid: string): Promise<StoredMessage | null> {
  const db = await openDB();
  const row: any = await new Promise((res, rej) => {
    const r = db.transaction(STORE, 'readonly').objectStore(STORE).get(key(nodeId, mid));
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
  return row ? fromRow(row) : null;
}
export async function put(nodeId: string, mid: string, rec: StoredMessage): Promise<void> {
  const e = await seal(rec);
  const row: SealedRow = { mid, e, ...(rec.readAt != null ? { readAt: rec.readAt } : {}) };
  const db = await openDB();
  return new Promise((res, rej) => {
    const r = db.transaction(STORE, 'readwrite').objectStore(STORE).put(row, key(nodeId, mid));
    r.onsuccess = () => res(); r.onerror = () => rej(r.error);
  });
}
export async function listForNode(nodeId: string): Promise<(StoredMessage & { mid: string })[]> {
  const db = await openDB();
  const rows: any[] = await new Promise((res, rej) => {
    const out: any[] = [];
    const range = IDBKeyRange.bound(`${nodeId}|`, `${nodeId}|￿`);
    const cur = db.transaction(STORE, 'readonly').objectStore(STORE).openCursor(range);
    cur.onsuccess = () => { const c = cur.result; if (c) { out.push(c.value); c.continue(); } else res(out); };
    cur.onerror = () => rej(cur.error);
  });
  const out: (StoredMessage & { mid: string })[] = [];
  const legacyMids: string[] = [];
  for (const row of rows) {
    const rec = await fromRow(row);
    if (!rec) continue; // undecryptable (locked) — skip rather than crash
    const mid = row.mid;
    out.push({ ...rec, mid });
    if (!row.e && mid) legacyMids.push(mid); // plaintext leftover → migrate below
  }
  // Opportunistically re-seal any legacy plaintext rows now that we hold the wrap
  // key, so the store converges to fully-encrypted at rest. Best-effort.
  for (const mid of legacyMids) {
    const rec = out.find(r => r.mid === mid);
    if (rec) { const { mid: _m, ...body } = rec; put(nodeId, mid, body as StoredMessage).catch(() => {}); }
  }
  return out;
}
/** Clear the key-changed flag on a sender's stored messages (after re-trust). */
export async function clearKeyChangedFrom(nodeId: string, senderId: string): Promise<number> {
  const rows = await listForNode(nodeId);
  let n = 0;
  for (const r of rows) {
    if (r.senderId === senderId && r.keyChanged) {
      const { mid, ...rec } = r;
      // v71: re-trusting the key restores `verified` only where every OTHER check
      // passed at ingest (v70 set it true for every message from that sender).
      await put(nodeId, mid, { ...rec, keyChanged: false, verified: !!rec.verifiedIfKeyOk } as StoredMessage);
      n++;
    }
  }
  return n;
}
/** Mark messages as read (a receipt arrived from a recipient). Fill-only.
 *  readAt lives in the clear on the row, so this never needs the wrap key. */
export async function markRead(nodeId: string, mids: string[]): Promise<number> {
  const db = await openDB();
  const now = Date.now();
  let n = 0;
  await Promise.all(mids.map(mid => new Promise<void>((res) => {
    const store = db.transaction(STORE, 'readwrite').objectStore(STORE);
    const g = store.get(key(nodeId, mid));
    g.onsuccess = () => {
      const rec = g.result;
      if (!rec || rec.readAt) return res();
      rec.readAt = now;
      const p = store.put(rec, key(nodeId, mid));
      p.onsuccess = () => { n++; res(); }; p.onerror = () => res();
    };
    g.onerror = () => res();
  })));
  return n;
}

// ---- v71 H1: delivery cursor ------------------------------------------------
// The highest server sequence number this device has fully processed for a node.
// Kept in THIS database (key `node#cursor`, outside every node's `node|…` message
// range) so it can never outlive the messages: if the browser evicts the store,
// the cursor goes with it and the device re-syncs from the start.
const cursorKey = (nodeId: string) => `${nodeId}#cursor`;
export async function getCursor(nodeId: string): Promise<number | null> {
  const db = await openDB();
  return new Promise((res) => {
    const g = db.transaction(STORE, 'readonly').objectStore(STORE).get(cursorKey(nodeId));
    g.onsuccess = () => { const v = g.result; res(v && Number.isSafeInteger(v.c) && v.c >= 0 ? v.c : null); };
    g.onerror = () => res(null);
  });
}
export async function setCursor(nodeId: string, seq: number): Promise<void> {
  if (!Number.isSafeInteger(seq) || seq < 0) return;
  const db = await openDB();
  return new Promise((res, rej) => {
    const r = db.transaction(STORE, 'readwrite').objectStore(STORE).put({ c: seq }, cursorKey(nodeId));
    r.onsuccess = () => res(); r.onerror = () => rej(r.error);
  });
}

export async function remove(nodeId: string, mid: string): Promise<void> {
  const db = await openDB();
  return new Promise((res, rej) => {
    const r = db.transaction(STORE, 'readwrite').objectStore(STORE).delete(key(nodeId, mid));
    r.onsuccess = () => res(); r.onerror = () => rej(r.error);
  });
}

/** V8 H-3: after a password-KDF upgrade, re-seal every row (all nodes) that is
 *  still under the legacy wrap key. Idempotent; returns the number re-sealed. */
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
      await new Promise<void>((res, rej) => { const r = db.transaction(STORE, 'readwrite').objectStore(STORE).put({ ...v, e }, k); r.onsuccess = () => res(); r.onerror = () => rej(r.error); });
      n++;
    } catch { /* unreadable with either key — leave it */ }
  }
  return n;
}

// ---- Backup snapshot -------------------------------------------------------
// Media data URLs are EXCLUDED from backups (they would blow past the size cap
// almost immediately); text history and message metadata are preserved. A message
// whose media is dropped restores with a placeholder so its existence is visible.
export async function exportForBackup(nodeId: string): Promise<any[]> {
  const rows = await listForNode(nodeId);
  return rows.map(r => {
    // Inline (legacy) media is heavy — omit from backups with a placeholder.
    // Attachment POINTERS are tiny and kept (the encrypted blobs live server-side).
    const hadInline = !!(r.imageUrl || r.audioUrl || r.videoUrl);
    const { imageUrl, audioUrl, videoUrl, ...rest } = r as any;
    return hadInline ? { ...rest, mediaOmitted: true } : rest;
  });
}
export async function importFromBackup(nodeId: string, rows: any[]): Promise<number> {
  let restored = 0;
  for (const r of rows) {
    if (!r || typeof r.mid !== 'string') continue;
    if (await has(nodeId, r.mid)) continue;
    const { mid, mediaOmitted, ...rec } = r;
    if (mediaOmitted && !rec.text) rec.text = '📎 [Media not restored — only text history is backed up]';
    await put(nodeId, mid, rec as StoredMessage);
    restored++;
  }
  return restored;
}
