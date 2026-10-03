// Scheduled messages — LOCAL bookkeeping for the server-side release system.
// The sealed envelope was handed to the server at schedule time (ciphertext
// only; delivery happens on time even with this device off). What lives here is
// the sender's OWN plaintext copy + routing, so that (a) the pending banner can
// show what's queued, and (b) once the server has fired it, this device writes
// the message into its local chat history. Cleared by panic wipe.

export interface ScheduledMessage {
  id: string;                   // local id
  serverId?: string;            // server-side schedule entry id
  mid?: string;                 // envelope message id (the chat message's id once fired)
  nodeId: string;               // the sending node (identity) this belongs to
  fireAt: number;               // epoch ms
  createdAt: number;
  text: string;
  // Routing captured at schedule time so the own-copy lands in the right chat.
  tab: 'ANCESTORS' | 'DESCENDANTS' | 'BROADCAST';
  targetUserId?: string;        // DM / hub / opened contact
  peerName?: string;            // for display in the pending list
}

// V8 M-12: the sender's plaintext copies live in the SEALED local store (AES-GCM
// under the account wrap key), not plaintext localStorage. Same key name as before
// so sealedLocal.init() imports (and deletes) any legacy plaintext list.
import * as sealedLocal from './sealedLocal';
const KEY = 'arbor_scheduled_v1';

function readAll(): ScheduledMessage[] {
  try { return JSON.parse(sealedLocal.get(KEY) || '[]'); } catch { return []; }
}
function writeAll(list: ScheduledMessage[]) {
  if (list.length) sealedLocal.set(KEY, JSON.stringify(list)); else sealedLocal.remove(KEY);
}

export function listScheduled(nodeId: string): ScheduledMessage[] {
  return readAll().filter(s => s.nodeId === nodeId).sort((a, b) => a.fireAt - b.fireAt);
}

export function addScheduled(msg: Omit<ScheduledMessage, 'id' | 'createdAt'>): ScheduledMessage {
  const rnd = Array.from(crypto.getRandomValues(new Uint8Array(6)), b => b.toString(16).padStart(2, '0')).join('');
  const full: ScheduledMessage = { ...msg, id: `sch_${Date.now()}_${rnd}`, createdAt: Date.now() };
  const all = readAll(); all.push(full); writeAll(all);
  return full;
}

export function removeScheduled(id: string) {
  writeAll(readAll().filter(s => s.id !== id));
}

/** All entries for this node whose time has arrived. */
export function dueScheduled(nodeId: string, now = Date.now()): ScheduledMessage[] {
  return readAll().filter(s => s.nodeId === nodeId && s.fireAt <= now);
}

/** Wipe everything (panic wipe / account logout). */
export function clearAll() {
  sealedLocal.remove(KEY);
  try { localStorage.removeItem(KEY); } catch { /* ignore legacy */ }
}
