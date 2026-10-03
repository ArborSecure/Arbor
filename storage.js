// ---------------------------------------------------------------------------
// SQLite storage layer (better-sqlite3).
//
// Design (deliberate, documented):
//  - MESSAGES are ~99% of all data (E2E media ciphertext rides inside message
//    envelopes). They are a true SQL table with an indexed recipients join
//    table: inserted and deleted per-row, streamed per-query, and NEVER held
//    in process RAM. This removes both failure modes of the old db.json —
//    unbounded memory and whole-file rewrites on every change.
//  - STATE BACKUPS (encrypted client snapshots, can be MBs each) get their own
//    table with row-level get/set/delete.
//  - The SMALL collections (accounts, users, invites, sessions, subscriptions,
//    prekeys, signal identities, tombstones — a few KB total) stay in RAM with
//    the exact same shapes the rest of server.js already uses, and persist as
//    a single fast transaction. Rewriting a few KB in one transaction is
//    microseconds; rewriting the entire message history was the problem.
//  - WAL mode: readers never block the writer; survives crashes cleanly.
//
// Migration: on first boot with an existing db.json, everything is imported
// and the old file is renamed db.json.migrated (kept as a safety copy).
// ---------------------------------------------------------------------------
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const DATA_DIR = process.env.ARBOR_DATA_DIR || '.';
const DB_PATH = path.join(DATA_DIR, 'arbor.db');
const LEGACY_JSON = path.join(DATA_DIR, 'db.json');

// Create the data directory if it doesn't exist yet — better-sqlite3 refuses to
// open a DB in a missing directory. Makes a fresh ARBOR_DATA_DIR (e.g.
// /var/lib/arbor on first run) work without a manual mkdir. mode 700: the DB
// holds account records, sessions, and ciphertext — keep it owner-only.
try { fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 }); }
catch (e) { console.error(`Cannot create data directory ${DATA_DIR}:`, e.message); throw e; }

export const db = new Database(DB_PATH);
/** On-disk size of the database (main file + WAL) in bytes (admin storage monitor). */
export const dbSizeBytes = () => {
  let n = 0;
  for (const f of [DB_PATH, DB_PATH + '-wal']) { try { n += fs.statSync(f).size; } catch {} }
  return n;
};
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL'); // safe with WAL; fsync on checkpoint
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS snapshots (
  name  TEXT PRIMARY KEY,          -- 'accounts' | 'users' | 'invites' | ...
  value TEXT NOT NULL              -- JSON of the whole (small) collection
);
CREATE TABLE IF NOT EXISTS messages (
  id          TEXT PRIMARY KEY,
  mid         TEXT,                -- envelope.mid (client message id, retract key)
  senderId    TEXT NOT NULL,
  timestamp   INTEGER NOT NULL,
  expiresAt   INTEGER,
  type        TEXT,
  depthLimit  INTEGER,
  targetCircle TEXT,
  envelope    TEXT NOT NULL,       -- JSON (holds the big ciphertext)
  ackRequested INTEGER DEFAULT 0   -- sender asked recipients to acknowledge
);
CREATE INDEX IF NOT EXISTS idx_messages_mid       ON messages(mid);
CREATE INDEX IF NOT EXISTS idx_messages_sender    ON messages(senderId);
CREATE INDEX IF NOT EXISTS idx_messages_expires   ON messages(expiresAt);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE TABLE IF NOT EXISTS message_recipients (
  messageId TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  publicId  TEXT NOT NULL,
  PRIMARY KEY (messageId, publicId)
);
CREATE INDEX IF NOT EXISTS idx_recipients_public ON message_recipients(publicId);
CREATE TABLE IF NOT EXISTS state_backups (
  nodeId  TEXT PRIMARY KEY,
  wrapped TEXT NOT NULL,
  ts      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attachments (
  id        TEXT PRIMARY KEY,       -- server-generated blob id
  ownerId   TEXT NOT NULL,          -- uploader's internal node id (for quota/cleanup)
  createdAt INTEGER NOT NULL,
  expiresAt INTEGER,                -- optional TTL (disappearing media)
  bytes     BLOB NOT NULL           -- OPAQUE ciphertext: encrypted client-side, never readable here
);
CREATE INDEX IF NOT EXISTS idx_attachments_owner   ON attachments(ownerId);
CREATE INDEX IF NOT EXISTS idx_attachments_expires ON attachments(expiresAt);
-- Profile photos, content-addressed (key = sha256 of the data URL). Kept OUT of
-- the users snapshot (V8 H-5): inline avatars made every debounced persist
-- re-serialize tens of MB. Nodes/accounts reference a photo by its hash, so the
-- same photo used in several places is stored once.
CREATE TABLE IF NOT EXISTS avatars (
  hash TEXT PRIMARY KEY,
  data TEXT NOT NULL
);
`);
// V8 L-9: envelope mids must be globally unique. server.js already rejects a
// duplicate before insert; the UNIQUE index makes that race-proof. Skipped (with
// a warning) if legacy duplicates exist, so an old DB still boots.
try { db.exec('CREATE UNIQUE INDEX IF NOT EXISTS uq_messages_mid ON messages(mid)'); }
catch (e) { console.warn('[storage] could not add UNIQUE(messages.mid) — duplicate legacy mids present:', e.message); }

// v72 B4: reactions, acks and retraction tombstones as tables (see storage-pg.js
// metaStore). No foreign key here: metaStore.sweep() drops rows whose message is gone.
db.exec(`
CREATE TABLE IF NOT EXISTS reactions (mid TEXT NOT NULL, emoji TEXT NOT NULL, pid TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (mid, emoji, pid));
CREATE INDEX IF NOT EXISTS idx_reactions_pid ON reactions(pid);
CREATE TABLE IF NOT EXISTS acks (mid TEXT NOT NULL, pid TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (mid, pid));
CREATE INDEX IF NOT EXISTS idx_acks_pid ON acks(pid);
CREATE TABLE IF NOT EXISTS tombstones (mid TEXT NOT NULL, pid TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (pid, mid));
CREATE INDEX IF NOT EXISTS idx_tombstones_ts ON tombstones(ts);
`);
const stmtTombPut = db.prepare(`INSERT INTO tombstones(mid, pid, ts) VALUES (?,?,?) ON CONFLICT(pid, mid) DO UPDATE SET ts = excluded.ts`);
const stmtReactDelMid = db.prepare(`DELETE FROM reactions WHERE mid = ?`);
const stmtAckDelMid = db.prepare(`DELETE FROM acks WHERE mid = ?`);
const stmtReactDelPid = db.prepare(`DELETE FROM reactions WHERE pid = ?`);
const stmtAckDelPid = db.prepare(`DELETE FROM acks WHERE pid = ?`);
const stmtTombDelPid = db.prepare(`DELETE FROM tombstones WHERE pid = ?`);

// ---- prepared statements ----------------------------------------------------
// Migration: ackRequested added for broadcast acknowledgments (no-op if present).
try { db.exec('ALTER TABLE messages ADD COLUMN ackRequested INTEGER DEFAULT 0'); } catch {}
// v71 H1: delivery cursor + stored size. `seq` is a strictly increasing server
// sequence (assigned inside the insert transaction, so commit order == seq order);
// it is copied onto each recipient row so "this recipient's messages after N" is
// one index range scan. `size` is the stored envelope length, used for per-account
// quotas and to cap each delivery page by bytes.
try { db.exec('ALTER TABLE messages ADD COLUMN seq INTEGER'); } catch {}
try { db.exec('ALTER TABLE messages ADD COLUMN size INTEGER'); } catch {}
try { db.exec('ALTER TABLE message_recipients ADD COLUMN seq INTEGER'); } catch {}
db.exec(`
UPDATE messages SET seq = rowid + (SELECT COALESCE(MAX(seq), 0) FROM messages) WHERE seq IS NULL;
UPDATE messages SET size = length(envelope) WHERE size IS NULL;
UPDATE message_recipients SET seq = (SELECT m.seq FROM messages m WHERE m.id = message_recipients.messageId) WHERE seq IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_messages_seq ON messages(seq);
CREATE INDEX IF NOT EXISTS idx_recipients_public_seq ON message_recipients(publicId, seq);
`);

const stmtSnapshotSet = db.prepare(`INSERT INTO snapshots(name, value) VALUES (?, ?)
  ON CONFLICT(name) DO UPDATE SET value = excluded.value`);
const stmtSnapshotGet = db.prepare(`SELECT value FROM snapshots WHERE name = ?`);

const stmtMsgInsert = db.prepare(`INSERT INTO messages
  (id, mid, senderId, timestamp, expiresAt, type, depthLimit, targetCircle, envelope, ackRequested, seq, size)
  VALUES (@id, @mid, @senderId, @timestamp, @expiresAt, @type, @depthLimit, @targetCircle, @envelope, @ackRequested, @seq, @size)`);
const stmtNextSeq = db.prepare(`SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM messages`);
const stmtRecipInsert = db.prepare(`INSERT OR IGNORE INTO message_recipients(messageId, publicId, seq) VALUES (?, ?, ?)`);
// Page metadata first (seq + size only, never the envelopes), newest-first or
// after a cursor; the caller cuts the page by bytes, then loads just that range.
const stmtPageMetaAfter = db.prepare(`
  SELECT r.seq AS seq, m.size AS size FROM message_recipients r
  JOIN messages m ON m.id = r.messageId
  WHERE r.publicId = ? AND r.seq > ? AND (m.expiresAt IS NULL OR m.expiresAt > ?)
  ORDER BY r.seq ASC LIMIT ?`);
const stmtPageMetaLatest = db.prepare(`
  SELECT r.seq AS seq, m.size AS size FROM message_recipients r
  JOIN messages m ON m.id = r.messageId
  WHERE r.publicId = ? AND (m.expiresAt IS NULL OR m.expiresAt > ?)
  ORDER BY r.seq DESC LIMIT ?`);
const stmtPageRange = db.prepare(`
  SELECT m.* FROM message_recipients r
  JOIN messages m ON m.id = r.messageId
  WHERE r.publicId = ? AND r.seq >= ? AND r.seq <= ? AND (m.expiresAt IS NULL OR m.expiresAt > ?)
  ORDER BY r.seq ASC`);
const stmtMsgByMid = db.prepare(`SELECT * FROM messages WHERE mid = ?`);
const stmtRecipsOf = db.prepare(`SELECT publicId FROM message_recipients WHERE messageId = ?`);
const stmtIsRecip = db.prepare(`SELECT 1 FROM message_recipients WHERE messageId = ? AND publicId = ?`);
const stmtMsgDelete = db.prepare(`DELETE FROM messages WHERE id = ?`);
const stmtMsgDeleteBySender = db.prepare(`DELETE FROM messages WHERE senderId = ?`);
const stmtMsgSweepExpired = db.prepare(`DELETE FROM messages WHERE expiresAt IS NOT NULL AND expiresAt <= ?`);
const stmtMsgSweepOld = db.prepare(`DELETE FROM messages WHERE timestamp < ?`);
const stmtRecipDeleteByPublic = db.prepare(`DELETE FROM message_recipients WHERE publicId = ?`);
const stmtMsgCount = db.prepare(`SELECT COUNT(*) AS n FROM messages`);

const stmtBackupGet = db.prepare(`SELECT wrapped, ts FROM state_backups WHERE nodeId = ?`);
// v72 M7: staged re-encryption during a password change (see storage-pg.js).
for (const c of ['pending_wrapped TEXT', 'pending_stage TEXT', 'pending_at INTEGER']) { try { db.exec(`ALTER TABLE state_backups ADD COLUMN ${c}`); } catch {} }
const stmtBackupSet = db.prepare(`INSERT INTO state_backups(nodeId, wrapped, ts) VALUES (?, ?, ?)
  ON CONFLICT(nodeId) DO UPDATE SET wrapped = excluded.wrapped, ts = excluded.ts,
    pending_wrapped = NULL, pending_stage = NULL, pending_at = NULL`);
const stmtBackupStage = db.prepare(`UPDATE state_backups SET pending_wrapped = ?, pending_stage = ?, pending_at = ? WHERE nodeId = ? AND ts = ?`);
const stmtBackupCommit = db.prepare(`UPDATE state_backups SET wrapped = pending_wrapped, pending_wrapped = NULL, pending_stage = NULL, pending_at = NULL
  WHERE nodeId = ? AND ts = ? AND pending_stage = ? AND pending_wrapped IS NOT NULL`);
const stmtBackupDel = db.prepare(`DELETE FROM state_backups WHERE nodeId = ?`);

// ---- messages API -------------------------------------------------------------
const rowToMessage = (row) => ({
  id: row.id,
  senderId: row.senderId,
  timestamp: row.timestamp,
  expiresAt: row.expiresAt ?? null,
  type: row.type,
  depthLimit: row.depthLimit ?? null,
  targetCircle: row.targetCircle ?? null,
  envelope: JSON.parse(row.envelope),
  ackRequested: !!row.ackRequested,
  seq: row.seq ?? null,
});

// Cut a page (rows in delivery order) so it holds at most maxBytes of envelopes —
// but always at least one message, so a single large message can't stall a cursor.
const cutPage = (rows, maxBytes) => {
  let bytes = 0, n = 0;
  for (const r of rows) {
    if (n > 0 && bytes + (r.size || 0) > maxBytes) break;
    bytes += r.size || 0; n++;
  }
  return n;
};

export const messagesStore = {
  insert: db.transaction((message) => {
    const envelope = JSON.stringify(message.envelope);
    const seq = stmtNextSeq.get().n;
    stmtMsgInsert.run({
      id: message.id,
      mid: message.envelope?.mid ?? null,
      senderId: message.senderId,
      timestamp: message.timestamp,
      expiresAt: message.expiresAt ?? null,
      type: message.type ?? null,
      depthLimit: message.depthLimit ?? null,
      targetCircle: message.targetCircle ?? null,
      envelope,
      ackRequested: message.ackRequested ? 1 : 0,
      seq,
      size: envelope.length,
    });
    for (const pid of new Set(message.recipients || [])) stmtRecipInsert.run(message.id, pid, seq);
    return seq;
  }),

  /**
   * v71 H1: one bounded delivery page for a recipient. With a cursor (`since`,
   * the highest seq the device has fully processed) it returns the next messages
   * in seq order; without one (an older client) it returns the NEWEST page. Each
   * page holds at most maxCount messages and maxBytes of envelopes (always at least
   * one message). Returns { messages, next, more }: `next` is the highest seq in
   * the page (the cursor to send next time), `more` says a further page exists.
   */
  page(publicId, { since = null, now = Date.now(), maxCount = 200, maxBytes = 8 * 1024 * 1024 } = {}) {
    if (since === null) {
      const meta = stmtPageMetaLatest.all(publicId, now, maxCount + 1);   // newest first
      const n = cutPage(meta.slice(0, maxCount), maxBytes);   // (meta holds one extra row: "is there more?")
      if (!n) return { messages: [], next: 0, more: false };
      const hi = meta[0].seq, lo = meta[n - 1].seq;
      const messages = stmtPageRange.all(publicId, lo, hi, now).map(rowToMessage);
      return { messages, next: hi, more: false, older: meta.length > n };
    }
    const meta = stmtPageMetaAfter.all(publicId, since, now, maxCount + 1);
    const n = cutPage(meta.slice(0, maxCount), maxBytes);   // (meta holds one extra row: "is there more?")
    if (!n) return { messages: [], next: since, more: false };
    const lo = meta[0].seq, hi = meta[n - 1].seq;
    const messages = stmtPageRange.all(publicId, lo, hi, now).map(rowToMessage);
    return { messages, next: hi, more: meta.length > n };
  },

  /** Total stored envelope bytes sent by these internal node ids (quota). */
  senderBytes(internalIds) {
    const ids = [...(internalIds || [])];
    if (!ids.length) return 0;
    return db.prepare(`SELECT COALESCE(SUM(size), 0) AS n FROM messages WHERE senderId IN (${ids.map(() => '?').join(',')})`).get(...ids).n;
  },

  /** Recipient public ids of a stored message row. */
  recipientsOf(messageId) { return stmtRecipsOf.all(messageId).map(r => r.publicId); },

  /** Look up a message by client mid (used by broadcast acknowledgments). */
  byMid(mid) { const row = stmtMsgByMid.get(mid); return row ? rowToMessage(row) : null; },
  /** Is publicId an addressed recipient of this message row id? */
  isRecipient(messageId, publicId) {
    return !!stmtIsRecip.get(messageId, publicId);
  },

  /** Sender-only retraction. Returns { removed: mid[], recipientPublicIds: Set,
   *  audienceByMid: { [mid]: publicId[] } } — the per-message audience lets
   *  tombstones be replayed only to that message's own recipients. */
  retract: db.transaction((mids, senderInternalId) => {
    const removed = [];
    const recipientPublicIds = new Set();
    const audienceByMid = {};
    for (const mid of mids) {
      const row = stmtMsgByMid.get(mid);
      if (!row || row.senderId !== senderInternalId) continue;
      const aud = stmtRecipsOf.all(row.id).map(r => r.publicId);
      for (const p of aud) recipientPublicIds.add(p);
      audienceByMid[mid] = aud;
      stmtMsgDelete.run(row.id);
      removed.push(mid);
      const ts = Date.now();
      for (const p of aud) stmtTombPut.run(mid, p, ts);          // v72: see metaStore
      stmtReactDelMid.run(mid); stmtAckDelMid.run(mid);
    }
    return { removed, recipientPublicIds, audienceByMid };
  }),

  /** Prune a departing branch: their sent messages go entirely; their address
   *  rows are removed from everything else. */
  pruneNodes: db.transaction((internalIds, publicIds) => {
    for (const id of internalIds) stmtMsgDeleteBySender.run(id);
    for (const pid of publicIds) { stmtRecipDeleteByPublic.run(pid); stmtReactDelPid.run(pid); stmtAckDelPid.run(pid); stmtTombDelPid.run(pid); }
  }),

  sweepExpired(now = Date.now()) { return stmtMsgSweepExpired.run(now).changes; },
  // v71: `keepSenderIds` (optional) are spared — Premium networks keep a longer history.
  sweepOlderThan(cutoffTs, keepSenderIds) {
    if (!keepSenderIds || !keepSenderIds.length) return stmtMsgSweepOld.run(cutoffTs).changes;
    return db.prepare(`DELETE FROM messages WHERE timestamp < ? AND senderId NOT IN (SELECT value FROM json_each(?))`).run(cutoffTs, JSON.stringify([...keepSenderIds])).changes;
  },
  count() { return stmtMsgCount.get().n; },
  totalBytes() {
    return db.prepare(`SELECT (SELECT COALESCE(SUM(size), 0) FROM messages) + (SELECT COALESCE(SUM(size), 0) FROM scheduled) AS n`).get().n;
  },
};

// ---- v72 B4: scheduled sends (same API as storage-pg.js) ----
db.exec(`
CREATE TABLE IF NOT EXISTS scheduled (id TEXT PRIMARY KEY, nodeId TEXT NOT NULL, fireAt INTEGER NOT NULL, createdAt INTEGER NOT NULL, mid TEXT NOT NULL UNIQUE, size INTEGER NOT NULL, item TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_scheduled_node ON scheduled(nodeId);
CREATE INDEX IF NOT EXISTS idx_scheduled_fire ON scheduled(fireAt);
`);
const rowToScheduled = (r) => ({ id: r.id, nodeId: r.nodeId, fireAt: r.fireAt, createdAt: r.createdAt, ...JSON.parse(r.item) });
export const scheduledStore = {
  add(e) {
    const item = JSON.stringify({ type: e.type, targetCircle: e.targetCircle, targetGroup: e.targetGroup, ackRequested: e.ackRequested, envelope: e.envelope });
    return db.prepare(`INSERT OR IGNORE INTO scheduled(id, nodeId, fireAt, createdAt, mid, size, item) VALUES (?,?,?,?,?,?,?)`)
      .run(e.id, e.nodeId, e.fireAt, e.createdAt, e.envelope.mid, e.size, item).changes > 0;
  },
  hasMid(mid) { return !!db.prepare(`SELECT 1 FROM scheduled WHERE mid = ?`).get(mid); },
  countForNode(nodeId) { return db.prepare(`SELECT COUNT(*) AS n FROM scheduled WHERE nodeId = ?`).get(nodeId).n; },
  bytesForNodes(nodeIds) {
    const ids = [...(nodeIds || [])];
    if (!ids.length) return 0;
    return db.prepare(`SELECT COALESCE(SUM(size), 0) AS n FROM scheduled WHERE nodeId IN (${ids.map(() => '?').join(',')})`).get(...ids).n;
  },
  listForNode(nodeId) { return db.prepare(`SELECT * FROM scheduled WHERE nodeId = ? ORDER BY fireAt`).all(nodeId).map(rowToScheduled); },
  cancel(id, nodeId) { return db.prepare(`DELETE FROM scheduled WHERE id = ? AND nodeId = ?`).run(id, nodeId).changes > 0; },
  due(now, limit = 500) { return db.prepare(`SELECT * FROM scheduled WHERE fireAt <= ? ORDER BY fireAt LIMIT ?`).all(now, limit).map(rowToScheduled); },
  remove(id) { db.prepare(`DELETE FROM scheduled WHERE id = ?`).run(id); },
  deleteByNodes(nodeIds) { const s = db.prepare(`DELETE FROM scheduled WHERE nodeId = ?`); for (const id of nodeIds || []) s.run(id); },
};

// ---- v72 B4: reactions, acks, retraction tombstones (same API as storage-pg.js) ----
const reactionMap = (rows) => {
  const out = {};
  for (const r of rows) ((out[r.mid] = out[r.mid] || {})[r.emoji] = out[r.mid][r.emoji] || []).push({ id: r.pid });
  return out;
};
const VISIBLE_MIDS = `SELECT m.mid FROM message_recipients r JOIN messages m ON m.id = r.messageId
    WHERE r.publicId = @pid AND (m.expiresAt IS NULL OR m.expiresAt > @now)
  UNION SELECT m.mid FROM messages m WHERE m.senderId = @iid AND (m.expiresAt IS NULL OR m.expiresAt > @now)`;
const TOMBSTONE_DAYS = 7;
export const metaStore = {
  toggleReaction: db.transaction((mid, emoji, pid) => {
    if (!db.prepare(`DELETE FROM reactions WHERE mid = ? AND emoji = ? AND pid = ?`).run(mid, emoji, pid).changes) {
      db.prepare(`INSERT OR IGNORE INTO reactions(mid, emoji, pid, at) VALUES (?,?,?,?)`).run(mid, emoji, pid, Date.now());
    }
    return reactionMap(db.prepare(`SELECT mid, emoji, pid FROM reactions WHERE mid = ? ORDER BY at, pid`).all(mid))[mid] || {};
  }),
  reactionsFor(publicId, internalId, limit = 20000) {
    const rows = db.prepare(`SELECT x.mid, x.emoji, x.pid FROM reactions x WHERE x.mid IN (${VISIBLE_MIDS}) ORDER BY x.at DESC LIMIT @limit`)
      .all({ pid: publicId, iid: internalId, now: Date.now(), limit });
    return reactionMap(rows.reverse());
  },
  addAck(mid, pid) {
    const added = db.prepare(`INSERT OR IGNORE INTO acks(mid, pid, ts) VALUES (?,?,?)`).run(mid, pid, Date.now()).changes > 0;
    return { added, count: db.prepare(`SELECT COUNT(*) AS n FROM acks WHERE mid = ?`).get(mid).n };
  },
  acksForSender(internalId) {
    const out = {};
    for (const r of db.prepare(`SELECT a.mid, a.pid, a.ts FROM acks a JOIN messages m ON m.mid = a.mid WHERE m.senderId = ? ORDER BY a.ts, a.pid`).all(internalId)) (out[r.mid] = out[r.mid] || []).push({ id: r.pid, ts: r.ts });
    return out;
  },
  retractedFor(publicId) {
    return db.prepare(`SELECT mid FROM tombstones WHERE pid = ? AND ts > ?`).all(publicId, Date.now() - TOMBSTONE_DAYS * 864e5).map(r => r.mid);
  },
  sweep() {
    db.prepare(`DELETE FROM tombstones WHERE ts <= ?`).run(Date.now() - TOMBSTONE_DAYS * 864e5);
    db.exec(`DELETE FROM reactions WHERE NOT EXISTS (SELECT 1 FROM messages m WHERE m.mid = reactions.mid);
             DELETE FROM acks WHERE NOT EXISTS (SELECT 1 FROM messages m WHERE m.mid = acks.mid);`);
  },
  importLegacy: db.transaction(({ reactions = {}, acks = {}, tombstones = {} }) => {
    const now = Date.now(); let nr = 0, na = 0, nt = 0;
    const exists = db.prepare(`SELECT 1 FROM messages WHERE mid = ?`);
    for (const [mid, forMid] of Object.entries(reactions)) {
      if (!forMid || typeof forMid !== 'object' || !exists.get(mid)) continue;
      for (const [emoji, list] of Object.entries(forMid)) for (const x of Array.isArray(list) ? list : []) if (x && typeof x.id === 'string') { db.prepare(`INSERT OR IGNORE INTO reactions(mid, emoji, pid, at) VALUES (?,?,?,?)`).run(mid, emoji, x.id, now); nr++; }
    }
    for (const [mid, e] of Object.entries(acks)) {
      if (!e || !Array.isArray(e.list) || !exists.get(mid)) continue;
      for (const a of e.list) if (a && typeof a.id === 'string') { db.prepare(`INSERT OR IGNORE INTO acks(mid, pid, ts) VALUES (?,?,?)`).run(mid, a.id, Number(a.ts) || now); na++; }
    }
    for (const [mid, t] of Object.entries(tombstones)) if (t && typeof t === 'object' && Array.isArray(t.r)) for (const p of t.r) if (typeof p === 'string') { stmtTombPut.run(mid, p, Number(t.ts) || now); nt++; }
    return { reactions: nr, acks: na, tombstones: nt };
  }),
};

// ---- state backups API ----------------------------------------------------------
export const backupsStore = {
  get(nodeId) { return stmtBackupGet.get(nodeId) || null; },
  set(nodeId, wrapped, ts) { stmtBackupSet.run(nodeId, wrapped, ts); },
  delete(nodeId) { stmtBackupDel.run(nodeId); },
  totalBytes() { return db.prepare(`SELECT COALESCE(SUM(length(wrapped) + COALESCE(length(pending_wrapped), 0)), 0) AS n FROM state_backups`).get().n; },
  stage(nodeId, stageId, wrapped, ts) { return stmtBackupStage.run(wrapped, stageId, Date.now(), nodeId, ts).changes === 1; },
  metaFor(nodeIds) {
    const out = new Map();
    for (const id of nodeIds) { const r = db.prepare(`SELECT ts, pending_stage FROM state_backups WHERE nodeId = ?`).get(id); if (r) out.set(id, { ts: r.ts, stage: r.pending_stage }); }
    return out;
  },
  clearStaleStages(maxAgeMs) {
    return db.prepare(`UPDATE state_backups SET pending_wrapped = NULL, pending_stage = NULL, pending_at = NULL WHERE pending_at IS NOT NULL AND pending_at < ?`).run(Date.now() - maxAgeMs).changes;
  },
};

// ---- attachment blobs API ----------------------------------------------------
// Signal-style: each media file is encrypted CLIENT-SIDE and stored here as an
// opaque byte blob, referenced from the (tiny) message by id. The server never
// sees plaintext, and messages stay small — so a chat with 100 photos is 100
// small rows plus 100 independently-fetchable blobs, not 100 multi-MB rows.
try { db.exec('ALTER TABLE attachments ADD COLUMN scope TEXT'); } catch {}   // v72 M2 (no-op if present)
const stmtAttInsert = db.prepare(`INSERT INTO attachments(id, ownerId, createdAt, expiresAt, bytes, scope)
  VALUES (@id, @ownerId, @createdAt, @expiresAt, @bytes, @scope)`);
const stmtAttGet = db.prepare(`SELECT bytes, expiresAt, ownerId, scope FROM attachments WHERE id = ?`);
const stmtAttDelOwner = db.prepare(`DELETE FROM attachments WHERE ownerId = ?`);
const stmtAttSweep = db.prepare(`DELETE FROM attachments WHERE expiresAt IS NOT NULL AND expiresAt <= ?`);
const stmtAttOwnerBytes = db.prepare(`SELECT COALESCE(SUM(length(bytes)),0) AS n FROM attachments WHERE ownerId = ?`);

export const attachmentsStore = {
  insert(id, ownerId, bytes, expiresAt = null, scope = null) {
    stmtAttInsert.run({ id, ownerId, createdAt: Date.now(), expiresAt, bytes, scope });
  },
  get(id) { return stmtAttGet.get(id) || null; },        // { bytes: Buffer, expiresAt }
  deleteByOwner(ownerId) { return stmtAttDelOwner.run(ownerId).changes; },
  sweepExpired(now = Date.now()) { return stmtAttSweep.run(now).changes; },
  ownerBytes(ownerId) { return stmtAttOwnerBytes.get(ownerId).n; },
  /** v71: all stored blob bytes on this server (the server-wide storage budget). */
  totalBytes() { return db.prepare('SELECT COALESCE(SUM(length(bytes)),0) AS n FROM attachments').get().n; },
  /** v71 L1: total stored blob bytes across several owners (per-account quota). */
  ownersBytes(ownerIds) {
    const ids = [...(ownerIds || [])];
    if (!ids.length) return 0;
    return db.prepare(`SELECT COALESCE(SUM(length(bytes)),0) AS n FROM attachments WHERE ownerId IN (${ids.map(() => '?').join(',')})`).get(...ids).n;
  },
};

// ---- avatars (content-addressed profile photos) -----------------------------
const stmtAvGet = db.prepare(`SELECT data FROM avatars WHERE hash = ?`);
const stmtAvPut = db.prepare(`INSERT OR IGNORE INTO avatars(hash, data) VALUES (?, ?)`);
const stmtAvDel = db.prepare(`DELETE FROM avatars WHERE hash = ?`);
const stmtAvAll = db.prepare(`SELECT hash FROM avatars`);
export const avatarsStore = {
  get(hash) { const r = stmtAvGet.get(hash); return r ? r.data : null; },
  put(hash, data) { stmtAvPut.run(hash, data); },
  delete(hash) { stmtAvDel.run(hash); },
  allHashes() { return stmtAvAll.all().map(r => r.hash); },
};

// ---- small-collection snapshots ---------------------------------------------
const SNAPSHOT_KEYS = ['accounts', 'users', 'invites', 'subscriptions', 'sessions', 'prekeys', 'signalIdentities', 'tombstones', 'xmrPayments', 'stripeEvents', 'recovery', 'acks', 'hubContacts', 'reactions', 'scheduledEnvelopes', 'accountHubInvites', 'certs', 'netBoxes', 'reactionAud', 'billingRefs', 'serverMeta'];
// Keyed maps (everything else is an array). `reactions` was missing here, so a
// fresh DB seeded it as [] — the root cause of V8 H-6/L-7.
const OBJECT_KEYS = ['prekeys', 'signalIdentities', 'tombstones', 'acks', 'reactions', 'reactionAud', 'billingRefs', 'serverMeta'];

export function loadSnapshots() {
  const out = {};
  for (const k of SNAPSHOT_KEYS) {
    const row = stmtSnapshotGet.get(k);
    out[k] = row ? JSON.parse(row.value) : (OBJECT_KEYS.includes(k) ? {} : []);
    if (out[k] === null) out[k] = OBJECT_KEYS.includes(k) ? {} : [];
    if (row) lastWritten.set(k, row.value);
  }
  return out;
}

// Write only collections whose serialized form changed since the last persist
// (V8 H-5): a reaction or a day-stamp no longer rewrites every collection.
const lastWritten = new Map();
const writeChanged = db.transaction((changed, bc) => {
  // v72 M7: staged backups swap in with the snapshots, all or nothing.
  for (const { nodeId, ts } of (bc ? bc.nodes : [])) {
    if (stmtBackupCommit.run(nodeId, ts, bc.stage).changes !== 1) throw Object.assign(new Error('a backup changed during the password change'), { code: 'BACKUP_CHANGED' });
  }
  for (const [k, json] of changed) stmtSnapshotSet.run(k, json);
});
// v72 B4: `keys` limits the write to those collections (null/undefined = all).
export const persistSnapshots = (cache, keys, extra) => {
  const changed = [];
  for (const k of keys ? SNAPSHOT_KEYS.filter(x => keys.includes(x)) : SNAPSHOT_KEYS) {
    const json = JSON.stringify(cache[k] ?? null);
    if (lastWritten.get(k) !== json) changed.push([k, json]);
  }
  const bc = extra && extra.backupCommit && extra.backupCommit.nodes.length ? extra.backupCommit : null;
  if (!changed.length && !bc) return;
  writeChanged(changed, bc);                               // throws (and rolls back) on failure…
  for (const [k, json] of changed) lastWritten.set(k, json); // …so the cache only advances on commit
};

// ---- one-time migration from db.json -----------------------------------------
export function migrateFromJsonIfPresent() {
  if (!fs.existsSync(LEGACY_JSON)) return false;
  const already = stmtSnapshotGet.get('users');
  if (already) {
    console.warn('[storage] db.json present but arbor.db already initialized — NOT migrating. Remove one to resolve.');
    return false;
  }
  const parsed = JSON.parse(fs.readFileSync(LEGACY_JSON, 'utf8'));
  const doImport = db.transaction(() => {
    persistSnapshots({
      accounts: parsed.accounts || [], users: parsed.users || [], invites: parsed.invites || [],
      subscriptions: parsed.subscriptions || [], sessions: parsed.sessions || [],
      prekeys: parsed.prekeys || {}, signalIdentities: parsed.signalIdentities || {},
      tombstones: parsed.tombstones || {},
    });
    for (const m of parsed.messages || []) messagesStore.insert(m);
    for (const [nodeId, b] of Object.entries(parsed.stateBackups || {})) {
      if (b && b.wrapped) backupsStore.set(nodeId, b.wrapped, b.ts || Date.now());
    }
  });
  doImport();
  fs.renameSync(LEGACY_JSON, LEGACY_JSON + '.migrated');
  console.log(`[storage] migrated db.json -> arbor.db (${(parsed.messages || []).length} messages, ${(parsed.users || []).length} users). Old file kept as db.json.migrated`);
  return true;
}
