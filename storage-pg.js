// ---------------------------------------------------------------------------
// PostgreSQL storage layer — a drop-in replacement for storage.js.
//
// The DATA MODEL IS DELIBERATELY UNCHANGED from the SQLite version:
//  - MESSAGES stay a true SQL table with an indexed recipients join table:
//    inserted/deleted per row, streamed per query, never held in process RAM.
//  - ATTACHMENTS stay opaque client-encrypted byte blobs in their own table,
//    referenced from the (tiny) message by id and fetched independently. This
//    is what keeps chats fast — a chat with 100 photos is 100 small message
//    rows plus 100 separately-fetchable blobs, NOT 100 multi-MB rows. Media
//    handling is byte-for-byte the same; only the engine underneath changed.
//  - The SMALL collections still live in RAM and persist as one snapshot
//    transaction.
//
// THE ONE REAL DIFFERENCE: better-sqlite3 is synchronous, node-postgres is
// not. Every method here returns a Promise. Call sites must await.
//
// Deliberate type choices:
//  - `envelope` and snapshot `value` stay TEXT, not JSONB. They hold large
//    ciphertext blobs; JSONB would parse and re-serialize them on every read
//    and write for zero benefit (we never query inside them). TEXT preserves
//    the exact bytes and avoids that overhead.
//  - JS millisecond timestamps are BIGINT. node-postgres returns int8 as a
//    string by default to avoid precision loss, so we register a parser to
//    hand back Numbers (ms timestamps are ~1.7e12, far below 2^53).
//  - camelCase identifiers are quoted throughout. Postgres folds unquoted
//    names to lowercase, which would silently change every row shape.
// ---------------------------------------------------------------------------
import pg from 'pg';
import fs from 'fs';

const { Pool, types } = pg;

// int8/BIGINT -> Number (safe for ms timestamps and byte counts).
types.setTypeParser(20, v => (v === null ? null : parseInt(v, 10)));
// numeric (SUM of lengths comes back as numeric) -> Number
types.setTypeParser(1700, v => (v === null ? null : parseFloat(v)));

const connectionString = process.env.DATABASE_URL || undefined;

// ---------------------------------------------------------------------------
// Database TLS — encryption AND certificate verification in transit.
//
// Posture, by PGSSL:
//   disable      -> no TLS. Only appropriate for a localhost/unix-socket DB
//                   where traffic never crosses a network.
//   verify /     -> TLS with FULL certificate verification (rejectUnauthorized:
//   require /       true). Supply the server CA via PGSSLROOTCERT (a file path)
//   verify-full     or PGSSLCA (inline PEM) to verify a managed/private CA that
//                   isn't in the system trust store. This is the secure default
//                   whenever DATABASE_URL is set.
//   no-verify    -> TLS but the certificate is NOT checked (encrypts against a
//                   passive eavesdropper, but an active MITM can still intercept).
//                   Escape hatch only; logged loudly at boot.
//
// Previously the DATABASE_URL path silently used rejectUnauthorized:false, which
// encrypted traffic but accepted ANY certificate — no protection against an
// active man-in-the-middle on the app<->DB link. Verification is now the default.
// ---------------------------------------------------------------------------
function loadDbCa() {
  try {
    if (process.env.PGSSLROOTCERT) return fs.readFileSync(process.env.PGSSLROOTCERT, 'utf8');
    if (process.env.PGSSLCA) return process.env.PGSSLCA;
  } catch (e) {
    console.error('[storage-pg] could not read PGSSLROOTCERT:', e.message);
  }
  return undefined;
}
function buildDbSsl({ usingUrl }) {
  const mode = (process.env.PGSSL || '').toLowerCase();
  if (mode === 'disable') return false;
  const ca = loadDbCa();
  if (mode === 'no-verify') {
    console.warn('[storage-pg] WARNING: PGSSL=no-verify — DB traffic is encrypted but the server certificate is NOT verified (active MITM is possible). Set PGSSLROOTCERT and PGSSL=verify to fix.');
    return { rejectUnauthorized: false, ...(ca ? { ca } : {}) };
  }
  if (mode === 'require' || mode === 'verify' || mode === 'verify-full') {
    return { rejectUnauthorized: true, ...(ca ? { ca } : {}) };
  }
  // No explicit PGSSL. When connecting via DATABASE_URL (typically a networked/
  // managed DB) default to VERIFIED TLS. When connecting via PG* host/port with
  // no DATABASE_URL (typically a localhost DB) default to no TLS — set PGSSL to
  // opt in. If a networked DB has a private CA, provide PGSSLROOTCERT.
  if (usingUrl) return { rejectUnauthorized: true, ...(ca ? { ca } : {}) };
  return false;
}

export const pool = new Pool(
  connectionString
    ? {
        connectionString,
        ssl: buildDbSsl({ usingUrl: true }),
        max: parseInt(process.env.PG_POOL_MAX || '20', 10),
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 10_000,
      }
    : {
        host: process.env.PGHOST || 'localhost',
        port: parseInt(process.env.PGPORT || '5432', 10),
        user: process.env.PGUSER || 'arbor',
        password: process.env.PGPASSWORD || '',
        database: process.env.PGDATABASE || 'arbor',
        ssl: buildDbSsl({ usingUrl: false }),
        max: parseInt(process.env.PG_POOL_MAX || '20', 10),
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 10_000,
      }
);

/** Live pool counters for the ops health endpoint: total open, idle, and the
 *  number of queries WAITING for a free connection (sustained waiting = the
 *  pool-of-20 saturating — the key backpressure signal under load). */
export const poolStats = () => ({ max: pool.options.max, total: pool.totalCount, idle: pool.idleCount, waiting: pool.waitingCount });
/** On-disk size of this database in bytes (admin storage monitor). */
export const dbSizeBytes = async () => {
  const { rows } = await pool.query('SELECT pg_database_size(current_database())::bigint AS n');
  return Number(rows[0].n);
};

pool.on('error', (err) => {
  // A pooled idle client dropped (network blip, failover). The pool replaces it;
  // log rather than crash the process.
  console.error('[storage-pg] idle client error:', err.message);
});

/** Run fn inside a transaction on a single dedicated client. */
async function withTx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

// ---- schema ----------------------------------------------------------------
export async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS snapshots (
      name  TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      id             TEXT PRIMARY KEY,
      mid            TEXT,
      "senderId"     TEXT NOT NULL,
      "timestamp"    BIGINT NOT NULL,
      "expiresAt"    BIGINT,
      type           TEXT,
      "depthLimit"   INTEGER,
      "targetCircle" TEXT,
      envelope       TEXT NOT NULL,
      "ackRequested" BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS idx_messages_mid       ON messages(mid);
    CREATE INDEX IF NOT EXISTS idx_messages_sender    ON messages("senderId");
    CREATE INDEX IF NOT EXISTS idx_messages_expires   ON messages("expiresAt");
    CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages("timestamp");
    CREATE TABLE IF NOT EXISTS message_recipients (
      "messageId" TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      "publicId"  TEXT NOT NULL,
      PRIMARY KEY ("messageId", "publicId")
    );
    CREATE INDEX IF NOT EXISTS idx_recipients_public ON message_recipients("publicId");
    CREATE TABLE IF NOT EXISTS state_backups (
      "nodeId" TEXT PRIMARY KEY,
      wrapped  TEXT NOT NULL,
      ts       BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attachments (
      id          TEXT PRIMARY KEY,
      "ownerId"   TEXT NOT NULL,
      "createdAt" BIGINT NOT NULL,
      "expiresAt" BIGINT,
      bytes       BYTEA NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_attachments_owner   ON attachments("ownerId");
    CREATE INDEX IF NOT EXISTS idx_attachments_expires ON attachments("expiresAt");
  `);
  // Composite index serving the hot path: "live messages for this recipient,
  // oldest first". Postgres can walk this instead of sorting after the join.
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_recipients_public_msg
      ON message_recipients("publicId", "messageId")
  `);
  // Content-addressed profile photos, kept out of the users snapshot (V8 H-5).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS avatars (
      hash TEXT PRIMARY KEY,
      data TEXT NOT NULL
    )
  `);
  // V8 L-9: make mid uniqueness race-proof (server.js pre-checks, but two
  // concurrent inserts could both pass that check on Postgres).
  try { await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_messages_mid ON messages(mid)`); }
  catch (e) { console.warn('[storage-pg] could not add UNIQUE(messages.mid) — duplicate legacy mids present:', e.message); }
  // v71 H1: delivery cursor (seq) + stored size, mirrored onto recipient rows so a
  // recipient's page is one index range scan. Backfill existing rows once, in
  // timestamp order, above any seq already assigned.
  await pool.query(`
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS seq BIGINT;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS size INTEGER;
    ALTER TABLE message_recipients ADD COLUMN IF NOT EXISTS seq BIGINT;
  `);
  await withTx(async (c) => {
    await c.query(`SELECT pg_advisory_xact_lock($1)`, [SEQ_LOCK]);
    await c.query(`
      UPDATE messages m SET seq = s.n + (SELECT COALESCE(MAX(seq), 0) FROM messages)
        FROM (SELECT id, row_number() OVER (ORDER BY "timestamp", id) AS n FROM messages WHERE seq IS NULL) s
       WHERE m.id = s.id`);
    await c.query(`UPDATE messages SET size = length(envelope) WHERE size IS NULL`);
    await c.query(`UPDATE message_recipients r SET seq = m.seq FROM messages m WHERE m.id = r."messageId" AND r.seq IS NULL`);
  });
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_messages_seq ON messages(seq)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_recipients_public_seq ON message_recipients("publicId", seq)`);
  // v72 B4: per-message metadata lives in tables, not in the in-RAM snapshot.
  // v71 kept reactions, acks and retraction tombstones in memory, each reaction
  // and tombstone with a full copy of the message's audience. Visibility is now
  // derived from messages/message_recipients at read time.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reactions (
      mid   TEXT NOT NULL,
      emoji TEXT NOT NULL,
      pid   TEXT NOT NULL,
      at    BIGINT NOT NULL,
      PRIMARY KEY (mid, emoji, pid)
    );
    CREATE INDEX IF NOT EXISTS idx_reactions_pid ON reactions(pid);
    CREATE TABLE IF NOT EXISTS acks (
      mid TEXT NOT NULL,
      pid TEXT NOT NULL,
      ts  BIGINT NOT NULL,
      PRIMARY KEY (mid, pid)
    );
    CREATE INDEX IF NOT EXISTS idx_acks_pid ON acks(pid);
    CREATE TABLE IF NOT EXISTS tombstones (
      mid TEXT NOT NULL,
      pid TEXT NOT NULL,
      ts  BIGINT NOT NULL,
      PRIMARY KEY (pid, mid)
    );
    CREATE INDEX IF NOT EXISTS idx_tombstones_ts ON tombstones(ts);
  `);
  await pool.query(`ALTER TABLE attachments ADD COLUMN IF NOT EXISTS scope TEXT`);   // v72 M2
  // v72 M7: a password change stages each re-encrypted backup here first, then swaps
  // all of them in inside the same transaction as the new password.
  await pool.query(`
    ALTER TABLE state_backups ADD COLUMN IF NOT EXISTS pending_wrapped TEXT;
    ALTER TABLE state_backups ADD COLUMN IF NOT EXISTS pending_stage TEXT;
    ALTER TABLE state_backups ADD COLUMN IF NOT EXISTS pending_at BIGINT;
  `);
  // v72 B4: scheduled (future-dated, sealed) sends — v71 held up to 4 MB of them
  // per account in RAM. `item` is the JSON of { type, targetCircle, targetGroup,
  // ackRequested, envelope }; `size` counts toward the sender's message quota.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scheduled (
      id          TEXT PRIMARY KEY,
      "nodeId"    TEXT NOT NULL,
      "fireAt"    BIGINT NOT NULL,
      "createdAt" BIGINT NOT NULL,
      mid         TEXT NOT NULL UNIQUE,
      size        INTEGER NOT NULL,
      item        TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_scheduled_node ON scheduled("nodeId");
    CREATE INDEX IF NOT EXISTS idx_scheduled_fire ON scheduled("fireAt");
  `);
  // Reactions and acks go with their message (retraction, expiry, retention,
  // pruning). Needs UNIQUE(messages.mid); if a legacy database couldn't get it, the
  // hourly metaStore.sweepOrphans() does the same job.
  for (const t of ['reactions', 'acks']) {
    const { rowCount } = await pool.query(`SELECT 1 FROM pg_constraint WHERE conname = $1`, [`fk_${t}_mid`]);
    if (rowCount) continue;
    try { await pool.query(`ALTER TABLE ${t} ADD CONSTRAINT fk_${t}_mid FOREIGN KEY (mid) REFERENCES messages(mid) ON DELETE CASCADE`); }
    catch (e) { console.warn(`[storage-pg] ${t}: no cascade on message delete (hourly sweep instead):`, e.message); }
  }
}
// Serializes message inserts so seq is assigned and committed in the same order —
// otherwise a reader could see seq N+1 committed before N and move its cursor past N.
const SEQ_LOCK = 727101;

// ---- avatars ------------------------------------------------------------------
export const avatarsStore = {
  async get(hash) {
    const { rows } = await pool.query(`SELECT data FROM avatars WHERE hash = $1`, [hash]);
    return rows[0] ? rows[0].data : null;
  },
  async put(hash, data) {
    await pool.query(`INSERT INTO avatars(hash, data) VALUES ($1,$2) ON CONFLICT (hash) DO NOTHING`, [hash, data]);
  },
  async delete(hash) { await pool.query(`DELETE FROM avatars WHERE hash = $1`, [hash]); },
  async allHashes() { const { rows } = await pool.query(`SELECT hash FROM avatars`); return rows.map(r => r.hash); },
};

// ---- messages ---------------------------------------------------------------
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

// Same page cut as storage.js: at most maxBytes, but never an empty page.
const cutPage = (rows, maxBytes) => {
  let bytes = 0, n = 0;
  for (const r of rows) {
    if (n > 0 && bytes + (r.size || 0) > maxBytes) break;
    bytes += r.size || 0; n++;
  }
  return n;
};
const PAGE_RANGE = `SELECT m.* FROM message_recipients r JOIN messages m ON m.id = r."messageId"
  WHERE r."publicId" = $1 AND r.seq >= $2 AND r.seq <= $3 AND (m."expiresAt" IS NULL OR m."expiresAt" > $4)
  ORDER BY r.seq ASC`;

export const messagesStore = {
  async insert(message) {
    return withTx(async (c) => {
      await c.query(`SELECT pg_advisory_xact_lock($1)`, [SEQ_LOCK]);
      const { rows: [{ n: seq }] } = await c.query(`SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM messages`);
      const envelope = JSON.stringify(message.envelope);
      await c.query(
        `INSERT INTO messages
           (id, mid, "senderId", "timestamp", "expiresAt", type, "depthLimit", "targetCircle", envelope, "ackRequested", seq, size)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          message.id,
          message.envelope?.mid ?? null,
          message.senderId,
          message.timestamp,
          message.expiresAt ?? null,
          message.type ?? null,
          message.depthLimit ?? null,
          message.targetCircle ?? null,
          envelope,
          !!message.ackRequested,
          seq,
          envelope.length,
        ]
      );
      const recips = [...new Set(message.recipients || [])];
      if (recips.length) {
        // One statement for all recipients via array unnest.
        await c.query(
          `INSERT INTO message_recipients("messageId", "publicId", seq)
           SELECT $1, u, $3 FROM unnest($2::text[]) AS u
           ON CONFLICT DO NOTHING`,
          [message.id, recips, seq]
        );
      }
      return seq;
    });
  },

  /** v71 H1: one bounded delivery page (see storage.js page()). */
  async page(publicId, { since = null, now = Date.now(), maxCount = 200, maxBytes = 8 * 1024 * 1024 } = {}) {
    if (since === null) {
      const { rows: meta } = await pool.query(
        `SELECT r.seq AS seq, m.size AS size FROM message_recipients r JOIN messages m ON m.id = r."messageId"
          WHERE r."publicId" = $1 AND (m."expiresAt" IS NULL OR m."expiresAt" > $2)
          ORDER BY r.seq DESC LIMIT $3`, [publicId, now, maxCount + 1]);
      const n = cutPage(meta.slice(0, maxCount), maxBytes);   // (meta holds one extra row: "is there more?")
      if (!n) return { messages: [], next: 0, more: false };
      const hi = meta[0].seq, lo = meta[n - 1].seq;
      const { rows } = await pool.query(PAGE_RANGE, [publicId, lo, hi, now]);
      return { messages: rows.map(rowToMessage), next: hi, more: false, older: meta.length > n };
    }
    const { rows: meta } = await pool.query(
      `SELECT r.seq AS seq, m.size AS size FROM message_recipients r JOIN messages m ON m.id = r."messageId"
        WHERE r."publicId" = $1 AND r.seq > $2 AND (m."expiresAt" IS NULL OR m."expiresAt" > $3)
        ORDER BY r.seq ASC LIMIT $4`, [publicId, since, now, maxCount + 1]);
    const n = cutPage(meta.slice(0, maxCount), maxBytes);   // (meta holds one extra row: "is there more?")
    if (!n) return { messages: [], next: since, more: false };
    const lo = meta[0].seq, hi = meta[n - 1].seq;
    const { rows } = await pool.query(PAGE_RANGE, [publicId, lo, hi, now]);
    return { messages: rows.map(rowToMessage), next: hi, more: meta.length > n };
  },

  /** Total stored envelope bytes sent by these internal node ids (quota). */
  async senderBytes(internalIds) {
    const ids = [...(internalIds || [])];
    if (!ids.length) return 0;
    const { rows } = await pool.query(`SELECT COALESCE(SUM(size), 0)::bigint AS n FROM messages WHERE "senderId" = ANY($1::text[])`, [ids]);
    return rows[0].n;
  },

  /** Recipient public ids of a stored message row. */
  async recipientsOf(messageId) {
    const { rows } = await pool.query(`SELECT "publicId" FROM message_recipients WHERE "messageId" = $1`, [messageId]);
    return rows.map(r => r.publicId);
  },

  async byMid(mid) {
    const { rows } = await pool.query(`SELECT * FROM messages WHERE mid = $1`, [mid]);
    return rows[0] ? rowToMessage(rows[0]) : null;
  },

  async isRecipient(messageId, publicId) {
    const { rowCount } = await pool.query(
      `SELECT 1 FROM message_recipients WHERE "messageId" = $1 AND "publicId" = $2`,
      [messageId, publicId]
    );
    return rowCount > 0;
  },

  /** Sender-only retraction. Returns { removed: mid[], recipientPublicIds: Set } */
  async retract(mids, senderInternalId) {
    if (!mids || !mids.length) return { removed: [], recipientPublicIds: new Set() };
    return withTx(async (c) => {
      const { rows: owned } = await c.query(
        `SELECT id, mid FROM messages WHERE mid = ANY($1::text[]) AND "senderId" = $2`,
        [mids, senderInternalId]
      );
      if (!owned.length) return { removed: [], recipientPublicIds: new Set() };
      const ids = owned.map(r => r.id);
      const { rows: recips } = await c.query(
        `SELECT "messageId", "publicId" FROM message_recipients WHERE "messageId" = ANY($1::text[])`,
        [ids]
      );
      await c.query(`DELETE FROM messages WHERE id = ANY($1::text[])`, [ids]);
      const midOf = new Map(owned.map(r => [r.id, r.mid]));
      const audienceByMid = {};
      for (const r of owned) audienceByMid[r.mid] = [];
      for (const r of recips) audienceByMid[midOf.get(r.messageId)].push(r.publicId);
      // v72: the tombstone (so an offline recipient still drops it) is one row per
      // recipient, written in the same transaction; kept 7 days (metaStore.sweep).
      if (recips.length) {
        await c.query(
          `INSERT INTO tombstones(mid, pid, ts) SELECT m, p, $3 FROM unnest($1::text[], $2::text[]) AS t(m, p)
           ON CONFLICT (pid, mid) DO UPDATE SET ts = EXCLUDED.ts`,
          [recips.map(r => midOf.get(r.messageId)), recips.map(r => r.publicId), Date.now()]);
      }
      return {
        removed: owned.map(r => r.mid),
        recipientPublicIds: new Set(recips.map(r => r.publicId)),
        audienceByMid,
      };
    });
  },

  /** Prune a departing branch: their sent messages go entirely; their address
   *  rows are removed from everything else. */
  async pruneNodes(internalIds, publicIds) {
    const ids = [...(internalIds || [])];
    const pids = [...(publicIds || [])];
    return withTx(async (c) => {
      if (ids.length) await c.query(`DELETE FROM messages WHERE "senderId" = ANY($1::text[])`, [ids]);
      if (pids.length) {
        await c.query(`DELETE FROM message_recipients WHERE "publicId" = ANY($1::text[])`, [pids]);
        // v72: their reactions/acks/tombstones (the ones ON their messages cascade).
        await c.query(`DELETE FROM reactions WHERE pid = ANY($1::text[])`, [pids]);
        await c.query(`DELETE FROM acks WHERE pid = ANY($1::text[])`, [pids]);
        await c.query(`DELETE FROM tombstones WHERE pid = ANY($1::text[])`, [pids]);
      }
    });
  },

  async sweepExpired(now = Date.now()) {
    const { rowCount } = await pool.query(
      `DELETE FROM messages WHERE "expiresAt" IS NOT NULL AND "expiresAt" <= $1`, [now]);
    return rowCount;
  },
  // v71: `keepSenderIds` (optional) are spared — Premium networks keep a longer history.
  async sweepOlderThan(cutoffTs, keepSenderIds) {
    const keep = keepSenderIds && keepSenderIds.length ? [...keepSenderIds] : null;
    const { rowCount } = keep
      ? await pool.query(`DELETE FROM messages WHERE "timestamp" < $1 AND NOT ("senderId" = ANY($2::text[]))`, [cutoffTs, keep])
      : await pool.query(`DELETE FROM messages WHERE "timestamp" < $1`, [cutoffTs]);
    return rowCount;
  },
  async count() {
    const { rows } = await pool.query(`SELECT COUNT(*)::bigint AS n FROM messages`);
    return rows[0].n;
  },
  /** v72 B4: stored envelope bytes on this server (+ queued scheduled sends) — the server-wide budget. */
  async totalBytes() {
    const { rows } = await pool.query(`SELECT (SELECT COALESCE(SUM(size), 0) FROM messages) + (SELECT COALESCE(SUM(size), 0) FROM scheduled) AS n`);
    return Number(rows[0].n);
  },
};

// ---- v72 B4: scheduled sends -----------------------------------------------------
const rowToScheduled = (r) => ({ id: r.id, nodeId: r.nodeId, fireAt: r.fireAt, createdAt: r.createdAt, ...JSON.parse(r.item) });
export const scheduledStore = {
  /** false if the mid is already queued. */
  async add(e) {
    const item = JSON.stringify({ type: e.type, targetCircle: e.targetCircle, targetGroup: e.targetGroup, ackRequested: e.ackRequested, envelope: e.envelope });
    const { rowCount } = await pool.query(
      `INSERT INTO scheduled(id, "nodeId", "fireAt", "createdAt", mid, size, item) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (mid) DO NOTHING`,
      [e.id, e.nodeId, e.fireAt, e.createdAt, e.envelope.mid, e.size, item]);
    return rowCount > 0;
  },
  async hasMid(mid) { return (await pool.query(`SELECT 1 FROM scheduled WHERE mid = $1`, [mid])).rowCount > 0; },
  async countForNode(nodeId) { return (await pool.query(`SELECT COUNT(*)::int AS n FROM scheduled WHERE "nodeId" = $1`, [nodeId])).rows[0].n; },
  /** Queued bytes of these nodes (they count toward the message quota). */
  async bytesForNodes(nodeIds) {
    const ids = [...(nodeIds || [])];
    if (!ids.length) return 0;
    return (await pool.query(`SELECT COALESCE(SUM(size), 0)::bigint AS n FROM scheduled WHERE "nodeId" = ANY($1::text[])`, [ids])).rows[0].n;
  },
  async listForNode(nodeId) {
    const { rows } = await pool.query(`SELECT * FROM scheduled WHERE "nodeId" = $1 ORDER BY "fireAt"`, [nodeId]);
    return rows.map(rowToScheduled);
  },
  async cancel(id, nodeId) { return (await pool.query(`DELETE FROM scheduled WHERE id = $1 AND "nodeId" = $2`, [id, nodeId])).rowCount > 0; },
  async due(now, limit = 500) {
    const { rows } = await pool.query(`SELECT * FROM scheduled WHERE "fireAt" <= $1 ORDER BY "fireAt" LIMIT $2`, [now, limit]);
    return rows.map(rowToScheduled);
  },
  async remove(id) { await pool.query(`DELETE FROM scheduled WHERE id = $1`, [id]); },
  async deleteByNodes(nodeIds) {
    const ids = [...(nodeIds || [])];
    if (ids.length) await pool.query(`DELETE FROM scheduled WHERE "nodeId" = ANY($1::text[])`, [ids]);
  },
};

// ---- v72 B4: reactions, acks, retraction tombstones ---------------------------
// Shapes returned match what v71 kept in RAM, so clients see no difference:
//   reactions: { [mid]: { [emoji]: [{ id }] } }   acks: { [mid]: [{ id, ts }] }
const reactionMap = (rows) => {
  const out = {};
  for (const r of rows) ((out[r.mid] = out[r.mid] || {})[r.emoji] = out[r.mid][r.emoji] || []).push({ id: r.pid });
  return out;
};
// Messages a node can see: sent by it, or addressed to it (and not expired).
const VISIBLE_MIDS = `SELECT m.mid FROM message_recipients r JOIN messages m ON m.id = r."messageId"
    WHERE r."publicId" = $1 AND (m."expiresAt" IS NULL OR m."expiresAt" > $3)
  UNION SELECT m.mid FROM messages m WHERE m."senderId" = $2 AND (m."expiresAt" IS NULL OR m."expiresAt" > $3)`;
const TOMBSTONE_DAYS = 7;

export const metaStore = {
  /** Toggle one emoji of one person on a message; returns that message's reactions. */
  async toggleReaction(mid, emoji, pid) {
    return withTx(async (c) => {
      const del = await c.query(`DELETE FROM reactions WHERE mid = $1 AND emoji = $2 AND pid = $3`, [mid, emoji, pid]);
      if (!del.rowCount) await c.query(`INSERT INTO reactions(mid, emoji, pid, at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, [mid, emoji, pid, Date.now()]);
      const { rows } = await c.query(`SELECT mid, emoji, pid FROM reactions WHERE mid = $1 ORDER BY at, pid`, [mid]);
      return reactionMap(rows)[mid] || {};
    });
  },
  /** Reactions on every message this node sent or received (newest `limit` rows). */
  async reactionsFor(publicId, internalId, limit = 20000) {
    const { rows } = await pool.query(
      `SELECT x.mid, x.emoji, x.pid, x.at FROM reactions x WHERE x.mid IN (${VISIBLE_MIDS})
        ORDER BY x.at DESC LIMIT $4`, [publicId, internalId, Date.now(), limit]);
    return reactionMap(rows.reverse());
  },
  /** Record an acknowledgement once; returns { added, count }. */
  async addAck(mid, pid) {
    const ins = await pool.query(`INSERT INTO acks(mid, pid, ts) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, [mid, pid, Date.now()]);
    const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM acks WHERE mid = $1`, [mid]);
    return { added: ins.rowCount > 0, count: rows[0].n };
  },
  /** Who acknowledged each message this node sent (only the sender sees this). */
  async acksForSender(internalId) {
    const { rows } = await pool.query(
      `SELECT a.mid, a.pid, a.ts FROM acks a JOIN messages m ON m.mid = a.mid WHERE m."senderId" = $1 ORDER BY a.ts, a.pid`, [internalId]);
    const out = {};
    for (const r of rows) (out[r.mid] = out[r.mid] || []).push({ id: r.pid, ts: r.ts });
    return out;
  },
  /** Retractions (last 7 days) of messages this node had received. */
  async retractedFor(publicId) {
    const { rows } = await pool.query(`SELECT mid FROM tombstones WHERE pid = $1 AND ts > $2`, [publicId, Date.now() - TOMBSTONE_DAYS * 864e5]);
    return rows.map(r => r.mid);
  },
  /** Hourly: old tombstones, and metadata whose message is gone (installs without the cascade). */
  async sweep() {
    await pool.query(`DELETE FROM tombstones WHERE ts <= $1`, [Date.now() - TOMBSTONE_DAYS * 864e5]);
    await pool.query(`DELETE FROM reactions x WHERE NOT EXISTS (SELECT 1 FROM messages m WHERE m.mid = x.mid)`);
    await pool.query(`DELETE FROM acks a WHERE NOT EXISTS (SELECT 1 FROM messages m WHERE m.mid = a.mid)`);
  },
  /** One-time import of the v71 in-RAM snapshot data (only rows whose message still exists). */
  async importLegacy({ reactions = {}, acks = {}, tombstones = {} }) {
    const R = { m: [], e: [], p: [], a: [] }, A = { m: [], p: [], t: [] }, T = { m: [], p: [], t: [] };
    const now = Date.now();
    for (const [mid, forMid] of Object.entries(reactions)) {
      if (!forMid || typeof forMid !== 'object') continue;
      for (const [emoji, list] of Object.entries(forMid)) for (const x of Array.isArray(list) ? list : []) if (x && typeof x.id === 'string') { R.m.push(mid); R.e.push(emoji); R.p.push(x.id); R.a.push(now); }
    }
    for (const [mid, e] of Object.entries(acks)) for (const a of (e && Array.isArray(e.list)) ? e.list : []) if (a && typeof a.id === 'string') { A.m.push(mid); A.p.push(a.id); A.t.push(Number(a.ts) || now); }
    for (const [mid, t] of Object.entries(tombstones)) if (t && typeof t === 'object' && Array.isArray(t.r)) for (const p of t.r) if (typeof p === 'string') { T.m.push(mid); T.p.push(p); T.t.push(Number(t.ts) || now); }
    await withTx(async (c) => {
      if (R.m.length) await c.query(`INSERT INTO reactions(mid, emoji, pid, at) SELECT u.m, u.e, u.p, u.a FROM unnest($1::text[], $2::text[], $3::text[], $4::bigint[]) AS u(m, e, p, a)
        WHERE EXISTS (SELECT 1 FROM messages x WHERE x.mid = u.m) ON CONFLICT DO NOTHING`, [R.m, R.e, R.p, R.a]);
      if (A.m.length) await c.query(`INSERT INTO acks(mid, pid, ts) SELECT u.m, u.p, u.t FROM unnest($1::text[], $2::text[], $3::bigint[]) AS u(m, p, t)
        WHERE EXISTS (SELECT 1 FROM messages x WHERE x.mid = u.m) ON CONFLICT DO NOTHING`, [A.m, A.p, A.t]);
      if (T.m.length) await c.query(`INSERT INTO tombstones(mid, pid, ts) SELECT * FROM unnest($1::text[], $2::text[], $3::bigint[]) ON CONFLICT DO NOTHING`, [T.m, T.p, T.t]);
    });
    return { reactions: R.m.length, acks: A.m.length, tombstones: T.m.length };
  },
};

// ---- state backups ----------------------------------------------------------
export const backupsStore = {
  async get(nodeId) {
    const { rows } = await pool.query(
      `SELECT wrapped, ts FROM state_backups WHERE "nodeId" = $1`, [nodeId]);
    return rows[0] || null;
  },
  async set(nodeId, wrapped, ts) {
    // A new backup voids any staged re-encryption of the old one (v72 M7).
    await pool.query(
      `INSERT INTO state_backups("nodeId", wrapped, ts) VALUES ($1,$2,$3)
       ON CONFLICT ("nodeId") DO UPDATE SET wrapped = EXCLUDED.wrapped, ts = EXCLUDED.ts,
         pending_wrapped = NULL, pending_stage = NULL, pending_at = NULL`,
      [nodeId, wrapped, ts]
    );
  },
  async delete(nodeId) {
    await pool.query(`DELETE FROM state_backups WHERE "nodeId" = $1`, [nodeId]);
  },
  /** v72 B4: all stored backup bytes, staged copies included (the server-wide budget). */
  async totalBytes() {
    const { rows } = await pool.query(`SELECT COALESCE(SUM(length(wrapped) + COALESCE(length(pending_wrapped), 0)), 0)::bigint AS n FROM state_backups`);
    return Number(rows[0].n);
  },
  /** v72 M7: stage a re-encrypted copy of the backup stored with this ts. false = it changed. */
  async stage(nodeId, stageId, wrapped, ts) {
    const { rowCount } = await pool.query(
      `UPDATE state_backups SET pending_wrapped = $3, pending_stage = $2, pending_at = $5
       WHERE "nodeId" = $1 AND ts = $4`, [nodeId, stageId, wrapped, ts, Date.now()]);
    return rowCount === 1;
  },
  /** v72 M7: { nodeId -> { ts, stage } } for these nodes (stage = staged id or null). */
  async metaFor(nodeIds) {
    const { rows } = await pool.query(
      `SELECT "nodeId", ts, pending_stage FROM state_backups WHERE "nodeId" = ANY($1::text[])`, [nodeIds]);
    return new Map(rows.map(r => [r.nodeId, { ts: Number(r.ts), stage: r.pending_stage }]));
  },
  /** v72 M7: drop staged copies older than maxAgeMs (abandoned password changes). */
  async clearStaleStages(maxAgeMs) {
    const { rowCount } = await pool.query(
      `UPDATE state_backups SET pending_wrapped = NULL, pending_stage = NULL, pending_at = NULL
       WHERE pending_at IS NOT NULL AND pending_at < $1`, [Date.now() - maxAgeMs]);
    return rowCount;
  },
};

// v72 M7: swap staged backups in (inside the snapshot transaction). Every listed
// node must still hold the stage and the ts it was staged for, or all of it rolls back.
async function commitStagedBackups(client, { stage, nodes }) {
  for (const { nodeId, ts } of nodes) {
    const { rowCount } = await client.query(
      `UPDATE state_backups SET wrapped = pending_wrapped, pending_wrapped = NULL, pending_stage = NULL, pending_at = NULL
       WHERE "nodeId" = $1 AND ts = $2 AND pending_stage = $3 AND pending_wrapped IS NOT NULL`, [nodeId, ts, stage]);
    if (rowCount !== 1) throw Object.assign(new Error('a backup changed during the password change'), { code: 'BACKUP_CHANGED' });
  }
}

// ---- attachment blobs -------------------------------------------------------
// Unchanged design: opaque client-encrypted bytes, one row per file, fetched by
// id and never joined into message queries. BYTEA in, Buffer out — the same
// shape better-sqlite3 returned, so callers need no changes.
export const attachmentsStore = {
  // v72 M2: scope 'global' = sent in a network's global chat (see server.js globalPeers).
  async insert(id, ownerId, bytes, expiresAt = null, scope = null) {
    await pool.query(
      `INSERT INTO attachments(id, "ownerId", "createdAt", "expiresAt", bytes, scope)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [id, ownerId, Date.now(), expiresAt, bytes, scope]
    );
  },
  async get(id) {
    const { rows } = await pool.query(
      `SELECT bytes, "expiresAt", "ownerId", scope FROM attachments WHERE id = $1`, [id]);
    return rows[0] || null;
  },
  async deleteByOwner(ownerId) {
    const { rowCount } = await pool.query(`DELETE FROM attachments WHERE "ownerId" = $1`, [ownerId]);
    return rowCount;
  },
  async sweepExpired(now = Date.now()) {
    const { rowCount } = await pool.query(
      `DELETE FROM attachments WHERE "expiresAt" IS NOT NULL AND "expiresAt" <= $1`, [now]);
    return rowCount;
  },
  async ownerBytes(ownerId) {
    const { rows } = await pool.query(
      `SELECT COALESCE(SUM(octet_length(bytes)),0)::bigint AS n FROM attachments WHERE "ownerId" = $1`,
      [ownerId]
    );
    return rows[0].n;
  },
  /** v71 L1: total stored blob bytes across several owners (per-account quota). */
  /** v71: all stored blob bytes on this server (the server-wide storage budget). */
  async totalBytes() {
    const { rows } = await pool.query('SELECT COALESCE(SUM(octet_length(bytes)),0)::bigint AS n FROM attachments');
    return Number(rows[0].n);
  },
  async ownersBytes(ownerIds) {
    const ids = [...(ownerIds || [])];
    if (!ids.length) return 0;
    const { rows } = await pool.query(
      `SELECT COALESCE(SUM(octet_length(bytes)),0)::bigint AS n FROM attachments WHERE "ownerId" = ANY($1::text[])`, [ids]);
    return rows[0].n;
  },
};

// ---- small-collection snapshots ---------------------------------------------
export const SNAPSHOT_KEYS = ['accounts', 'users', 'invites', 'subscriptions', 'sessions', 'prekeys', 'signalIdentities', 'tombstones', 'xmrPayments', 'stripeEvents', 'recovery', 'acks', 'hubContacts', 'reactions', 'scheduledEnvelopes', 'accountHubInvites', 'certs', 'netBoxes', 'reactionAud', 'billingRefs', 'serverMeta'];
// `reactions` is a keyed map; omitting it here seeded it as [] (V8 H-6/L-7).
const OBJECT_KEYS = ['prekeys', 'signalIdentities', 'tombstones', 'acks', 'reactions', 'reactionAud', 'billingRefs', 'serverMeta'];
const lastWritten = new Map(); // name -> last persisted JSON (skip unchanged writes, V8 H-5)

export async function loadSnapshots() {
  const { rows } = await pool.query(`SELECT name, value FROM snapshots`);
  const found = new Map(rows.map(r => [r.name, r.value]));
  const out = {};
  for (const k of SNAPSHOT_KEYS) {
    const raw = found.get(k);
    out[k] = raw != null ? JSON.parse(raw) : (OBJECT_KEYS.includes(k) ? {} : []);
    // A snapshot explicitly stored as null must still yield the right empty shape.
    if (out[k] === null) out[k] = OBJECT_KEYS.includes(k) ? {} : [];
    if (raw != null) lastWritten.set(k, raw);
  }
  return out;
}

// v72 B4: `keys` limits the write to those collections (null/undefined = all).
// v72 M7: `extra.backupCommit` ({ stage, nodes: [{ nodeId, ts }] }) is applied in the
// same transaction as the snapshots — a password change commits all of it or none.
export async function persistSnapshots(cache, keys, extra) {
  const names = [];
  const values = [];
  for (const k of keys ? SNAPSHOT_KEYS.filter(x => keys.includes(x)) : SNAPSHOT_KEYS) {
    const json = JSON.stringify(cache[k] ?? null);
    if (lastWritten.get(k) === json) continue;
    names.push(k);
    values.push(json);
  }
  const bc = extra && extra.backupCommit;
  if (!names.length && !(bc && bc.nodes.length)) return;
  // Single round trip: unnest two parallel arrays into a multi-row upsert.
  const upsert = (q) => q.query(
    `INSERT INTO snapshots(name, value)
     SELECT * FROM unnest($1::text[], $2::text[])
     ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value`,
    [names, values]
  );
  if (bc && bc.nodes.length) await withTx(async (c) => { await commitStagedBackups(c, bc); if (names.length) await upsert(c); });
  else await upsert(pool);
  names.forEach((k, i) => lastWritten.set(k, values[i])); // only after the write succeeded
}

export async function close() {
  await pool.end();
}
