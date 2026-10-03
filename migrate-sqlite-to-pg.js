// ---------------------------------------------------------------------------
// One-time data migration: arbor.db (SQLite) -> PostgreSQL.
//
//   node migrate-sqlite-to-pg.js [--force] [--batch=500] [--dry-run]
//
// Reads the live SQLite file at $ARBOR_DATA_DIR/arbor.db and copies every table
// into the Postgres database described by $DATABASE_URL (or the PG* vars).
//
// Safety properties:
//  - Refuses to run if the target already holds data, unless --force.
//  - Copies with keyset pagination in batches, so a multi-GB attachment table
//    never has to fit in RAM.
//  - Verifies row counts on both sides at the end and exits non-zero on any
//    mismatch, so a partial copy can't be mistaken for a successful one.
//  - Read-only with respect to SQLite. The original file is never modified,
//    so a failed run costs nothing and you can simply run it again.
// ---------------------------------------------------------------------------
import './env.js';
import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { pool, initSchema } from './storage-pg.js';

const args = process.argv.slice(2);
const FORCE = args.includes('--force');
const DRY = args.includes('--dry-run');
const BATCH = parseInt((args.find(a => a.startsWith('--batch=')) || '').split('=')[1] || '500', 10);

const DATA_DIR = process.env.ARBOR_DATA_DIR || '.';
const DB_PATH = path.join(DATA_DIR, 'arbor.db');

const log = (...a) => console.log('[migrate]', ...a);

if (!fs.existsSync(DB_PATH)) {
  console.error(`[migrate] No SQLite database at ${DB_PATH}. Set ARBOR_DATA_DIR or run from the data directory.`);
  process.exit(1);
}

const sq = new Database(DB_PATH, { readonly: true });

/** Tables that exist in the source, so an older DB missing one doesn't abort. */
const hasTable = (t) =>
  !!sq.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`).get(t);

const srcCount = (t) => (hasTable(t) ? sq.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n : 0);

async function pgCount(t) {
  const { rows } = await pool.query(`SELECT COUNT(*)::bigint AS n FROM ${t}`);
  return rows[0].n;
}

async function main() {
  log(`source: ${DB_PATH}`);
  log(`target: ${process.env.DATABASE_URL ? 'DATABASE_URL' : `${process.env.PGHOST || 'localhost'}/${process.env.PGDATABASE || 'arbor'}`}`);

  const counts = {
    snapshots: srcCount('snapshots'),
    messages: srcCount('messages'),
    message_recipients: srcCount('message_recipients'),
    state_backups: srcCount('state_backups'),
    attachments: srcCount('attachments'),
  };
  log('source rows:', JSON.stringify(counts));

  if (DRY) { log('--dry-run: nothing written.'); await pool.end(); sq.close(); return; }

  await initSchema();
  log('target schema ready.');

  // --- guard: never silently merge into a populated database ------------------
  const existing = {
    messages: await pgCount('messages'),
    snapshots: await pgCount('snapshots'),
    attachments: await pgCount('attachments'),
    state_backups: await pgCount('state_backups'),
  };
  const populated = Object.values(existing).some(n => n > 0);
  if (populated && !FORCE) {
    console.error('[migrate] TARGET ALREADY HAS DATA:', JSON.stringify(existing));
    console.error('[migrate] Refusing to run. Re-run with --force to wipe and re-import.');
    await pool.end(); sq.close();
    process.exit(2);
  }
  if (populated && FORCE) {
    log('--force: clearing target tables…');
    // Order matters only for message_recipients, which cascades from messages.
    await pool.query('TRUNCATE messages, message_recipients, state_backups, attachments, snapshots RESTART IDENTITY CASCADE');
  }

  // --- snapshots (tiny) -------------------------------------------------------
  if (hasTable('snapshots')) {
    const rows = sq.prepare('SELECT name, value FROM snapshots').all();
    if (rows.length) {
      await pool.query(
        `INSERT INTO snapshots(name, value)
         SELECT * FROM unnest($1::text[], $2::text[])
         ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value`,
        [rows.map(r => r.name), rows.map(r => r.value)]
      );
    }
    log(`snapshots: ${rows.length}`);
  }

  // --- messages (keyset paginated) -------------------------------------------
  if (hasTable('messages')) {
    // Older databases may predate the ackRequested column.
    const cols = sq.prepare(`PRAGMA table_info(messages)`).all().map(c => c.name);
    const hasAck = cols.includes('ackRequested');
    const sel = sq.prepare(
      `SELECT id, mid, senderId, timestamp, expiresAt, type, depthLimit, targetCircle, envelope
              ${hasAck ? ', ackRequested' : ''}
         FROM messages WHERE id > ? ORDER BY id LIMIT ?`
    );
    let last = '';
    let done = 0;
    for (;;) {
      const rows = sel.all(last, BATCH);
      if (!rows.length) break;
      await pool.query(
        `INSERT INTO messages
           (id, mid, "senderId", "timestamp", "expiresAt", type, "depthLimit", "targetCircle", envelope, "ackRequested")
         SELECT * FROM unnest(
           $1::text[], $2::text[], $3::text[], $4::bigint[], $5::bigint[],
           $6::text[], $7::int[], $8::text[], $9::text[], $10::boolean[])
         ON CONFLICT (id) DO NOTHING`,
        [
          rows.map(r => r.id),
          rows.map(r => r.mid),
          rows.map(r => r.senderId),
          rows.map(r => r.timestamp),
          rows.map(r => r.expiresAt),
          rows.map(r => r.type),
          rows.map(r => r.depthLimit),
          rows.map(r => r.targetCircle),
          rows.map(r => r.envelope),
          rows.map(r => (hasAck ? !!r.ackRequested : false)),
        ]
      );
      last = rows[rows.length - 1].id;
      done += rows.length;
      if (done % (BATCH * 10) === 0) log(`  messages: ${done}/${counts.messages}`);
    }
    log(`messages: ${done}`);
  }

  // --- message_recipients (composite keyset) ----------------------------------
  if (hasTable('message_recipients')) {
    const sel = sq.prepare(
      `SELECT messageId, publicId FROM message_recipients
        WHERE (messageId > ?) OR (messageId = ? AND publicId > ?)
        ORDER BY messageId, publicId LIMIT ?`
    );
    let lastM = '', lastP = '';
    let done = 0;
    for (;;) {
      const rows = sel.all(lastM, lastM, lastP, BATCH);
      if (!rows.length) break;
      await pool.query(
        `INSERT INTO message_recipients("messageId", "publicId")
         SELECT * FROM unnest($1::text[], $2::text[])
         ON CONFLICT DO NOTHING`,
        [rows.map(r => r.messageId), rows.map(r => r.publicId)]
      );
      lastM = rows[rows.length - 1].messageId;
      lastP = rows[rows.length - 1].publicId;
      done += rows.length;
    }
    log(`message_recipients: ${done}`);
  }

  // --- state backups ----------------------------------------------------------
  if (hasTable('state_backups')) {
    const sel = sq.prepare(`SELECT nodeId, wrapped, ts FROM state_backups WHERE nodeId > ? ORDER BY nodeId LIMIT ?`);
    let last = '';
    let done = 0;
    for (;;) {
      const rows = sel.all(last, BATCH);
      if (!rows.length) break;
      await pool.query(
        `INSERT INTO state_backups("nodeId", wrapped, ts)
         SELECT * FROM unnest($1::text[], $2::text[], $3::bigint[])
         ON CONFLICT ("nodeId") DO UPDATE SET wrapped = EXCLUDED.wrapped, ts = EXCLUDED.ts`,
        [rows.map(r => r.nodeId), rows.map(r => r.wrapped), rows.map(r => r.ts)]
      );
      last = rows[rows.length - 1].nodeId;
      done += rows.length;
    }
    log(`state_backups: ${done}`);
  }

  // --- attachments (small batches: rows carry multi-MB blobs) ------------------
  if (hasTable('attachments')) {
    const ATT_BATCH = Math.max(1, Math.min(BATCH, 50));
    const sel = sq.prepare(
      `SELECT id, ownerId, createdAt, expiresAt, bytes FROM attachments
        WHERE id > ? ORDER BY id LIMIT ?`
    );
    let last = '';
    let done = 0;
    let bytes = 0;
    for (;;) {
      const rows = sel.all(last, ATT_BATCH);
      if (!rows.length) break;
      // Insert one at a time: blobs are large and a bad batch would be costly to
      // retry. This is a one-time migration, so clarity beats throughput.
      for (const r of rows) {
        await pool.query(
          `INSERT INTO attachments(id, "ownerId", "createdAt", "expiresAt", bytes)
           VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.ownerId, r.createdAt, r.expiresAt, r.bytes]
        );
        bytes += r.bytes ? r.bytes.length : 0;
      }
      last = rows[rows.length - 1].id;
      done += rows.length;
      log(`  attachments: ${done}/${counts.attachments} (${(bytes / 1e6).toFixed(1)} MB)`);
    }
    log(`attachments: ${done} (${(bytes / 1e6).toFixed(1)} MB)`);
  }

  // --- verification -----------------------------------------------------------
  log('verifying…');
  const after = {
    snapshots: await pgCount('snapshots'),
    messages: await pgCount('messages'),
    message_recipients: await pgCount('message_recipients'),
    state_backups: await pgCount('state_backups'),
    attachments: await pgCount('attachments'),
  };
  let bad = 0;
  for (const k of Object.keys(counts)) {
    const ok = after[k] === counts[k];
    if (!ok) bad++;
    console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${k}: sqlite=${counts[k]} postgres=${after[k]}`);
  }

  await pool.end();
  sq.close();

  if (bad) {
    console.error(`[migrate] ${bad} table(s) did not match. NOTHING has been changed in SQLite — fix and re-run.`);
    process.exit(3);
  }
  log('migration complete — all row counts match.');
}

main().catch(async (e) => {
  console.error('[migrate] FAILED:', e);
  try { await pool.end(); } catch {}
  try { sq.close(); } catch {}
  process.exit(1);
});
