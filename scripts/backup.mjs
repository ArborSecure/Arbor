// Nightly backup of the Arbor database (Postgres) and the secrets it can't be
// restored without.
//
// v72 B5: production runs on Postgres; the v71 script only knew SQLite (it looked
// for arbor.db and exited), so a Postgres install had NO database backups. Now:
//   arbor-<stamp>.dump.enc     pg_dump (custom format), encrypted
//   secrets-<stamp>.json.enc   .env + server-salt.json + vapid.json, encrypted —
//                              a database restored without ITS salt locks every
//                              account out (the server refuses to start with a
//                              different one), so they are always kept together.
// Both are AES-256-GCM under a key derived (scrypt) from ARBOR_BACKUP_KEY. Keep that
// passphrase OUTSIDE the backup location (e.g. a password manager). Without it the
// script refuses to run (it never writes the database in the clear) unless
// ARBOR_BACKUP_ALLOW_PLAINTEXT=1 is set on purpose.
//
// Usage:  node scripts/backup.mjs                          (the nightly timer runs this)
//         ARBOR_BACKUP_KEY=... node scripts/backup.mjs --decrypt <file.enc> > <out>
//         e.g. ... --decrypt arbor-<stamp>.dump.enc > arbor.dump
//              pg_restore --clean --if-exists --no-owner -d <database> arbor.dump
//         (--decrypt-env still opens a v71 env.backup.enc)
// Env:    DATABASE_URL / PG*     the database (same settings as the server)
//         ARBOR_DATA_DIR         where server-salt.json / vapid.json live
//         ARBOR_BACKUP_DIR       where backups go        (default: $ARBOR_DATA_DIR/backups)
//         ARBOR_BACKUP_KEEP      how many of each to keep (default: 14)
//         ARBOR_BACKUP_KEY       passphrase (16+ chars) that encrypts everything
//         PG_DUMP                pg_dump binary          (default: pg_dump on PATH; must be
//                                                        the server's major version or newer)
// Backups on the same disk as the database don't survive losing that disk — copy
// the backup directory off the server (see PRODUCTION.md).
import '../env.js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { spawn } from 'child_process';
import { pipeline } from 'stream/promises';
import { Readable, Transform } from 'stream';
import { fileURLToPath } from 'url';

const MAGIC_ENV = 'ARBORENV1';       // v71 .env-only format (still readable)
const MAGIC = 'ARBORBK2';            // v72: header | ciphertext | 16-byte tag (streamed)
const deriveKey = (pass, salt) => crypto.scryptSync(pass, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });

// ---- v71 .env backup format (kept so old backups can still be opened) ----------
export function encryptEnv(plain, pass) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', deriveKey(pass, salt), iv);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([Buffer.from(MAGIC_ENV), salt, iv, c.getAuthTag(), ct]);
}
export function decryptEnv(blob, pass) {
  if (blob.subarray(0, MAGIC_ENV.length).toString() !== MAGIC_ENV) throw new Error('not an Arbor encrypted env backup');
  let o = MAGIC_ENV.length;
  const salt = blob.subarray(o, o += 16), iv = blob.subarray(o, o += 12), tag = blob.subarray(o, o += 16);
  const d = crypto.createDecipheriv('aes-256-gcm', deriveKey(pass, salt), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(blob.subarray(o)), d.final()]);
}

// ---- v72 streamed format ---------------------------------------------------------
/** Transform: plaintext in → MAGIC | salt | iv | ciphertext | tag out. */
export function encryptStream(pass) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', deriveKey(pass, salt), iv);
  let started = false;
  const header = () => { if (!started) { started = true; return Buffer.concat([Buffer.from(MAGIC), salt, iv]); } return null; };
  return new Transform({
    transform(chunk, _e, cb) { const h = header(); if (h) this.push(h); cb(null, c.update(chunk)); },
    flush(cb) { const h = header(); if (h) this.push(h); this.push(c.final()); this.push(c.getAuthTag()); cb(); },
  });
}
/** Stream-decrypt a v72 backup file to `out`. Throws if the key is wrong or the file
 *  was altered — then discard whatever was written. */
export async function decryptFileTo(file, pass, out) {
  const fd = fs.openSync(file, 'r');
  const size = fs.fstatSync(fd).size;
  const head = Buffer.alloc(MAGIC.length + 28);
  fs.readSync(fd, head, 0, head.length, 0);
  if (head.subarray(0, MAGIC.length).toString() !== MAGIC) { fs.closeSync(fd); throw new Error('not an Arbor v72 backup file'); }
  const tag = Buffer.alloc(16);
  fs.readSync(fd, tag, 0, 16, size - 16);
  fs.closeSync(fd);
  const salt = head.subarray(MAGIC.length, MAGIC.length + 16), iv = head.subarray(MAGIC.length + 16);
  const d = crypto.createDecipheriv('aes-256-gcm', deriveKey(pass, salt), iv);
  d.setAuthTag(tag);
  const src = size - 16 > head.length ? fs.createReadStream(file, { start: head.length, end: size - 17 }) : Readable.from([]);
  await pipeline(src, d, out);
}

// libpq settings for pg_dump from the server's own configuration. The password goes
// in the child's ENVIRONMENT, never on its command line (visible to other users).
export function pgEnv(env = process.env) {
  const out = {};
  if (env.DATABASE_URL) {
    const u = new URL(env.DATABASE_URL);
    out.PGHOST = decodeURIComponent(u.hostname.replace(/^\[|\]$/g, ''));
    if (u.port) out.PGPORT = u.port;
    if (u.username) out.PGUSER = decodeURIComponent(u.username);
    if (u.password) out.PGPASSWORD = decodeURIComponent(u.password);
    out.PGDATABASE = decodeURIComponent(u.pathname.replace(/^\//, ''));
    const q = u.searchParams.get('sslmode'); if (q) out.PGSSLMODE = q;
  } else {
    for (const k of ['PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD', 'PGDATABASE']) if (env[k]) out[k] = env[k];
    out.PGHOST = out.PGHOST || 'localhost'; out.PGUSER = out.PGUSER || 'arbor'; out.PGDATABASE = out.PGDATABASE || 'arbor';
  }
  // Same TLS posture as storage-pg.js: verified by default for a DATABASE_URL.
  const mode = (env.PGSSL || '').toLowerCase();
  if (!out.PGSSLMODE) {
    if (mode === 'disable') out.PGSSLMODE = 'disable';
    else if (mode === 'no-verify') out.PGSSLMODE = 'require';
    else if (mode === 'require' || mode === 'verify' || mode === 'verify-full' || env.DATABASE_URL) out.PGSSLMODE = 'verify-full';
    else out.PGSSLMODE = 'prefer';
  }
  if (env.PGSSLROOTCERT) out.PGSSLROOTCERT = env.PGSSLROOTCERT;
  return out;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain && (process.argv[2] === '--decrypt' || process.argv[2] === '--decrypt-env')) {
  const file = process.argv[3];
  const pass = process.env.ARBOR_BACKUP_KEY;
  if (!file || !pass) { console.error('usage: ARBOR_BACKUP_KEY=... node scripts/backup.mjs --decrypt <file.enc> > <out>'); process.exit(2); }
  try {
    const first = Buffer.alloc(MAGIC_ENV.length);
    const fd = fs.openSync(file, 'r'); fs.readSync(fd, first, 0, first.length, 0); fs.closeSync(fd);
    if (first.toString() === MAGIC_ENV) process.stdout.write(decryptEnv(fs.readFileSync(file), pass));
    else await decryptFileTo(file, pass, process.stdout);
  } catch (e) {
    console.error('[backup] decryption FAILED (wrong key, or the file was altered) — discard the output:', e.message);
    process.exit(1);
  }
} else if (isMain) {
  const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const dataDir = path.resolve(process.env.ARBOR_DATA_DIR || appDir);
  const backupDir = process.env.ARBOR_BACKUP_DIR || path.join(dataDir, 'backups');
  const keep = parseInt(process.env.ARBOR_BACKUP_KEEP || '14', 10);
  const pass = process.env.ARBOR_BACKUP_KEY || '';
  const enc = pass.length >= 16;
  const backend = (process.env.STORAGE_BACKEND || (process.env.DATABASE_URL ? 'postgres' : 'sqlite')).toLowerCase();

  if (backend !== 'postgres') { console.error('[backup] this script backs up the Postgres database (production); STORAGE_BACKEND is ' + backend); process.exit(1); }
  if (!enc && process.env.ARBOR_BACKUP_ALLOW_PLAINTEXT !== '1') {
    console.error('[backup] refusing: set ARBOR_BACKUP_KEY (16+ characters, stored outside the backup location) — the database is never written unencrypted. (ARBOR_BACKUP_ALLOW_PLAINTEXT=1 overrides this on purpose.)');
    process.exit(1);
  }
  fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[:T]/g, '-').replace(/\..*$/, '').slice(0, 19) + '-' + crypto.randomBytes(2).toString('hex');

  // 1. Database: pg_dump (a consistent snapshot while the server keeps running).
  const dumpFile = path.join(backupDir, `arbor-${stamp}.dump${enc ? '.enc' : ''}`);
  const tmp = dumpFile + '.partial';
  const child = spawn(process.env.PG_DUMP || 'pg_dump', ['--format=custom', '--no-owner', '--no-privileges'], {
    env: { ...process.env, ...pgEnv() }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let errText = '';
  child.stderr.on('data', d => { errText += d; });
  const exited = new Promise((resolve) => { child.on('error', (e) => resolve({ code: -1, err: e })); child.on('close', (code) => resolve({ code })); });
  try {
    const out = fs.createWriteStream(tmp, { mode: 0o600 });
    if (enc) await pipeline(child.stdout, encryptStream(pass), out);
    else await pipeline(child.stdout, out);
  } catch (e) { errText += '\n' + e.message; }
  const { code, err } = await exited;
  if (code !== 0) {
    try { fs.unlinkSync(tmp); } catch {}
    console.error(`[backup] pg_dump FAILED (${err ? err.message : 'exit ' + code}): ${errText.trim().slice(0, 2000)}`);
    process.exit(1);
  }
  fs.renameSync(tmp, dumpFile);
  console.log(`[backup] wrote ${dumpFile} (${(fs.statSync(dumpFile).size / 1024).toFixed(0)} KB)`);

  // 2. Secrets the database can't be restored without.
  if (enc) {
    const bundle = {};
    const envSrc = path.join(appDir, '.env');
    if (fs.existsSync(envSrc)) bundle.env = fs.readFileSync(envSrc, 'utf8');
    for (const f of ['server-salt.json', 'vapid.json']) {
      for (const dir of [dataDir, appDir]) {
        const p = path.join(dir, f);
        if (fs.existsSync(p)) { bundle[f] = fs.readFileSync(p, 'utf8'); break; }
      }
    }
    const secFile = path.join(backupDir, `secrets-${stamp}.json.enc`);
    await pipeline(Readable.from([Buffer.from(JSON.stringify(bundle))]), encryptStream(pass), fs.createWriteStream(secFile, { mode: 0o600 }));
    console.log(`[backup] wrote encrypted ${secFile} (${Object.keys(bundle).join(', ') || 'nothing found'})`);
  } else {
    console.warn('[backup] ARBOR_BACKUP_ALLOW_PLAINTEXT: the database dump is UNENCRYPTED and the secrets (.env, salt, VAPID) were NOT backed up — back them up separately.');
  }
  const legacyPlain = path.join(backupDir, 'env.backup');
  if (fs.existsSync(legacyPlain)) { fs.unlinkSync(legacyPlain); console.log('[backup] removed legacy PLAINTEXT env.backup'); }

  // 3. Keep the newest `keep` of each kind.
  for (const re of [/^arbor-.*\.dump(\.enc)?$/, /^secrets-.*\.json\.enc$/]) {
    const old = fs.readdirSync(backupDir).filter(f => re.test(f)).sort().reverse().slice(keep);
    for (const f of old) { fs.unlinkSync(path.join(backupDir, f)); console.log(`[backup] pruned ${f}`); }
  }
}
