// ---------------------------------------------------------------------------
// Storage backend selector.
//
// server.js imports storage exclusively from here and awaits every call. Both
// backends satisfy that: `await` on a synchronous return value resolves
// immediately, so the SQLite path is unchanged in behaviour and cost, while the
// Postgres path is genuinely asynchronous.
//
// That single property is what makes this migration safe: ONE code path serves
// both engines, so switching is an environment variable, and rolling back is
// the same variable. There is no half-migrated state to reason about.
//
//   STORAGE_BACKEND=sqlite      (default when DATABASE_URL is unset)
//   STORAGE_BACKEND=postgres    (default when DATABASE_URL is set)
//
// The chosen module is imported dynamically, so the unused backend is never
// loaded — importing storage.js has side effects (it creates the data
// directory and opens arbor.db), which we must not trigger when running on
// Postgres.
// ---------------------------------------------------------------------------

export const BACKEND = (process.env.STORAGE_BACKEND
  || (process.env.DATABASE_URL ? 'postgres' : 'sqlite')).toLowerCase();

if (!['sqlite', 'postgres'].includes(BACKEND)) {
  throw new Error(`Unknown STORAGE_BACKEND "${BACKEND}" — expected "sqlite" or "postgres".`);
}

const impl = BACKEND === 'postgres'
  ? await import('./storage-pg.js')
  : await import('./storage.js');

export const messagesStore = impl.messagesStore;
export const backupsStore = impl.backupsStore;
export const attachmentsStore = impl.attachmentsStore;
export const avatarsStore = impl.avatarsStore;
export const metaStore = impl.metaStore;          // v72: reactions, acks, retraction tombstones
export const scheduledStore = impl.scheduledStore; // v72: scheduled (future-dated) sends
export const loadSnapshots = impl.loadSnapshots;
export const persistSnapshots = impl.persistSnapshots;
// Live DB pool counters (Postgres only; null on SQLite, which has no pool).
export const poolStats = impl.poolStats || (() => null);
// On-disk database size in bytes (admin storage monitor); null if unknown.
export const dbSizeBytes = impl.dbSizeBytes || (() => null);

/** Create tables/indexes if absent. SQLite does this at import; Postgres needs
 *  an awaited round trip, so callers must await this before first use. */
export async function initStorage() {
  if (impl.initSchema) await impl.initSchema();
}

/** One-time db.json import — a SQLite-era concern only. On Postgres the data
 *  arrives via migrate-sqlite-to-pg.js instead, so this is a no-op. */
export function migrateFromJsonIfPresent() {
  return impl.migrateFromJsonIfPresent ? impl.migrateFromJsonIfPresent() : false;
}

export async function closeStorage() {
  if (impl.close) await impl.close();
  else if (impl.db?.close) impl.db.close();
}
