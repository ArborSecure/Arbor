/**
 * Sealed device-local key/value store for UI data that contains MESSAGE TEXT:
 * unsent drafts and the sender's own copy of scheduled messages.
 *
 * Security review V8 M-12: both used to live in PLAINTEXT localStorage (and
 * survived an ordinary logout), unlike the message/snapshot/Signal stores, which
 * are AES-GCM-sealed under the account wrap key. This store closes that gap:
 *   - values are held in memory for synchronous reads (the composer needs them
 *     on every keystroke / conversation switch);
 *   - every write is persisted as ONE blob sealed with keyStore.wrapBytes (the
 *     same non-extractable account key that protects the other local stores);
 *   - if the session is locked (no wrap key), NOTHING is written to disk — data
 *     stays in memory rather than falling back to plaintext;
 *   - legacy plaintext entries (arbor_draft_*, arbor_scheduled_v1) are imported
 *     on first load and deleted;
 *   - clearAll() runs on logout and Panic Wipe.
 */
import { wrapBytes, unwrapBytes, hasWrapKey, ensureWrapKey, needsReseal } from './keyStore';

const STORE_KEY = 'arbor_sealed_local_v1';
const LEGACY_PREFIXES = ['arbor_draft_'];
const LEGACY_KEYS = ['arbor_scheduled_v1'];

let mem: Record<string, string> = {};
let loadPromise: Promise<void> | null = null;
let loaded = false;
let persistTimer: ReturnType<typeof setTimeout> | null = null;

const enc = new TextEncoder();
const dec = new TextDecoder();

/** Load + unseal (idempotent). Safe to call repeatedly; resolves once loaded. */
export function init(): Promise<void> {
  if (loaded) return Promise.resolve();
  if (loadPromise) return loadPromise;
  loadPromise = (async () => {
    if (!hasWrapKey()) await ensureWrapKey();
    if (!hasWrapKey()) { loadPromise = null; return; }           // locked: retry on a later call
    let restored: Record<string, string> = {};
    try {
      const blob = localStorage.getItem(STORE_KEY);
      if (blob) restored = JSON.parse(dec.decode(await unwrapBytes(blob))) || {};
    } catch { restored = {}; }
    // Import + delete legacy plaintext entries.
    let migrated = false;
    try {
      for (let i = localStorage.length - 1; i >= 0; i--) {
        const k = localStorage.key(i);
        if (!k) continue;
        if (LEGACY_PREFIXES.some(p => k.startsWith(p)) || LEGACY_KEYS.includes(k)) {
          const v = localStorage.getItem(k);
          if (v != null && restored[k] == null) restored[k] = v;
          localStorage.removeItem(k);
          migrated = true;
        }
      }
    } catch { /* ignore */ }
    mem = { ...restored, ...mem };                               // in-memory writes made while loading win
    loaded = true;
    if (migrated) schedulePersist();
  })();
  return loadPromise;
}
export function isLoaded(): boolean { return loaded; }

function schedulePersist(): void {
  if (persistTimer) return;
  persistTimer = setTimeout(async () => {
    persistTimer = null;
    try {
      if (!hasWrapKey()) await ensureWrapKey();
      if (!hasWrapKey()) return;                                 // never persist in the clear
      const sealed = await wrapBytes(enc.encode(JSON.stringify(mem)).buffer as ArrayBuffer);
      localStorage.setItem(STORE_KEY, sealed);
    } catch { /* storage full / locked — memory copy survives this session */ }
  }, 250);
}

/** v71: after a key change (KDF upgrade / password change), re-seal the stored blob
 *  under the current key while an earlier key can still open it. A blob no key
 *  opens is left alone, and a newer write made meanwhile always wins. */
export async function resealNow(): Promise<void> {
  const blob = localStorage.getItem(STORE_KEY);
  if (!blob || !(await needsReseal(blob))) return;
  const sealed = await wrapBytes(await unwrapBytes(blob));
  if (localStorage.getItem(STORE_KEY) === blob) localStorage.setItem(STORE_KEY, sealed);
}

export function get(key: string): string | null { return Object.prototype.hasOwnProperty.call(mem, key) ? mem[key] : null; }
export function set(key: string, value: string): void { mem[key] = value; schedulePersist(); }
export function remove(key: string): void { if (Object.prototype.hasOwnProperty.call(mem, key)) { delete mem[key]; schedulePersist(); } }

/** Wipe everything (logout / Panic Wipe), including any legacy plaintext leftovers. */
export function clearAll(): void {
  mem = {};
  loaded = false;
  loadPromise = null;
  if (persistTimer) { clearTimeout(persistTimer); persistTimer = null; }
  try {
    localStorage.removeItem(STORE_KEY);
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k && (LEGACY_PREFIXES.some(p => k.startsWith(p)) || LEGACY_KEYS.includes(k))) localStorage.removeItem(k);
    }
  } catch { /* ignore */ }
}
