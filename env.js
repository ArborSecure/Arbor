// Loads .env BEFORE any other module reads process.env.
//
// This must be the FIRST import in server.js: ES module imports execute in
// order, and storage.js reads ARBOR_DATA_DIR at import time — loading .env
// from server.js's own body (the old approach) ran too late for it.
//
// Also anchors to the .env sitting NEXT TO THE APP rather than process.cwd(),
// so `systemctl start arbor` or launching from another directory still works.
// Real environment variables always win over .env values.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)));
const file = path.join(dir, '.env');

try {
  if (fs.existsSync(file)) {
    if (process.loadEnvFile) {
      process.loadEnvFile(file); // Node 20.12+ / 21.7+
    } else {
      // Minimal fallback parser for older Node: KEY=VALUE lines, # comments,
      // optional single/double quotes around the value.
      for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t.startsWith('#')) continue;
        const i = t.indexOf('=');
        if (i < 1) continue;
        const k = t.slice(0, i).trim();
        let v = t.slice(i + 1).trim();
        if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
        if (!(k in process.env)) process.env[k] = v;
      }
    }
  }
} catch (e) {
  console.warn('[env] failed to load .env:', e.message);
}
