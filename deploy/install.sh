#!/usr/bin/env bash
# Arbor production install — run as root from the repo root:  sudo bash deploy/install.sh
# Idempotent: safe to re-run for redeploys (preserves .env and all data).
set -euo pipefail

APP_DIR=/opt/arbor
DATA_DIR=/var/lib/arbor
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "== Arbor install: $SRC_DIR -> $APP_DIR (data: $DATA_DIR) =="

command -v node >/dev/null || { echo "node not found — install Node 20+ first"; exit 1; }
NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')
[ "$NODE_MAJOR" -ge 20 ] || { echo "Node 20+ required (found $(node -v))"; exit 1; }

# 1. Service user + directories
id -u arbor &>/dev/null || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin arbor
mkdir -p "$DATA_DIR" && chown arbor:arbor "$DATA_DIR" && chmod 700 "$DATA_DIR"
mkdir -p "$APP_DIR"

# 2. Sync app (preserve the live .env if one exists in APP_DIR)
if [ "$SRC_DIR" != "$APP_DIR" ]; then
  [ -f "$APP_DIR/.env" ] && cp "$APP_DIR/.env" /tmp/arbor-env-keep
  rsync -a --delete --exclude node_modules --exclude '.env' --exclude 'arbor.db*' \
    --exclude 'server-salt.json' --exclude 'vapid.json' "$SRC_DIR/" "$APP_DIR/"
  [ -f /tmp/arbor-env-keep ] && mv /tmp/arbor-env-keep "$APP_DIR/.env"
fi

# 3. First-run .env
ENV_FILE="$APP_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  if [ -f "$SRC_DIR/.env" ]; then cp "$SRC_DIR/.env" "$ENV_FILE";
  else
    cp "$APP_DIR/.env.example" "$ENV_FILE"
    echo ">> Wrote fresh .env from .env.example — fill in DATABASE_URL, PUBLIC_ORIGIN and payment keys."
  fi
fi
has() { grep -q "^$1=." "$ENV_FILE"; }
add() { grep -v "^$1=" "$ENV_FILE" > "$ENV_FILE.tmp" || true; echo "$1=$2" >> "$ENV_FILE.tmp"; mv "$ENV_FILE.tmp" "$ENV_FILE"; }
has ARBOR_DATA_DIR || add ARBOR_DATA_DIR "$DATA_DIR"
# Behind Caddy/nginx (deploy/Caddyfile, deploy/nginx.conf): trust exactly one proxy hop.
has TRUST_PROXY || add TRUST_PROXY 1
# v72 B5: the server salt must never change once accounts exist. Only create one if
# neither .env nor a salt file (data dir, or next to the code from an older version)
# already has it — the server refuses to start with a salt that doesn't match its DB.
if ! has SERVER_SALT && [ ! -f "$DATA_DIR/server-salt.json" ] && [ ! -f "$APP_DIR/server-salt.json" ]; then
  add SERVER_SALT "$(node -e 'console.log(require("crypto").randomBytes(32).toString("hex"))')"
  echo ">> Generated SERVER_SALT in .env"
fi
# Backups are encrypted with ARBOR_BACKUP_KEY (scripts/backup.mjs refuses to run without it).
if ! has ARBOR_BACKUP_KEY; then
  add ARBOR_BACKUP_KEY "$(node -e 'console.log(require("crypto").randomBytes(24).toString("base64url"))')"
  echo ">> Generated ARBOR_BACKUP_KEY in .env — COPY IT TO A PASSWORD MANAGER NOW:"
  echo "   without it, the backups can't be restored if this server is lost."
fi
chown arbor:arbor "$ENV_FILE" && chmod 600 "$ENV_FILE"

# 4. Dependencies + client build (as the service user, app dir stays root-owned/read-only)
cd "$APP_DIR"
npm ci --omit=dev 2>/dev/null || npm install --omit=dev
if [ ! -d dist ]; then
  npm install            # dev deps needed once for vite build
  npm run build
  npm prune --omit=dev
fi

# 4b. v72 B5: push (VAPID) keys, same rule as the salt: create once, then keep —
# new keys would silently break every existing push subscription.
if ! has VAPID_PUBLIC_KEY && [ ! -f "$DATA_DIR/vapid.json" ] && [ ! -f "$APP_DIR/vapid.json" ]; then
  KEYS=$(cd "$APP_DIR" && node -e 'const k=require("web-push").generateVAPIDKeys();console.log(k.publicKey+" "+k.privateKey)')
  add VAPID_PUBLIC_KEY "${KEYS% *}"
  add VAPID_PRIVATE_KEY "${KEYS#* }"
  chown arbor:arbor "$ENV_FILE" && chmod 600 "$ENV_FILE"
  echo ">> Generated VAPID push keys in .env"
fi

# 4c. Settings only you can provide — the server refuses to start in production without them.
MISSING=""
has DATABASE_URL || MISSING="$MISSING DATABASE_URL"
grep -q '^PUBLIC_ORIGIN=https://' "$ENV_FILE" || MISSING="$MISSING PUBLIC_ORIGIN(https://your.domain)"
if [ -n "$MISSING" ]; then
  echo "!! Set these in $ENV_FILE, then re-run this script:$MISSING"
  echo "   (see .env.example and PRODUCTION.md)"
  exit 1
fi
command -v pg_dump >/dev/null || echo "!! pg_dump not found — install the PostgreSQL client (same major version as the server) or nightly backups will fail."

# 5. systemd units
cp deploy/arbor.service deploy/arbor-backup.service deploy/arbor-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now arbor
systemctl enable --now arbor-backup.timer
systemctl restart arbor

sleep 1
if curl -fsS http://127.0.0.1:3000/healthz >/dev/null; then
  echo "== Arbor is up: http://127.0.0.1:3000 =="
else
  echo "!! Health check failed — inspect: journalctl -u arbor -n 50"; exit 1
fi
echo "Next: point Caddy or nginx at it (deploy/Caddyfile or deploy/nginx.conf)"
echo "      and set TURN_* in $APP_DIR/.env (deploy/turnserver.conf) for calls."
