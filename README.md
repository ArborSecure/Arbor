# Arbor

**End-to-end encrypted messaging with structure.**

Arbor is a private messenger built around networks that branch like a tree. Every person is a node: you invite people beneath you, and what anyone can read depends on where they sit in the structure. That boundary is enforced by encryption, not by server-side permission checks. Each message is encrypted only to the people allowed to read it, so the server holds nothing but sealed ciphertext and opaque identifiers.

Live at [arborsecure.app](https://arborsecure.app) · Version 1.0.0

## Features

- **End-to-end encrypted** with the Signal protocol (X3DH + Double Ratchet): forward secrecy, trust-on-first-use key pinning, safety-number verification, and a warning when a contact's key changes.
- **Three network shapes:**
  - a hierarchical **Network**, where you invite people beneath you;
  - a one-to-one **Direct** roster;
  - a **Personal** hub for your own chats.
- **Chats that follow the tree.** Your Descendants chat is a group with everyone you invited directly, and it appears as the Ancestors chat on their side.
- **Isolated groups.** Groups are separate chats with their own members and keys, walled off from each other and from the main chat. Groups can be linked when you want them to talk.
- **Bounded oversight.** A network can allow monitoring, but a leader can read at most two levels below them. The cap applies to the founder too, and the network owner can turn monitoring off entirely. Messages outside that window are never encrypted to the leader, so they can't be read rather than merely being hidden.
- **Encrypted voice and video calls.** Signaling travels through the encrypted channel, and media is WebRTC DTLS-SRTP with fingerprints verified end to end. Group calls are a mesh of pairwise-encrypted connections, with no media server in the middle.
- **Encrypted attachments**, with photo and video metadata (location, camera details) stripped before upload. The server also strips image metadata and refuses anything it can't verify.
- **Encrypted on your device too.** Messages, keys and drafts stored on the device are sealed under a key derived from your password.
- **You hold the keys:**
  - a 12-word recovery phrase that only you keep;
  - a panic button that wipes the device;
  - account deletion.
- **No phone number or email required.** Sign-ups are rate-limited with a proof-of-work check instead.

## How it works

- Content is encrypted once with a fresh content key. That key is delivered separately to each allowed recipient over their Signal session.
- The recipient list is computed from the tree. A copy is never made for anyone outside it, so the boundaries are cryptographic.
- The server routes ciphertext, stores sealed blobs and enforces membership. It never sees message text, media or the keys to them, and the server's own clock stamps message times.

## Tech stack

- **Client:** React, TypeScript, Vite, Tailwind, and `@privacyresearch/libsignal-protocol-typescript`. It runs as an installable web app.
- **Server:** Node.js 20+ and Express.
- **Database:** PostgreSQL in production. SQLite is supported for local development.
- **Push:** Web Push (VAPID) notifications carry no message content.

## Running locally

Requires Node.js 20 or newer. The browser must be on a secure context (HTTPS, or `http://localhost`); the crypto layer refuses to run otherwise.

```bash
npm install
npm run build      # builds the client into dist/
npm start          # serves dist/ and the API on :3000 (SQLite when no DATABASE_URL is set)
```

For hot reload, run `npm start` in one terminal and `npm run dev` in another. Vite serves on :5173 and proxies `/api` to :3000.

## Production

- `deploy/install.sh` (run as root) sets up the service user, directories, the systemd unit and a nightly backup timer. It's safe to re-run for redeploys and keeps `.env` and all data. PostgreSQL must already be installed.
- Reverse proxy examples are in `deploy/Caddyfile` and `deploy/nginx.conf`. A coturn template for calls is in `deploy/turnserver.conf`.
- Copy `.env.example` to `.env` and fill it in; every setting is documented there. In production the server refuses to start unless the essentials are set.
- **Keep the server salt and VAPID keys safe.** Every public ID is derived from the salt, so changing it breaks every account. Changing the VAPID keys breaks every push subscription.
- `scripts/backup.mjs` makes encrypted backups and needs `ARBOR_BACKUP_KEY`. Copy backups off the server.

## Security

Found a flaw? Please report it responsibly to **bugreports@arborsecure.app**. Security is an ongoing process done in the open, not a one-time claim: read the code, and tell us what you find.

General contact: contact@arborsecure.app

## License

Arbor is free and open-source software under the [GNU General Public License v3.0](LICENSE).

Arbor is an independent project. It uses the open Signal **protocol** and is **not affiliated with, endorsed by, or connected to** Signal Messenger LLC or the Signal Foundation. "Signal" is a trademark of its respective owners.
