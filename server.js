import './env.js'; // MUST be first: loads .env before storage.js reads ARBOR_DATA_DIR
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import './async-errors.js'; // Express 4: forward async handler rejections to the error pipeline
import { messagesStore, backupsStore, attachmentsStore, avatarsStore, metaStore, scheduledStore, loadSnapshots, persistSnapshots, migrateFromJsonIfPresent, initStorage, BACKEND, poolStats, dbSizeBytes } from './storage-adapter.js';
import { scrubImageDataUrl, ImageRejected } from './imageScrub.js';
import _rateLimit from 'express-rate-limit';
// Load-test ONLY: rate limiters become no-ops so a single-IP generator can seed at
// scale. Double-gated — requires LOADTEST=1 AND a database literally named *loadtest*
// — so it can NEVER engage on prod (whose DB is not a loadtest DB), even if the env
// var were somehow set. A complete no-op in every normal deployment.
const _loadtestMode = process.env.LOADTEST === '1' && /loadtest/i.test(process.env.DATABASE_URL || '');
// v71 H3: one shared client key for every IP-keyed limiter. express-rate-limit 7
// keys each full IPv6 address separately, so a single /64 (2^64 addresses) was an
// unlimited supply of fresh budgets. IPv6 clients are grouped by /56 (the smallest
// allocation ISPs commonly hand one customer); IPv4-mapped addresses use the IPv4.
const ipKey = (req) => {
  const ip = String(req.ip || (req.socket && req.socket.remoteAddress) || '');
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) return mapped[1];
  if (ip.includes(':')) {
    const b = ipv6Bytes(ip);
    if (b) return 'v6:' + Array.from(b.subarray(0, 7), x => x.toString(16).padStart(2, '0')).join('') + '::/56';
  }
  return ip;
};
const rateLimit = _loadtestMode ? (() => (req, res, next) => next()) : ((opts) => _rateLimit({ keyGenerator: ipKey, ...opts }));
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import webpush from 'web-push';
import os from 'node:os';
import zlib from 'node:zlib';
import https from 'node:https';
import { isSafePushEndpoint, safeLookup, ipv6Bytes } from './netGuard.js';
import { monitorEventLoopDelay } from 'node:perf_hooks';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.resolve(path.dirname(__filename));

const app = express();
app.set('query parser', 'simple'); // flat querystring, not qs (see the urlencoded note below)
// Trust proxy is OFF by default so a directly-exposed server cannot have its rate
// limiting bypassed by a spoofed X-Forwarded-For. Set TRUST_PROXY (e.g. "1" or a
// CIDR) ONLY when running behind a known reverse proxy / TLS terminator.
const TRUST_PROXY = process.env.TRUST_PROXY;
if (TRUST_PROXY !== undefined && TRUST_PROXY !== '') {
  app.set('trust proxy', /^\d+$/.test(TRUST_PROXY) ? Number(TRUST_PROXY) : TRUST_PROXY);
} else {
  app.set('trust proxy', false);
}

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');
const DIST_PATH = path.join(__dirname, 'dist');
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const IS_PROD = process.env.NODE_ENV === 'production';

// ---------------------------------------------------------------------------
// v72 B5: production refuses to start on a configuration that can't work safely,
// instead of failing later in ways that are hard to see.
// ---------------------------------------------------------------------------
if (IS_PROD) {
  const problems = [];
  const pub = process.env.PUBLIC_ORIGIN || '';
  if (BACKEND !== 'postgres') problems.push('production runs on Postgres: set DATABASE_URL (STORAGE_BACKEND=postgres)');
  if (!/^https:\/\/[^/]+$/.test(pub.replace(/\/+$/, ''))) problems.push('set PUBLIC_ORIGIN to the site’s https:// address (e.g. https://arbor.example) — payment redirects and HTTPS redirects are built from it');
  if (!TRUST_PROXY) problems.push('set TRUST_PROXY=1 — Arbor runs behind a TLS proxy (Caddy/nginx); without it every visitor shares the proxy’s address, so one person can rate-limit everyone');
  if (!process.env.ARBOR_DATA_DIR) problems.push('set ARBOR_DATA_DIR (e.g. /var/lib/arbor) — the server salt and push keys are kept there');
  for (const k of ['PREMIUM_DAY_MS', 'GRACE_MS_OVERRIDE', 'LOADTEST']) {
    if (process.env[k]) problems.push(`remove ${k} — it is a test-only override (it changes billing periods / rate limits)`);
  }
  if (problems.length) {
    console.error('FATAL: refusing to start in production:\n  - ' + problems.join('\n  - '));
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// v72 B5: persisted secrets live in the DATA directory. v71 wrote them next to
// the code, which the systemd unit makes read-only: the write failed silently and
// a NEW salt (and new push keys) were made on every restart — every public id and
// username hash changed, so no one could log in. Now: SERVER_SALT / VAPID_* from
// the environment win; otherwise the file in ARBOR_DATA_DIR (a file left next to
// the code by an older version is still read, and copied over); otherwise a new
// one is created there. In production a secret that can't be saved stops the boot.
// ---------------------------------------------------------------------------
const DATA_DIR = path.resolve(process.env.ARBOR_DATA_DIR || __dirname);
const persistedSecret = (name, make, envHint) => {
  const file = path.join(DATA_DIR, name);
  for (const f of [file, path.join(__dirname, name)]) {
    if (!fs.existsSync(f)) continue;
    const v = JSON.parse(fs.readFileSync(f, 'utf8'));
    if (f !== file) { try { fs.writeFileSync(file, JSON.stringify(v), { mode: 0o600, flag: 'wx' }); } catch {} }
    return { v, created: false };
  }
  const v = make();
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, JSON.stringify(v), { mode: 0o600, flag: 'wx' });
  } catch (e) {
    const msg = `cannot save ${name} in ${DATA_DIR} (${e.message}) — it would change on every restart. Make ARBOR_DATA_DIR writable or set ${envHint} in .env`;
    if (IS_PROD) { console.error('FATAL: ' + msg); process.exit(1); }
    console.warn('[WARN] ' + msg);
  }
  return { v, created: true };
};

// Stable server salt: public-id HMAC, username hashes, anti-enumeration fake salts.
let SERVER_SALT = process.env.SERVER_SALT;
let SALT_CREATED = false;
if (!SERVER_SALT) {
  const s = persistedSecret('server-salt.json', () => ({ salt: crypto.randomBytes(32).toString('hex') }), 'SERVER_SALT');
  SERVER_SALT = s.v.salt; SALT_CREATED = s.created;
}
// A fingerprint of the salt is stored in the database (initDB): starting with a
// DIFFERENT salt — a lost file, a wrong SERVER_SALT — would silently lock every
// account out, so it stops the boot instead.
const SALT_CHECK = crypto.createHmac('sha256', SERVER_SALT).update('arbor-salt-check-v1').digest('hex').slice(0, 32);

// ---------------------------------------------------------------------------
// Security headers. CSP: scripts are SELF-ONLY (no CDNs, no inline) so a CDN
// compromise or injected inline script cannot run in our origin and read keys or
// plaintext. Styles/fonts are allowed inline / from Google Fonts (not a script
// execution vector); self-hosting fonts is the next hardening step.
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'blob:'],
      mediaSrc: ["'self'", 'data:', 'blob:'],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  // Align the legacy X-Frame-Options header with CSP frame-ancestors 'none'
  // (helmet defaults to SAMEORIGIN, which is more permissive than the CSP).
  frameguard: { action: 'deny' },
  crossOriginEmbedderPolicy: false,
}));

// CORS: same-origin only by default. Set ALLOWED_ORIGINS (comma-separated) to opt
// in. credentials:true so cross-origin (if explicitly allowed) can send the cookie.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: allowedOrigins.length ? allowedOrigins : false, credentials: true }));

// Cross-site request refusal (login-CSRF / signup-CSRF defence, V8 M-10).
// The authenticated API already requires an X-CSRF-Token, but the PRE-session
// routes (signup, login, salt, recovery) can't — there is no session yet — and a
// forged cross-site <form> POST to them would plant an attacker-known session
// cookie in the victim's browser. Browsers tag every request with Sec-Fetch-Site;
// anything other than same-origin (or 'none' = user-typed) is refused for every
// state-changing /api call. Older browsers without Fetch Metadata still send
// Origin on cross-site POSTs, so that is checked as the fallback. Server-to-server
// webhooks (Stripe, NOWPayments) send neither header and are exempt by path.
const CROSS_SITE_EXEMPT = new Set(['/api/billing/stripe/webhook', '/api/billing/monero/ipn']);
const originAllowed = (origin, req) => {
  if (allowedOrigins.includes(origin)) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
};
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  if (CROSS_SITE_EXEMPT.has(req.originalUrl.split('?')[0])) return next();
  const sfs = req.headers['sec-fetch-site'];
  if (sfs && sfs !== 'same-origin' && sfs !== 'none') {
    const origin = req.headers.origin;
    // An explicitly allow-listed cross-origin client (ALLOWED_ORIGINS) is fine.
    if (!(origin && allowedOrigins.includes(origin))) return res.status(403).json({ error: 'Cross-site request refused' });
  }
  const origin = req.headers.origin;
  if (origin && origin !== 'null' && !originAllowed(origin, req)) return res.status(403).json({ error: 'Cross-site request refused' });
  if (origin === 'null') return res.status(403).json({ error: 'Cross-site request refused' });
  next();
});

// Optional hard redirect of any plain-HTTP request to HTTPS. Off by default so
// local/dev isn't affected; set FORCE_HTTPS=1 in production (behind a TLS proxy,
// also set TRUST_PROXY). The proxy should ideally redirect too — this is a belt.
app.use((req, res, next) => {
  if (process.env.FORCE_HTTPS === '1') {
    if (!isHttps(req)) {
      // v72 (L): only to the configured origin — v71 fell back to the request's own
      // Host header, i.e. a redirect to wherever the request said.
      if (!PUBLIC_ORIGIN) return res.status(400).type('text/plain').send('HTTPS required.');
      return res.redirect(301, PUBLIC_ORIGIN + req.originalUrl);
    }
  }
  next();
});

// ---------------------------------------------------------------------------
// Billing / paywall (free plan: FREE_TREE_LIMIT members per network).
// The Stripe webhook MUST be registered before express.json — signature
// verification requires the raw request bytes. It authenticates via the
// webhook signing secret, not a session.
// ---------------------------------------------------------------------------
const FREE_TREE_LIMIT = parseInt(process.env.FREE_TREE_LIMIT || '20', 10);
const PREMIUM_USD = 20;              // $/month
const PREMIUM_DAYS_PER_PAYMENT = 30; // one Monero payment buys this many days
// v72 (L): a payment provider's error text is logged here, never passed to the user —
// it can describe this server's account setup or key problems. The user gets a
// fixed message saying what failed.
const CARD_PAGE_FAILED = 'The card payment page could not be opened. Try again shortly.';
const MONERO_CREATE_FAILED = 'The Monero payment service could not create the payment. Try again shortly.';
const providerFailed = (res, tag, status, code, message) => {
  console.error(`[billing] ${tag} refused: HTTP ${status}${code ? ' ' + String(code).slice(0, 60) : ''}`);
  return res.status(502).json({ error: message });
};

// v71: opaque one-time checkout references (the payment provider never learns an
// internal account id) and the invoices each network's paid days came from.
const billingRef = (accountId, rootPid) => {
  const refs = (dbCache.billingRefs = dbCache.billingRefs || {});
  const cut = Date.now() - 30 * 864e5;
  for (const [k, v] of Object.entries(refs)) if (!v || v.at < cut) delete refs[k];
  const ref = 'cr_' + crypto.randomBytes(16).toString('hex');
  refs[ref] = { accountId, rootPid, at: Date.now() };
  persistDB();
  return ref;
};
const noteStripeInvoice = (acc, invoiceId, rootId, days) => {
  if (!acc || typeof invoiceId !== 'string' || !invoiceId) return;
  acc.stripeInvoices = acc.stripeInvoices || {};
  acc.stripeInvoices[invoiceId] = { rootId, days, at: Date.now() };
  // v72 M3: kept ~400 days (v71: the newest 24) — a refund or dispute of an older
  // payment must still find the invoice to take back the days it bought, and a
  // re-delivered invoice must still be recognised as already credited.
  const cut = Date.now() - 400 * 864e5;
  for (const k of Object.keys(acc.stripeInvoices)) if (!acc.stripeInvoices[k] || acc.stripeInvoices[k].at < cut) delete acc.stripeInvoices[k];
  const keys = Object.keys(acc.stripeInvoices);
  if (keys.length > 1000) for (const k of keys.sort((a, b) => acc.stripeInvoices[a].at - acc.stripeInvoices[b].at).slice(0, keys.length - 1000)) delete acc.stripeInvoices[k];
  persistDB();
};
// The account a checkout session was started by (the opaque one-time reference;
// sessions created before v71 carried the account id itself).
const checkoutAccount = (s) => {
  const ref = s && s.client_reference_id && hasOwn(dbCache.billingRefs || {}, s.client_reference_id) ? dbCache.billingRefs[s.client_reference_id] : null;
  const accountId = ref ? ref.accountId : (s?.client_reference_id || s?.metadata?.accountId);
  return (accountId && dbCache.accounts.find(a => a.id === accountId)) || null;
};
// A PAID checkout session buys 30 days for the network named in its metadata —
// exactly once, whether the webhook or the buyer's return (/stripe/confirm) gets
// here first. Returns the credited root, or null.
const applyCheckoutSession = (s) => {
  const acc = checkoutAccount(s);
  if (!acc || !s || s.payment_status !== 'paid') return null;
  if (typeof s.customer === 'string' && s.customer) acc.stripeCustomerId = s.customer; // links renewals back to the account
  const root = rootForPayment(acc.id, s.metadata?.rootId);
  if (!root) return null;
  // Remember which network this SUBSCRIPTION pays for, so renewals (invoice.paid)
  // extend that same network — not whichever one is biggest.
  const subId = typeof s.subscription === 'string' ? s.subscription : s.subscription?.id;
  if (subId) { acc.stripeSubs = acc.stripeSubs || {}; acc.stripeSubs[subId] = root.id; }
  const invoiceId = typeof s.invoice === 'string' ? s.invoice : s.invoice?.id;
  const key = invoiceId || ('cs:' + s.id);
  if (acc.stripeInvoices && hasOwn(acc.stripeInvoices, key)) return root;      // already credited
  grantPremium(root.id, 30); // day 30: Stripe auto-renews (invoice.paid extends)
  noteStripeInvoice(acc, key, root.id, 30);
  return root;
};

// v71 L3: the invoice a refunded charge / disputed payment belongs to. Older Stripe
// API versions put it on the charge; from 2025-03-31 ("basil") on it isn't there,
// and a dispute only names its charge and payment intent — so it is looked up from
// the payment intent through the InvoicePayments API. Returns null when there is
// no such invoice, undefined when the lookup itself failed (Stripe should retry).
const stripeInvoiceFor = async (obj) => {
  const charge = obj && obj.object === 'dispute' ? (obj.charge && typeof obj.charge === 'object' ? obj.charge : null) : obj;
  if (charge && typeof charge.invoice === 'string' && charge.invoice) return charge.invoice;
  const pi = typeof obj?.payment_intent === 'string' ? obj.payment_intent : (charge && typeof charge.payment_intent === 'string' ? charge.payment_intent : null);
  const KEY = process.env.STRIPE_SECRET_KEY;
  if (!pi || !KEY) return null;
  try {
    const r = await fetch(`https://api.stripe.com/v1/invoice_payments?payment[type]=payment_intent&payment[payment_intent]=${encodeURIComponent(pi)}&limit=1`,
      { headers: { Authorization: `Bearer ${KEY}`, 'Stripe-Version': '2025-03-31.basil' }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return r.status >= 500 || r.status === 429 ? undefined : null;
    const j = await r.json();
    const ip = Array.isArray(j?.data) ? j.data[0] : null;
    return ip && typeof ip.invoice === 'string' ? ip.invoice : null;
  } catch { return undefined; }
};
const webhookLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
app.post('/api/billing/stripe/webhook', webhookLimiter, express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const whsec = process.env.STRIPE_WEBHOOK_SECRET || '';
    if (!whsec) return res.status(503).end();
    const sig = String(req.headers['stripe-signature'] || '');
    const t = (sig.split(',').find(p => p.startsWith('t=')) || '').slice(2);
    const v1s = sig.split(',').filter(p => p.startsWith('v1=')).map(p => p.slice(3));
    if (!t || !v1s.length) return res.status(400).end();
    if (Math.abs(Date.now() / 1000 - Number(t)) > 300) return res.status(400).end(); // replay guard
    const expected = crypto.createHmac('sha256', whsec).update(`${t}.${req.body}`).digest('hex');
    const okSig = v1s.some(v => { try { return crypto.timingSafeEqual(Buffer.from(v, 'hex'), Buffer.from(expected, 'hex')); } catch { return false; } });
    if (!okSig) { console.warn('[billing] Stripe webhook rejected: signature does not match STRIPE_WEBHOOK_SECRET (each endpoint has its own secret)'); return res.status(400).end(); }
    const event = JSON.parse(req.body.toString('utf8'));
    console.log('[billing] Stripe event', event.type);
    // Stripe re-delivers events (retries, duplicates) — dedupe by event id so
    // a re-delivered payment event can never grant premium days twice.
    // v72 M3: remembered for 30 days (Stripe retries for up to 3), not just the last
    // 500 — a burst of events could push an id out before its retry arrived.
    dbCache.stripeEvents = dbCache.stripeEvents || [];
    if (event.id) {
      if (dbCache.stripeEvents.some(e => e.id === event.id)) return res.json({ received: true });
      const cut = Date.now() - 30 * 864e5;
      dbCache.stripeEvents = dbCache.stripeEvents.filter(e => e.at >= cut).slice(-50000);
      dbCache.stripeEvents.push({ id: event.id, at: Date.now() });
      persistDB('stripeEvents');
    }
    if (event.type === 'checkout.session.completed') {
      applyCheckoutSession(event.data.object);
    } else if (event.type === 'invoice.paid') {
      const inv = event.data.object;
      const acc = dbCache.accounts.find(a => a.stripeCustomerId && a.stripeCustomerId === inv.customer);
      // subscription_create is already granted by checkout.session.completed
      if (acc && inv.billing_reason !== 'subscription_create') {
        const subId = inv.subscription || inv.parent?.subscription_details?.subscription;
        const mapped = subId && acc.stripeSubs && acc.stripeSubs[subId];
        const metaRoot = inv.subscription_details?.metadata?.rootId || inv.parent?.subscription_details?.metadata?.rootId;
        const root = mapped ? dbCache.users.find(u => u.id === mapped) : rootForPayment(acc.id, metaRoot);
        // v72 M3: one invoice is credited once, however many events carry it.
        const credited = typeof inv.id === 'string' && acc.stripeInvoices && hasOwn(acc.stripeInvoices, inv.id);
        if (root && !credited) { grantPremium(root.id, 30); noteStripeInvoice(acc, inv.id, root.id, 30); }
      }
    } else if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
      // Cancelled / resumed in Stripe itself: keep the app's view in step.
      const sub = event.data.object || {};
      const acc = typeof sub.id === 'string' && dbCache.accounts.find(a => a.stripeSubs && hasOwn(a.stripeSubs, sub.id));
      if (acc) {
        acc.stripeSubsCanceled = acc.stripeSubsCanceled || {};
        if (event.type === 'customer.subscription.deleted' || sub.cancel_at_period_end === true || sub.status === 'canceled') acc.stripeSubsCanceled[sub.id] = true;
        else delete acc.stripeSubsCanceled[sub.id];
        persistDB();
      }
    } else if (event.type === 'charge.refunded' || event.type === 'charge.dispute.created') {
      // v71 L3: a refunded or disputed payment takes back the days it bought.
      const ch = event.data.object || {};
      const fullRefund = event.type === 'charge.dispute.created' || ch.refunded === true || (ch.amount_refunded && ch.amount && ch.amount_refunded >= ch.amount);
      const invoiceId = fullRefund ? await stripeInvoiceFor(ch) : null;
      if (invoiceId === undefined) {
        // Couldn't reach Stripe to resolve it: forget the event id so the retry is processed.
        dbCache.stripeEvents = dbCache.stripeEvents.filter(e => e.id !== event.id);
        persistDB();
        return res.status(503).end();
      }
      // A dispute names no customer: find the account by the invoice it recorded.
      const acc = invoiceId ? dbCache.accounts.find(a => a.stripeInvoices && hasOwn(a.stripeInvoices, invoiceId)) : null;
      const paid = acc ? acc.stripeInvoices[invoiceId] : null;
      if (paid && !paid.reversed) {
        const root = dbCache.users.find(u => u.id === paid.rootId);
        if (root && root.premiumUntil) root.premiumUntil = Math.max(Date.now(), root.premiumUntil - paid.days * DAY_MS());
        paid.reversed = true;
        persistDB();
        if (root) notify(new Set([root.accountId]));
      }
    }
    res.json({ received: true });
  } catch (e) { res.status(400).end(); }
});

// v71 H3: request bodies. Every route used to accept (and fully parse) 16 MB of
// JSON — including pre-login routes, and before any rate limit ran. Now almost
// everything gets a small limit, and the few routes that legitimately carry large
// ciphertext are parsed ONLY after their session check and rate limiter
// (bigBody(), attached per route below).
const SMALL_BODY = '256kb';
const BIG_BODY_ROUTES = new Set(['/api/attachments', '/api/messages', '/api/messages/schedule', '/api/state-backup/set',
  '/api/certs/submit', '/api/auth/change-password', '/api/auth/change-password/stage-backup', '/api/profile/set', '/api/account/profile', '/api/netkeys/box', '/api/users/groups']);
const smallJson = express.json({ limit: SMALL_BODY });
app.use((req, res, next) => (BIG_BODY_ROUTES.has(req.path) ? next() : smallJson(req, res, next)));
const _bigParsers = new Map();
const bigBody = (limit) => {
  if (!_bigParsers.has(limit)) _bigParsers.set(limit, express.json({ limit }));
  return _bigParsers.get(limit);
};

// NOWPayments IPN webhook — must be before the session auth middleware since
// NOWPayments calls it server-to-server without a session cookie.
// Verified via HMAC-SHA512 with the IPN secret key (timing-safe comparison).
app.post('/api/billing/monero/ipn', webhookLimiter, (req, res) => {
  const IPN_SECRET = process.env.NOWPAYMENTS_IPN_SECRET;
  if (!IPN_SECRET) return res.status(503).end();
  const sig = String(req.headers['x-nowpayments-sig'] || '');
  if (!sig || typeof req.body !== 'object' || req.body === null || Array.isArray(req.body)) return res.status(400).end();
  // (v72: unchanged from v71 — this verification works with NOWPayments in production.)
  const sorted = JSON.stringify(req.body, Object.keys(req.body).sort());
  const expected = crypto.createHmac('sha512', IPN_SECRET).update(sorted).digest('hex');
  let okSig = false;
  try { okSig = sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(expected, 'utf8')); } catch { okSig = false; }
  if (!okSig) return res.status(400).end();
  const { payment_id, payment_status } = req.body;
  if (payment_status === 'finished' || payment_status === 'confirmed') {
    const pr = (dbCache.xmrPayments || []).find(p => p.npPaymentId === String(payment_id) && p.status !== 'paid');
    // v71 L3: the notification must describe THIS order at the price we set.
    const orderOk = pr && (req.body.order_id === undefined || String(req.body.order_id) === pr.id || String(req.body.order_id) === pr.accountId);
    const priceOk = req.body.price_amount === undefined || (Number(req.body.price_amount) >= PREMIUM_USD && String(req.body.price_currency || 'usd').toLowerCase() === 'usd');
    if (pr && (!orderOk || !priceOk)) console.error(`[billing] NOWPayments IPN for ${payment_id} did not match its order — ignored`);
    if (pr && orderOk && priceOk) {
      pr.status = 'paid';
      const root = rootForPayment(pr.accountId, pr.rootId);
      if (root) grantPremium(root.id, PREMIUM_DAYS_PER_PAYMENT);
      persistDB();
      console.log(`[billing] NOWPayments IPN: payment ${payment_id} confirmed, premium granted to ${pr.accountId}`);
    }
  }
  res.json({ ok: true });
});
// V8 INFO (npm audit: qs GHSA-x5fp-wj9c-mxmx / GHSA-4mjr-xmp4-gh2g): the only
// production path to `qs` was the extended urlencoded parser and Express's
// "extended" query parser. Nothing in Arbor uses nested form/query fields (the
// sole form is the admin token login), so both use Node's flat querystring
// parser instead — `qs` is unreachable regardless of the installed version.
app.use(express.urlencoded({ extended: false, limit: '8kb' })); // only the admin token login form

// ---- Ops instrumentation (for the admin health endpoint) ----
// Event-loop delay histogram: the single best "is this one Node core overwhelmed"
// signal — when the loop lags, every request (and SSE flush) is late.
const eventLoopDelay = monitorEventLoopDelay({ resolution: 20 });
eventLoopDelay.enable();
// Bounded ring of recent request durations, so the health endpoint can report
// live req/s + p95 (overall and for the hot /tree-context path) over a short window.
const reqLog = [];
const REQLOG_MAX = 8000;
app.use((req, res, next) => {
  const start = performance.now();
  const isTc = req.path === '/tree-context' || req.originalUrl.startsWith('/api/tree-context');
  res.on('finish', () => {
    reqLog.push({ t: Date.now(), ms: performance.now() - start, tc: isTc });
    if (reqLog.length > REQLOG_MAX) reqLog.splice(0, reqLog.length - REQLOG_MAX);
  });
  next();
});

// Response compression for JSON (dependency-free). The hot path, /tree-context, is
// large highly-compressible JSON (per-member public-key JWKs) — ~359KB for a 500-user
// tree — and BANDWIDTH, not CPU, is the constraint for big trees. gzip cuts it ~4-5x.
// Done ASYNC via zlib (libuv threadpool) so it never blocks the event loop; only kicks
// in when the client sent Accept-Encoding: gzip and the body is worth compressing.
// Overrides res.json only (leaves static files + small HTML untouched); browsers/fetch
// transparently decode, so no client change is needed.
app.use((req, res, next) => {
  const acceptsGzip = /\bgzip\b/.test(req.headers['accept-encoding'] || '');
  const _json = res.json.bind(res);
  res.json = (obj) => {
    let buf;
    try { buf = Buffer.from(JSON.stringify(obj)); } catch { return _json(obj); }
    const sendPlain = () => { if (!res.headersSent) res.setHeader('Content-Type', 'application/json; charset=utf-8'); return res.end(buf); };
    if (!acceptsGzip || buf.length < 1400 || res.headersSent) return sendPlain();
    zlib.gzip(buf, (err, gz) => {
      if (err || res.headersSent) return sendPlain();
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Content-Encoding', 'gzip');
      res.setHeader('Vary', 'Accept-Encoding');
      res.setHeader('Content-Length', gz.length);
      res.end(gz);
    });
    return res;
  };
  next();
});

// ---------------------------------------------------------------------------
// Donations (public — no account needed; from the app or the marketing site).
// Arbor is donation-supported: these create ONE-TIME payments, unlock nothing,
// and require no webhook. Amount is validated server-side. Both endpoints
// return { url } for the browser to redirect to.
// ---------------------------------------------------------------------------
const donateLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const validDonation = (v) => { const n = Number(v); return Number.isFinite(n) && n >= 1 && n <= 10000 ? Math.round(n * 100) : null; };

// Stripe one-time donation (dynamic amount — no pre-made Price needed).
app.post('/api/donate/stripe', donateLimiter, async (req, res) => {
  const KEY = process.env.STRIPE_SECRET_KEY;
  if (!KEY) return res.status(503).json({ error: 'Card donations are not configured yet.' });
  const cents = validDonation(req.body && req.body.amount);
  if (!cents) return bad(res, 'Enter an amount between $1 and $10,000.');
  const origin = originFor(req);
  if (!origin) return res.status(500).json({ error: 'Server origin not configured — set PUBLIC_ORIGIN.' });
  const form = new URLSearchParams({
    mode: 'payment',
    submit_type: 'donate',
    'line_items[0][price_data][currency]': 'usd',
    'line_items[0][price_data][product_data][name]': 'Donation to Arbor',
    'line_items[0][price_data][unit_amount]': String(cents),
    'line_items[0][quantity]': '1',
    success_url: origin + '/start?donate=thanks',
    cancel_url: origin + '/start?donate=cancel',
  });
  try {
    const r = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    const j = await r.json();
    if (!r.ok) return providerFailed(res, 'Stripe donation checkout', r.status, j && j.error && (j.error.code || j.error.type), CARD_PAGE_FAILED);
    res.json({ url: j.url });
  } catch (e) { res.status(502).json({ error: 'Payment provider unreachable' }); }
});

// Crypto donation via NOWPayments hosted invoice — donor picks the coin
// (Monero and 300+ others) on NOWPayments' page.
app.post('/api/donate/crypto', donateLimiter, async (req, res) => {
  const NP_KEY = process.env.NOWPAYMENTS_API_KEY;
  if (!NP_KEY) return res.status(503).json({ error: 'Crypto donations are not configured yet.' });
  const cents = validDonation(req.body && req.body.amount);
  if (!cents) return bad(res, 'Enter an amount between $1 and $10,000.');
  const NP_API = process.env.NOWPAYMENTS_SANDBOX === 'true'
    ? 'https://api-sandbox.nowpayments.io/v1' : 'https://api.nowpayments.io/v1';
  const origin = originFor(req);
  if (!origin) return res.status(500).json({ error: 'Server origin not configured — set PUBLIC_ORIGIN.' });
  try {
    const r = await fetch(NP_API + '/invoice', {
      method: 'POST',
      headers: { 'x-api-key': NP_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        price_amount: cents / 100,
        price_currency: 'usd',
        order_description: 'Donation to Arbor',
        success_url: origin + '/start?donate=thanks',
        cancel_url: origin + '/start?donate=cancel',
      }),
    });
    const j = await r.json();
    if (!r.ok) return providerFailed(res, 'NOWPayments donation invoice', r.status, j && (j.code || j.statusCode), MONERO_CREATE_FAILED);
    res.json({ url: j.invoice_url });
  } catch (e) { res.status(502).json({ error: 'Payment provider unreachable' }); }
});

// Which donation methods are live (so the UI can hide unavailable ones).
app.get('/api/donate/config', donateLimiter, (req, res) => {
  res.json({ card: !!process.env.STRIPE_SECRET_KEY, crypto: !!process.env.NOWPAYMENTS_API_KEY });
});



// Minimal cookie reader (we only need to read; express res.cookie handles writing).
const parseCookies = (req) => {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* malformed: ignore this cookie */ }
  }
  return out;
};
// X-Forwarded-Proto is only meaningful from a trusted proxy. With TRUST_PROXY
// unset, any client could set it — so honour it only when a proxy is configured
// (req.secure already reflects it in that case via Express's trust-proxy logic).
const isHttps = (req) => req.secure || (!!TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');

// Canonical public origin for building user-facing redirect URLs (payment
// success/cancel pages). Prefer an explicitly configured PUBLIC_ORIGIN so a
// spoofed/injected Host header can never point a Stripe or NOWPayments redirect
// at an attacker-controlled domain. Falls back to the request host when unset
// (fine for the default single-origin deployment behind one proxy).
const PUBLIC_ORIGIN = (process.env.PUBLIC_ORIGIN || '').replace(/\/+$/, '');
const originFor = (req) => {
  if (PUBLIC_ORIGIN) return PUBLIC_ORIGIN;
  // in prod, don't build payment URLs off the client Host header — require PUBLIC_ORIGIN
  if (process.env.NODE_ENV === 'production') return null;
  return `${isHttps(req) ? 'https' : 'http'}://${req.headers.host}`;
};

// ---------------------------------------------------------------------------
// Push (VAPID)
// ---------------------------------------------------------------------------
let vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
let vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;
if (!vapidPublicKey || !vapidPrivateKey) {
  // v72 B5: kept in ARBOR_DATA_DIR (see persistedSecret). New keys would silently
  // break every existing push subscription.
  const keys = persistedSecret('vapid.json', () => webpush.generateVAPIDKeys(), 'VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY').v;
  vapidPublicKey = keys.publicKey; vapidPrivateKey = keys.privateKey;
}
webpush.setVapidDetails('mailto:admin@arbor.network', vapidPublicKey, vapidPrivateKey);

// ---------------------------------------------------------------------------
// DB
// ---------------------------------------------------------------------------
let clients = [];
// Small collections live in RAM (same shapes as always) and snapshot to SQLite.
// Messages and state backups are SQL-only — see storage.js for the rationale.
let dbCache = { accounts: [], users: [], invites: [], subscriptions: [], sessions: [], prekeys: {}, signalIdentities: {}, tombstones: {}, xmrPayments: [], stripeEvents: [], recovery: [], acks: {}, hubContacts: [], reactions: {}, scheduledEnvelopes: [], accountHubInvites: [], certs: [], netBoxes: [], reactionAud: {}, billingRefs: {} };

// ---------------------------------------------------------------------------
// Personal hubs (Signal-style contacts). A hub is NOT a tree: every hub node
// is its own single-node root, and conversations exist as symmetric CONTACT
// EDGES between two hub nodes — when A adds B, B equally has A in their own
// hub. Nobody "joins under" anyone, and nobody can invite into someone else's
// hub (you only ever add contacts to your own).
//   edge = { a, b, pending, requestedBy, addedAt }   (internal node ids)
// ---------------------------------------------------------------------------
const hubEdges = () => (dbCache.hubContacts = dbCache.hubContacts || []);
const hubEdgeBetween = (x, y) => hubEdges().find(e => (e.a === x && e.b === y) || (e.a === y && e.b === x));
const hubContactsOf = (nodeId, includePending = false) => hubEdges()
  .filter(e => (e.a === nodeId || e.b === nodeId) && (includePending || !e.pending))
  .map(e => ({ edge: e, other: dbCache.users.find(u => u.id === (e.a === nodeId ? e.b : e.a)) }))
  .filter(x => !!x.other);
const accountHubRoot = (accountId) => dbCache.users.find(u => u.accountId === accountId && u.treeMode === 'HUB' && !u.invitedBy);
// When someone used "Add to hub" against an account that had no personal hub yet,
// the request was parked in accountHubInvites. The instant that account first
// creates/opens its hub root, turn every parked request into a real pending
// contact edge so it shows up under their Contact Requests like any other.
const bindAccountHubInvites = (hubRoot) => {
  const list = dbCache.accountHubInvites = dbCache.accountHubInvites || [];
  const mine = list.filter(x => x.toAccount === hubRoot.accountId);
  if (!mine.length) return;
  for (const inv of mine) {
    const from = dbCache.users.find(u => u.id === inv.fromHub && u.treeMode === 'HUB' && !u.invitedBy);
    if (from && from.id !== hubRoot.id && !hubEdgeBetween(from.id, hubRoot.id)) {
      hubEdges().push({ a: from.id, b: hubRoot.id, pending: true, requestedBy: from.id, addedAt: inv.at || Date.now(),
        ...(inv.attest ? { attest: inv.attest, attestTo: inv.attestTo } : {}) }); // v72 B2
    }
  }
  dbCache.accountHubInvites = list.filter(x => x.toAccount !== hubRoot.accountId);
};
// Drop edges that reference nodes being deleted.
const dropHubEdgesFor = (internalIds) => {
  const dead = internalIds instanceof Set ? internalIds : new Set(internalIds);
  const before = hubEdges().length;
  // A contact who held my hub's profile key is gone: my app should replace it
  // (V8 phase 2 — see flagRotation).
  for (const e of hubEdges()) {
    if (e.pending) continue;
    for (const [gone, keep] of [[e.a, e.b], [e.b, e.a]]) {
      if (dead.has(gone) && !dead.has(keep)) { const k = dbCache.users.find(u => u.id === keep); if (k) k.rotateNeededAt = Date.now(); }
    }
  }
  dbCache.hubContacts = hubEdges().filter(e => !dead.has(e.a) && !dead.has(e.b));
  return before !== dbCache.hubContacts.length;
};
// One-time migration: hubs used to be trees (owner root + member children).
// Promote every legacy HUB member to a standalone hub root of their own and
// replace the parent/child link with a contact edge — history, keys and Signal
// sessions all survive because node ids never change.
const migrateHubMembers = () => {
  let changed = false;
  for (const u of dbCache.users) {
    if ((u.treeMode === 'HUB') && u.invitedBy) {
      const owner = dbCache.users.find(x => x.id === u.invitedBy);
      if (owner && !hubEdgeBetween(u.id, owner.id)) {
        hubEdges().push({ a: owner.id, b: u.id, pending: !!u.pending, requestedBy: u.id, addedAt: u.requestedAt || Date.now() });
      }
      u.invitedBy = null; u.role = 'ROOT'; u.level = 0; u.path = u.id;
      delete u.pending; // the EDGE carries pending now; the node is simply their hub
      changed = true;
    }
  }
  if (changed) { persistDB(); console.log('[migrate] legacy hub members promoted to peer hubs'); }
};

// v70: set once the database has loaded completely. Nothing is written back —
// no snapshot persist, no avatar sweep — unless it is, so a failed load can never
// overwrite real data with an empty in-memory copy.
let dbLoaded = false;
const initDB = async () => {
  try {
    await initStorage();
    migrateFromJsonIfPresent();           // one-time db.json -> arbor.db import
    dbCache = await loadSnapshots();
    dbCache.xmrPayments = dbCache.xmrPayments || [];
    dbCache.stripeEvents = (dbCache.stripeEvents || []).map(e => (typeof e === 'string' ? { id: e, at: Date.now() } : e)); // v72 M3: {id, at}
    dbCache.recovery = dbCache.recovery || [];
    dbCache.acks = asPlainMap(dbCache.acks);
    dbCache.hubContacts = dbCache.hubContacts || [];
    // mid -> { [emoji]: [{id,name}] }. asPlainMap repairs a legacy `[]` snapshot
    // (V8 H-6/L-7: `[] || {}` kept the array, so keyed reactions were dropped on
    // every persist and `reactions["__proto__"]` hit Array.prototype).
    dbCache.reactions = asPlainMap(dbCache.reactions);
    dbCache.tombstones = asPlainMap(dbCache.tombstones);
    dbCache.reactionAud = asPlainMap(dbCache.reactionAud);   // v71: mid -> audience public ids
    dbCache.billingRefs = asPlainMap(dbCache.billingRefs);   // v71: opaque checkout refs -> { accountId, rootPid, at }
    dbCache.scheduledEnvelopes = dbCache.scheduledEnvelopes || []; // sealed, future-dated sends
    dbCache.accountHubInvites = dbCache.accountHubInvites || []; // "add to hub" requests parked for accounts with no hub yet
    dbCache.certs = Array.isArray(dbCache.certs) ? dbCache.certs : [];       // V8 phase 2: signed membership certificates
    dbCache.netBoxes = Array.isArray(dbCache.netBoxes) ? dbCache.netBoxes : []; // V8 phase 2: sealed network-key boxes
    // v72 B5: the salt this database was created with must be the one in use.
    dbCache.serverMeta = asPlainMap(dbCache.serverMeta);
    const saltCheck = dbCache.serverMeta.saltCheck;
    if (saltCheck && saltCheck !== SALT_CHECK) {
      throw new Error('SERVER_SALT does not match the one this database was created with — every account would be locked out. Restore the original SERVER_SALT (.env) or server-salt.json (ARBOR_DATA_DIR) from your backup.');
    }
    if (!saltCheck && SALT_CREATED && dbCache.accounts.length) {
      throw new Error('a NEW server salt was just generated, but this database already has accounts — they would all be locked out. Restore the original SERVER_SALT (.env) or server-salt.json (ARBOR_DATA_DIR) from your backup, then start again. (The new server-salt.json in ARBOR_DATA_DIR must be deleted first.)');
    }
    // V8 phase 2 (M-8): ack and reaction lists used to copy the reactor's display
    // name in plaintext. Names are end-to-end encrypted now; strip the copies.
    for (const e of Object.values(dbCache.acks)) if (e && Array.isArray(e.list)) e.list = e.list.map(a => ({ id: a.id, ts: a.ts }));
    for (const forMid of Object.values(dbCache.reactions)) if (forMid && typeof forMid === 'object') for (const k of Object.keys(forMid)) if (Array.isArray(forMid[k])) forMid[k] = forMid[k].map(x => ({ id: x.id }));
    dbLoaded = true;
    if (!saltCheck) { dbCache.serverMeta.saltCheck = SALT_CHECK; persistDB('serverMeta'); }
    migrateHubMembers(); // v26: personal hubs became peer-to-peer contact pairs
    // v72 B4: reactions, acks and retraction tombstones moved from the in-RAM
    // snapshot to tables (metaStore). Import what v71 left once, then empty the
    // old snapshot entries. A failure here stops the boot like any load failure.
    if ([dbCache.reactions, dbCache.acks, dbCache.tombstones, dbCache.reactionAud].some(m => Object.keys(m).length)) {
      const n = await metaStore.importLegacy(dbCache);
      console.log(`[migrate] message metadata moved to tables: ${n.reactions} reactions, ${n.acks} acks, ${n.tombstones} tombstone rows`);
      dbCache.reactions = {}; dbCache.acks = {}; dbCache.tombstones = {}; dbCache.reactionAud = {};
      persistDB('reactions', 'acks', 'tombstones', 'reactionAud');
    }
    // v72 B4: scheduled sends moved to the `scheduled` table the same way.
    if (Array.isArray(dbCache.scheduledEnvelopes) && dbCache.scheduledEnvelopes.length) {
      let n = 0;
      for (const x of dbCache.scheduledEnvelopes) {
        if (!x || !x.id || !x.nodeId || !x.envelope || !x.envelope.mid) continue;
        if (await scheduledStore.add({ ...x, size: envelopeBytes(x.envelope) })) n++;
      }
      console.log(`[migrate] ${n} scheduled messages moved to the scheduled table`);
      dbCache.scheduledEnvelopes = [];
      persistDB('scheduledEnvelopes');
    }
  } catch (e) {
    // v70: this used to carry on with EMPTY data — the next save then overwrote
    // every account and user, and the boot avatar sweep deleted every photo.
    // Stop instead: the stored data is untouched, and the supervisor's restart
    // (or an operator) can retry once the database is reachable/readable again.
    dbLoaded = false;
    console.error('FATAL: the database could not be loaded — refusing to start so nothing is overwritten:', (e && (e.stack || e.message)) || e);
    process.exit(1);
  }
};

let persistTimer = null;
let dataVersion = 0; // bumped on every mutation (see visitedGroupsOf)
// v72 B4/B6. Debounced snapshot of the small collections (message/backup writes
// are row-level and immediate in storage*.js).
//  - Dirty keys: persistDB('prekeys') saves only that collection; persistDB() with
//    no keys still means "anything may have changed" and checks them all. Hot paths
//    name their collection so a prekey fetch no longer stringifies all 20.
//  - One save at a time: v71 cleared the timer BEFORE awaiting the write, so on
//    Postgres two overlapping upserts could commit out of order (an older snapshot
//    winning). Now a save that is requested while one runs waits for it, and
//    shutdown waits for the in-flight save before its final full flush.
let persistRunning = null;
let dirtyAll = false;
const dirtyKeys = new Set();
const persistDB = (...keys) => {
  dataVersion++;
  if (!dbLoaded) return;                 // v70: never write before a complete load
  if (keys.length) for (const k of keys) dirtyKeys.add(k); else dirtyAll = true;
  schedulePersist(150);
};
const schedulePersist = (ms) => { if (!persistTimer) persistTimer = setTimeout(runPersist, ms); };
async function runPersist() {
  persistTimer = null;
  if (persistRunning) return;            // the running save re-schedules when it ends
  const keys = dirtyAll ? null : [...dirtyKeys];
  dirtyAll = false; dirtyKeys.clear();
  if (keys && !keys.length) return;
  let failed = false;
  const mine = persistRunning = (async () => {
    try { await persistSnapshots(dbCache, keys); }
    catch (e) {
      failed = true;
      console.error('DB write error:', e.message);
      if (keys) keys.forEach(k => dirtyKeys.add(k)); else dirtyAll = true;   // retried below
    }
  })();
  await mine;
  if (persistRunning === mine) persistRunning = null;
  if (dirtyAll || dirtyKeys.size) schedulePersist(failed ? 5000 : 150);
}
// Wait for any in-flight save, then write everything that changed (shutdown).
const flushPersist = async () => {
  if (persistTimer) { clearTimeout(persistTimer); persistTimer = null; }
  while (persistRunning) await persistRunning;
  dirtyAll = false; dirtyKeys.clear();
  await persistSnapshots(dbCache);
};
// v72 M7: write these collections NOW, in one transaction with `extra` (see
// persistSnapshots), for a change that must be saved as a whole before the reply.
// Takes its turn with the debounced saves (never overlaps one); throws on failure.
const persistNow = async (keys, extra) => {
  while (persistRunning) await persistRunning;
  const p = Promise.resolve().then(() => persistSnapshots(dbCache, keys, extra));
  const guard = persistRunning = p.catch(() => {});
  try { await p; }
  finally {
    if (persistRunning === guard) persistRunning = null;
    if (dirtyAll || dirtyKeys.size) schedulePersist(150);
  }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const uuid = (p) => p + crypto.randomUUID();

// ---------------------------------------------------------------------------
// Usage statistics (aggregate only).
//
// PRIVACY NOTE: the only thing recorded per account is a COARSE UTC DAY STRING
// ("2026-07-25") of the last day that account was active — no clock times, no
// IP addresses, no request logs, no history. It is overwritten each day rather
// than appended to, so there is never an activity trail to seize or subpoena;
// at most it reveals "this account was used at some point on this date".
// That is the minimum needed to compute daily/weekly/monthly active users.
// ---------------------------------------------------------------------------
const dayStamp = (ms = Date.now()) => new Date(ms).toISOString().slice(0, 10);
const dayStampAgo = (n) => dayStamp(Date.now() - n * 86400000);

// Called on authenticated activity. Writes at most once per account per day.
const touchAccountSeen = (accountId) => {
  if (!accountId) return;
  const acc = dbCache.accounts.find(a => a.id === accountId);
  if (!acc) return;
  const today = dayStamp();
  if (acc.lastSeenDay === today) return;   // already counted today, no write
  acc.lastSeenDay = today;
  persistDB('accounts');
};
const sha256hex = (s) => crypto.createHmac('sha256', SERVER_SALT).update(String(s)).digest('hex');

// v71 H2: memoised — the same few thousand node ids are mapped on every request,
// and an HMAC per user per call made several routes O(users) in hashing alone.
// Bounded: cleared if it ever grows past PID_MEMO_MAX (one-off ids also pass here).
const PID_MEMO_MAX = 200000;
const _pidMemo = new Map();
const getPublicId = (internalId) => {
  if (!internalId) return null;
  const k = String(internalId);
  let v = _pidMemo.get(k);
  if (v) return v;
  v = 'n_' + crypto.createHmac('sha256', SERVER_SALT).update(k).digest('hex').substring(0, 24);
  if (_pidMemo.size >= PID_MEMO_MAX) _pidMemo.clear();
  _pidMemo.set(k, v);
  return v;
};
// cached; rebuilt only when the users array changes (reference or length)
let _pidCache = { ref: null, size: -1, map: null };
const publicIdMap = () => {
  const users = dbCache.users;
  if (_pidCache.map && _pidCache.ref === users && _pidCache.size === users.length) return _pidCache.map;
  const m = new Map();
  for (const u of users) m.set(getPublicId(u.id), u.id);
  _pidCache = { ref: users, size: users.length, map: m };
  return m;
};
const resolveInternalId = (publicId) => publicIdMap().get(publicId) || null;

// scrypt password hashing with per-record salt; constant-time verify.
// v71 H3: asynchronous scrypt (libuv thread pool). scryptSync blocked the event
// loop ~50 ms per login/signup — for every user of the server at once.
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };
const scryptAsync = (value, salt, len) => new Promise((resolve, reject) =>
  crypto.scrypt(value, salt, len, SCRYPT_PARAMS, (err, key) => (err ? reject(err) : resolve(key))));
const hashPassword = async (value) => {
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(value, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
};
const verifyPassword = async (value, stored) => {
  try {
    const [scheme, saltHex, hashHex] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const expected = Buffer.from(hashHex, 'hex');
    const actual = await scryptAsync(value, Buffer.from(saltHex, 'hex'), expected.length);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
};
// Decoy hash so unknown-username logins still spend scrypt time (no enumeration).
// Computed once at boot (synchronously — nothing else is running yet).
const DECOY_HASH = (() => {
  const salt = crypto.randomBytes(16);
  return `scrypt$${salt.toString('hex')}$${crypto.scryptSync(crypto.randomBytes(32), salt, 64, SCRYPT_PARAMS).toString('hex')}`;
})();

// Per-account login throttle (independent of IP-based limiter).
//
// We deliberately do NOT hard-lock an account on failed attempts. Because there
// is no IP dimension (by design — the server logs no IPs), a username-keyed hard
// lock let anyone who knew a username deny that user access: 10 wrong guesses and
// the real owner was 429'd too ("targeted lockout" DoS). Instead we apply a
// progressive per-attempt DELAY that grows with recent failures and decays after
// a quiet period. A legitimate user who submits the correct password is admitted
// on the first try regardless of the counter and can never be locked out; an
// attacker guessing wrong passwords is merely slowed. Online brute force is
// already impractical against the 12+ char passphrase policy + scrypt verify —
// this delay is a secondary speed bump, not the primary defence.
const loginFails = new Map(); // username -> { count, lastFailAt }
const LOGIN_FAIL_DECAY_MS = 15 * 60 * 1000; // failures older than this are forgiven
const LOGIN_MAX_DELAY_MS = 3000;            // cap: a legit login is slowed, never blocked
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const loginDelayFor = (count) => Math.min(count * 400, LOGIN_MAX_DELAY_MS);
const throttleState = (username) => {
  // v71: keyed by the username's keyed hash — the server keeps no plaintext
  // username anywhere, including this in-memory map.
  const k = usernameHash(username);
  const s = loginFails.get(k) || { count: 0, lastFailAt: 0 };
  // Decay: a quiet period wipes the counter so old failures never accumulate.
  if (s.lastFailAt && Date.now() - s.lastFailAt > LOGIN_FAIL_DECAY_MS) s.count = 0;
  return { k, s };
};
// Opportunistic prune so the map can't grow without bound from one-off attempts.
const pruneLoginFails = () => {
  const cut = Date.now() - LOGIN_FAIL_DECAY_MS;
  for (const [k, s] of loginFails) if (!s.lastFailAt || s.lastFailAt < cut) loginFails.delete(k);
};

// ---- Sessions (cookie-based; only a HASH of the token is stored) ----
// Constant-time string compare (hash both sides so length never leaks and
// timingSafeEqual always gets equal-length buffers). Used for CSRF tokens.
const ctEq = (a, b) => {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
};
const MAX_SESSIONS_PER_ACCOUNT = 10; // bound session accumulation / fixation
const newSession = (accountId) => {
  const token = crypto.randomBytes(32).toString('hex');
  const csrf = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  dbCache.sessions.push({ tokenHash: sha256hex(token), csrf, accountId, expiresAt: now + SESSION_TTL_MS });
  // Sweep expired sessions and cap the number of live sessions per account,
  // evicting the oldest beyond the cap.
  dbCache.sessions = dbCache.sessions.filter(s => s.expiresAt > now);
  const mine = dbCache.sessions.filter(s => s.accountId === accountId);
  if (mine.length > MAX_SESSIONS_PER_ACCOUNT) {
    const drop = new Set(mine.sort((a, b) => a.expiresAt - b.expiresAt)
      .slice(0, mine.length - MAX_SESSIONS_PER_ACCOUNT).map(s => s.tokenHash));
    dbCache.sessions = dbCache.sessions.filter(s => !drop.has(s.tokenHash));
  }
  persistDB('sessions');
  return { token, csrf };
};
const sessionFromReq = (req) => {
  const token = parseCookies(req)['arbor_session'];
  if (!token) return null;
  const h = sha256hex(token);
  const s = dbCache.sessions.find(s => s.tokenHash === h);
  if (!s || s.expiresAt < Date.now()) return null;
  return s;
};
const setSessionCookies = (req, res, token, csrf) => {
  const secure = isHttps(req);
  res.cookie('arbor_session', token, { httpOnly: true, sameSite: 'strict', secure, path: '/', maxAge: SESSION_TTL_MS });
  // NOTE: the CSRF token is NOT stored in a JS-readable cookie. The server
  // validates it against the session record; the client receives it in the
  // login/signup JSON and via GET /api/csrf, and holds it in memory only.
};
const clearSessionCookies = (res) => {
  res.clearCookie('arbor_session', { path: '/' });
  res.clearCookie('arbor_csrf', { path: '/' });
};

// Validation helpers
const isStr = (v, max = 2000) => typeof v === 'string' && v.length > 0 && v.length <= max;
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const isJwk = (v) => isObj(v) && typeof v.kty === 'string';
// v71 M4: a node's legacy public keys are P-256 JWKs; keep exactly those fields
// (they are stored on the node and served to everyone who can see it).
const JWK_OPS = new Set(['deriveBits', 'deriveKey', 'verify']);
const cleanJwk = (v) => {
  if (!isObj(v) || v.kty !== 'EC' || v.crv !== 'P-256') return null;
  const b64u = (x) => typeof x === 'string' && x.length > 0 && x.length <= 64 && /^[A-Za-z0-9_-]+$/.test(x);
  if (!b64u(v.x) || !b64u(v.y)) return null;
  const out = { kty: 'EC', crv: 'P-256', x: v.x, y: v.y };
  if (typeof v.ext === 'boolean') out.ext = v.ext;
  if (Array.isArray(v.key_ops)) { if (v.key_ops.length > 3 || !v.key_ops.every(o => JWK_OPS.has(o))) return null; out.key_ops = [...v.key_ops]; }
  return out;
};
const MAX_WRAPPED_KEYS = 16384;       // a wrapped P-256 key pair is ~1.2 KB
// Strict #rrggbb only — this string is written into an inline style on the
// client, so anything looser would be a CSS-injection vector.
const isHexColor = (v) => typeof v === 'string' && /^#[0-9a-fA-F]{6}$/.test(v);
const bad = (res, msg) => res.status(400).json({ error: msg });
// Prototype-pollution guard (V8 H-6). Any client-chosen string that becomes a
// property KEY on a server-side map (message ids, group/link ids, labels) must
// not be one of the magic names — `map["__proto__"]` resolves to a prototype,
// and writing through it pollutes every object/array in the process.
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const isSafeKey = (k) => typeof k === 'string' && !FORBIDDEN_KEYS.has(k);
// Message ids are client-generated base64 of 16 random bytes (24 chars). Accept
// base64/base64url charset, 16–64 chars — which also excludes every magic key.
const isMid = (v) => isStr(v, 64) && /^[A-Za-z0-9+/=_-]{16,64}$/.test(v) && isSafeKey(v);
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Display-name hygiene (V8 L-8). Names are shown to other members, so reject the
// characters used for impersonation and visual spoofing: control characters and
// newlines (collapsed to a space), bidi overrides/isolates (e.g. U+202E flips
// text), zero-width and other invisible format characters, Hangul/braille-style
// fillers. NFKC folds full-width and compatibility look-alikes to their base form.
// U+200D (ZWJ) survives only INSIDE emoji sequences (👨‍👩‍👧), where it is needed.
const INVISIBLE_FILLERS = /[͏ᅟᅠ឴឵⠀ㅤﾠ]/u;
const cleanName = (raw, max = 64) => {
  if (typeof raw !== 'string') return null;
  const s = raw.normalize('NFKC').replace(/\s+/gu, ' ').trim();
  if (!s || s.length > max) return null;
  if (/[\p{Cc}\p{Cs}\p{Co}\p{Cn}]/u.test(s)) return null;
  if (/(?!‍)\p{Cf}/u.test(s)) return null;                  // bidi, zero-width, soft hyphen, tags…
  if (INVISIBLE_FILLERS.test(s)) return null;
  if (s.includes('‍') && /(?<!\p{Extended_Pictographic}️?)‍|‍(?!\p{Extended_Pictographic})/u.test(s)) return null;
  if (!/[\p{L}\p{N}\p{Extended_Pictographic}]/u.test(s)) return null; // something visible
  return s;
};
// Confusable "skeleton" used to flag look-alike names within one network (e.g.
// Latin "Alice" vs Cyrillic "Аlice"). Coarse on purpose: it drives a warning
// badge, never a hard rejection, so two real people named "Sam" still coexist.
const CONFUSABLE = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ӏ': 'l', 'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', '0': 'o', '1': 'l', '|': 'l', '3': 'e', '5': 's', '$': 's', '@': 'a' };
const nameSkeleton = (n) => String(n || '').normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase()
  .replace(/./gsu, ch => CONFUSABLE[ch] || ch).replace(/rn/g, 'm').replace(/[^\p{L}\p{N}\p{Extended_Pictographic}]/gu, '');
// Coerce a persisted collection to a plain keyed object (repairs the V8 H-6/L-7
// mis-seed where `reactions` was stored as `[]`) and drop any magic keys.
const asPlainMap = (v) => {
  const out = {};
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    for (const k of Object.keys(v)) if (isSafeKey(k)) out[k] = v[k];
  }
  return out;
};

// Usernames are stored ONLY as a keyed hash (HMAC keyed by SERVER_SALT), never
// in cleartext — a database dump, backup, or a curious operator cannot enumerate
// who holds an account. Login/salt still work: the client sends its username and
// we hash it to find the record. (The username still arrives in plaintext at
// login over TLS, so this protects data AT REST — dumps, backups, subpoenas —
// not an actively malicious live server that logs incoming requests.)
const usernameHash = (u) => crypto.createHmac('sha256', SERVER_SALT)
  .update('arbor-username-v1:' + String(u || '').toLowerCase()).digest('hex');
const findByUsername = (u) => {
  if (typeof u !== 'string' || !u) return null;
  const h = usernameHash(u);
  return dbCache.accounts.find(a => a.usernameHash === h) || null;
};

// ---------------------------------------------------------------------------
// Tree / recipient logic — SINGLE source of truth for "who can read a message".
// ---------------------------------------------------------------------------
const pathDepth = (p) => String(p || '').split('/').length;

// A member may belong to MULTIPLE of their inviter's groups. Membership is stored
// on the inviter's inviteeGroups map as EITHER a single string (legacy / one
// group) OR an array of strings (multi-group); null/absent means ungrouped. Read
// every membership through gidsOf() so both shapes work identically, and write
// through the same normalisation (scalar when one, array when many) so existing
// single-group data on disk is never rewritten.
const gidsOf = (v) => v == null ? []
  : Array.isArray(v) ? v.filter(x => typeof x === 'string' && x)
  : (typeof v === 'string' && v ? [v] : []);
const memberGids = (inviter, memberId) => gidsOf(inviter && inviter.inviteeGroups && inviter.inviteeGroups[memberId]);

// Cross-level VISITORS: an owner/admin may add any user as a FULL participant in a
// group they aren't structurally under (across levels). Stored as internal user
// ids on the group OWNER node: groupVisitors[gid] = [userId,...]. This is
// cross-compartment access (same class as cross-level links) — the routing below
// treats a visitor exactly like a member OF THAT GROUP for that group's chat only.
const gidVisitorIds = (owner, gid) => (owner && owner.groupVisitors && Array.isArray(owner.groupVisitors[gid])) ? owner.groupVisitors[gid] : [];
const visitorGroupOwner = (allUsers, gid, userId) => allUsers.find(u => gidVisitorIds(u, gid).includes(userId));
// Reverse index visitorId -> [{ o: ownerNode, gid }] (V8 M-14). /tree-context and
// sanitizeUser used to scan every user in the database on every call to find the
// groups the viewer visits. Rebuilt lazily whenever user data changed (dataVersion
// is bumped by persistDB, which every mutation path calls).
let _visitIdx = { v: -1, map: new Map() };
const visitedGroupsOf = (userId) => {
  if (_visitIdx.v !== dataVersion) {
    const m = new Map();
    for (const o of dbCache.users) {
      for (const [gid, ids] of Object.entries(o.groupVisitors || {})) {
        if (!Array.isArray(ids)) continue;
        for (const id of ids) { if (!m.has(id)) m.set(id, []); m.get(id).push({ o, gid }); }
      }
    }
    _visitIdx = { v: dataVersion, map: m };
  }
  return _visitIdx.map.get(userId) || [];
};

// Two siblings (same inviter) may see each other IFF their common inviter has
// not separated them into disjoint groups. Ungrouped invitees (no assignment)
// are treated as mutually visible, which preserves the pre-groups behaviour.
// With multi-group membership the test is set INTERSECTION: they share a chat
// when their group sets overlap (or both are empty). Disjoint sets stay walled
// off exactly as before — the compartment guarantee is unchanged. The grouping
// data lives on the INVITER's node, so only the inviter controls this partition.
const sameInviteeGroup = (a, b, allUsers) => {
  if (a.invitedBy == null || a.invitedBy !== b.invitedBy) return false;
  const inviter = allUsers.find(u => u.id === a.invitedBy);
  const map = inviter && inviter.inviteeGroups;
  if (!map) return true;                       // no groups defined at all
  const ga = gidsOf(map[a.id]);
  const gb = gidsOf(map[b.id]);
  if (ga.length === 0 && gb.length === 0) return true; // both ungrouped -> visible
  return ga.some(g => gb.includes(g));         // else: must share at least one group
};

// The participant node ids of a cross-level link (a root-owned channel that spans
// groups anywhere in the tree). A user is IN it when their inviter+group matches
// one of the link's { o: ownerPublicId, g: groupId } refs. The root is always in.
const crossLevelParticipants = (root, cl, allUsers) => {
  // v71 H2: resolved through the cached id map and walked over the ROOT'S TREE only
  // (never every user in the database), and memoised until any data changes.
  const memoKey = root.id + '|' + JSON.stringify(cl.refs || []);
  if (_clpMemo.v === dataVersion && _clpMemo.map.has(memoKey)) return _clpMemo.map.get(memoKey);
  if (_clpMemo.v !== dataVersion) _clpMemo = { v: dataVersion, map: new Map() };
  const refSet = new Set((cl.refs || []).map(r => r.o + '|' + r.g));
  const owners = new Set();
  const ids = new Set([root.id]);
  // The OWNER of each linked group is a participant — a user with a group directly
  // below them belongs to any link chat created from that group.
  for (const r of (cl.refs || [])) { const oid = resolveInternalId(r.o); if (oid) { ids.add(oid); owners.add(oid); } }
  const inTree = treeMembersOf(root, allUsers);
  const byId = new Map(inTree.map(u => [u.id, u]));
  for (const u of inTree) {
    if (u.pending || !owners.has(u.invitedBy)) continue;
    const inv = byId.get(u.invitedBy);
    if (!inv) continue;
    const pub = getPublicId(inv.id);
    if (memberGids(inv, u.id).some(g => refSet.has(pub + '|' + g))) ids.add(u.id);
  }
  _clpMemo.map.set(memoKey, ids);
  return ids;
};
let _clpMemo = { v: -1, map: new Map() };
// Every node of the tree rooted at `root` (root included).
const treeMembersOf = (root, allUsers = dbCache.users) => allUsers.filter(u => u.path === root.id || u.path.startsWith(root.id + '/'));

// Pending (unapproved) nodes are never part of any audience, in ANY branch below
// (V8 M-15: the per-branch filters missed PEER/BROADCAST/DM/HUB). Enforced once
// here so a new branch can't forget it. The sender itself is always kept.
const usersWhoCanRead = (sender, type, targetCircle, allUsers, targets, targetGroup) =>
  usersWhoCanReadRaw(sender, type, targetCircle, allUsers, targets, targetGroup)
    .filter(u => u.id === sender.id || !u.pending);
const usersWhoCanReadRaw = (sender, type, targetCircle, allUsers, targets, targetGroup) => {
  // Global chat: when the root has enabled it, EVERY member of the tree can read
  // (and send) — a single network-wide channel that bypasses the compartments.
  // Fan-out: the sender encrypts to all of them. Disabled = nobody but the sender.
  if (type === 'GLOBAL') {
    const root = treeRootUser(sender);
    if (!root || !root.globalChat) return [sender];
    const treeRootId = sender.path.split('/')[0];
    return allUsers.filter(u => (u.path === treeRootId || u.path.startsWith(treeRootId + '/')) && !u.pending);
  }
  // Cross-level link: a root-owned channel that spans groups ANYWHERE in the tree
  // (it deliberately punches through the compartments — the root creates it behind
  // an explicit warning). Delivery is purely the participant set (UP/DOWN circles
  // don't apply). Only participants can send; archived links deliver to no one.
  if (type === 'PEER' && targetGroup) {
    const troot = treeRootUser(sender);
    const cl = troot && troot.groupLinks && troot.groupLinks[targetGroup];
    if (cl && cl.crossLevel) {
      if (cl.archived) return [sender];
      const parts = crossLevelParticipants(troot, cl, allUsers);
      if (!parts.has(sender.id)) return [sender];
      return allUsers.filter(u => parts.has(u.id));
    }
    // Cross-level VISITOR posting into a plain group: if the SENDER is a visitor of
    // targetGroup, the readable set is that group's full channel — its owner, the
    // owner's members-of-the-group, and every visitor of it. (Owner/member sends are
    // handled in the DOWN/UP branches, which also fan out to these visitors.)
    const vOwner = visitorGroupOwner(allUsers, targetGroup, sender.id);
    if (vOwner) {
      const parts = new Set([vOwner.id, ...gidVisitorIds(vOwner, targetGroup)]);
      for (const u of allUsers) if (!u.pending && u.invitedBy === vOwner.id && memberGids(vOwner, u.id).includes(targetGroup)) parts.add(u.id);
      return allUsers.filter(u => parts.has(u.id));
    }
  }
  // Personal hub: readable set = the sender plus their ACTIVE contacts (the
  // symmetric edges), across trees. Pending contacts can't exchange messages.
  if (sender.treeMode === 'HUB') {
    const contactIds = new Set(hubContactsOf(sender.id).map(x => x.other.id));
    return allUsers.filter(u => u.id === sender.id || contactIds.has(u.id));
  }
  // DM is hub-and-spoke: you can only ever read messages between yourself and
  // your inviter or your direct invitees.
  if (sender.treeMode === 'DM') {
    return allUsers.filter(u =>
      u.id === sender.id || u.id === sender.invitedBy || u.invitedBy === sender.id);
  }
  // Announcements (BROADCAST) target explicit people: `targets` is a list of
  // node ids inside the sender's subtree. A targeted announcement reaches the
  // selected people themselves plus everyone ON THE CHAIN ABOVE each of them
  // (oversight) — it does NOT cascade to anyone below a selected person.
  // No targets = the sender's entire subtree. Ancestors of the sender always
  // receive a copy (oversight) regardless of targeting.
  const targetPaths = Array.isArray(targets)
    ? targets.map(tid => allUsers.find(u => u.id === tid))
        .filter(t => t && t.path.startsWith(sender.path + '/')) // must be a strict descendant
        .map(t => t.path)
    : null;
  // v72 B1: the root's Monitoring switch is enforced HERE (it used to only hide the
  // Monitor tab). Off = no oversight copies to ancestors at all — the UP/DOWN window
  // and the announcement copy alike. Only NEW messages are affected: stored
  // messages keep the recipient list they were sent with. Unset = legacy ON.
  const monitoringOn = monitoringOnFor(sender);
  return allUsers.filter(viewer => {
    if (viewer.id === sender.id) return true;
    if (type === 'BROADCAST') {
      const viewerIsDescendantOfSender = viewer.path.startsWith(sender.path + '/');
      const viewerIsAncestorOfSender = sender.path.startsWith(viewer.path + '/');
      if (viewerIsAncestorOfSender) return monitoringOn; // oversight copy (monitoring on only)
      if (viewerIsDescendantOfSender) {
        if (!targetPaths) return true; // no targeting = whole subtree
        // Viewer receives iff they ARE a target or sit ABOVE a target (on the
        // chain between the sender and that target). People below a target are
        // excluded on purpose — the announcement stops at the person picked.
        return targetPaths.some(tp => viewer.path === tp || tp.startsWith(viewer.path + '/'));
      }
      return false;
    }
    // PEER
    const isParent = sender.id === viewer.invitedBy;
    const isChild = sender.invitedBy === viewer.id;
    // Siblings share a chat ONLY when their common inviter has NOT split them
    // into different groups. If the inviter placed them in distinct groups,
    // they are not siblings for visibility — the sender's client also refuses
    // to encrypt to them, so this is enforced on both ends.
    const rawSibling = sender.invitedBy === viewer.invitedBy && viewer.invitedBy !== null;
    const isSibling = rawSibling && sameInviteeGroup(sender, viewer, allUsers);
    const viewerIsAncestorOfSender = sender.path.startsWith(viewer.path + '/');
    // MONITORING DEPTH CAP — applies to EVERYONE, the founder/root included.
    // An ancestor may only oversee conversations of people at most 2 levels
    // below them: their direct invitees (1 below) and grandchildren (2 below).
    // Concretely, for a viewer at depth D:
    //   - DOWN messages are readable only when the sender is ≤ 2 below D
    //     (the sender is the monitored person talking to their invitees), and
    //   - UP replies are readable only when the sender is ≤ 3 below D
    //     (the reply belongs to the circle of the sender's parent, who must
    //      themselves be ≤ 2 below D).
    // Anything deeper is cryptographically unreachable: the sender's client
    // never encrypts a copy to ancestors outside this window.
    const depthDiff = pathDepth(sender.path) - pathDepth(viewer.path);
    const canMonitor = monitoringOn && viewerIsAncestorOfSender && (
      targetCircle === 'DOWN' ? depthDiff <= 2 : depthDiff <= 3
    );
    if (targetCircle === 'UP') {
      const inviter = allUsers.find(u => u.id === sender.invitedBy);
      const sg = inviter ? memberGids(inviter, sender.id) : [];
      // A LINKED chat message travelling UP (a group member posting): it reaches
      // the inviter (isChild), every sibling whose group is in the same link, and
      // visitors of the linked groups the sender is in. The link lives on the
      // inviter's node. Archived links are read-only (fall through: nobody).
      const uplink0 = targetGroup && inviter && inviter.groupLinks && inviter.groupLinks[targetGroup];
      const uplink = uplink0 && !uplink0.archived && Array.isArray(uplink0.groups) ? uplink0 : null;
      if (uplink) {
        if (isChild) return true;                        // the inviter/owner
        if (uplink.groups.filter(g => sg.includes(g)).some(g => gidVisitorIds(inviter, g).includes(viewer.id))) return true;
        if (rawSibling) return memberGids(inviter, viewer.id).some(g => uplink.groups.includes(g)); // a sibling in a linked group
        return canMonitor;
      }
      // A reply TAGGED to a group is that group's chat only: the inviter, the group's
      // other members and its visitors (plus oversight) — the group stays walled off.
      // Only a member of the group may post in it.
      if (targetGroup) {
        if (!sg.includes(targetGroup)) return false;
        if (isChild) return true;
        if (gidVisitorIds(inviter, targetGroup).includes(viewer.id)) return true;
        if (rawSibling) return memberGids(inviter, viewer.id).includes(targetGroup);
        return canMonitor;
      }
      // UNTAGGED = the main Descendants/Ancestors chat: the inviter and ALL of their
      // direct invitees, whatever groups they're in (groups are separate extra chats).
      return isChild || rawSibling || canMonitor;
    }
    if (targetCircle === 'DOWN') {
      // A cross-level VISITOR of this group receives the owner's group message,
      // even though the owner isn't their structural parent.
      if (targetGroup && gidVisitorIds(sender, targetGroup).includes(viewer.id)) return true;
      // Group-scoped descendants chat: when the inviter addresses a specific
      // group, only that group's direct invitees receive it (plus oversight
      // ancestors within the monitoring window). When targetGroup is null/absent
      // the message goes to the MAIN descendants chat: every direct invitee,
      // grouped or not (their groups are separate extra chats).
      if (isParent) {
        const myGids = memberGids(sender, viewer.id);
        // Linked chat addressed by the owner: any invitee in one of the linked
        // groups. Archived links are read-only (no new recipients).
        const link0 = targetGroup && sender.groupLinks && sender.groupLinks[targetGroup];
        const link = link0 && !link0.archived ? link0 : null;
        if (link) return myGids.some(g => link.groups.includes(g));
        if (targetGroup) return myGids.includes(targetGroup); // this group's members only
        return true;                                      // main chat = every direct invitee
      }
      return canMonitor;
    }
    return isParent || isChild || isSibling || canMonitor;
  });
};

// Announcements are a granted power: the root always has it; everyone else
// needs permissions.announce (granted from the Network tab by the root).
const canAnnounce = (u) => u.role === 'ROOT' || !!(u.permissions && u.permissions.announce);
// Global chat is on when the tree's root has enabled it (any member may then use it).
const globalChatOn = (u) => { const r = treeRootUser(u); return !!(r && r.globalChat); };
// Monitoring (ancestor oversight) is on unless the tree's root turned it off.
function monitoringOnFor(u) { const r = treeRootUser(u); return !r || r.monitorEnabled !== false; }
// Resolve + sanity-cap a client-sent target list (public ids -> internal ids).
const resolveTargets = (targets) => {
  if (!Array.isArray(targets)) return undefined;
  return targets.slice(0, 200).filter(t => isStr(t, 128)).map(t => resolveInternalId(t)).filter(Boolean);
};

const accountsForUsers = (users) => {
  const s = new Set();
  for (const u of users) if (u.accountId) s.add(u.accountId);
  return s;
};
const ancestorsOf = (user) => dbCache.users.filter(u => user.path.startsWith(u.path + '/'));
const subtreeOf = (user) => dbCache.users.filter(u => u.id === user.id || u.path.startsWith(user.path + '/'));

// ---- Premium / free-plan helpers -------------------------------------------
const treeRootUser = (anyNode) => {
  const rootId = String(anyNode.path || anyNode.id).split('/')[0];
  return dbCache.users.find(u => u.id === rootId) || null;
};
const treeMemberCount = (anyNode) => {
  const rootId = String(anyNode.path || anyNode.id).split('/')[0];
  return dbCache.users.filter(u => !u.pending && (u.path === rootId || String(u.path).startsWith(rootId + '/'))).length;
};
const accountById = (id) => dbCache.accounts.find(a => a.id === id) || null;
// PREMIUM IS PER NETWORK (V8 H-4). The plan is "$20/month per network", so paid
// time lives on the ROOT NODE of the network it was bought for (root.premiumUntil),
// never on the account — otherwise one payment covered every network the account
// could create. Two ACCOUNT-level exceptions remain, both explicit operator grants:
//   acc.compedPremium  — permanent free access (admin / grandfathering)
//   acc.compUntil      — timed free access (admin "+N days")
const DAY_MS = () => parseInt(process.env.PREMIUM_DAY_MS || '', 10) || 864e5; // test override
const accountComped = (acc) => !!(acc && (acc.compedPremium || (acc.compUntil && acc.compUntil > Date.now())));
// v72 M8: the premium / archived rules take their inputs, so a sweep can apply them
// from one index instead of scanning every user again for every network.
const premiumGiven = (root, acc) => !!root && ((root.premiumUntil && root.premiumUntil > Date.now()) || accountComped(acc));
const isTreePremium = (anyNode) => {
  const root = treeRootUser(anyNode);
  return premiumGiven(root, root && accountById(root.accountId));
};
/** v72 M8: one pass over users + accounts: root id -> { root, members (non-pending),
 *  accounts (their accounts), ids (every node, pending too) }, and accounts by id. */
const networkIndex = () => {
  const byRoot = new Map();
  for (const u of dbCache.users) {
    const rid = String(u.path).split('/')[0];
    let s = byRoot.get(rid);
    if (!s) byRoot.set(rid, s = { root: null, members: 0, accounts: new Set(), ids: [] });
    if (u.id === rid) s.root = u;
    s.ids.push(u.id);
    if (!u.pending) { s.members++; s.accounts.add(u.accountId); }
  }
  return { byRoot, accounts: new Map(dbCache.accounts.map(a => [a.id, a])) };
};
// Credit paid days to ONE network (by its internal root id).
const grantPremium = (rootId, days) => {
  const rootNode = dbCache.users.find(u => u.id === rootId && !String(u.path).includes('/'));
  if (!rootNode) return false;
  const wasArchived = isTreeArchived(rootNode);
  rootNode.premiumUntil = Math.max(Date.now(), rootNode.premiumUntil || 0) + days * DAY_MS();
  persistDB();
  notify(new Set([rootNode.accountId]));
  if (wasArchived && !isTreeArchived(rootNode)) {
    const members = treeAccountIds(rootNode);
    notifyPayload(members, { type: 'BILLING', reason: 'unarchived', ts: Date.now() });
    for (const accId of members) sendPushToAccount(accId, 'Arbor', 'This network is active again — the subscription was renewed.');
  }
  return true;
};
// Admin-only timed comp: account-wide by design (an operator decision about a person).
const grantAccountComp = (accountId, days) => {
  const acc = accountById(accountId);
  if (!acc) return;
  acc.compUntil = Math.max(Date.now(), acc.compUntil || 0) + days * DAY_MS();
  persistDB();
  notify(new Set([accountId]));
  for (const r of dbCache.users.filter(u => u.accountId === accountId && !String(u.path).includes('/'))) {
    notifyPayload(treeAccountIds(r), { type: 'BILLING', reason: 'unarchived', ts: Date.now() });
  }
};
// The account's "primary" paid network: its largest non-hub root. Used only to
// migrate legacy account-level premium and to map legacy payment records.
const primaryRootOf = (accountId) => {
  const roots = dbCache.users.filter(u => u.accountId === accountId && !String(u.path).includes('/') && (u.treeMode || '') !== 'HUB');
  if (!roots.length) return null;
  return roots.map(r => [r, treeMemberCount(r)]).sort((a, b) => b[1] - a[1])[0][0];
};
// Resolve a Stripe/NOWPayments record to the network it paid for.
const rootForPayment = (accountId, rootRef) => {
  if (rootRef) {
    const internal = resolveInternalId(rootRef) || rootRef;
    const r = dbCache.users.find(u => u.id === internal);
    if (r && r.accountId === accountId && !String(r.path).includes('/')) return r;
  }
  return primaryRootOf(accountId);
};
// ---- Archive lifecycle ------------------------------------------------------
// Premium lasts 30 days. After it lapses there is a 24-hour grace period
// (Stripe's renewal webhook arrives within minutes; Monero payers get a day to
// send a manual payment). A tree that is still over the free limit after the
// grace expires becomes ARCHIVED: reads still work, but messaging, calls, and
// growth are suspended until the root pays (unarchive) or deletes the network.
const GRACE_MS = parseInt(process.env.GRACE_MS_OVERRIDE || '', 10) || 24 * 60 * 60 * 1000; // test override
const archivedGiven = (root, memberCount, acc) => {
  if (process.env.PAYWALL_DISABLED === '1') return false; // donation-only mode
  if (memberCount <= FREE_TREE_LIMIT) return false;       // free plan is fine
  if (!root || !acc) return false;
  if (acc.compedPremium) return false; // permanent free access never archives
  const paidThrough = Math.max(root.premiumUntil || 0, acc.compUntil || 0);
  return paidThrough + GRACE_MS < Date.now();
};
const isTreeArchived = (anyNode) => {
  if (process.env.PAYWALL_DISABLED === '1') return false;
  const count = treeMemberCount(anyNode);
  if (count <= FREE_TREE_LIMIT) return false;
  const root = treeRootUser(anyNode);
  return archivedGiven(root, count, root && accountById(root.accountId));
};
const treeAccountIds = (anyNode) => {
  const rootId = String(anyNode.path || anyNode.id).split('/')[0];
  return new Set(dbCache.users
    .filter(u => !u.pending && (u.path === rootId || String(u.path).startsWith(rootId + '/')))
    .map(u => u.accountId));
};
// Sweep: notify every member once per lapse when a tree transitions to archived.
// v72 M8: from one index (v71 scanned every user for every network: roots × users).
const sweepArchives = () => {
  const { byRoot, accounts } = networkIndex();
  for (const s of byRoot.values()) {
    const root = s.root;
    if (!root) continue;
    const acc = accounts.get(root.accountId);
    const paidThrough = Math.max(root.premiumUntil || 0, (acc && acc.compUntil) || 0);
    if (!acc || acc.compedPremium || !paidThrough) continue; // never-premium/comped trees can't archive
    const archived = archivedGiven(root, s.members, acc);
    if (archived && (root.archiveNotifiedAt || 0) < paidThrough) {
      root.archiveNotifiedAt = Date.now();
      persistDB('users');
      const members = s.accounts;
      notifyPayload(members, { type: 'BILLING', reason: 'archived', ts: Date.now() });
      for (const accId of members) sendPushToAccount(accId, 'Arbor', 'This network is now archived — its subscription lapsed. The network root can restore it by renewing.');
    }
  }
};
setInterval(sweepArchives, 10 * 60 * 1000);

// Growth gate: returns null if the tree may add a member, else a message for
// the requester. Notifies the root (throttled) that an upgrade is needed.
const limitNoticeAt = new Map(); // rootAccountId -> last push ts (don't spam)
// v72: the most members any network can have — Premium's limit ("2,000 members"
// in the plan panel), and the largest audience one message can carry
// (MSG_MAX_RECIPS). v71 advertised "Unlimited" and enforced nothing.
// NETWORK_MEMBER_MAX can only LOWER it (tests use a small value).
const NETWORK_MEMBER_MAX = Math.min(2000, parseInt(process.env.NETWORK_MEMBER_MAX || '2000', 10) || 2000);
const growthGate = (anyNode) => {
  if ((anyNode.treeMode || '') === 'HUB') return null;
  if (treeMemberCount(anyNode) >= NETWORK_MEMBER_MAX) {
    return `This network has reached the limit of ${NETWORK_MEMBER_MAX.toLocaleString('en-US')} members.`;
  }
  if (process.env.PAYWALL_DISABLED === '1') return null; // donation-only mode
  if (treeMemberCount(anyNode) < FREE_TREE_LIMIT || isTreePremium(anyNode)) return null;
  const root = treeRootUser(anyNode);
  if (root) {
    const last = limitNoticeAt.get(root.accountId) || 0;
    if (Date.now() - last > 60 * 60 * 1000) {
      limitNoticeAt.set(root.accountId, Date.now());
      sendPushToAccount(root.accountId, 'Arbor', `Your network reached the free limit of ${FREE_TREE_LIMIT} members. Upgrade to Arbor Premium ($${PREMIUM_USD}/month) in the sidebar to keep growing.`);
      notifyPayload(new Set([root.accountId]), { type: 'BILLING', reason: 'limit', ts: Date.now() });
    }
  }
  return `This network is on the free plan (limit ${FREE_TREE_LIMIT} members). The network root has been notified that an upgrade to Arbor Premium ($${PREMIUM_USD}/month) is needed to add more people.`;
};

const sanitizeUser = (user, viewer) => {
  if (!user) return null;
  const isMe = viewer && user.id === viewer.id;
  const privilegedViewer = !!(viewer && (viewer.role === 'ROOT' || viewer?.permissions?.viewTrueLevel));
  const clean = {
    id: getPublicId(user.id),
    role: user.role, color: user.color, isMe, encPub: user.encPub, sigPub: user.sigPub,
  };
  // V8 phase 2 (M-8): profiles are end-to-end encrypted. The ciphertext rides
  // along; a plaintext name is only present for a legacy node whose owner hasn't
  // opened an updated app yet (it is deleted the moment they upload their
  // encrypted profile). `ik` is the node's Signal identity key as the server has
  // it — clients trust it only where a signed certificate agrees.
  if (user.profileCt) { clean.profileCt = user.profileCt; clean.profileAt = user.profileAt || 0; }
  else if (user.name) clean.name = user.name;
  { const ik = identityKeyOf(user); if (ik) clean.ik = ik; }
  // Network Profile: a lightweight avatar-version marker rides in the tree/context
  // payload so a client knows whether this node has a profile photo (and can
  // cache-bust when it changes) WITHOUT the image bytes bloating the list — the
  // bytes load lazily from /api/users/:id/avatar. Bio + name history are heavier
  // and only needed on the profile info view, so they are NOT sent here; they come
  // from /api/users/:id/profile on demand.
  if (user.avatarAt) clean.avatarAt = user.avatarAt;
  // Own profile (bio + full name history) rides along in the context payload so the
  // client's tree-context reconcile keeps it instead of spreading it back to
  // undefined (the recurring "reverts until reload" race). Other users' bio/history
  // stay lazy — fetched on demand for the profile info view — to keep the list lean.
  if (isMe && !user.profileCt) {
    if (user.bio) clean.bio = user.bio;
    if (Array.isArray(user.nameHistory) && user.nameHistory.length) clean.nameHistory = user.nameHistory;
  }
  if (isMe) {
    clean.treeRoot = treePidOf(user);
    if (user.selfCt) clean.selfCt = user.selfCt;
    if (user.anchorCt) clean.anchorCt = user.anchorCt;
    if (user.rotateNeededAt && user.role === 'ROOT' && !user.invitedBy) clean.rotateNeeded = true;
  }
  if (viewer) {
    clean.isDescendant = user.path.startsWith(viewer.path + '/');
    clean.isAncestor = viewer.path.startsWith(user.path + '/') && !isMe;
    clean.invitedBy = user.invitedBy ? getPublicId(user.invitedBy) : null;
    // Referral provenance (DM referral mode): the member who actually shared the
    // link, distinct from invitedBy (the root everyone is flattened onto). Exposed
    // as a public id so the client can render the display tree by who-referred-whom
    // while messaging stays 1:1-with-root. Opaque to viewers who can't see that node.
    if (user.referredBy) clean.referredBy = getPublicId(user.referredBy);
    if (isMe || clean.isDescendant) clean.permissions = user.permissions || {};
  }
  if (isMe || privilegedViewer) { clean.path = user.path; clean.level = user.level; }
  // Invitee-group exposure, least-privilege:
  //  - The inviter (isMe) and privileged/oversight viewers get the full map,
  //    which they legitimately need to render tabs / monitor structure.
  //  - A plain invitee learns ONLY which group id they themselves were placed
  //    in by this inviter — enough for their client to know its own sibling
  //    set, without revealing how the rest of the invitees are partitioned.
  if (isMe || privilegedViewer) {
    // ALWAYS present (even empty) for the owner/oversight: an explicit {} is how
    // the client distinguishes "deleted everything" from "stale fetch" — omitting
    // the fields made a delete look like missing data and get resurrected.
    const pubKeyed = {};
    for (const [internalId, gid] of Object.entries(user.inviteeGroups || {})) {
      pubKeyed[getPublicId(internalId)] = gid;
    }
    clean.inviteeGroups = pubKeyed;
    clean.groupLabels = user.groupLabels || {};
    clean.groupParents = user.groupParents || {}; // nested-group hierarchy (opaque group ids)
    clean.groupLinks = user.groupLinks || {};     // cross-group shared channels
    // Cross-level visitors of this node's groups (gid -> [public id,...]), so the
    // owner/oversight client can render them as visitor nodes and edit the list.
    { const vp = {}; for (const [gid, ids] of Object.entries(user.groupVisitors || {})) vp[gid] = (ids || []).map(getPublicId); clean.groupVisitors = vp; }
  } else if (viewer && user.inviteeGroups && user.inviteeGroups[viewer.id] != null) {
    const myGids = gidsOf(user.inviteeGroups[viewer.id]); // the viewer's OWN group(s)
    clean.myGroupUnder = user.inviteeGroups[viewer.id]; // scalar or array, exactly as stored
    // Also expose the NAME(S) of the viewer's own group(s) (their own membership
    // only — no leak of how the rest of the invitees are partitioned) so their
    // client can label their own node "in group: X" in every tree view.
    { const _gns = myGids.map(g => (user.groupLabels || {})[g]).filter(Boolean);
      if (_gns.length) { clean.myGroupName = _gns[0]; if (_gns.length > 1) clean.myGroupNames = _gns; } }
    // id -> name of the viewer's OWN groups, so their Ancestors tab can list each
    // group chat they're in (still nothing about anyone else's grouping).
    { const _gl = {}; for (const g of myGids) { const nm = (user.groupLabels || {})[g]; if (nm) _gl[g] = nm; }
      if (Object.keys(_gl).length) clean.myGroupLabels = _gl; }
    // A plain invitee also learns which LINKED chats their group(s) take part in
    // (id + name only) so their client can show the shared channel — without
    // revealing how the rest of the invitees are partitioned.
    const mine = {};
    for (const [lid, spec] of Object.entries(user.groupLinks || {})) {
      if (spec && Array.isArray(spec.groups) && myGids.some(g => spec.groups.includes(g))) mine[lid] = { name: spec.name, ...(spec.archived ? { archived: true } : {}) };
    }
    if (Object.keys(mine).length) clean.myLinks = mine;
    // ROSTER of the viewer's OWN group(s): expose the labels of just those groups,
    // the membership entries of CO-MEMBERS (restricted to the shared group ids), and
    // the CO-VISITORS of those groups — so the viewer can see who else is in their
    // group in every tree view. Other groups' names/members stay hidden.
    if (myGids.length) {
      const rlabels = {}; for (const g of myGids) if ((user.groupLabels || {})[g]) rlabels[g] = user.groupLabels[g];
      const rgroups = {};
      for (const [internalId, val] of Object.entries(user.inviteeGroups || {})) {
        const shared = gidsOf(val).filter(g => myGids.includes(g));
        if (shared.length) rgroups[getPublicId(internalId)] = shared.length === 1 ? shared[0] : shared;
      }
      const rvis = {};
      for (const g of myGids) { const ids = gidVisitorIds(user, g); if (ids.length) rvis[g] = ids.map(getPublicId); }
      clean.groupLabels = rlabels;
      clean.inviteeGroups = rgroups;
      if (Object.keys(rvis).length) clean.groupVisitors = rvis;
    }
  }
  if (isMe) { if (user.treeNameCt) clean.treeNameCt = user.treeNameCt; else if (user.treeName) clean.treeName = user.treeName; clean.treeNameVisible = !!user.treeNameVisible; clean.permissions = user.permissions; clean.treeMode = user.treeMode || 'HIERARCHICAL'; const _r = treeRootUser(user); clean.monitorEnabled = _r ? (_r.monitorEnabled !== false) : true; clean.referralOpen = !!(_r && _r.referralOpen); clean.globalChat = !!(_r && _r.globalChat); clean.autoAcceptInvites = !!(_r && _r.autoAcceptInvites);
    // My own group membership (name) under my inviter, so my node shows "in group: X"
    // in every tree view — even when my inviter's group map isn't exposed to me.
    if (user.invitedBy) { const _inv = dbCache.users.find(u => u.id === user.invitedBy); const _gns = _inv ? memberGids(_inv, user.id).map(g => (_inv.groupLabels || {})[g]).filter(Boolean) : []; if (_gns.length) { clean.myGroupName = _gns[0]; if (_gns.length > 1) clean.myGroupNames = _gns; } }
    // Groups on OTHER branches this user is a cross-level VISITOR of, so their client
    // can show a "Visiting: <group>" chat tab (owner public id + group id + names).
    const _visiting = [];
    for (const { o, gid } of visitedGroupsOf(user.id)) {
      const ids = gidVisitorIds(o, gid);
      // Roster of the visited group so the client can show it (with members) in the
      // tree: the owner, the owner's members-of-the-group, and co-visitors.
      const members = [getPublicId(o.id)];
      for (const inv of dbCache.users) if (!inv.pending && inv.invitedBy === o.id && memberGids(o, inv.id).includes(gid)) members.push(getPublicId(inv.id));
      for (const vid of ids) if (vid !== user.id) members.push(getPublicId(vid));
      _visiting.push({ o: getPublicId(o.id), g: gid, name: (o.groupLabels || {})[gid] || 'Group', members }); // owner's name resolves client-side
    }
    if (_visiting.length) clean.visiting = _visiting;
  }
  if (user.role === 'ROOT') {
    // Network-name visibility is its OWN switch, decoupled from True Sight.
    // When the root turns it on, every member sees the real network name in the
    // header (True Sight still governs only who can see the whole tree). When
    // off, only privileged viewers (root / True Sight holders) see it.
    clean.treeNameVisible = !!user.treeNameVisible;
    if (privilegedViewer || user.treeNameVisible) { if (user.treeNameCt) clean.treeNameCt = user.treeNameCt; else if (user.treeName) clean.treeName = user.treeName; }
  }
  return clean;
};

// ---------------------------------------------------------------------------
// SSE — authenticated via the session COOKIE (no token in the URL).
// ---------------------------------------------------------------------------
const notify = (accountIdSet) => {
  clients.forEach(c => { if (accountIdSet.has(c.accountId)) c.res.write(`data: ${JSON.stringify({ type: 'REFRESH' })}\n\n`); });
};
// Targeted payload event (used for ephemeral RTC signaling + typing indicators).
// Nothing here is persisted — the payload passes through and is gone.
const notifyPayload = (accountIdSet, obj) => {
  const line = `data: ${JSON.stringify(obj)}\n\n`;
  clients.forEach(c => { if (accountIdSet.has(c.accountId)) { try { c.res.write(line); } catch (e) {} } });
};

// SSE connection establishment is rate-limited (bounds reconnect storms) and the
// number of concurrent live streams per account is capped, so one account can't
// pin open unbounded server-side connections/timers. A normal client holds ONE
// stream open; a few is fine across tabs/devices.
const sseLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
const MAX_SSE_PER_ACCOUNT = 12;
app.get('/api/events', sseLimiter, (req, res) => {
  const session = sessionFromReq(req);
  if (!session) return res.status(401).end();
  // Evict this account's oldest live stream once over the cap (don't accumulate).
  const mine = clients.filter(c => c.accountId === session.accountId);
  if (mine.length >= MAX_SSE_PER_ACCOUNT) {
    const victim = mine[0];
    try { victim.res.end(); } catch (e) {}
    clients = clients.filter(c => c !== victim);
  }
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  res.write(': connected\n\n');
  const clientId = crypto.randomUUID();
  const heartbeat = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) {} }, 20000);
  clients.push({ id: clientId, res, accountId: session.accountId, tokenHash: session.tokenHash });
  touchAccountSeen(session.accountId);
  req.on('close', () => { clearInterval(heartbeat); clients = clients.filter(c => c.id !== clientId); });
});

app.get('/api/vapid-public-key', (req, res) => res.json({ publicKey: vapidPublicKey }));

// ---------------------------------------------------------------------------
// Auth (pre-session endpoints)
// ---------------------------------------------------------------------------
// Env-overridable ONLY so the local regression suite (many signups from one IP)
// can run; production keeps the default of 40 per 15 minutes per IP.
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: parseInt(process.env.AUTH_IP_PER_15MIN || '40', 10), standardHeaders: true, legacyHeaders: false });
// Recovery-blob fetch is a pre-auth lookup. Unknown ids already return a
// deterministic decoy (so real vs. fake accounts are indistinguishable), but a
// tighter dedicated limiter also raises the cost of bulk recoveryId probing
// from a single source. A legitimate user makes exactly one such request.
const recoveryLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

// ---------------------------------------------------------------------------
// Signup proof-of-work (anti-spam; no PII, no third party, no IP dependence).
//
// With no phone/email gate, signup was protected only by an IP rate limit (weak
// against proxy/botnet spam). PoW adds a per-account CPU cost: the client must
// find a nonce whose SHA-256(token '.' nonce) has >= difficulty leading zero
// bits. The challenge token is STATELESS — a MAC over {seed,issuedAt,difficulty}
// — so the server stores nothing between challenge and signup except a short-
// lived set of already-spent tokens (single-use => one solved puzzle = one
// account). Tunable via POW_SIGNUP_BITS (0 disables); TTL bounds precompute.
// Adaptive difficulty: POW_SIGNUP_BITS is the calm-state FLOOR; difficulty
// escalates toward POW_MAX_BITS as the recent successful-signup rate climbs past
// POW_ESCALATE_THRESHOLD (per POW_ESCALATE_WINDOW_MS). A flood makes each new
// account exponentially costlier while normal signups stay cheap. Base 0 disables.
const POW_SIGNUP_BITS = parseInt(process.env.POW_SIGNUP_BITS ?? '16', 10);
const POW_MAX_BITS = parseInt(process.env.POW_MAX_BITS ?? '21', 10);
const POW_ESCALATE_THRESHOLD = parseInt(process.env.POW_ESCALATE_THRESHOLD ?? '30', 10);
const POW_ESCALATE_WINDOW_MS = parseInt(process.env.POW_ESCALATE_WINDOW_MS ?? String(10 * 60 * 1000), 10);
const POW_TTL_MS = parseInt(process.env.POW_TTL_MS ?? String(10 * 60 * 1000), 10);
// Sliding window of recent successful signups -> current difficulty. Measuring
// COMPLETED signups (not challenge requests) means the rate signal can't be
// cheaply inflated to force hard puzzles on everyone: driving it up costs the
// attacker the escalating work itself.
let signupTimes = [];
const recordSignup = () => { signupTimes.push(Date.now()); };
const currentPowBits = () => {
  if (POW_SIGNUP_BITS <= 0) return 0;
  const cut = Date.now() - POW_ESCALATE_WINDOW_MS;
  signupTimes = signupTimes.filter(t => t >= cut);
  const over = signupTimes.length / POW_ESCALATE_THRESHOLD;
  const extra = over > 1 ? 2 * Math.ceil(Math.log2(over)) : 0; // +2 bits (4x) per doubling over threshold
  return Math.min(POW_SIGNUP_BITS + extra, POW_MAX_BITS);
};
const powMac = (payload) => crypto.createHmac('sha256', SERVER_SALT + ':pow').update(payload).digest('base64url');
const powSpent = new Map(); // mac -> issuedAt; in-memory (a restart only re-opens a <=TTL window)
const prunePowSpent = () => { const cut = Date.now() - POW_TTL_MS; for (const [m, t] of powSpent) if (t < cut) powSpent.delete(m); };
const leadingZeroBits = (buf) => {
  let bits = 0;
  for (const b of buf) {
    if (b === 0) { bits += 8; continue; }
    let x = b, c = 0; while ((x & 0x80) === 0) { c++; x <<= 1; }
    return bits + c;
  }
  return bits;
};
// Validate a submitted proof. Returns null on success (and SPENDS the token), or
// a user-facing error string. A no-op that returns null when PoW is disabled.
const verifyPow = (token, nonce) => {
  if (POW_SIGNUP_BITS <= 0) return null;
  if (typeof token !== 'string' || typeof nonce !== 'string' || token.length > 256 || nonce.length > 64) return 'Proof of work required — please retry.';
  const parts = token.split('.');
  if (parts.length !== 4) return 'Invalid proof of work.';
  const [seed, issuedAtStr, diffStr, mac] = parts;
  const expected = powMac(`${seed}.${issuedAtStr}.${diffStr}`);
  let macOk = false;
  try { macOk = mac.length === expected.length && crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected)); } catch {}
  if (!macOk) return 'Invalid proof of work.';
  const issuedAt = Number(issuedAtStr), difficulty = Number(diffStr);
  if (!Number.isFinite(issuedAt) || Date.now() - issuedAt > POW_TTL_MS || issuedAt > Date.now() + 60000) return 'Proof of work expired — please retry.';
  if (!Number.isFinite(difficulty) || difficulty < POW_SIGNUP_BITS) return 'Invalid proof of work.';
  prunePowSpent();
  if (powSpent.has(mac)) return 'Proof of work already used — please retry.';
  const digest = crypto.createHash('sha256').update(token + '.' + nonce).digest();
  if (leadingZeroBits(digest) < difficulty) return 'Invalid proof of work.';
  powSpent.set(mac, issuedAt); // single-use: consume only on a fully valid proof
  return null;
};

// Issue a fresh signup challenge. Pre-session, rate-limited. Reports disabled so
// an old client / disabled deployment can skip straight to signup.
app.get('/api/auth/pow-challenge', authLimiter, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const bits = currentPowBits();
  if (bits <= 0) return res.json({ disabled: true });
  const seed = crypto.randomBytes(16).toString('hex');
  const payload = `${seed}.${Date.now()}.${bits}`;
  res.json({ token: `${payload}.${powMac(payload)}`, difficulty: bits, ttlMs: POW_TTL_MS });
});

// Per-account wrap salt. Returns a STABLE fake salt for unknown users so this
// endpoint cannot be used to enumerate accounts.
app.post('/api/auth/salt', authLimiter, (req, res) => {
  const { username } = req.body || {};
  if (!isStr(username, 64)) return bad(res, 'Invalid input');
  const account = findByUsername(username);
  const salt = account?.wrapSalt || crypto.createHmac('sha256', SERVER_SALT).update('saltfake:' + username.toLowerCase()).digest('hex').slice(0, 32);
  // Password-KDF version (V8 H-3): 1 = legacy PBKDF2 (upgraded by the client on
  // its next successful login), 2 = memory-hard scrypt. Unknown usernames report
  // the default (2), same as every new account, so this adds no oracle beyond
  // "an un-migrated legacy account" — which the signup username check already
  // reveals for any existing name.
  res.json({ salt, kdf: account ? (account.kdf || 1) : 2 });
});

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  const { username, authHash, wrapSalt, powToken, powNonce, kdf } = req.body || {};
  if (!isStr(username, 64) || !isStr(authHash, 512) || !isStr(wrapSalt, 128)) return bad(res, 'Invalid input');
  if (kdf !== undefined && kdf !== 1 && kdf !== 2) return bad(res, 'Invalid input');
  if (!/^[A-Za-z0-9_.\-]{3,64}$/.test(username)) return bad(res, 'Username must be 3-64 chars (letters, numbers, _ . -).');
  if (findByUsername(username))
    return res.status(400).json({ error: 'Username taken' }); // cheap check before spending the proof
  // Anti-spam gate: a valid, unspent proof of work is required to create an account.
  const powErr = verifyPow(powToken, powNonce);
  if (powErr) return res.status(400).json({ error: powErr });
  // kdf 2 = client derived authHash + wrap key with scrypt (V8 H-3). An old cached
  // client omits it (kdf 1) and is upgraded transparently at its next login.
  const passwordHash = await hashPassword(authHash);
  // The hash ran asynchronously: another signup could have taken the name meanwhile.
  if (findByUsername(username)) return res.status(400).json({ error: 'Username taken' });
  const account = { id: uuid('acc_'), usernameHash: usernameHash(username), passwordHash, wrapSalt,
    kdf: kdf === 2 ? 2 : 1, createdDay: dayStamp(), lastSeenDay: dayStamp() };
  dbCache.accounts.push(account);
  recordSignup(); // feeds adaptive PoW difficulty (escalates under signup floods)
  const { token, csrf } = newSession(account.id);
  setSessionCookies(req, res, token, csrf);
  res.json({ id: account.id, username, csrf }); // echo submitted username; server keeps only its hash
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { username, authHash } = req.body || {};
  if (!isStr(username, 64) || !isStr(authHash, 512)) return bad(res, 'Invalid input');

  const { k, s } = throttleState(username);
  // Progressive delay from recent failures — NOT a hard lock. A correct password
  // still succeeds after the (bounded) delay, so a third party cannot lock a user
  // out by spamming failures against their username.
  const delay = loginDelayFor(s.count);
  if (delay) await sleep(delay);

  const account = findByUsername(username);
  // Always run scrypt (against a decoy when the user is unknown) for constant time.
  const ok = account ? await verifyPassword(authHash, account.passwordHash) : (await verifyPassword(authHash, DECOY_HASH), false);
  if (!ok || !accountById(account.id)) {             // (deleted while we were hashing)
    s.count += 1;
    s.lastFailAt = Date.now();
    loginFails.set(k, s);
    if (loginFails.size > 5000) pruneLoginFails();
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  loginFails.delete(k);
  // v71: this browser's previous session (its cookie is about to be overwritten)
  // ends now, instead of lingering unreachable until it expires — it would show as
  // an "other signed-in session" and keep its live event stream.
  const prior = sessionFromReq(req);
  if (prior) { dbCache.sessions = dbCache.sessions.filter(s => s !== prior); endOrphanStreams(prior.accountId); }
  const { token, csrf } = newSession(account.id);
  setSessionCookies(req, res, token, csrf);
  // v71 M6: after a password change, the earlier wrap key(s), sealed under the NEW
  // one (unreadable without the new password), so this device can re-seal the
  // local data it encrypted under the old key.
  const prevWraps = livePrevWraps(account);
  res.json({ id: account.id, username, csrf, ...(prevWraps.length ? { prevWraps } : {}) }); // echo submitted username; server keeps only its hash
});

// ---------------------------------------------------------------------------
// Seed-phrase recovery (replaces password resets).
// At signup (or later, from Settings) the client derives from a random seed
// phrase: a lookup id (hash) and an encryption key, then stores ONLY
// ciphertext here — the server can never read the recovered credentials.
// Fetch is pre-auth (the user has forgotten their login). Anti-enumeration:
// unknown ids return a deterministic fake blob (HMAC-seeded), so an attacker
// cannot learn whether a given seed phrase exists.
// ---------------------------------------------------------------------------
app.post('/api/auth/recovery/fetch', authLimiter, recoveryLimiter, (req, res) => {
  const { recoveryId } = req.body || {};
  if (!isStr(recoveryId, 128)) return bad(res, 'Invalid input');
  const rec = (dbCache.recovery || []).find(r => r.recoveryId === recoveryId);
  if (rec) return res.json({ blob: rec.blob });
  // Deterministic decoy: same shape, same id -> same bytes, undecryptable.
  // v72 (L): and the same SIZE as a real blob — the app pads the recovery plaintext
  // to 512 bytes (+16-byte tag); v71's decoy was always 64 bytes, unlike real ones.
  const fake = crypto.createHmac('sha256', SERVER_SALT + ':recovery-decoy').update(recoveryId).digest();
  const fakeIv = fake.subarray(0, 12).toString('base64');
  const fakeCt = Buffer.from(crypto.hkdfSync('sha256', SERVER_SALT, recoveryId, 'arbor-recovery-decoy-ct', 512 + 16)).toString('base64');
  res.json({ blob: JSON.stringify({ v: 2, iv: fakeIv, ct: fakeCt }) });   // v71: same version as real blobs
});

// ---------------------------------------------------------------------------
// Auth middleware — session from cookie; CSRF double-submit on state changes.
// Everything registered BELOW this line requires a valid session.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Admin statistics — AGGREGATE COUNTS ONLY.
//
// Registered BEFORE the session middleware so it is gated purely on the admin
// token, not on a user session. If ADMIN_TOKEN is unset the route 404s exactly
// like a nonexistent path, so an un-configured server gives nothing away.
//
// This endpoint never returns usernames, node names, message content, or any
// per-account row — only totals. There is deliberately no way to ask it "who
// was online"; that data does not exist on the server.
// ---------------------------------------------------------------------------
const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || '').trim();
// The admin pages submit plain HTML forms (login / logout). Under the site-wide
// "no-referrer" policy a browser sends those POSTs with `Origin: null`, which the
// cross-site guard rightly refuses. "same-origin" keeps the real Origin on
// same-site requests only; nothing is ever sent to another site.
app.use('/api/admin', (req, res, next) => { res.setHeader('Referrer-Policy', 'same-origin'); next(); });
// A signed-in dashboard (valid admin cookie) isn't throttled: its live refresh
// alone polls every 2s and used to use up this whole budget, so the next page
// load or login answered "Too many requests". Unauthenticated calls stay capped.
const adminLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, skip: (req) => adminCookieOk(req) });
// Token guesses get their own tight budget; the form shows why it refused.
const adminLoginLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => res.redirect(302, '/api/admin?e=2') });

const adminTokenOk = (given) => {
  if (typeof given === 'string') given = given.trim(); // a pasted token often carries a line break
  if (!ADMIN_TOKEN || typeof given !== 'string' || !given) return false;
  // Hash both sides so timingSafeEqual always gets equal-length buffers.
  const a = crypto.createHash('sha256').update(given).digest();
  const b = crypto.createHash('sha256').update(ADMIN_TOKEN).digest();
  return crypto.timingSafeEqual(a, b);
};

// Admin browser sessions: the token is entered ONCE into a password field, POSTed,
// validated, and exchanged for a random HttpOnly cookie id — so the long-lived
// ADMIN_TOKEN never rides in a URL (bookmarks, history, proxy logs) or in
// page-readable JS. Scripts/curl can still pass the token via the x-admin-token
// header or ?token=. In-memory: an admin re-enters the token after a restart.
const adminSessions = new Map(); // id -> expiresAt
const ADMIN_SESSION_TTL = 8 * 60 * 60 * 1000; // 8h
const newAdminSession = () => {
  const now = Date.now();
  for (const [k, exp] of adminSessions) if (exp < now) adminSessions.delete(k); // prune
  const id = crypto.randomBytes(32).toString('base64url');
  adminSessions.set(id, now + ADMIN_SESSION_TTL);
  return id;
};
// True if the request carries a live admin session cookie.
function adminCookieOk(req) {
  const cid = parseCookies(req)['arbor_admin'];
  if (!cid) return false;
  const exp = adminSessions.get(cid);
  if (exp && Date.now() < exp) return true;
  if (exp) adminSessions.delete(cid);
  return false;
}
// True if the request carries a valid admin cookie OR a valid token header.
const adminAuthed = (req) => adminCookieOk(req)
  || adminTokenOk(req.headers['x-admin-token']);   // v71 L2: header or cookie only — never ?token= (URLs are logged)

const buildStats = () => {
  const accounts = dbCache.accounts || [];
  const users = dbCache.users || [];
  const now = Date.now();
  const today = dayStamp();
  const d7 = dayStampAgo(6);     // inclusive 7-day window (today + 6 prior)
  const d30 = dayStampAgo(29);

  // ISO day strings compare correctly with plain string ordering.
  const seenSince = (cut) => accounts.filter(a => a.lastSeenDay && a.lastSeenDay >= cut).length;
  const madeSince = (cut) => accounts.filter(a => a.createdDay && a.createdDay >= cut).length;

  const liveAccounts = new Set(clients.map(c => c.accountId));
  const roots = users.filter(u => u.role === 'ROOT');

  const dau = seenSince(today), wau = seenSince(d7), mau = seenSince(d30);

  return {
    generatedAt: new Date(now).toISOString(),
    accounts: {
      total: accounts.length,
      newToday: madeSince(today),
      new7d: madeSince(d7),
      new30d: madeSince(d30),
      // Accounts that predate stats collection have no createdDay/lastSeenDay.
      withoutHistory: accounts.filter(a => !a.lastSeenDay).length,
    },
    active: {
      today: dau,
      last7d: wau,
      last30d: mau,
      connectedNow: liveAccounts.size,
      // Stickiness: DAU/MAU. Industry shorthand for how habitual usage is.
      dauOverMau: mau ? +(dau / mau).toFixed(3) : 0,
    },
    nodes: {
      total: users.length,
      pending: users.filter(u => u.pending).length,
      hierarchical: users.filter(u => u.treeMode !== 'HUB' && u.treeMode !== 'DM').length,
      direct: users.filter(u => u.treeMode === 'DM').length,
      personalHubs: users.filter(u => u.treeMode === 'HUB').length,
    },
    networks: {
      total: roots.length,
      hierarchical: roots.filter(u => u.treeMode !== 'HUB' && u.treeMode !== 'DM').length,
      personalHubs: roots.filter(u => u.treeMode === 'HUB').length,
      largest: roots.reduce((m, r) => {
        const size = users.filter(u => u.path && u.path.startsWith(r.id)).length;
        return Math.max(m, size);
      }, 0),
    },
    premium: {
      // Premium is per network now: count accounts owning >=1 paid network, plus comps.
      active: accounts.filter(a => accountComped(a) || users.some(u => u.accountId === a.id && u.premiumUntil > now)).length,
      comped: accounts.filter(a => a.compedPremium).length,
      // paid balance, not comped
      paying: accounts.filter(a => !a.compedPremium && users.some(u => u.accountId === a.id && u.premiumUntil > now)).length,
    },
  };
};

const statsHtml = (st) => {
  const card = (label, value, sub) => `
    <div class="card">
      <div class="lbl">${label}</div>
      <div class="val">${value}</div>
      ${sub ? `<div class="sub">${sub}</div>` : ''}
    </div>`;
  return `<!DOCTYPE html><html><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="robots" content="noindex,nofollow"/>
<title>Arbor · Stats</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"Inter",system-ui,sans-serif;padding:28px;-webkit-font-smoothing:antialiased}
h1{font-size:15px;font-weight:800;letter-spacing:.22em;text-transform:uppercase;color:#10b981;margin-bottom:4px}
.ts{font-size:11px;color:#52525b;margin-bottom:26px}
h2{font-size:10px;font-weight:800;letter-spacing:.2em;text-transform:uppercase;color:#71717a;margin:26px 0 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}
.card{background:#111;border:1px solid #1c1c1c;border-radius:16px;padding:16px}
.lbl{font-size:9px;font-weight:800;letter-spacing:.16em;text-transform:uppercase;color:#10b981;margin-bottom:8px}
.val{font-size:30px;font-weight:800;letter-spacing:-.02em;line-height:1}
.sub{font-size:10px;color:#52525b;margin-top:6px}
.note{margin-top:32px;font-size:11px;color:#3f3f46;line-height:1.7;border-top:1px solid #1a1a1a;padding-top:16px}
</style></head><body>
<h1>Arbor Statistics</h1>
<div class="ts">Generated ${st.generatedAt}</div>

<h2>Active users</h2>
<div class="grid">
${card('Daily active', st.active.today, 'DAU')}
${card('Weekly active', st.active.last7d, 'WAU · 7 days')}
${card('Monthly active', st.active.last30d, 'MAU · 30 days')}
${card('Connected now', st.active.connectedNow, 'live connections')}
${card('Stickiness', st.active.dauOverMau, 'DAU / MAU')}
</div>

<h2>User base</h2>
<div class="grid">
${card('Total accounts', st.accounts.total, 'registered')}
${card('New today', st.accounts.newToday)}
${card('New this week', st.accounts.new7d, '7 days')}
${card('New this month', st.accounts.new30d, '30 days')}
${card('Paying', st.premium.paying, '$${PREMIUM_USD}/mo subscribers')}
${card('Comped', st.premium.comped, 'free access granted')}
${card('Premium total', st.premium.active, 'paying + comped')}
</div>

<h2>Networks &amp; nodes</h2>
<div class="grid">
${card('Networks', st.networks.total, 'root nodes')}
${card('Hierarchical', st.networks.hierarchical)}
${card('Personal hubs', st.networks.personalHubs)}
${card('Largest network', st.networks.largest, 'members')}
${card('Total nodes', st.nodes.total, 'identities')}
${card('Pending', st.nodes.pending, 'awaiting approval')}
</div>

<div class="note">
Aggregate counts only. The server stores one coarse UTC day stamp per account
(last day active), overwritten daily — no clock times, no IP addresses, no
activity history, and no message content is used to produce these numbers.
${st.accounts.withoutHistory ? `<br/>${st.accounts.withoutHistory} account(s) predate stats collection and are excluded from active counts until their next sign-in.` : ''}
</div>
</body></html>`;
};

app.get('/api/admin/stats', adminLimiter, (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).end();                 // feature off
  if (!adminAuthed(req)) return res.status(404).end();             // cookie or token; no oracle
  const st = buildStats();
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  if (req.query.format === 'html') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(statsHtml(st));
  }
  res.json(st);
});

// ---- Live server HEALTH (operational stress) — same ADMIN_TOKEN gate as /stats.
// Aggregate numbers only (no user data): event-loop lag, req/s + p95, SSE count,
// memory/swap, and PG pool saturation. Default response is a self-refreshing HTML
// dashboard (open it in a browser tab); add &format=json for curl/watch/jq.
const _pctH = (arr, p) => { if (!arr.length) return 0; const a = [...arr].sort((x, y) => x - y); return a[Math.min(a.length - 1, Math.floor(p / 100 * a.length))]; };
const readSwap = () => {
  try {
    const mi = fs.readFileSync('/proc/meminfo', 'utf8');
    const g = k => { const m = mi.match(new RegExp(k + ':\\s+(\\d+)')); return m ? +m[1] : 0; };
    const tot = g('SwapTotal'), free = g('SwapFree');
    if (tot) return { usedMB: Math.round((tot - free) / 1024), totalMB: Math.round(tot / 1024) };
  } catch {}
  return null; // not Linux / no swap info
};
// Storage: the filesystem holding the app + database (statfs is a cheap syscall,
// read live on every refresh) and the database's own size (a query, so cached
// and refreshed every 30s in the background).
const readDisk = () => {
  for (const p of [process.env.ARBOR_DATA_DIR, '/'].filter(Boolean)) {
    try {
      const s = fs.statfsSync(p);
      const total = s.blocks * s.bsize, avail = s.bavail * s.bsize, used = total - s.bfree * s.bsize;
      if (!total) continue;
      return { totalGB: +(total / 1e9).toFixed(1), usedGB: +(used / 1e9).toFixed(1), freeGB: +(avail / 1e9).toFixed(1), usedPct: +(100 * used / (used + avail)).toFixed(1) };
    } catch { /* try the next path */ }
  }
  return null;
};
let _dbSize = { bytes: null, at: 0 };
const refreshDbSize = async () => { try { const n = await dbSizeBytes(); if (n != null) _dbSize = { bytes: Number(n), at: Date.now() }; } catch {} };
refreshDbSize();
setInterval(refreshDbSize, 30000).unref();
const buildHealth = () => {
  const now = Date.now(), winMs = 10000;
  const recent = reqLog.filter(r => now - r.t <= winMs);
  const tc = recent.filter(r => r.tc);
  const lat = recent.map(r => r.ms), tcLat = tc.map(r => r.ms);
  const mem = process.memoryUsage();
  const totalMem = os.totalmem(), freeMem = os.freemem();
  const ps = poolStats();
  const elm = eventLoopDelay.mean / 1e6, elp99 = eventLoopDelay.percentile(99) / 1e6, elmax = eventLoopDelay.max / 1e6;
  eventLoopDelay.reset(); // report lag since the previous read → a live rolling view
  // CPU capacity: load average vs core count. loadPerCorePct ~100% = cores fully
  // busy, >100% = work queuing (requests waiting on CPU). Linux only; os.loadavg()
  // returns [0,0,0] on Windows, so this reads ~0 on the local box and true on prod.
  const cores = os.cpus().length;
  const [l1, l5, l15] = os.loadavg();
  const swap = readSwap();
  return {
    generatedAt: new Date(now).toISOString(),
    uptimeSec: Math.round(process.uptime()),
    backend: BACKEND,
    server: { cpuCores: cores, totalMemMB: Math.round(totalMem / 1048576), platform: os.platform() },
    cpu: { cores, load1: +l1.toFixed(2), load5: +l5.toFixed(2), load15: +l15.toFixed(2), loadPerCorePct: +(100 * l1 / cores).toFixed(1) },
    eventLoopLagMs: { mean: +elm.toFixed(1), p99: +elp99.toFixed(1), max: +elmax.toFixed(1) },
    requests: {
      windowSec: winMs / 1000,
      perSec: +(recent.length / (winMs / 1000)).toFixed(1),
      p50Ms: Math.round(_pctH(lat, 50)), p95Ms: Math.round(_pctH(lat, 95)), p99Ms: Math.round(_pctH(lat, 99)),
      treeContextPerSec: +(tc.length / (winMs / 1000)).toFixed(1),
      treeContextP95Ms: Math.round(_pctH(tcLat, 95)),
    },
    sse: { connections: clients.length, accounts: new Set(clients.map(c => c.accountId)).size },
    push: { ...pushStats, inFlight: pushInFlight, waiting: pushWaiters.length },   // v72 M8 (counts since start)
    memory: {
      rssMB: Math.round(mem.rss / 1048576), heapUsedMB: Math.round(mem.heapUsed / 1048576),
      systemUsedMB: Math.round((totalMem - freeMem) / 1048576), systemTotalMB: Math.round(totalMem / 1048576),
      systemUsedPct: +(100 * (totalMem - freeMem) / totalMem).toFixed(1),
      swap: swap ? { ...swap, usedPct: swap.totalMB ? +(100 * swap.usedMB / swap.totalMB).toFixed(1) : 0 } : null,
    },
    db: ps ? { poolMax: ps.max, poolInUse: ps.total - ps.idle, poolIdle: ps.idle, poolWaiting: ps.waiting, poolUsedPct: ps.max ? +(100 * (ps.total - ps.idle) / ps.max).toFixed(1) : 0 } : null,
    storage: { disk: readDisk(), dbMB: _dbSize.bytes != null ? +(_dbSize.bytes / 1048576).toFixed(1) : null },
  };
};
const _hColor = (v, warn, bad) => v >= bad ? '#ef4444' : v >= warn ? '#f59e0b' : '#10b981';
const _hBar = (pct, c) => `<div style="height:8px;background:#ffffff10;border-radius:99px;overflow:hidden;margin-top:9px"><div style="height:100%;width:${Math.max(0, Math.min(100, pct))}%;background:${c};border-radius:99px;transition:width .45s ease,background .45s ease"></div></div>`;
// gauge = a metric shown as a fill-bar toward its max (pct != null); meter = a raw
// indicator value with no natural 0-100 ceiling (pct null → no bar).
const _hCard = (label, big, unit, pct, c, sub) => `<div style="background:#111;border:1px solid #ffffff14;border-radius:14px;padding:15px 17px;flex:1;min-width:172px">
  <div style="font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#71717a;font-weight:800">${label}</div>
  <div style="font-size:27px;font-weight:800;color:${c};margin-top:5px;line-height:1.1">${big}<span style="font-size:13px;color:#52525b;font-weight:600"> ${unit || ''}</span></div>
  ${pct != null ? _hBar(pct, c) : ''}
  ${sub ? `<div style="font-size:11px;color:#71717a;margin-top:7px">${sub}</div>` : ''}</div>`;
const healthCards = (h) => {
  const m = h.memory, db = h.db, sw = m.swap, cpu = h.cpu, dk = h.storage && h.storage.disk, dbMB = h.storage && h.storage.dbMB;
  return `
    ${dk ? _hCard('Disk', dk.usedPct, '%', dk.usedPct, _hColor(dk.usedPct, 75, 90), dk.usedGB + ' / ' + dk.totalGB + 'GB used · ' + dk.freeGB + 'GB free') : ''}
    ${dbMB != null ? _hCard('Database', dbMB >= 1024 ? (dbMB / 1024).toFixed(2) : dbMB, dbMB >= 1024 ? 'GB' : 'MB', dk ? Math.min(100, 100 * (dbMB / 1024) / dk.totalGB) : null, '#38bdf8', 'messages, media & accounts' + (dk ? ' · ' + (100 * (dbMB / 1024) / dk.totalGB).toFixed(1) + '% of disk' : '')) : ''}
    ${_hCard('CPU load / core', cpu.loadPerCorePct, '%', cpu.loadPerCorePct, _hColor(cpu.loadPerCorePct, 70, 95), cpu.cores + ' cores · load ' + cpu.load1 + ' (1m)' + (cpu.loadPerCorePct === 0 ? ' · n/a on Windows' : ''))}
    ${_hCard('Memory', m.systemUsedPct, '%', m.systemUsedPct, _hColor(m.systemUsedPct, 75, 90), m.systemUsedMB + ' / ' + m.systemTotalMB + 'MB · Node ' + m.rssMB + 'MB')}
    ${sw ? _hCard('Swap', sw.usedPct, '%', sw.usedPct, _hColor(sw.usedMB, 1, 100), sw.usedMB + ' / ' + sw.totalMB + 'MB · ANY swap = danger') : ''}
    ${db ? _hCard('DB pool', db.poolUsedPct, '%', db.poolUsedPct, _hColor(db.poolWaiting, 1, 5), db.poolInUse + ' / ' + db.poolMax + ' used' + (db.poolWaiting ? ' · ' + db.poolWaiting + ' WAITING' : '')) : ''}
    ${_hCard('Event-loop lag p99', h.eventLoopLagMs.p99, 'ms', h.eventLoopLagMs.p99 / 2, _hColor(h.eventLoopLagMs.p99, 50, 200), 'max ' + h.eventLoopLagMs.max + 'ms · >50 = CPU strain')}
    ${_hCard('Requests / sec', h.requests.perSec, '', null, '#38bdf8', 'p95 ' + h.requests.p95Ms + 'ms · tree-ctx ' + h.requests.treeContextPerSec + '/s p95 ' + h.requests.treeContextP95Ms + 'ms')}
    ${_hCard('SSE live', h.sse.connections, '', null, _hColor(h.sse.connections, 1500, 3000), h.sse.accounts + ' accounts connected')}`;
};
const _hPage = (title, bodyInner) => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title></head>
  <body style="margin:0;background:#0a0a0a;color:#e4e4e7;font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;padding:20px">${bodyInner}</body></html>`;
const healthHtml = (h) => {
  const up = `${Math.floor(h.uptimeSec / 3600)}h${Math.floor(h.uptimeSec / 60) % 60}m`;
  return _hPage('Arbor · Live Health', `
    <div style="display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:16px">
      <div style="font-size:16px;font-weight:800">Arbor · Live Server Health</div>
      <div style="font-size:11px;color:#52525b">${h.server.cpuCores} cores · ${(h.server.totalMemMB / 1024).toFixed(1)}GB RAM · ${h.backend} · up ${up} · updates live · ${new Date(h.generatedAt).toLocaleTimeString()}</div></div>
    <div id="arbor-health" style="display:flex;flex-wrap:wrap;gap:12px">${healthCards(h)}</div>
    <div style="font-size:11px;color:#3f3f46;margin-top:18px">Bars fill toward the server's max · green ok · amber watch · red act · <code style="color:#71717a">&format=json</code> for raw output.</div>
    <script src="/api/admin/health.js" defer></script>`);
};
app.get('/api/admin/health', adminLimiter, (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).end();                 // feature off
  if (!adminAuthed(req)) return res.status(404).end();             // cookie or token; no oracle
  const h = buildHealth();
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  if (req.query.format === 'json') return res.json(h);
  if (req.query.format === 'fragment') { res.setHeader('Content-Type', 'text/html; charset=utf-8'); return res.send(healthCards(h)); }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(healthHtml(h));
});
// Tiny CSP-safe script (served from 'self') that refreshes ONLY the #arbor-health
// cards every 2s via fetch — so the dashboard updates seamlessly with no page reload.
app.get('/api/admin/health.js', adminLimiter, (req, res) => {
  // V8 L-5: same gate as every sibling admin route — unconfigured or
  // unauthenticated means a plain 404, so the route is no existence oracle.
  if (!ADMIN_TOKEN) return res.status(404).end();
  if (!adminAuthed(req)) return res.status(404).end();
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.send(`(function(){var el=document.getElementById('arbor-health');if(!el)return;function tick(){fetch('/api/admin/health?format=fragment',{credentials:'same-origin'}).then(function(r){return r.ok?r.text():null;}).then(function(h){if(h!=null)el.innerHTML=h;}).catch(function(){});}setInterval(tick,2000);})();`);
});
// Script for the Free-access panel (grant/revoke/check). Uses the admin cookie.
app.get('/api/admin/comp.js', adminLimiter, (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).end();
  if (!adminAuthed(req)) return res.status(404).end();
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.send(`(function(){
    var out=document.getElementById('cmpOut');
    function uname(){return (document.getElementById('cmpU').value||'').trim();}
    function show(ok,msg){out.style.color=ok?'#6ee7b7':'#fca5a5';out.textContent=msg;}
    function call(path,body){return fetch('/api/admin/'+path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify(body)}).then(function(r){return r.json().catch(function(){return null;}).then(function(d){return {status:r.status,d:d};});});}
    function status(){var u=uname();if(!u)return;call('comp/status',{username:u}).then(function(x){if(x.status!==200)return show(false,(x.d&&x.d.error)||'Not found');var d=x.d;show(true,u+' — '+(d.compedPremium?'Permanent free access':(d.premiumActive?('Premium until '+((d.premiumUntilISO||'').slice(0,10)||'—')):'No premium')));});}
    function grant(mode,days){var u=uname();if(!u)return;var body=mode==='permanent'?{username:u,mode:'permanent'}:{username:u,mode:'days',days:days};call('comp',body).then(function(x){show(x.status===200,x.status===200?(mode==='permanent'?('Granted permanent free access to '+u):(days+' free days granted to '+u)):((x.d&&x.d.error)||'Failed'));});}
    function revoke(){var u=uname();if(!u)return;if(!confirm('Revoke premium for '+u+'? (paid time is kept)'))return;call('comp/revoke',{username:u}).then(function(x){show(x.status===200,x.status===200?('Revoked comped access for '+u):((x.d&&x.d.error)||'Failed'));});}
    var els=document.querySelectorAll('[data-cmp]');
    for(var i=0;i<els.length;i++){(function(b){b.addEventListener('click',function(){var k=b.getAttribute('data-cmp');if(k==='status')status();else if(k==='perm')grant('permanent');else if(k==='30')grant('days',30);else if(k==='365')grant('days',365);else if(k==='revoke')revoke();});})(els[i]);}
  })();`);
});

// Combined admin landing: business metrics on top, live server health below —
// the one page to open during a launch. Same ADMIN_TOKEN gate.
// The combined dashboard = the FULL existing stats page (unchanged) with the live
// health section injected beneath it, made auto-refreshing. Reusing statsHtml keeps
// the old interface byte-for-byte; healthCards is inline-styled so it renders inside.
const adminDashboard = (st, h) => {
  const page = statsHtml(st); // full existing stats page, unchanged (no whole-page refresh)
  const cbtn = (k, label, style) => `<button data-cmp="${k}" style="border:none;border-radius:10px;padding:10px 14px;font-size:12px;font-weight:800;cursor:pointer;${style}">${label}</button>`;
  const comp = `
<h2>Free access · grant / revoke premium</h2>
<div class="card" style="max-width:700px">
  <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <input id="cmpU" placeholder="username" autocomplete="off" spellcheck="false" style="flex:1;min-width:150px;background:#0a0a0a;border:1px solid #262626;border-radius:10px;padding:10px 12px;color:#fff;font-size:14px;outline:none"/>
    ${cbtn('status', 'Check', 'background:#1c1c1c;color:#e4e4e7')}
    ${cbtn('perm', 'Grant permanent', 'background:#10b981;color:#04120c')}
    ${cbtn('30', '+30 days', 'background:#1c1c1c;color:#e4e4e7')}
    ${cbtn('365', '+1 year', 'background:#1c1c1c;color:#e4e4e7')}
    ${cbtn('revoke', 'Revoke', 'background:#3f1414;color:#fca5a5')}
  </div>
  <div id="cmpOut" style="margin-top:12px;font-size:13px;color:#a1a1aa;min-height:18px"></div>
  <div style="margin-top:8px;font-size:11px;color:#52525b;line-height:1.6">Permanent = free forever (never archives). Days = adds to their balance, same as a real payment. Revoke removes comped access (any paid time is kept).</div>
</div>
<script src="/api/admin/comp.js" defer></script>`;
  const health = `
<h2>Live server health · usage vs. server max</h2>
<div id="arbor-health" style="display:flex;flex-wrap:wrap;gap:12px">${healthCards(h)}</div>
<div class="note">${h.server.cpuCores} cores · ${(h.server.totalMemMB / 1024).toFixed(1)}GB RAM · ${h.backend} · updates live · bars fill toward the box's real limits · green ok · amber watch · red act · <form method="POST" action="/api/admin/logout" style="display:inline"><button type="submit" style="background:none;border:0;padding:0;color:#52525b;text-decoration:underline;cursor:pointer;font:inherit">log out</button></form></div>
<script src="/api/admin/health.js" defer></script>`;
  return page.replace('</body></html>', comp + health + '</body></html>');
};
// Login screen: a single password field that POSTs the token (never a URL param).
const adminLoginHtml = (err) => `<!DOCTYPE html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><meta name="robots" content="noindex,nofollow"/><title>Arbor · Admin</title></head>
<body style="margin:0;background:#0a0a0a;color:#e4e4e7;font-family:-apple-system,system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center">
<form method="POST" action="/api/admin/login" style="background:#111;border:1px solid #ffffff14;border-radius:16px;padding:28px;width:300px;display:flex;flex-direction:column;gap:12px">
  <div style="font-size:14px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:#10b981">Arbor Admin</div>
  <div style="font-size:12px;color:#71717a;margin-top:-4px">Enter the admin token to view live stats.</div>
  ${err === '1' ? '<div style="font-size:12px;color:#ef4444">That token doesn’t match ADMIN_TOKEN on the server — try again.</div>'
    : err === '2' ? '<div style="font-size:12px;color:#f59e0b">Too many attempts — wait a minute, then try again.</div>' : ''}
  <input type="password" name="token" placeholder="Admin token" autofocus autocomplete="current-password" style="background:#0a0a0a;border:1px solid #ffffff1a;border-radius:10px;padding:11px 13px;color:#fff;font-size:14px;outline:none"/>
  <button type="submit" style="background:#10b981;border:none;border-radius:10px;padding:11px;color:#000;font-size:12px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;cursor:pointer">Enter</button>
</form></body></html>`;
app.get('/api/admin', adminLimiter, (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).end();
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  if (!adminAuthed(req)) {
    if (req.query.format === 'json') return res.status(404).end(); // scripts: no oracle
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(adminLoginHtml(String(req.query.e || '')));    // browsers: login form
  }
  const st = buildStats(), h = buildHealth();
  if (req.query.format === 'json') return res.json({ metrics: st, health: h });
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(adminDashboard(st, h));
});
app.post('/api/admin/login', adminLoginLimiter, (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).end();
  if (!adminTokenOk(req.body && req.body.token)) return res.redirect(302, '/api/admin?e=1');
  res.cookie('arbor_admin', newAdminSession(), { httpOnly: true, sameSite: 'strict', secure: isHttps(req), path: '/api/admin', maxAge: ADMIN_SESSION_TTL });
  res.redirect(302, '/api/admin');
});
app.get('/api/admin/logout', (req, res) => res.redirect(302, '/api/admin'));
app.post('/api/admin/logout', adminLimiter, (req, res) => {
  const cid = parseCookies(req)['arbor_admin']; if (cid) adminSessions.delete(cid);
  res.clearCookie('arbor_admin', { path: '/api/admin' });
  res.redirect(302, '/api/admin');
});

// ---------------------------------------------------------------------------
// Admin: grant / revoke free premium access ("comp").
//
// Same admin-token gate as /stats — 404s entirely when ADMIN_TOKEN is unset,
// and 404s (not 403) on a bad token so it never confirms the route exists.
//
// Two flavours:
//   - permanent: sets compedPremium=true — free forever, never archives, never
//     needs renewal. Best for you, staff, lifetime comps.
//   - days: extends the account's compUntil by N days — a timed comp (e.g. 365
//     for a year, 30 for a trial) covering all of that person's networks.
//
// Revoke clears the permanent flag; it does NOT claw back paid time the user
// actually purchased (per-network premiumUntil is left alone unless clearPaid).
// ---------------------------------------------------------------------------
const findAccountByUsername = (u) => findByUsername(u);

// premiumUntil here is the ACCOUNT's admin comp horizon (compUntil). Paid time is
// per network (root.premiumUntil) and listed separately under `networks`.
const compResult = (acc, uname) => ({
  username: uname,
  compedPremium: !!acc.compedPremium,
  premiumUntil: acc.compUntil || null,
  premiumUntilISO: acc.compUntil ? new Date(acc.compUntil).toISOString() : null,
  premiumActive: accountComped(acc),
  networks: dbCache.users
    .filter(u => u.accountId === acc.id && !String(u.path).includes('/') && u.premiumUntil)
    .map(u => ({ premiumUntilISO: new Date(u.premiumUntil).toISOString(), active: u.premiumUntil > Date.now() })),
});

app.post('/api/admin/comp', adminLimiter, express.json(), (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).end();
  if (!adminAuthed(req)) return res.status(404).end();

  const { username, mode, days } = req.body || {};
  const acc = findAccountByUsername(username);
  if (!acc) return res.status(404).json({ error: 'No such user' });

  if (mode === 'permanent') {
    acc.compedPremium = true;
    persistDB();
    notify(new Set([acc.id]));                       // push the unlock to their devices
    // If they were archived for being over the free limit, wake the tree up.
    const rootNode = dbCache.users.find(u => u.accountId === acc.id && !u.path.includes('/'));
    if (rootNode) {
      const members = treeAccountIds(rootNode);
      notifyPayload(members, { type: 'BILLING', reason: 'unarchived', ts: Date.now() });
    }
    console.log(`[comp] permanent free access granted to ${acc.id}`);
    return res.json({ ok: true, ...compResult(acc, username) });
  }

  if (mode === 'days') {
    const n = parseInt(days, 10);
    if (!Number.isFinite(n) || n < 1 || n > 3650) return bad(res, 'days must be 1–3650');
    grantAccountComp(acc.id, n);                      // admin comp: account-wide by design
    console.log(`[comp] ${n} free days granted to ${acc.id}`);
    return res.json({ ok: true, granted: n, ...compResult(acc, username) });
  }

  return bad(res, "mode must be 'permanent' or 'days'");
});

app.post('/api/admin/comp/revoke', adminLimiter, express.json(), (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).end();
  if (!adminAuthed(req)) return res.status(404).end();

  const { username, clearPaid } = req.body || {};
  const acc = findAccountByUsername(username);
  if (!acc) return res.status(404).json({ error: 'No such user' });

  acc.compedPremium = false;
  if (clearPaid === true) {                           // also wipe timed comp + every network's paid balance
    acc.compUntil = 0;
    for (const r of dbCache.users) if (r.accountId === acc.id && !String(r.path).includes('/')) r.premiumUntil = 0;
  }
  persistDB();
  notify(new Set([acc.id]));
  console.log(`[comp] free access revoked for ${acc.id}${clearPaid === true ? ' (paid time cleared)' : ''}`);
  res.json({ ok: true, ...compResult(acc, username) });
});

// Look up one account's premium status (admin only).
app.post('/api/admin/comp/status', adminLimiter, express.json(), (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).end();
  if (!adminAuthed(req)) return res.status(404).end();
  const uname = req.body && req.body.username;
  const acc = findAccountByUsername(uname);
  if (!acc) return res.status(404).json({ error: 'No such user' });
  res.json(compResult(acc, uname));
});

// ---------------------------------------------------------------------------
// Admin dashboard — a single self-contained page. The page itself is public
// (it's just HTML/JS, no secrets baked in); everything it DOES requires the
// admin token, which the operator pastes into the login box. The token lives
// only in the browser tab's sessionStorage and is sent as x-admin-token on
// each call — never in a URL, so it stays out of logs and history.
// Served whether or not ADMIN_TOKEN is set, because it reveals nothing on its
// own; the API calls behind it 404 without a valid token.
// ---------------------------------------------------------------------------
// The admin console (page + its script) is only served when the feature is
// actually enabled (ADMIN_TOKEN set). With the token unset every /api/admin*
// path 404s exactly like a nonexistent route, so a deployment that isn't using
// admin gives an outsider nothing to probe — not even the login page. When
// enabled, the page is still safe on its own (no secrets baked in) and every
// action behind it independently requires the admin token.
app.get('/api/admin/', adminLimiter, (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).end();
  res.redirect('/api/admin');
});
// v72 (L): any other /api/admin path is a plain 404 too. v71 let unknown ones fall
// through to the session check (401), so 401 vs 404 told a prober which admin
// routes exist. Every admin route is registered above this line.
app.use('/api/admin', adminLimiter, (req, res) => res.status(404).end());

app.use('/api', (req, res, next) => {
  const session = sessionFromReq(req);
  if (!session) return res.status(401).json({ error: 'Unauthenticated' });
  // All authenticated routes here are POST (state-changing) -> require CSRF token.
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const header = req.headers['x-csrf-token'];
    if (!header || !ctEq(header, session.csrf)) return res.status(403).json({ error: 'Bad CSRF token' });
  }
  req.accountId = session.accountId;
  req.sessionRef = session;
  // Sensitive API responses must never be cached by browsers or intermediaries.
  res.setHeader('Cache-Control', 'no-store');
  touchAccountSeen(session.accountId);   // coarse day stamp only (see note above)
  next();
});

// V8 phase 2: every app build that understands encrypted profiles and signed
// membership sends X-Arbor-Proto: 2. Older builds would upload plaintext names
// and photos and would encrypt to unverified recipients, so they are turned away
// from the routes that read/write profiles or send messages, and told to reload
// (which loads the current app).
const ARBOR_PROTO = 2;
const PROTO_ROUTES = ['/register', '/tree-context', '/my-nodes', '/recipients', '/messages', '/messages/schedule',
  '/users/name', '/users/profile', '/account/profile', '/tree/settings', '/join-requests/respond',
  '/invites/permanent', '/hub/connect', '/profile/set', '/certs/submit', '/netkeys/box', '/invites/info', '/messages/sync'];
app.use('/api', (req, res, next) => {
  const p = req.path;
  const gated = PROTO_ROUTES.includes(p) || /^\/users\/[^/]+\/(profile|avatar)$/.test(p);
  if (!gated || parseInt(req.get('X-Arbor-Proto') || '0', 10) >= ARBOR_PROTO) return next();
  res.status(426).json({ error: 'Arbor was updated. Please reload the app to continue.', code: 'update-required' });
});

// Hands the current session's CSRF token to the client (session cookie proves
// identity). Lets the client hold the token in memory instead of in a readable
// cookie, and recover it after a page reload.
app.get('/api/csrf', (req, res) => res.json({ csrf: req.sessionRef.csrf }));

// Per-ACCOUNT rate limiter for authenticated routes. The IP-keyed limiters above
// bound a single source; these bound a single ACCOUNT no matter how many IPs it
// uses (V8 H-5/M-14/M-17/L-4 all describe one account amplifying server load).
// Only usable on routes registered after the session middleware (req.accountId).
const accountLimiter = (windowMs, max) => rateLimit({
  windowMs, max, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => 'acc:' + (req.accountId || 'anon'),
});
app.use('/api', accountLimiter(60 * 1000, 1500));   // v71: backstop for every authenticated route

// ---- v71 M6: password change + ending other sessions ---------------------------
// Live event streams belong to a session; end any whose session no longer exists
// (logout, "log out other devices", password change, account deletion).
const endOrphanStreams = (accountId) => {
  const live = new Set(dbCache.sessions.filter(s => s.accountId === accountId).map(s => s.tokenHash));
  for (const c of clients.filter(c => c.accountId === accountId && !live.has(c.tokenHash))) { try { c.res.end(); } catch {} }
  clients = clients.filter(c => c.accountId !== accountId || live.has(c.tokenHash));
};
// Earlier wrap keys, each sealed under the current one (see /auth/change-password).
const MAX_PREV_WRAPS = 3;
const PREV_WRAP_TTL_MS = 30 * 864e5;
const livePrevWraps = (acc) => {
  const now = Date.now();
  const list = Array.isArray(acc.prevWraps) ? acc.prevWraps.filter(p => p && typeof p.ct === 'string' && now - (p.at || 0) < PREV_WRAP_TTL_MS) : [];
  if (Array.isArray(acc.prevWraps) && list.length !== acc.prevWraps.length) { if (list.length) acc.prevWraps = list; else delete acc.prevWraps; persistDB(); }
  return list.map(p => p.ct);
};
const pwChangeLimiter = accountLimiter(15 * 60 * 1000, 10);
// v72 M7: one password change per account at a time; while it commits, ordinary
// backup uploads wait (they would void the staged copies).
const pwChangeBusy = new Set();
const STAGE_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const STAGE_MAX_AGE_MS = 60 * 60 * 1000;
/**
 * v72 M7: step 1 of a password change for encrypted state backups. They are too
 * large to travel inside the change request (up to 3 MB per identity), so the
 * client uploads each one, re-encrypted under the new key, here first. It is kept
 * next to the current backup (which stays in force) and swapped in only by
 * /auth/change-password, in the same transaction as the new password. `ts` must
 * be the stored backup's ts: a newer backup since then must be re-encrypted too.
 */
const stageLimiter = accountLimiter(60 * 1000, 150);     // ≤ 60 identities per change, a couple of retries
app.post('/api/auth/change-password/stage-backup', stageLimiter, bigBody('4mb'), async (req, res) => {
  const { nodeId, stage, wrapped, ts } = req.body || {};
  if (!isStr(nodeId, 128) || !isStr(stage, 64) || !STAGE_ID_RE.test(stage) || !isStr(wrapped, BACKUP_MAX_CHARS) || typeof ts !== 'number' || !Number.isFinite(ts)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (pwChangeBusy.has(req.accountId)) return res.status(409).json({ error: 'A password change is already in progress.', code: 'busy' });
  if (!(await backupsStore.stage(me.id, stage, wrapped, ts))) {
    return res.status(409).json({ error: 'A backup was updated while your password was being changed. Nothing was changed — try again.', code: 'backup-changed' });
  }
  res.json({ ok: true });
});
/**
 * Change the account password. The server can't re-encrypt anything, so the
 * client sends EVERY server-held blob sealed under the old password's key again
 * under the new one, and this route swaps them in together with the new auth
 * value in one step (all or nothing). It also keeps the old key(s) sealed under
 * the new key (prevWraps, 30 days) so each of the account's devices can re-seal
 * its local data at its next login, clears the recovery phrase (it holds the old
 * password), and ends every other session.
 * v72 M7: the encrypted state backups are part of that step too (staged above;
 * `nodes[].backup = { ts, staged }`, staged:false = the client could not open that
 * backup and leaves it as it is). v71 re-wrapped them AFTER the change, best
 * effort — a failure there left them under the old password. Now the password,
 * keys and backups are written in one database transaction before the reply; if
 * that fails nothing changes, in memory either.
 */
app.post('/api/auth/change-password', pwChangeLimiter, bigBody('4mb'), async (req, res) => {
  const { oldAuthHash, newAuthHash, nodes, defaultProfileCt, prevWraps, backupStage } = req.body || {};
  if (!isStr(oldAuthHash, 512) || !isStr(newAuthHash, 512) || oldAuthHash === newAuthHash) return bad(res, 'Invalid input');
  if (!Array.isArray(nodes) || nodes.length > MAX_NODES_PER_ACCOUNT) return bad(res, 'Invalid input');
  if (!Array.isArray(prevWraps) || prevWraps.length < 1 || prevWraps.length > MAX_PREV_WRAPS || !prevWraps.every(p => isStr(p, 1024))) return bad(res, 'Invalid input');
  if (defaultProfileCt !== undefined && defaultProfileCt !== null && !isStr(defaultProfileCt, MAX_DEFAULT_PROFILE_CT)) return bad(res, 'Invalid input');
  if (backupStage !== undefined && !(isStr(backupStage, 64) && STAGE_ID_RE.test(backupStage))) return bad(res, 'Invalid input');
  const acc = accountById(req.accountId);
  if (!acc) return res.status(404).json({ error: 'No account' });
  if ((acc.kdf || 1) < 2) return res.status(409).json({ error: 'Sign out and back in once to finish a security upgrade, then try again.', code: 'kdf-upgrade-first' });
  const mine = new Map(dbCache.users.filter(u => u.accountId === acc.id).map(u => [getPublicId(u.id), u]));
  const byPid = new Map();
  const LIMITS = { wrappedKeys: MAX_WRAPPED_KEYS, identityWrapped: 4096, anchorCt: 4000, selfCt: 8000 };
  for (const n of nodes) {
    if (!isObj(n) || !isStr(n.nodeId, 128) || byPid.has(n.nodeId)) return bad(res, 'Invalid input');
    if (!mine.has(n.nodeId)) return res.status(403).json({ error: 'Access denied' });
    for (const [f, max] of Object.entries(LIMITS)) if (n[f] !== undefined && !isStr(n[f], max)) return bad(res, 'Invalid input');
    if (n.backup !== undefined && !(isObj(n.backup) && typeof n.backup.ts === 'number' && Number.isFinite(n.backup.ts) && typeof n.backup.staged === 'boolean')) return bad(res, 'Invalid input');
    byPid.set(n.nodeId, n);
  }
  // Every private blob must come re-encrypted, or it would stay locked under the
  // old password forever.
  for (const [pid, u] of mine) {
    const n = byPid.get(pid);
    if ((u.wrappedKeys && !(n && n.wrappedKeys)) || (dbCache.signalIdentities[u.id]?.wrapped && !(n && n.identityWrapped))) {
      return res.status(409).json({ error: 'Not every identity was re-encrypted. Reload Arbor and try again.', code: 'incomplete' });
    }
  }
  if (pwChangeBusy.has(acc.id)) return res.status(409).json({ error: 'A password change is already in progress.', code: 'busy' });
  pwChangeBusy.add(acc.id);
  try {
    const before = acc.passwordHash;
    if (!(await verifyPassword(oldAuthHash, before))) return res.status(403).json({ error: 'Your current password is incorrect.' });
    // v72 M7: every stored backup must be accounted for — staged under this change
    // for the ts it has now, or (unreadable to the client) explicitly left as it is.
    const stored = await backupsStore.metaFor([...mine.values()].map(u => u.id));
    const commitBackups = [];
    for (const [pid, u] of mine) {
      const b = stored.get(u.id);
      if (!b) continue;
      const nb = byPid.get(pid)?.backup;
      if (!nb || nb.ts !== b.ts || (nb.staged && (!backupStage || b.stage !== backupStage))) {
        return res.status(409).json({ error: 'A backup was updated while your password was being changed. Nothing was changed — try again.', code: 'backup-changed' });
      }
      if (nb.staged) commitBackups.push({ nodeId: u.id, ts: b.ts });
    }
    const next = await hashPassword(newAuthHash);
    let dpRef = null;
    if (typeof defaultProfileCt === 'string') { dpRef = 'dp:' + avatarHashOf(defaultProfileCt); await avatarsStore.put(dpRef, defaultProfileCt); }
    // Anything could have happened during the awaits: re-check before committing.
    if (!accountById(acc.id) || acc.passwordHash !== before) return res.status(409).json({ error: 'Your password changed meanwhile. Sign in again.' });
    // Apply in memory, remembering how to undo each step if the write below fails.
    const undo = [];
    const put = (o, k, v) => {
      const had = Object.prototype.hasOwnProperty.call(o, k), old = o[k];
      undo.push(() => { if (had) o[k] = old; else delete o[k]; });
      if (v === undefined) delete o[k]; else o[k] = v;
    };
    for (const [pid, n] of byPid) {
      const u = mine.get(pid);
      if (!dbCache.users.includes(u)) continue;                     // removed meanwhile
      if (n.wrappedKeys !== undefined) put(u, 'wrappedKeys', n.wrappedKeys);
      if (n.identityWrapped !== undefined && dbCache.signalIdentities[u.id]) put(dbCache.signalIdentities[u.id], 'wrapped', n.identityWrapped);
      if (n.anchorCt !== undefined) put(u, 'anchorCt', n.anchorCt);
      if (n.selfCt !== undefined) put(u, 'selfCt', n.selfCt);
    }
    if (defaultProfileCt === null) put(acc, 'defaultProfileRef', undefined); else if (dpRef) put(acc, 'defaultProfileRef', dpRef);
    put(acc, 'passwordHash', next);
    put(acc, 'pwChangedAt', Date.now());
    put(acc, 'prevWraps', prevWraps.map(ct => ({ ct, at: Date.now() })));
    const droppedRecovery = (dbCache.recovery || []).filter(r => r.accountId === acc.id);
    dbCache.recovery = (dbCache.recovery || []).filter(r => r.accountId !== acc.id);
    const droppedSessions = dbCache.sessions.filter(s => s.accountId === acc.id && s !== req.sessionRef);
    dbCache.sessions = dbCache.sessions.filter(s => s.accountId !== acc.id || s === req.sessionRef);
    undo.push(() => { dbCache.recovery = [...(dbCache.recovery || []), ...droppedRecovery]; dbCache.sessions = [...dbCache.sessions, ...droppedSessions]; });
    const KEYS = ['accounts', 'users', 'signalIdentities', 'recovery', 'sessions'];
    try {
      await persistNow(KEYS, { backupCommit: { stage: backupStage, nodes: commitBackups } });
    } catch (e) {
      for (const f of undo.reverse()) f();
      persistDB(...KEYS);
      if (e.code === 'BACKUP_CHANGED') return res.status(409).json({ error: 'A backup was updated while your password was being changed. Nothing was changed — try again.', code: 'backup-changed' });
      console.error('[change-password] write failed:', e.message);
      return res.status(503).json({ error: 'Your new password could not be saved. Nothing was changed — try again.' });
    }
    dataVersion++;
    endOrphanStreams(acc.id);
    res.json({ ok: true, recoveryCleared: droppedRecovery.length > 0, sessionsEnded: droppedSessions.length });
  } finally { pwChangeBusy.delete(acc.id); }
});
// The current earlier-key list (the changing device folds it into its new list).
app.post('/api/auth/prev-wraps', (req, res) => {
  const acc = accountById(req.accountId);
  res.json({ prevWraps: acc ? livePrevWraps(acc) : [] });
});
// End every session of this account except the current one. Needs the password:
// with just a stolen cookie this would let an intruder log the owner out.
const revokeLimiter = accountLimiter(15 * 60 * 1000, 10);
// v72 M4: destructive actions (delete a network, prune a member) need the password,
// not just a session cookie — a stolen cookie must not be able to wipe networks. A
// successful confirmation covers this session for 10 minutes, so pruning several
// people doesn't mean typing it each time. Failed attempts are capped per account.
const REAUTH_WINDOW_MS = 10 * 60 * 1000;
const reauthFails = new Map();                        // accountId -> { n, since }
const REAUTH_REQUIRED = { error: 'Enter your password to confirm this.', code: 'reauth-required' };
const checkReauthPassword = async (req, authHash) => {
  const f = reauthFails.get(req.accountId);
  if (f && Date.now() - f.since < 15 * 60 * 1000 && f.n >= 10) return 'limited';
  const acc = accountById(req.accountId);
  if (acc && isStr(authHash, 512) && (await verifyPassword(authHash, acc.passwordHash))) {
    reauthFails.delete(req.accountId);
    req.sessionRef.reauthAt = Date.now();
    return 'ok';
  }
  const cur = f && Date.now() - f.since < 15 * 60 * 1000 ? f : { n: 0, since: Date.now() };
  cur.n++; reauthFails.set(req.accountId, cur);
  return 'bad';
};
/** true when this session confirmed the password recently (or does so now via body.authHash). */
const reauthOr403 = async (req, res) => {
  if (req.sessionRef && req.sessionRef.reauthAt && Date.now() - req.sessionRef.reauthAt < REAUTH_WINDOW_MS) return true;
  const authHash = req.body && req.body.authHash;
  if (authHash === undefined) { res.status(403).json(REAUTH_REQUIRED); return false; }
  const r = await checkReauthPassword(req, authHash);
  if (r === 'ok') return true;
  if (r === 'limited') res.status(429).json({ error: 'Too many wrong passwords — try again in 15 minutes.' });
  else res.status(403).json({ error: 'Password check failed.', code: 'reauth-required' });
  return false;
};
app.post('/api/auth/reauth', async (req, res) => {
  const r = await checkReauthPassword(req, (req.body || {}).authHash);
  if (r === 'ok') return res.json({ ok: true, validMs: REAUTH_WINDOW_MS });
  if (r === 'limited') return res.status(429).json({ error: 'Too many wrong passwords — try again in 15 minutes.' });
  res.status(403).json({ error: 'Password check failed.' });
});

app.post('/api/auth/sessions/revoke-others', revokeLimiter, async (req, res) => {
  const { authHash } = req.body || {};
  if (!isStr(authHash, 512)) return bad(res, 'Invalid input');
  const acc = accountById(req.accountId);
  if (!acc || !(await verifyPassword(authHash, acc.passwordHash))) return res.status(403).json({ error: 'Password check failed.' });
  const before = dbCache.sessions.length;
  dbCache.sessions = dbCache.sessions.filter(s => s.accountId !== acc.id || s === req.sessionRef);
  const ended = before - dbCache.sessions.length;
  persistDB('sessions');
  endOrphanStreams(acc.id);
  res.json({ ok: true, ended });
});

app.post('/api/auth/logout', (req, res) => {
  dbCache.sessions = dbCache.sessions.filter(s => s !== req.sessionRef);
  persistDB('sessions');
  endOrphanStreams(req.accountId);
  clearSessionCookies(res);
  res.json({});
});

// Push subscribe/unsubscribe are rate-limited so the endpoint can't be used to
// churn the subscription table.
const pushLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
// web-push dials whatever endpoint we store, so keep it to public https hosts —
// reject non-https and every non-public address (SSRF). Two layers:
//   1. isSafePushEndpoint: validates the URL at subscribe time. IP literals are
//      classified by isPublicIp (netGuard.js), which handles every IPv4 special range
//      and treats IPv6 by ALLOW-list — only global unicast 2000::/3 passes, minus
//      the ranges that embed an IPv4 address (6to4, Teredo) or are reserved.
//      This closes the V8 M-16 bypasses: NAT64 64:ff9b::/96 and IPv4-compatible
//      ::a.b.c.d literals both sit outside 2000::/3.
//   2. pushAgent: an https.Agent whose DNS lookup refuses to CONNECT to any
//      non-public address, so a hostname that resolves (or later re-resolves —
//      DNS rebinding) to a private/metadata IP is stopped at connect time, not
//      just at subscribe time. No check-then-use gap.
// Implementation lives in netGuard.js (unit-tested in security-tests/v8-regression.mjs).
const pushAgent = new https.Agent({ keepAlive: true, lookup: safeLookup });
// v71 M4: a subscription is stored EXACTLY as web-push needs it — endpoint, the
// two client keys, optional expiry — never the client's whole object (v70 kept
// anything up to the body limit, in RAM and in every snapshot write).
const MAX_PUSH_SUBS_PER_ACCOUNT = 10;
const isB64url = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max && /^[A-Za-z0-9_-]+={0,2}$/.test(v);
const cleanSubscription = (s) => {
  if (!isObj(s) || !isStr(s.endpoint, 2000) || !isObj(s.keys)) return null;
  if (!isB64url(s.keys.p256dh, 128) || !isB64url(s.keys.auth, 64)) return null;
  const exp = s.expirationTime;
  if (exp !== undefined && exp !== null && !(typeof exp === 'number' && Number.isFinite(exp))) return null;
  return { endpoint: s.endpoint, expirationTime: exp ?? null, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } };
};
app.post('/api/push/subscribe', pushLimiter, (req, res) => {
  const subscription = cleanSubscription((req.body || {}).subscription);
  if (!subscription) return bad(res, 'Invalid subscription');
  if (!isSafePushEndpoint(subscription.endpoint)) return bad(res, 'Invalid subscription');
  // A push endpoint is a per-device capability URL and must map to exactly ONE
  // account. We drop any prior row for this endpoint (including one owned by a
  // different account — e.g. a shared device that switched logins) and re-bind it
  // to the caller. This is deliberate: it prevents a stale mapping from ever
  // delivering this account's "new message" pings to whoever the device used to
  // belong to. Re-binding requires possessing the (unguessable, secret) endpoint,
  // which is equivalent to controlling the device itself.
  dbCache.subscriptions = dbCache.subscriptions.filter(s => s.subscription.endpoint !== subscription.endpoint);
  // Per-account cap: the oldest device registration is replaced (a person has a
  // handful of devices; each push to an account dials every registration).
  const mine = dbCache.subscriptions.filter(s => s.accountId === req.accountId);
  if (mine.length >= MAX_PUSH_SUBS_PER_ACCOUNT) {
    const drop = new Set(mine.slice(0, mine.length - MAX_PUSH_SUBS_PER_ACCOUNT + 1));
    dbCache.subscriptions = dbCache.subscriptions.filter(s => !drop.has(s));
  }
  dbCache.subscriptions.push({ accountId: req.accountId, subscription });
  persistDB();
  res.status(201).json({});
});

// Turn notifications OFF: remove this device's subscription (by endpoint), or
// every subscription for the account when no endpoint is given.
app.post('/api/push/unsubscribe', pushLimiter, (req, res) => {
  const { endpoint } = req.body || {};
  if (endpoint !== undefined && !isStr(endpoint, 2000)) return bad(res, 'Invalid endpoint');
  const before = dbCache.subscriptions.length;
  dbCache.subscriptions = dbCache.subscriptions.filter(s =>
    !(s.accountId === req.accountId && (!endpoint || s.subscription.endpoint === endpoint)));
  if (dbCache.subscriptions.length !== before) persistDB();
  res.json({ ok: true });
});

// Store (or replace) this account's encrypted recovery blob. The blob was
// encrypted CLIENT-SIDE under a key derived from the seed phrase.
// v72 (L): needs the password (or a confirmation in the last 10 minutes) — with only
// a session cookie, v71 let anyone replace the owner's recovery phrase with their own,
// silently breaking the owner's. The app always has the password here.
app.post('/api/auth/recovery/set', async (req, res) => {
  const { recoveryId, blob } = req.body || {};
  if (!isStr(recoveryId, 128) || !isStr(blob, 4096)) return bad(res, 'Invalid input');
  if (!(await reauthOr403(req, res))) return;
  // V8 L-6: a recoveryId owned by ANOTHER account must never be shadowed (the
  // fetch is first-match, so a collision silently broke someone's recovery).
  if ((dbCache.recovery || []).some(r => r.recoveryId === recoveryId && r.accountId !== req.accountId)) {
    return res.status(409).json({ error: 'That recovery phrase can’t be used — generate a new one.' });
  }
  dbCache.recovery = (dbCache.recovery || []).filter(r => r.accountId !== req.accountId);
  dbCache.recovery.push({ recoveryId, blob, accountId: req.accountId, createdAt: Date.now() });
  persistDB();
  res.json({ ok: true });
});

// ---- Password-KDF upgrade (V8 H-3) -------------------------------------------
// Legacy accounts derived their auth value and wrap key with PBKDF2 alone, which
// a malicious server / DB thief can brute-force offline at GPU speed. On the next
// login the client re-derives both with scrypt (memory-hard), RE-WRAPS every
// server-held blob under the new key (/api/nodes/rewrap + state-backup/set), and
// finally commits the new auth value here. Requiring the OLD auth value makes
// this equivalent to a password change: a stolen session cookie alone cannot
// swap the account's credentials.
const kdfLimiter = accountLimiter(15 * 60 * 1000, 10);
app.post('/api/auth/kdf-upgrade', kdfLimiter, async (req, res) => {
  const { oldAuthHash, newAuthHash, kdf } = req.body || {};
  if (!isStr(oldAuthHash, 512) || !isStr(newAuthHash, 512) || kdf !== 2) return bad(res, 'Invalid input');
  const acc = accountById(req.accountId);
  if (!acc) return res.status(404).json({ error: 'No account' });
  if ((acc.kdf || 1) >= 2) return res.json({ ok: true, kdf: acc.kdf });           // idempotent
  const before = acc.passwordHash;
  if (!(await verifyPassword(oldAuthHash, before))) return res.status(403).json({ error: 'Re-authentication failed' });
  const next = await hashPassword(newAuthHash);
  if (acc.passwordHash !== before) return res.status(409).json({ error: 'Your password changed meanwhile. Sign in again.' });
  acc.passwordHash = next;
  acc.kdf = 2;
  // Other sessions were established with the old credential — end them, keeping
  // only the one that just proved the password.
  dbCache.sessions = dbCache.sessions.filter(s => s.accountId !== acc.id || s === req.sessionRef);
  persistDB();
  endOrphanStreams(acc.id);   // v72 (L): their live event streams end too (v71 left them open)
  res.json({ ok: true, kdf: 2 });
});

// Replace a node's password-wrapped PRIVATE blobs (node keys and/or the wrapped
// Signal identity private key) with versions re-encrypted under a new wrap key.
// Owner-gated. The public identity (pub/regId) can never change here — the
// first-write-wins identity pin is preserved; only the ciphertext is swapped.
const rewrapLimiter = accountLimiter(60 * 1000, 120);
app.post('/api/nodes/rewrap', rewrapLimiter, async (req, res) => {
  const { nodeId, wrappedKeys, identityWrapped, authHash } = req.body || {};
  if (!isStr(nodeId, 128) || !isStr(authHash, 512)) return bad(res, 'Invalid input');
  if (wrappedKeys !== undefined && !isStr(wrappedKeys, MAX_WRAPPED_KEYS)) return bad(res, 'Invalid input');
  if (identityWrapped !== undefined && !isStr(identityWrapped, 4096)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  // v71 L4: replacing the wrapped private keys needs the password, not just a
  // session cookie — a stolen session could otherwise overwrite them with junk
  // and lock the owner out of their identity on every other device.
  const acc = accountById(req.accountId);
  if (!acc || !(await verifyPassword(authHash, acc.passwordHash))) return res.status(403).json({ error: 'Re-authentication failed' });
  if (wrappedKeys !== undefined) me.wrappedKeys = wrappedKeys;
  if (identityWrapped !== undefined && dbCache.signalIdentities[me.id]) dbCache.signalIdentities[me.id].wrapped = identityWrapped;
  persistDB();
  res.json({ ok: true });
});

app.post('/api/auth/recovery/status', (req, res) => {
  res.json({ hasRecovery: (dbCache.recovery || []).some(r => r.accountId === req.accountId) });
});

// ---- Per-account settings (read receipts are reciprocal) --------------------
app.post('/api/settings/get', (req, res) => {
  const acc = accountById(req.accountId);
  const otherSessions = dbCache.sessions.filter(s => s.accountId === req.accountId && s !== req.sessionRef && s.expiresAt > Date.now()).length;
  res.json({ readReceipts: acc?.settings?.readReceipts !== false, notifyPref: acc?.settings?.notifyPref || 'all', otherSessions });
});
app.post('/api/settings/update', (req, res) => {
  const { readReceipts, notifyPref } = req.body || {};
  const acc = accountById(req.accountId);
  if (!acc) return res.status(404).json({ error: 'No account' });
  const next = { ...(acc.settings || {}) };
  if (readReceipts !== undefined) { if (typeof readReceipts !== 'boolean') return bad(res, 'Invalid input'); next.readReceipts = readReceipts; }
  if (notifyPref !== undefined) { if (!['all', 'mentions', 'alias'].includes(notifyPref)) return bad(res, 'Invalid notifyPref'); next.notifyPref = notifyPref; }
  acc.settings = next;
  persistDB();
  res.json({ ok: true });
});

// v72 M8: push fan-out.
//  - Subscriptions by account, rebuilt only when the list changes (it is only ever
//    replaced or appended to) — v71 scanned every subscription for every recipient.
//  - At most PUSH_CONCURRENCY deliveries in flight; the rest wait their turn (v71
//    opened one connection per recipient at once — 2,000 for one message).
//  - Message pushes are coalesced per account (pushMessageTo, below).
let subsIdx = { arr: null, len: -1, map: new Map() };
const subsFor = (accountId) => {
  const arr = dbCache.subscriptions;
  if (subsIdx.arr !== arr || subsIdx.len !== arr.length) {
    const map = new Map();
    for (const s of arr) { let l = map.get(s.accountId); if (!l) map.set(s.accountId, l = []); l.push(s); }
    subsIdx = { arr, len: arr.length, map };
  }
  return (subsIdx.map.get(accountId) || []).slice();
};
const PUSH_CONCURRENCY = 32;
const pushStats = { attempted: 0, delivered: 0, failed: 0, coalesced: 0 };   // shown in the admin health data
let pushInFlight = 0;
const pushWaiters = [];
const withPushSlot = async (fn) => {
  if (pushInFlight >= PUSH_CONCURRENCY) await new Promise(r => pushWaiters.push(r)); else pushInFlight++;
  try { return await fn(); }
  finally { const next = pushWaiters.shift(); if (next) next(); else pushInFlight--; }   // hand the slot on
};
const sendPushToAccount = async (accountId, title, body, extra = {}) => {
  const subs = subsFor(accountId);
  for (const sub of subs) {
    // Legacy rows stored before the stricter filter are re-checked at send time,
    // and the connection itself goes through pushAgent's public-IP-only lookup.
    if (!isSafePushEndpoint(sub.subscription.endpoint)) {
      dbCache.subscriptions = dbCache.subscriptions.filter(s => s.subscription.endpoint !== sub.subscription.endpoint);
      persistDB('subscriptions');
      continue;
    }
    pushStats.attempted++;
    try { await withPushSlot(() => webpush.sendNotification(sub.subscription, JSON.stringify({ title, body, ...extra }), { agent: pushAgent, timeout: 10000 })); pushStats.delivered++; }
    catch (e) {
      pushStats.failed++;
      if (e.statusCode === 410 || e.statusCode === 404) {
        dbCache.subscriptions = dbCache.subscriptions.filter(s => s.subscription.endpoint !== sub.subscription.endpoint);
        persistDB('subscriptions');
      }
    }
  }
};

// v72 M8: "new message" pushes are coalesced per account — at most one per
// PUSH_COALESCE_MS (default 5 s; 0 = off). v71 pushed every recipient for every
// message, so a busy group chat sent each member a push per line. The push only
// says that something new arrived (never what), so one per burst carries the same.
const PUSH_COALESCE_MS = Math.max(0, parseInt(process.env.PUSH_COALESCE_MS ?? '5000', 10) || 0);
const lastMsgPushAt = new Map();                                // accountId -> ts
const pushMessageTo = (accountId, title, body) => {
  const now = Date.now();
  if (PUSH_COALESCE_MS && now - (lastMsgPushAt.get(accountId) || 0) < PUSH_COALESCE_MS) { pushStats.coalesced++; return false; }
  lastMsgPushAt.set(accountId, now);
  sendPushToAccount(accountId, title, body);
  return true;
};
setInterval(() => { const cut = Date.now() - PUSH_COALESCE_MS; for (const [k, t] of lastMsgPushAt) if (t < cut) lastMsgPushAt.delete(k); }, 60 * 1000).unref();

app.post('/api/my-nodes', (req, res) => {
  const myNodes = dbCache.users.filter(u => u.accountId === req.accountId);
  res.json(myNodes.map(u => {
    // Surface the tree's mode + name for every node (not just roots) so the
    // chooser can group "Personal Chats" (hubs you own AND hubs you've joined)
    // separately from structured networks. When someone is added through a
    // personal hub, the node they get lands in THEIR Personal Chats this way.
    const root = treeRootUser(u);
    // V8 phase 2: names are ciphertext. selfCt (under the ACCOUNT key) labels the
    // identity in the picker; the plaintext fields only exist for legacy nodes
    // until their owner's app migrates them.
    return {
      id: getPublicId(u.id), role: u.role, color: u.color,
      ...(u.selfCt ? { selfCt: u.selfCt } : {}),
      ...(!u.profileCt && u.name ? { name: u.name } : {}),
      ...(!(root && root.treeNameCt) && (u.treeName || (root && root.treeName)) ? { treeName: u.treeName || root.treeName } : {}),
      treeMode: u.treeMode || (root ? root.treeMode : undefined) || 'HIERARCHICAL',
      level: u.level, path: u.path, treeRoot: treePidOf(u),
      encPub: u.encPub, sigPub: u.sigPub, wrappedKeys: u.wrappedKeys,
    };
  }));
});

const ownNodeOr403 = (req, res, publicNodeId) => {
  const internal = resolveInternalId(publicNodeId);
  const node = dbCache.users.find(u => u.id === internal);
  if (!node || node.accountId !== req.accountId) { res.status(403).json({ error: 'Access denied' }); return null; }
  return node;
};

// ---------------------------------------------------------------------------
// V8 phase 2 — signed membership (H-2) + end-to-end encrypted profiles (M-8).
//
// The server STORES and RELAYS membership certificates, network-key boxes and
// profile ciphertext. It cannot create or read any of them: certificates are
// signed with members' Signal identity keys (checked by every client), boxes are
// sealed between two members' identity keys, profiles are encrypted under a
// network key the server never sees. The checks below are shape, size and
// anti-spam only — they are NOT what makes membership trustworthy.
// ---------------------------------------------------------------------------
// v70 H4: certificates live in the in-memory snapshot, so every byte is RAM and
// every change rewrites the collection. Shapes are exact (no padding fields), sizes
// are small, signatures are checked, and each tree / account has a budget.
const CERT_FIELDS = {
  root: ['k', 'v', 'tree', 'pid', 'ik', 'ts'],
  inv: ['k', 'v', 'tree', 'by', 'ip', 'aa', 'g', 'ts'],
  join: ['k', 'v', 'tree', 'pid', 'ik', 'inv', 'ts'],
  vouch: ['k', 'v', 'tree', 'by', 'pid', 'ik', 'ts'],
  epoch: ['k', 'v', 'tree', 'by', 'kid', 'ts'],
  legacy: ['k', 'v', 'tree', 'by', 'pids', 'ts'],
};
const CERT_KINDS = Object.keys(CERT_FIELDS);
const CERT_MAX_CHARS = 1024;             // every kind but legacy is ~250 chars
const LEGACY_MAX_PIDS = 500;             // clients split the roster (membership.ts LEGACY_CHUNK)
const LEGACY_MAX_CHARS = 20000;
const CERT_FUTURE_MS = 60 * 60 * 1000;   // a certificate may not be dated more than an hour ahead
const MAX_CERTS_PER_TREE = 20000;
const MAX_CERT_BYTES_PER_TREE = 4 * 1024 * 1024;
const MAX_CERT_BYTES_PER_ACCOUNT = 2 * 1024 * 1024;
// v72 B4: 128 MB by default (v71: 256 MB) — certificates are held in RAM, and the
// production unit caps the whole process at 1 GB. ~1.6 KB per member → ~80k members.
const MAX_CERT_BYTES_TOTAL = parseInt(process.env.MAX_CERT_BYTES_TOTAL || String(128 * 1024 * 1024), 10);
const MAX_INV_PER_NODE = 1000;
const MAX_BOXES_PER_TREE = 100000;
const MAX_BOXES_PER_ACCOUNT = 20000;
// v72 B4: server-wide, like MAX_CERT_BYTES_TOTAL — boxes are kept in RAM (~300 B each).
const MAX_BOXES_TOTAL = parseInt(process.env.MAX_BOXES_TOTAL || '300000', 10);
const MAX_KIDS_PER_BOX_PAIR = 32;        // key ids kept per (tree, from, to); the oldest is replaced
const MAX_SELF_BOX_KIDS = 16;            // key ids kept in a node's boxes to itself, per tree
const treePidOf = (u) => getPublicId(String(u.path).split('/')[0]);
const certList = () => (dbCache.certs = dbCache.certs || []);
const boxList = () => (dbCache.netBoxes = dbCache.netBoxes || []);
// Same canonical form the client signs (services/membership.ts canon()), so the
// server can index certificates by the id clients reference them by.
const canonJson = (v) => {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonJson).join(',') + ']';
  return '{' + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ':' + canonJson(v[k])).join(',') + '}';
};
const b64urlOf = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const isIk = (v) => isB64(v, 64) && (() => { const n = Buffer.from(v, 'base64').length; return n === 33 || n === 32; })();
// Exact shape per kind (the same rules clients apply, services/membership.ts).
const certShape = (raw) => {
  if (typeof raw !== 'string' || raw.length > LEGACY_MAX_CHARS) return null;
  let o; try { o = JSON.parse(raw); } catch { return null; }
  if (!isObj(o) || Object.keys(o).some(k => k !== 'b' && k !== 's')) return null;
  const b = o.b;
  if (!isObj(b) || b.v !== 1 || !CERT_KINDS.includes(b.k) || !isStr(b.tree, 128) || typeof b.ts !== 'number' || !Number.isFinite(b.ts) || b.ts <= 0) return null;
  if (Object.keys(b).some(k => !CERT_FIELDS[b.k].includes(k))) return null;
  if (!isB64(o.s, 100) || Buffer.from(o.s, 'base64').length !== 64) return null;
  if (b.k !== 'legacy' && raw.length > CERT_MAX_CHARS) return null;
  const ok = {
    root: () => isStr(b.pid, 128) && isIk(b.ik),
    inv: () => isStr(b.by, 128) && isIk(b.ip) && typeof b.aa === 'boolean' && (b.g === undefined || isStr(b.g, 64)),
    join: () => isStr(b.pid, 128) && isIk(b.ik) && isStr(b.inv, 64),
    vouch: () => isStr(b.by, 128) && isStr(b.pid, 128) && isIk(b.ik),
    epoch: () => isStr(b.by, 128) && /^[0-9a-f]{16}$/.test(String(b.kid)),
    legacy: () => isStr(b.by, 128) && Array.isArray(b.pids) && b.pids.length <= LEGACY_MAX_PIDS && b.pids.every(p => isStr(p, 128)),
  }[b.k]();
  if (!ok) return null;
  const cid = b64urlOf(crypto.createHash('sha256').update(canonJson(b) + '|' + o.s).digest());
  return { b, s: o.s, cid };
};
// XEdDSA verification (the scheme libsignal's curve25519 signs with) on Node's
// Ed25519: map the Montgomery u-coordinate to Edwards y = (u-1)/(u+1), take the
// sign bit the signer stored in the signature's top bit, then verify as Ed25519.
const P25519 = (1n << 255n) - 19n;
const modp = (a) => ((a % P25519) + P25519) % P25519;
const powp = (b, e) => { let r = 1n; b = modp(b); while (e > 0n) { if (e & 1n) r = r * b % P25519; b = b * b % P25519; e >>= 1n; } return r; };
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const rawIk = (ikB64) => { const u = Buffer.from(String(ikB64), 'base64'); return u.length === 33 && u[0] === 5 ? u.subarray(1) : u.length === 32 ? u : null; };
const sameIk = (a, b) => { const x = a && rawIk(a), y = b && rawIk(b); return !!x && !!y && x.equals(y); };
const xeddsaVerify = (ikB64, msg, sigB64) => {
  try {
    const mont = rawIk(ikB64); const sig = Buffer.from(String(sigB64), 'base64');
    if (!mont || sig.length !== 64) return false;
    let u = 0n; for (let i = 31; i >= 0; i--) u = (u << 8n) | BigInt(i === 31 ? mont[i] & 0x7f : mont[i]);
    const den = modp(u + 1n);
    if (den === 0n) return false;
    let y = modp((u - 1n) * powp(den, P25519 - 2n));
    const ed = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) { ed[i] = Number(y & 0xffn); y >>= 8n; }
    ed[31] = (ed[31] & 0x7f) | (sig[63] & 0x80);
    const s = Buffer.from(sig); s[63] &= 0x7f;
    const key = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI, ed]), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(msg, 'utf8'), key, s);
  } catch { return false; }
};
const certSigOk = (b, s, ikB64) => !!ikB64 && xeddsaVerify(ikB64, 'arbor-cert-v1\n' + canonJson(b), s);
// Who a stored certificate's bytes count against (submitter pid).
const certSubmitter = (c) => c.sb || (c.k === 'join' ? c.sub : c.k === 'root' ? c.t : c.by);
const certIk = (c) => { if (c.ik) return c.ik; try { return JSON.parse(c.c).b.ik || null; } catch { return null; } };
let certVer = 0;
let _certIdx = { ver: -1, byTree: null, byCid: null, pos: null, bytesByTree: null, bytesBySubmitter: null, total: 0 };
const certIndex = () => {
  if (_certIdx.byTree && _certIdx.ver === certVer) return _certIdx;
  const byTree = new Map(), byCid = new Map(), pos = new Map(), bytesByTree = new Map(), bytesBySubmitter = new Map();
  let total = 0;
  certList().forEach((c, i) => {
    if (!byTree.has(c.t)) byTree.set(c.t, []);
    byTree.get(c.t).push(c);
    byCid.set(c.cid, c);
    pos.set(c, i);
    const n = (c.c || '').length;
    total += n;
    bytesByTree.set(c.t, (bytesByTree.get(c.t) || 0) + n);
    const sb = certSubmitter(c);
    if (sb) bytesBySubmitter.set(sb, (bytesBySubmitter.get(sb) || 0) + n);
  });
  _certIdx = { ver: certVer, byTree, byCid, pos, bytesByTree, bytesBySubmitter, total };
  return _certIdx;
};
// Certificates a viewer needs to verify `pids`: the tree's root/epoch/legacy
// certs, each pid's own join/vouch certs, and — recursively — whatever vouches
// for the invite or voucher behind them. Not the whole tree: a member in one
// compartment doesn't learn the pids of people walled off from them.
const certChainsFor = (treePid, pids) => {
  const { byTree, byCid } = certIndex();
  const all = byTree.get(treePid) || [];
  const out = new Set();
  const bySub = new Map();
  for (const c of all) {
    if (c.k === 'root' || c.k === 'epoch' || c.k === 'legacy') out.add(c);
    if (c.sub) { if (!bySub.has(c.sub)) bySub.set(c.sub, []); bySub.get(c.sub).push(c); }
  }
  const seen = new Set();
  const visit = (pid) => {
    if (!pid || seen.has(pid)) return;
    seen.add(pid);
    for (const c of bySub.get(pid) || []) {
      out.add(c);
      if (c.k === 'join') {
        const inv = byCid.get(c.inv);
        if (inv && inv.t === treePid) { out.add(inv); visit(inv.by); }
      } else if (c.k === 'vouch') visit(c.by);
    }
  };
  for (const p of pids) visit(p);
  // In the order the server received them: clients keep a member's FIRST key
  // binding (v70 H1), so the order is part of what they verify.
  const { pos } = certIndex();
  return [...out].sort((a, b) => pos.get(a) - pos.get(b)).map(c => c.c);
};
// Current network-key id of a tree = newest epoch cert the root posted. Clients
// re-check the root's signature; the server only uses this to spot who lacks it.
const currentKid = (treePid) => {
  let best = null;
  for (const c of certIndex().byTree.get(treePid) || []) if (c.k === 'epoch' && c.by === treePid && (!best || c.ts > best.ts)) best = c;
  return best ? best.kid : null;
};
const identityKeyOf = (u) => (dbCache.signalIdentities[u.id] && dbCache.signalIdentities[u.id].pub) || (dbCache.prekeys[u.id] && dbCache.prekeys[u.id].identityKey) || null;
// After someone leaves a network (pruned, deleted, contact removed) the network
// key they held should be replaced. The server can't do it; it flags the root,
// whose app rotates the key on its next refresh.
const flagRotation = (rootNode) => { if (rootNode) rootNode.rotateNeededAt = Date.now(); };
// Housekeeping when nodes go away: their certificates (as subject or as the tree
// itself) and every key box to/from them. (Not a security control — a malicious
// server could keep them — just no dead weight.)
const dropMembershipFor = (gonePub) => {
  const before = certList().length;
  dbCache.certs = certList().filter(c => !gonePub.has(c.t) && !(c.sub && gonePub.has(c.sub)));
  if (dbCache.certs.length !== before) certVer++;
  dbCache.netBoxes = boxList().filter(b => !gonePub.has(b.to) && !gonePub.has(b.from) && !gonePub.has(b.tree));
};
// What an approver needs to show a join/contact request: the requester's
// encrypted profile + identity key (legacy plaintext name only if not migrated).
const requesterProfile = (u) => ({
  ...(u.profileCt ? { profileCt: u.profileCt } : { name: u.name }),
  ...(identityKeyOf(u) ? { ik: identityKeyOf(u) } : {}),
});
// Membership material for one viewer: cert chains for everyone it can see (and
// its pending requesters), key boxes addressed to it, and which visible members
// still lack a box for the current network key (any member holding the key may
// fill those in — self-healing when the root is offline).
const membershipFor = (me, visibleUsers, extraPids = []) => {
  const myPid = getPublicId(me.id);
  const myTree = treePidOf(me);
  const pids = new Set([myPid, ...visibleUsers.map(u => getPublicId(u.id)), ...extraPids]);
  const kid = currentKid(myTree);
  const boxes = boxList().filter(b => b.to === myPid);
  const have = kid ? new Set(boxList().filter(b => b.tree === myTree && b.kid === kid).map(b => b.to)) : null;
  const netNeed = kid ? visibleUsers.filter(u => !u.pending && identityKeyOf(u) && !have.has(getPublicId(u.id))).map(u => getPublicId(u.id)).slice(0, 500) : [];
  // The network name ciphertext for this member's own picker label (the header
  // still follows the root's visibility switch via the root's user entry).
  const root = treeRootUser(me);
  return { treeRoot: myTree, certs: certChainsFor(myTree, pids), boxes, kid, netNeed, ...(root && root.treeNameCt ? { treeNameCt: root.treeNameCt } : {}) };
};

// Submit certificates. Only the node a cert is ABOUT (join) or BY (everything
// else) may post it, into its own tree — so nobody can bloat someone else's set.
const certLimiter = accountLimiter(60 * 1000, 120);
app.post('/api/certs/submit', certLimiter, bigBody('4mb'), (req, res) => {
  const { nodeId, certs } = req.body || {};
  if (!isStr(nodeId, 128) || !Array.isArray(certs) || certs.length === 0 || certs.length > 500) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const myPid = getPublicId(me.id);
  const myTree = treePidOf(me);
  const isRootNode = me.role === 'ROOT' && !me.invitedBy;
  // A hub joiner's join cert lives in the INVITER's hub (its tree), reachable
  // through a contact edge (pending or active).
  const contactTrees = new Set((me.treeMode || '') === 'HUB' ? hubContactsOf(me.id, true).map(({ other }) => getPublicId(other.id)) : []);
  const myIk = identityKeyOf(me);
  // Validate the WHOLE batch against one index snapshot, then commit it all at
  // once (a rejected certificate no longer leaves the ones before it half-added).
  const idx = certIndex();
  const known = new Set(idx.byCid.keys());
  // v70 H4: this account's certificate budget across all of its identities.
  const acctPids = dbCache.users.filter(u => u.accountId === me.accountId).map(u => getPublicId(u.id));
  let acctBytes = acctPids.reduce((n, p) => n + (idx.bytesBySubmitter.get(p) || 0), 0);
  let totalBytes = idx.total;
  const addBytes = new Map(), addCount = new Map(), addRoots = new Map();
  let myInv = (idx.byTree.get(myTree) || []).filter(c => c.k === 'inv' && c.by === myPid).length;
  const pending = [];
  for (const raw of certs) {
    const sh = certShape(raw);
    if (!sh) return bad(res, 'Malformed certificate');
    const { b, s, cid } = sh;
    let ok = false;
    if (b.k === 'root') ok = isRootNode && b.tree === myPid && b.pid === myPid;
    else if (b.k === 'epoch' || b.k === 'legacy') ok = isRootNode && b.tree === myPid && b.by === myPid;
    else if (b.k === 'inv' || b.k === 'vouch') ok = b.by === myPid && b.tree === myTree && !me.pending;
    else if (b.k === 'join') ok = b.pid === myPid && (b.tree === myTree || contactTrees.has(b.tree));
    if (!ok) return res.status(403).json({ error: 'Certificate not accepted from this node.' });
    if (known.has(cid)) continue;
    if (b.ts > Date.now() + CERT_FUTURE_MS) return bad(res, 'Certificate is dated in the future.');
    const inTree = idx.byTree.get(b.tree) || [];
    // v70 H4: only well-signed certificates are stored. The signer is this node's
    // registered identity (for a join: the invite link's key). v70 H1: a key a
    // certificate binds must be the one its owner registered.
    let signer = null;
    if (b.k === 'root') signer = sameIk(b.ik, myIk) ? b.ik : null;
    else if (b.k === 'join') {
      const inv = idx.byCid.get(b.inv);
      signer = inv && inv.k === 'inv' && inv.t === b.tree ? inv.ip : null;
      // v72 (L): the key a join cert binds must be the one this node registered — also
      // when it has registered none yet (v71 then accepted any key). The app publishes
      // its identity before it submits the join cert.
      if (!myIk || !sameIk(b.ik, myIk)) signer = null;
    } else signer = myIk;
    if (!signer) return res.status(409).json({ error: 'Certificate doesn’t match the keys this server holds. Refresh and try again.' });
    if (!certSigOk(b, s, signer)) return res.status(403).json({ error: 'Certificate signature is invalid.' });
    if (b.k === 'vouch') {
      const tid = resolveInternalId(b.pid);
      const target = tid && dbCache.users.find(u => u.id === tid);
      if (!target || !sameIk(b.ik, identityKeyOf(target))) return res.status(409).json({ error: 'That person’s key has changed or isn’t published yet. Refresh and try again.' });
      // Only the root, or the member itself, may re-key a member someone already bound.
      if (b.by !== b.tree && b.by !== b.pid) {
        const prior = inTree.find(c => c.sub === b.pid && (c.k === 'join' || c.k === 'vouch') && !sameIk(certIk(c), b.ik));
        if (prior) return res.status(409).json({ error: 'Only the network owner can confirm a new key for an existing member.' });
      }
    }
    if (b.k === 'inv' && ++myInv > MAX_INV_PER_NODE) return res.status(429).json({ error: 'Too many invite links. Remove some old ones first.' });
    const n = raw.length;
    const tb = (idx.bytesByTree.get(b.tree) || 0) + (addBytes.get(b.tree) || 0);
    if (inTree.length + (addCount.get(b.tree) || 0) >= MAX_CERTS_PER_TREE || tb + n > MAX_CERT_BYTES_PER_TREE) return res.status(429).json({ error: 'This network has too many certificates.' });
    if (acctBytes + n > MAX_CERT_BYTES_PER_ACCOUNT) return res.status(429).json({ error: 'This account has reached its certificate limit.' });
    if (totalBytes + n > MAX_CERT_BYTES_TOTAL) {
      console.error('[certs] server-wide certificate budget reached — refusing new certificates');
      return res.status(503).json({ error: 'The server can’t store more certificates right now.' });
    }
    if (b.k === 'root' && inTree.filter(c => c.k === 'root').length + (addRoots.get(b.tree) || 0) >= 5) continue;
    const entry = { t: b.tree, cid, k: b.k, c: raw, at: Date.now(), ts: b.ts, sb: myPid };
    if (b.k === 'join' || b.k === 'vouch') { entry.sub = b.pid; entry.ik = b.ik; }
    if (b.k === 'inv' || b.k === 'vouch' || b.k === 'epoch' || b.k === 'legacy') entry.by = b.by;
    if (b.k === 'inv') entry.ip = b.ip;
    if (b.k === 'join') entry.inv = b.inv;
    if (b.k === 'epoch') entry.kid = b.kid;
    if (b.k === 'root') addRoots.set(b.tree, (addRoots.get(b.tree) || 0) + 1);
    acctBytes += n; totalBytes += n;
    addBytes.set(b.tree, (addBytes.get(b.tree) || 0) + n);
    addCount.set(b.tree, (addCount.get(b.tree) || 0) + 1);
    known.add(cid);
    pending.push(entry);
  }
  for (const entry of pending) {
    certList().push(entry);
    if (entry.k === 'epoch' && me.rotateNeededAt && entry.ts >= me.rotateNeededAt) delete me.rotateNeededAt; // the root rotated
  }
  const added = pending.length;
  if (added) {
    certVer++;
    persistDB('certs', 'users');   // users: rotateNeededAt
    const root = treeRootUser(me);
    notify(root ? profileWatchers(root) : new Set([me.accountId]));
  }
  res.json({ ok: true, added });
});

// A joiner opening an invite link asks for the invite certificate matching the
// key in its link (it knows the key's public half; the server does not know the
// private half, so it can't substitute one). Also returns the network's root
// certificates, which the joiner checks against the pin carried in its link.
const inviteInfoLimiter = accountLimiter(60 * 1000, 30);
app.post('/api/invites/info', inviteInfoLimiter, (req, res) => {
  const { code, ip } = req.body || {};
  if (!isStr(code, 64) || !isStr(ip, 64)) return bad(res, 'Invalid input');
  const inv = dbCache.invites.find(i => i.code === code.trim().toUpperCase() && !i.isUsed && (!i.expiresAt || i.expiresAt > Date.now()));
  const inviter = inv && dbCache.users.find(u => u.id === inv.inviterId);
  if (!inviter) return res.status(404).json({ error: 'Invalid or expired invite code.' });
  const tree = treePidOf(inviter);
  const all = certIndex().byTree.get(tree) || [];
  // Newest wins: re-issuing a link (e.g. after auto-accept is toggled) posts a
  // fresh certificate for the same link key.
  const cert = all.filter(c => c.k === 'inv' && c.ip === ip).sort((a, b) => b.ts - a.ts)[0];
  if (!cert) return res.status(404).json({ error: 'This invite link is not valid any more. Ask for a new one.' });
  res.json({ tree, cert: cert.c, rootCerts: all.filter(c => c.k === 'root').map(c => c.c), hub: (inviter.treeMode || '') === 'HUB' });
});

// Network-key boxes: a member seals the network key to another member's identity
// key. `from` is always the caller. Recipients must belong to the caller's tree
// (or be the caller's hub contacts, for a hub owner's own key), or be the caller
// itself (a self-box, used to keep a key across devices).
const boxLimiter = accountLimiter(60 * 1000, 120);
app.post('/api/netkeys/box', boxLimiter, bigBody('1mb'), (req, res) => {
  const { nodeId, boxes } = req.body || {};
  if (!isStr(nodeId, 128) || !Array.isArray(boxes) || boxes.length === 0 || boxes.length > 500) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const myPid = getPublicId(me.id);
  const myTree = treePidOf(me);
  const isHubOwner = (me.treeMode || '') === 'HUB' && !me.invitedBy;
  const contactPids = new Set(isHubOwner ? hubContactsOf(me.id, true).map(({ other }) => getPublicId(other.id)) : []);
  const inTree = (pid) => { const id = resolveInternalId(pid); const u = id && dbCache.users.find(x => x.id === id); return !!u && treePidOf(u) === myTree; };
  for (const bx of boxes) {
    if (!isObj(bx) || bx.v !== 1 || !isStr(bx.tree, 128) || !/^[0-9a-f]{16}$/.test(String(bx.kid)) || bx.from !== myPid || !isStr(bx.to, 128) || !isB64(bx.iv, 32) || !isB64(bx.ct, 128)) return bad(res, 'Malformed box');
    const self = bx.to === myPid;
    const ok = self ? (bx.tree === myTree || contactPids.has(bx.tree))
      : bx.tree === myTree && !me.pending && (isHubOwner ? contactPids.has(bx.to) : inTree(bx.to));
    if (!ok) return res.status(403).json({ error: 'Box not accepted.' });
  }
  // v70 H4: bounded storage. Each (tree, from, to) keeps its newest
  // MAX_KIDS_PER_BOX_PAIR key ids (a node's boxes to itself: MAX_SELF_BOX_KIDS) —
  // replacing the oldest, so made-up key ids can't grow the list — and each
  // account and tree has a ceiling.
  const acctPids = new Set(dbCache.users.filter(u => u.accountId === me.accountId).map(u => getPublicId(u.id)));
  // v71 L11: one pass to index the list, then O(1) per box (v70 scanned the whole
  // list for every box — up to 500 boxes × every stored box, per request).
  const list = boxList();
  let acctCount = 0;
  const treeCount = new Map();
  const pairs = new Map();                        // tree|from|to -> boxes
  const pk = (o) => o.tree + '|' + o.from + '|' + o.to;
  for (const o of list) {
    if (acctPids.has(o.from)) acctCount++;
    treeCount.set(o.tree, (treeCount.get(o.tree) || 0) + 1);
    if (!pairs.has(pk(o))) pairs.set(pk(o), []);
    pairs.get(pk(o)).push(o);
  }
  const dropped = new Set();
  let added = 0;
  for (const bx of boxes) {
    const rec = { tree: bx.tree, kid: bx.kid, from: bx.from, to: bx.to, iv: bx.iv, ct: bx.ct, at: Date.now() };
    const pair = pairs.get(pk(bx)) || [];
    const same = pair.find(o => o.kid === bx.kid);
    if (same) { Object.assign(same, rec); added++; continue; }
    const cap = bx.to === bx.from ? MAX_SELF_BOX_KIDS : MAX_KIDS_PER_BOX_PAIR;
    if (pair.length >= cap) {
      const drop = pair.sort((a, b) => a.at - b.at).slice(0, pair.length - cap + 1);
      for (const d of drop) dropped.add(d);
      pair.splice(0, drop.length);
      acctCount -= drop.length;
      treeCount.set(bx.tree, (treeCount.get(bx.tree) || 0) - drop.length);
    }
    if ((treeCount.get(bx.tree) || 0) >= MAX_BOXES_PER_TREE) return res.status(429).json({ error: 'Too many key boxes.' });
    if (acctCount >= MAX_BOXES_PER_ACCOUNT) return res.status(429).json({ error: 'This account has reached its key-box limit.' });
    if (list.length - dropped.size >= MAX_BOXES_TOTAL) {                 // v72 B4: boxes live in RAM
      console.error('[netkeys] server-wide key-box budget reached — refusing new boxes');
      return res.status(503).json({ error: 'The server can’t store more network keys right now.' });
    }
    list.push(rec);
    pair.push(rec); pairs.set(pk(bx), pair);
    acctCount++;
    treeCount.set(bx.tree, (treeCount.get(bx.tree) || 0) + 1);
    added++;
  }
  if (dropped.size) dbCache.netBoxes = list.filter(o => !dropped.has(o));
  persistDB('netBoxes');
  const touched = new Set([me.accountId]);
  for (const bx of boxes) { const u = dbCache.users.find(x => x.id === resolveInternalId(bx.to)); if (u) touched.add(u.accountId); }
  notify(touched);
  res.json({ ok: true, added });
});

// Encrypted profile writes. Everything here is ciphertext the server can't read:
//   profileCt  — name/bio/name-history/photo key, under the network key
//   avatarCt   — the photo, under a per-photo key (enc1:…)
//   selfCt     — the owner's own name + network name, under the ACCOUNT key
//                (so the network picker can label identities without keys)
//   treeNameCt — the network name (root only), under the network key
//   anchorCt   — the owner's pinned root identity, under the account key
// Uploading a profileCt deletes the legacy plaintext name/bio/history for good.
const MAX_PROFILE_CT = 16000;
const MAX_AVATAR_CT = 700000;
const profileSetLimiter = accountLimiter(60 * 1000, 60);
app.post('/api/profile/set', profileSetLimiter, bigBody('1mb'), async (req, res) => {
  const { nodeId, profileCt, avatarCt, removeAvatar, selfCt, treeNameCt, anchorCt, replaceAnchor } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const ctOk = (v, max) => v === undefined || (isStr(v, max) && (() => { try { const o = JSON.parse(v); return isObj(o) && o.v === 1; } catch { return false; } })());
  if (!ctOk(profileCt, MAX_PROFILE_CT) || !ctOk(treeNameCt, 4000)) return bad(res, 'Invalid profile ciphertext');
  if (selfCt !== undefined && !isStr(selfCt, 8000)) return bad(res, 'Invalid input');
  if (anchorCt !== undefined && !isStr(anchorCt, 4000)) return bad(res, 'Invalid input');
  if (avatarCt !== undefined && !(isStr(avatarCt, MAX_AVATAR_CT) && /^enc1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$/.test(avatarCt))) return bad(res, 'Invalid photo ciphertext');
  if (treeNameCt !== undefined && !(me.role === 'ROOT' && !me.invitedBy)) return res.status(403).json({ error: 'Only the network owner can rename it.' });
  // Archived networks can still re-encrypt (migration / key rotation), but can't
  // park new photos.
  if (avatarCt !== undefined && isTreeArchived(me)) return res.status(402).json(ARCHIVED_402);
  let changed = false;
  if (profileCt !== undefined) {
    me.profileCt = profileCt; me.profileAt = Date.now();
    delete me.name; delete me.bio; delete me.nameHistory; delete me.provisionName;
    changed = true;
  }
  const prevAvatar = me.avatarHash;
  if (avatarCt !== undefined) {
    const hash = avatarHashOf(avatarCt);
    await avatarsStore.put(hash, avatarCt);
    me.avatarHash = hash; me.avatarAt = Date.now(); changed = true;
  } else if (removeAvatar === true) { delete me.avatarHash; delete me.avatarAt; changed = true; }
  // v72 B4: a replaced/removed photo is deleted now (if nothing else uses it), not
  // at the hourly sweep — repeated uploads can't pile up photos in between.
  if (prevAvatar && prevAvatar !== me.avatarHash) await dropAvatarIfUnused(prevAvatar);
  if (treeNameCt !== undefined) { me.treeNameCt = treeNameCt; delete me.treeName; changed = true; }
  if (selfCt !== undefined) me.selfCt = selfCt;
  // First pin wins; the owner's app may re-seal it under a new account key (v70 H2:
  // the password-hashing upgrade). The server can't read or forge either version.
  if (anchorCt !== undefined && (!me.anchorCt || replaceAnchor === true)) me.anchorCt = anchorCt;
  persistDB();
  if (changed) notify(profileWatchers(me));
  res.json({ ok: true, avatarAt: me.avatarAt || 0, profileAt: me.profileAt || 0 });
});

// Acks are metadata (like read receipts): recipient X acknowledged message mid.
// Only the SENDER of a message may see who acknowledged it. Reactions are returned
// for every message a node SENT or RECEIVED. v72 B4: both live in tables
// (metaStore) and visibility comes from messages/message_recipients at read time —
// v71 kept them in RAM with a copy of each message's whole audience.

// ---- v71 H1: bounded message storage + delivery ------------------------------
// Messages carry only text + small attachment pointers since V8 (media travels as
// separate blobs), so an envelope's ciphertext is small: the padded content is at
// most a few 64 KB buckets. These caps bound every stored row and every delivery.
const MSG_MAX_CT_CHARS = parseInt(process.env.MSG_MAX_CT_CHARS || String(1024 * 1024), 10); // base64 chars (~768 KB)
const MSG_MAX_SLOT_CHARS = 2048;          // one ratchet key slot is a few hundred chars
const MSG_MAX_RECIPS = 2000;              // one slot per reader; an audience is never larger
const MAX_MESSAGE_BYTES_PER_ACCOUNT = parseInt(process.env.MAX_MESSAGE_BYTES_PER_ACCOUNT || String(256 * 1024 * 1024), 10);
// Server-side retention (days). Unset = 90; 0 = keep forever (explicit opt-out).
const MESSAGE_RETENTION_DAYS = (() => { const v = process.env.MESSAGE_RETENTION_DAYS; if (v === undefined || v === '') return 90; const n = parseInt(v, 10); return Number.isFinite(n) && n >= 0 ? n : 90; })();
// Premium networks keep a year of history (never less than the free window).
const PREMIUM_RETENTION_DAYS = parseInt(process.env.PREMIUM_RETENTION_DAYS || '365', 10) || 365;
const premiumRetentionDays = () => (MESSAGE_RETENTION_DAYS > 0 ? Math.max(MESSAGE_RETENTION_DAYS, PREMIUM_RETENTION_DAYS) : 0);
const retentionDaysFor = (node) => (isTreePremium(node) ? premiumRetentionDays() : MESSAGE_RETENTION_DAYS);
const MSG_PAGE_COUNT = 200;
// v72 B4: 2 MB pages (v71: 8 MB). A page is held in memory several times over while
// it is serialized; on a 1 GB server a few dozen concurrent 8 MB syncs were enough
// to run out. The client follows `msgMore`, so nothing is skipped — a big backlog
// just takes more (smaller) round trips. (Never an empty page: see cutPage.)
const MSG_PAGE_BYTES = parseInt(process.env.MSG_PAGE_BYTES || String(2 * 1024 * 1024), 10);
// A delivery cursor: a non-negative safe integer, or null (absent / invalid).
const parseCursor = (v) => (Number.isSafeInteger(v) && v >= 0 ? v : null);
// Validate a v5 envelope and return a copy holding ONLY the known fields (nothing a
// client adds rides into storage). Returns null when malformed.
const cleanEnvelope = (e, maxCt = MSG_MAX_CT_CHARS) => {
  if (!isObj(e) || e.v !== 5 || !isMid(e.mid) || !isB64(e.ct, maxCt) || !Array.isArray(e.recips)) return null;
  if (e.recips.length === 0 || e.recips.length > MSG_MAX_RECIPS) return null;
  const seen = new Set();
  const recips = [];
  for (const r of e.recips) {
    if (!isObj(r) || !isStr(r.id, 128) || !Number.isInteger(r.kt) || r.kt < 0 || r.kt > 16 || !isStr(r.kb, MSG_MAX_SLOT_CHARS)) return null;
    if (seen.has(r.id)) return null;                    // one slot per recipient
    seen.add(r.id);
    recips.push({ id: r.id, kt: r.kt, kb: r.kb });
  }
  const out = { v: 5, mid: e.mid, ct: e.ct, recips };
  if (e.ts !== undefined) { if (typeof e.ts !== 'number' || !Number.isFinite(e.ts)) return null; out.ts = e.ts; }
  if (e.exp !== undefined) { if (e.exp !== null && (typeof e.exp !== 'number' || !Number.isFinite(e.exp))) return null; out.exp = e.exp; }
  if (e.iv !== undefined) { if (!isB64(e.iv, 64)) return null; out.iv = e.iv; }
  if (e.sigBy !== undefined) { if (!isStr(e.sigBy, 128)) return null; out.sigBy = e.sigBy; }
  if (e.targetGroup !== undefined && e.targetGroup !== null) { if (!isStr(e.targetGroup, 64) || !isSafeKey(e.targetGroup)) return null; out.targetGroup = e.targetGroup; }
  return out;
};
const accountNodeIds = (accountId) => dbCache.users.filter(u => u.accountId === accountId).map(u => u.id);
// Would storing `bytes` more put this account over its message storage quota?
// (Queued scheduled envelopes count too — they become stored messages.)
const messageQuotaExceeded = async (accountId, bytes) => {
  const ids = accountNodeIds(accountId);
  const queued = await scheduledStore.bytesForNodes(ids);
  return (await messagesStore.senderBytes(ids)) + queued + bytes > MAX_MESSAGE_BYTES_PER_ACCOUNT;
};
const QUOTA_413 = { error: 'This account has reached its message storage limit. Older messages expire over time; delete some of your sent messages to free space now.', code: 'message-quota' };
// Node by internal id, cached per data version (a page can hold 200 messages —
// a linear scan of every user for each one was the hot path). A miss re-scans.
let _userIdx = { v: -1, n: -1, map: new Map() };
const userByIdCached = (id) => {
  if (_userIdx.v !== dataVersion || _userIdx.n !== dbCache.users.length) _userIdx = { v: dataVersion, n: dbCache.users.length, map: new Map(dbCache.users.map(u => [u.id, u])) };
  return _userIdx.map.get(id) || dbCache.users.find(u => u.id === id);
};
// The wire shape of one stored message for recipient `myPid`.
const wireMessage = (m, myPid) => {
  const s = userByIdCached(m.senderId);
  // V8 L-2: deliver ONLY this recipient's own key slot. Relaying the full recips
  // list told every recipient every other recipient's public id — the message's
  // whole audience (monitors included).
  const env = m.envelope && Array.isArray(m.envelope.recips)
    ? { ...m.envelope, recips: m.envelope.recips.filter(r => r && r.id === myPid) }
    : m.envelope;
  return {
    id: m.id, seq: m.seq, senderId: getPublicId(m.senderId), envelope: env, timestamp: m.timestamp,
    expiresAt: m.expiresAt, type: m.type, depthLimit: m.depthLimit, targetCircle: m.targetCircle,
    ackRequested: !!m.ackRequested,
    // Level of the announcer at send time (root = 0). Only meaningful for
    // BROADCAST; used purely to label "Announcement from level N".
    senderLevel: m.type === 'BROADCAST' && s ? (s.level ?? 0) : undefined,
  };
};

// V8 M-14: the hot path had no limiter at all. A client polls every 8s and
// re-fetches on SSE nudges; 240/min per account leaves ample headroom for several
// devices plus the network-picker pre-warm, while bounding amplification.
const treeContextLimiter = accountLimiter(60 * 1000, 240);
app.post('/api/tree-context', treeContextLimiter, async (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;

  // A requester awaiting approval sees only themselves — no tree, no messages.
  if (me.pending) {
    const inviter = dbCache.users.find(u => u.id === me.invitedBy);
    return res.json({
      users: [{ ...sanitizeUser(me, me), pending: true }],
      messages: [], invites: [],
      pendingApproval: true,
      // The inviter's name is encrypted; a joiner holds the network key from its
      // invite link, so its app decrypts it.
      ...(inviter ? { inviterId: getPublicId(inviter.id), inviterProfileCt: inviter.profileCt || undefined, inviterIk: identityKeyOf(inviter) || undefined, inviterName: inviter.profileCt ? undefined : (inviter.name || null) } : {}),
      boxes: boxList().filter(b => b.to === getPublicId(me.id)),
    });
  }

  const privileged = me.role === 'ROOT' || me.permissions?.viewTrueLevel;
  let visibleRaw;
  let hubPending = null; // contactId -> 'in' | 'out' (pending edge direction)
  if ((me.treeMode || '') === 'HUB') {
    // A hub is just me + my contact edges (active AND pending, so the client can
    // render "waiting for accept" rows) — never a tree walk.
    hubPending = new Map();
    visibleRaw = [me];
    for (const { edge, other } of hubContactsOf(me.id, true)) {
      visibleRaw.push(other);
      if (edge.pending) hubPending.set(other.id, edge.requestedBy === me.id ? 'out' : 'in');
    }
  } else if (privileged) {
    const treeRootId = me.path.split('/')[0];
    visibleRaw = dbCache.users.filter(u => u.path === treeRootId || u.path.startsWith(treeRootId + '/'));
  } else if (me.treeMode === 'DM' || me.treeMode === 'HUB') {
    visibleRaw = dbCache.users.filter(u =>
      u.id === me.id || u.id === me.invitedBy || u.path.startsWith(me.path + '/'));
  } else {
    visibleRaw = dbCache.users.filter(u => {
      if (u.id === me.id) return true;
      const isDescendant = u.path.startsWith(me.path + '/');
      const isAncestor = me.path.startsWith(u.path + '/');
      // Every direct sibling is visible: they all share the main Ancestors chat
      // (mainChatPeers). Which GROUPS a sibling is in is not disclosed, and group
      // chats themselves stay walled off (usersWhoCanRead).
      const isSibling = mainChatPeers(me, u);
      return isDescendant || isAncestor || isSibling;
    });
  }
  // Cross-level VISITOR: also surface every participant of a group I visit (its
  // owner, that group's members, and co-visitors), so I can see and message that
  // group's people even though they're on another branch.
  {
    const seen = new Set(visibleRaw.map(u => u.id));
    // Indexed (V8 M-14): only the groups I actually visit, not a scan of every user.
    for (const { o, gid } of visitedGroupsOf(me.id)) {
      const ids = gidVisitorIds(o, gid);
      if (!seen.has(o.id)) { visibleRaw.push(o); seen.add(o.id); }
      for (const u of dbCache.users) if (!u.pending && u.invitedBy === o.id && memberGids(o, u.id).includes(gid) && !seen.has(u.id)) { visibleRaw.push(u); seen.add(u.id); }
      for (const vid of ids) { const vu = dbCache.users.find(x => x.id === vid); if (vu && !seen.has(vid)) { visibleRaw.push(vu); seen.add(vid); } }
    }
  }
  visibleRaw = visibleRaw.filter(u => !u.pending); // requests aren't in the tree until accepted

  const users = visibleRaw.map(u => {
    const clean = sanitizeUser(u, me);
    if (hubPending && hubPending.has(u.id)) {
      // Pending CONTACT (not a pending node): outgoing shows as "waiting" in the
      // requester's chat list; incoming ones additionally appear as requests.
      clean.pending = true;
      clean.pendingDirection = hubPending.get(u.id);
    }
    return clean;
  });
  // V8 L-8 look-alike warnings are computed by the CLIENT now: names are
  // end-to-end encrypted (phase 2, M-8), so only the viewer can compare them.

  const now = Date.now();
  const myPublicId = getPublicId(me.id);
  // v71 H1: ONE bounded page of this recipient's messages — never the whole
  // history. A current client sends `since` (the highest seq it has fully
  // processed) and pages forward with /api/messages/sync while `msgMore` is set; an
  // older client (no cursor) gets the NEWEST page, which is all an 8-second poll
  // needs. Only THIS recipient's rows are read (indexed by recipient + seq).
  const page = await messagesStore.page(myPublicId, { since: parseCursor(req.body.since), now, maxCount: MSG_PAGE_COUNT, maxBytes: MSG_PAGE_BYTES });
  const messages = page.messages.map(m => wireMessage(m, myPublicId));

  const invites = dbCache.invites
    .filter(i => i.inviterId === me.id && (!i.expiresAt || i.expiresAt > now))
    .map(i => ({ code: i.code, isUsed: i.isUsed, recipientName: i.recipientName, expiresAt: i.expiresAt, permanent: !!i.permanent }));

  const joinRequests = (me.treeMode || '') === 'HUB'
    ? hubContactsOf(me.id, true)
        .filter(({ edge }) => edge.pending && edge.requestedBy !== me.id)
        .map(({ edge, other }) => ({ id: getPublicId(other.id), requestedAt: edge.addedAt || 0, ...requesterProfile(other), ...hubAttestFor(edge, me) }))
    : dbCache.users
        .filter(u => u.pending && u.invitedBy === me.id)
        .map(u => {
          // Referral joins keep a pointer to who actually shared the link; show
          // that name so the root knows the chain a pending person came through.
          const ref = u.referredBy && dbCache.users.find(x => x.id === u.referredBy);
          // A person who used a GROUP's join link is pre-assigned to that group;
          // surface its name so the approver sees which branch they want to join.
          const _bnames = memberGids(me, u.id).map(g => (me.groupLabels || {})[g]).filter(Boolean);
          const branchName = _bnames.length ? _bnames.join(', ') : null;
          return { id: getPublicId(u.id), requestedAt: u.requestedAt || 0, ...requesterProfile(u),
            ...(ref ? { referredBy: getPublicId(ref.id), referredByProfileCt: ref.profileCt || undefined, referredByIk: identityKeyOf(ref) || undefined, ...(ref.profileCt ? {} : { referredByName: ref.name }) } : {}),
            ...(branchName ? { branchName } : {}) };
        });

  // Recent retractions (last 7 days) so a recipient that missed the live event
  // still drops the message on sync. V8 L-1: scoped to tombstones whose audience
  // included this node — previously every user saw every tenant's deletions.
  // (v72: one tombstone row per recipient, in the tombstones table.)
  const retracted = await metaStore.retractedFor(myPublicId);

  // Reactions on every message this node sent or received (not only the delivered
  // page, so the sender also sees reactions on its own messages after a refresh).
  const reactions = await metaStore.reactionsFor(myPublicId, me.id);
  const acks = await metaStore.acksForSender(me.id);

  // Cross-level links (root-owned channels that span compartments) this node is a
  // participant of — so a member's client can render the shared chat even though
  // the link data lives on the root's node. Root also sees full refs in its own
  // groupLinks (for editing); members get only { name, archived }.
  const crossLinks = {};
  {
    const troot = treeRootUser(me);
    const gl = (troot && troot.groupLinks) || {};
    for (const [lid, L] of Object.entries(gl)) {
      if (!L || !L.crossLevel) continue;
      if (crossLevelParticipants(troot, L, dbCache.users).has(me.id)) {
        crossLinks[lid] = { name: L.name, ...(L.archived ? { archived: true } : {}) };
      }
    }
  }

  // V8 phase 2: membership certificates + network-key material for this viewer.
  // Hub contacts are their own trees; their certs come from their owners.
  const activeVisible = visibleRaw.filter(u => !(hubPending && hubPending.has(u.id)));
  const membership = membershipFor(me, activeVisible, joinRequests.map(j => j.id));
  res.json({ users, messages, msgNext: page.next, msgMore: page.more, invites, joinRequests, retracted, acks, reactions, crossLinks, ...membership });
});

// v71 H1: the next page of this node's messages after a cursor. The client calls
// this while tree-context (or a previous page) reported `msgMore`.
const syncLimiter = accountLimiter(60 * 1000, 240);
app.post('/api/messages/sync', syncLimiter, async (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const since = parseCursor(req.body.since);
  if (since === null) return bad(res, 'Invalid cursor');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (me.pending) return res.json({ messages: [], next: since, more: false });
  const myPublicId = getPublicId(me.id);
  const page = await messagesStore.page(myPublicId, { since, now: Date.now(), maxCount: MSG_PAGE_COUNT, maxBytes: MSG_PAGE_BYTES });
  res.json({ messages: page.messages.map(m => wireMessage(m, myPublicId)), next: page.next, more: page.more });
});

app.post('/api/recipients', (req, res) => {
  const { nodeId, type, targetCircle, targets, targetGroup } = req.body || {};
  if (!isStr(nodeId, 128) || !['PEER', 'BROADCAST', 'GLOBAL'].includes(type)) return bad(res, 'Invalid input');
  if (targetCircle !== undefined && !['UP', 'DOWN'].includes(targetCircle)) return bad(res, 'Invalid targetCircle');
  if (targetGroup !== undefined && targetGroup !== null && (!isStr(targetGroup, 64) || !isSafeKey(targetGroup))) return bad(res, 'Invalid targetGroup');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (me.pending) return res.status(403).json({ error: 'Awaiting approval' }); // V8 M-15
  if (type === 'BROADCAST' && !canAnnounce(me)) return res.status(403).json({ error: 'You have not been granted announcement rights.' });
  if (type === 'GLOBAL' && !globalChatOn(me)) return res.status(403).json({ error: 'Global chat is not enabled for this network.' });
  // V8 phase 2 (H-2): this list is only the server's CLAIM. It ships with the
  // membership certificates for every listed node; the sender's app encrypts only
  // to those whose chain of signatures leads back to the pinned network root.
  // Names are ciphertext now — the app labels recipients from decrypted profiles.
  const readers = usersWhoCanRead(me, type, targetCircle, dbCache.users, resolveTargets(targets), targetGroup || null).filter(u => u.encPub);
  const recips = readers.map(u => ({ id: getPublicId(u.id), encPub: u.encPub, ...(identityKeyOf(u) ? { ik: identityKeyOf(u) } : {}) }));
  const tree = treePidOf(me);
  res.json({ recipients: recips, treeRoot: tree, certs: certChainsFor(tree, new Set([getPublicId(me.id), ...recips.map(r => r.id)])) });
});

// ---------------------------------------------------------------------------
// Signal prekey directory (public key material; safe to store and serve).
// Each node publishes an identity key, a signed prekey, and a batch of one-time
// prekeys. Fetching a bundle consumes one one-time prekey (X3DH).
// ---------------------------------------------------------------------------
const isB64 = (v, max = 200000) => typeof v === 'string' && v.length > 0 && v.length <= max && /^[A-Za-z0-9+/]*={0,2}$/.test(v);

// Shared limiter for key-directory + backup endpoints (bounds abuse without
// impeding normal use: session setup bursts stay well under these caps).
const keyLimiter = rateLimit({ windowMs: 60 * 1000, max: 240, standardHeaders: true, legacyHeaders: false });
// Two accounts are related iff they have nodes in the same tree (same path root).
const sameTree = (a, b) => a && b && a.path.split('/')[0] === b.path.split('/')[0];
// Broader relation for cross-account gates: same tree OR an active personal-hub
// contact edge between the two nodes. (Pending edges do NOT relate — no
// messaging, calls, receipts, prekey draining or blob access before accept.)
const relatedNodes = (a, b) => sameTree(a, b) || !!(a && b && (() => { const e = hubEdgeBetween(a.id, b.id); return e && !e.pending; })());
// SECURITY (compartment isolation): two nodes with the SAME inviter that the
// inviter has split into DISJOINT groups are walled off. Messaging already
// enforces this via usersWhoCanRead; this predicate lets the metadata/call/
// prekey side-channels (typing, receipts, RTC signaling, prekey draining)
// enforce it too, so compartmentalized peers cannot reach each other there.
//
// V8 M-1: the wall is TRANSITIVE. The old check compared only direct siblings, so
// a walled node's child/grandchild (or any cousin) could still ring, type at,
// receipt, and drain the prekeys of someone across the wall. Now we find the two
// BRANCH HEADS directly under the pair's lowest common ancestor and apply the
// sibling rule to those heads — so everything below a walled branch inherits the
// wall. An ancestor↔descendant pair is never walled (that's the oversight line).
// Explicit cross-compartment channels the OWNERS created still connect people:
// group links, cross-level links and cross-level visitors (each of those
// deliberately spans compartments, and messaging over them needs sessions).
// v72 M2: global chat is NOT one of them any more — it used to make every pair in
// the network "share a channel", which removed the walls for calls, typing,
// receipts, visitors and profiles alike. See globalPeers() for the few paths the
// global channel itself needs.
// Direct-Only (DM) trees are hub-and-spoke: members never reach each other.
const sharesExplicitChannel = (a, b) => {
  const users = dbCache.users;
  const root = treeRootUser(a);
  if (!root || !sameTree(a, b)) return false;
  // Cross-level links (root-owned): both are participants of one live link.
  for (const L of Object.values(root.groupLinks || {})) {
    if (!L || !L.crossLevel || L.archived) continue;
    const parts = crossLevelParticipants(root, L, users);
    if (parts.has(a.id) && parts.has(b.id)) return true;
  }
  // Group links on a shared inviter: both sit in groups joined by one live link.
  if (a.invitedBy && a.invitedBy === b.invitedBy) {
    const inv = users.find(u => u.id === a.invitedBy);
    const ga = memberGids(inv, a.id), gb = memberGids(inv, b.id);
    for (const L of Object.values((inv && inv.groupLinks) || {})) {
      if (!L || L.crossLevel || L.archived || !Array.isArray(L.groups)) continue;
      if (ga.some(g => L.groups.includes(g)) && gb.some(g => L.groups.includes(g))) return true;
    }
  }
  // Cross-level visitors: x is a visitor of a group whose owner/member/co-visitor is y.
  // v71 H2: through the visitor index (the groups x visits), not a scan of every
  // user in the database on each typing/receipt/call/prekey/profile check.
  const inVisitedGroup = (x, y) => {
    for (const { o, gid } of visitedGroupsOf(x.id)) {
      const ids = gidVisitorIds(o, gid);
      if (y.id === o.id || ids.includes(y.id)) return true;
      if (y.invitedBy === o.id && memberGids(o, y.id).includes(gid)) return true;
    }
    return false;
  };
  return inVisitedGroup(a, b) || inVisitedGroup(b, a);
};
// v72 M2 (your decision): with global chat on, EVERY member is in that one channel
// — with no walls inside it, and no crossover outside it. Two members walled apart
// elsewhere are 'global peers' ONLY for what the channel strictly needs: its message
// audience (usersWhoCanRead GLOBAL), fetching each other's prekeys (to encrypt to
// each other), seeing each other's profile (to show who is talking), and
// downloading attachments sent IN the channel. Calls, typing, receipts, DMs, group
// and visitor changes and hub requests keep the wall.
const globalPeers = (a, b) => {
  if (!a || !b || a.id === b.id || a.pending || b.pending || !sameTree(a, b)) return false;
  const root = treeRootUser(a);
  return !!(root && root.globalChat);
};
// Direct siblings (same inviter) share the MAIN Descendants/Ancestors chat whatever
// groups they're in. Like global-chat peers they may see each other in the roster
// and profile, fetch each other's keys, and download attachments sent IN that chat.
// Calls, typing, receipts, DMs and group chats keep the wall. Not in 1:1 (DM) trees.
const mainChatPeers = (a, b) => {
  if (!a || !b || a.id === b.id || a.pending || b.pending || !a.invitedBy || a.invitedBy !== b.invitedBy || !sameTree(a, b)) return false;
  const root = treeRootUser(a);
  return !!root && (root.treeMode || '') !== 'DM' && (root.treeMode || '') !== 'HUB';
};
const compartmentBlocked = (a, b) => {
  if (!a || !b || a.id === b.id || !sameTree(a, b)) return false; // cross-tree is handled by relatedNodes (hub edges)
  if (a.path.startsWith(b.path + '/') || b.path.startsWith(a.path + '/')) return false; // direct line
  const root = treeRootUser(a);
  if (root && (root.treeMode || '') === 'DM') return !sharesExplicitChannel(a, b);
  const pa = a.path.split('/'), pb = b.path.split('/');
  let i = 0;
  while (i < pa.length && i < pb.length && pa[i] === pb[i]) i++;
  const ha = dbCache.users.find(u => u.id === pa[i]);
  const hb = dbCache.users.find(u => u.id === pb[i]);
  if (!ha || !hb) return true;                                    // malformed path: fail closed
  if (sameInviteeGroup(ha, hb, dbCache.users)) return false;      // branch heads share a compartment
  return !sharesExplicitChannel(a, b);
};

app.post('/api/prekeys/publish', keyLimiter, (req, res) => {
  const { nodeId, bundle } = req.body || {};
  if (!isStr(nodeId, 128) || !isObj(bundle)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (isTreeArchived(me)) return res.status(402).json({ error: 'This network is archived.' });
  const b = bundle;
  // v71 M4: exact sizes. A Curve25519 public key is 33 bytes (44 base64 chars), a
  // signature 64 bytes (88 chars), ids are 31-bit integers — v70 allowed 200 KB each.
  const isKeyId = (v) => Number.isInteger(v) && v >= 0 && v <= 0x7fffffff;
  if (!isB64(b.identityKey, 64) || !isKeyId(b.registrationId) || !isObj(b.signedPreKey)) return bad(res, 'Invalid bundle');
  const spk = b.signedPreKey;
  if (!isKeyId(spk.keyId) || !isB64(spk.publicKey, 64) || !isB64(spk.signature, 128)) return bad(res, 'Invalid signed prekey');
  const oneTime = Array.isArray(b.oneTimePreKeys) ? b.oneTimePreKeys : [];
  if (oneTime.length > 200 || !oneTime.every(p => isObj(p) && isKeyId(p.keyId) && isB64(p.publicKey, 64))) return bad(res, 'Invalid one-time prekeys');

  const existing = dbCache.prekeys[me.id] || { oneTimePreKeys: [] };
  const merged = existing.oneTimePreKeys || [];
  const seen = new Set(merged.map(p => p.keyId));
  for (const p of oneTime) if (!seen.has(p.keyId)) { merged.push({ keyId: p.keyId, publicKey: p.publicKey }); seen.add(p.keyId); }
  // Cap stored one-time prekeys to bound storage.
  const capped = merged.slice(-200);
  dbCache.prekeys[me.id] = {
    identityKey: b.identityKey,
    registrationId: b.registrationId,
    signedPreKey: { keyId: spk.keyId, publicKey: spk.publicKey, signature: spk.signature },
    oneTimePreKeys: capped,
  };
  persistDB('prekeys');
  res.json({ ok: true, remaining: capped.length });
});

app.post('/api/prekeys/status', keyLimiter, (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const pk = dbCache.prekeys[me.id];
  res.json({ published: !!pk, remaining: pk ? (pk.oneTimePreKeys || []).length : 0 });
});

// Fetching a bundle CONSUMES a one-time prekey, so it gets a tighter limiter than
// the rest of the key-directory endpoints: this bounds how fast any one source can
// drain a target's one-time prekeys. Draining them is not a break — X3DH falls
// back to the signed prekey (still authenticated and confidential, exactly as a
// stock Signal server behaves when a bundle is out of one-time keys) — and clients
// republish more whenever their remaining count drops below 5. The gate below
// still restricts fetches to nodes in the same tree / an active hub contact.
const prekeyFetchLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
app.post('/api/prekeys/fetch', prekeyFetchLimiter, (req, res) => {
  const { forNodeId } = req.body || {};
  if (!isStr(forNodeId, 128)) return bad(res, 'Invalid input');
  const internal = resolveInternalId(forNodeId);
  const target = internal && dbCache.users.find(u => u.id === internal);
  // One-time prekeys are a consumable: only members of the SAME TREE as the target
  // may fetch (and thereby consume) them. Without this gate, any authenticated
  // account could silently drain a stranger's one-time prekeys (weakening their
  // X3DH to signed-prekey-only) — a quiet denial-of-forward-secrecy attack.
  const requesterNodes = dbCache.users.filter(u => u.accountId === req.accountId && !u.pending);
  if (!target || target.pending || isTreeArchived(target) || !requesterNodes.some(n => relatedNodes(n, target) && (!compartmentBlocked(n, target) || globalPeers(n, target) || mainChatPeers(n, target)))) {   // v72 M2: global peers must be able to encrypt to each other
    return res.status(404).json({ error: 'No prekey bundle for that node yet' });
  }
  const pk = dbCache.prekeys[internal];
  if (!pk) return res.status(404).json({ error: 'No prekey bundle for that node yet' });
  // Consume one one-time prekey if available (otherwise fall back to signed prekey).
  let preKey;
  if (pk.oneTimePreKeys && pk.oneTimePreKeys.length) {
    preKey = pk.oneTimePreKeys.shift();
    persistDB('prekeys');
  }
  res.json({
    identityKey: pk.identityKey,
    registrationId: pk.registrationId,
    signedPreKey: pk.signedPreKey,
    preKey: preKey ? { keyId: preKey.keyId, publicKey: preKey.publicKey } : undefined,
  });
});

// Stable Signal identity (device-independent). The PRIVATE key is stored only in
// its client-wrapped (AES-GCM under the user's session key) form; the server never
// sees identity private key bytes. This lets a node keep ONE identity across logins
// and devices instead of regenerating (which peers would flag as an identity change).
app.post('/api/signal-identity/get', keyLimiter, (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const sid = dbCache.signalIdentities[me.id];
  res.json({ identity: sid || null });
});

app.post('/api/signal-identity/set', keyLimiter, (req, res) => {
  const { nodeId, signalIdentity } = req.body || {};
  if (!isStr(nodeId, 128) || !isObj(signalIdentity)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const sid = signalIdentity;
  if (!isB64(sid.pub, 64) || !(Number.isInteger(sid.regId) && sid.regId >= 0 && sid.regId <= 0x7fffffff) || !isStr(sid.wrapped, 4096)) return bad(res, 'Invalid identity');   // v71 M4: exact sizes
  // First write wins per node (don't silently overwrite an established identity).
  if (!dbCache.signalIdentities[me.id]) {
    dbCache.signalIdentities[me.id] = { pub: sid.pub, regId: sid.regId, wrapped: sid.wrapped };
    persistDB('signalIdentities');
  }
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Encrypted state backup. The client serializes its Signal ratchet state and
// message text history, encrypts it UNDER THE USER'S PASSWORD-DERIVED KEY, and
// stores the resulting opaque blob here so a phone that loses IndexedDB (iOS
// evicts storage aggressively) or a new device can restore and keep working.
// The server sees only ciphertext. Owner-gated; last-write-wins by timestamp.
// ---------------------------------------------------------------------------
const BACKUP_MAX_CHARS = 3_000_000; // ~3MB of wrapped JSON (text-only history)

app.post('/api/state-backup/get', keyLimiter, async (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const b = await backupsStore.get(me.id);
  res.json({ backup: b ? { wrapped: b.wrapped, ts: b.ts } : null });
});

app.post('/api/state-backup/set', keyLimiter, bigBody('4mb'), async (req, res) => {
  const { nodeId, wrapped, ts } = req.body || {};
  if (!isStr(nodeId, 128) || !isStr(wrapped, BACKUP_MAX_CHARS) || typeof ts !== 'number' || !Number.isFinite(ts) || ts < 0) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  // v72 M7: not while this account's password change commits (the app retries later).
  if (pwChangeBusy.has(req.accountId)) return res.status(409).json({ error: 'A password change is in progress. Try again in a moment.', code: 'busy' });
  const existing = await backupsStore.get(me.id);
  // v71 L4: a stamp can't be in the future (clamped to server time) — a far-future
  // ts from a stolen session would otherwise make every later backup "stale"
  // forever. The in-place re-encryption path echoes the stored (clamped) value.
  const tsC = Math.min(ts, Date.now());
  // Archived networks can't grow their backups — EXCEPT an in-place re-encryption
  // of the existing snapshot (same ts), which the password-KDF upgrade performs
  // (V8 H-3). That rewrite is owner-only ciphertext, so it is no relay channel.
  const inPlaceRewrap = !!(existing && existing.ts === tsC);
  if (isTreeArchived(me) && !inPlaceRewrap) return res.status(402).json({ error: 'This network is archived.' });
  if (existing && existing.ts > tsC) return res.json({ ok: true, stale: true }); // never regress to older state
  // v72 B4: growth counts toward the server-wide backup budget (a re-encryption in
  // place is never refused — a password change depends on it). Per account, backups
  // are already bounded: one per identity (≤ MAX_NODES_PER_ACCOUNT) × BACKUP_MAX_CHARS.
  const grow = wrapped.length - (existing ? String(existing.wrapped).length : 0);
  if (grow > 0 && !inPlaceRewrap && await budgetFull('backups', grow)) {
    return res.status(507).json({ error: 'This server’s backup storage is full right now. Try again later.', code: 'server-storage-full' });
  }
  await backupsStore.set(me.id, wrapped, tsC); // row-level write, no snapshot churn
  res.json({ ok: true });
});

// Panic-wipe support: remove the encrypted backup blob entirely.
app.post('/api/state-backup/delete', keyLimiter, async (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  await backupsStore.delete(me.id);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Encrypted attachment blobs (Signal-style out-of-band media).
//
// The client encrypts each media file with its own random key and uploads the
// ciphertext here as an opaque blob; the message itself only carries a small
// pointer + the key (which rides the E2E envelope, so the server never sees it).
// This keeps messages tiny and lets recipients fetch/decrypt media lazily.
// ---------------------------------------------------------------------------
const ATTACHMENT_MAX_BYTES = 12 * 1024 * 1024;          // 12 MB ciphertext per blob (free)
const ATTACHMENT_MAX_BYTES_PREMIUM = 20 * 1024 * 1024;  // 20 MB on a Premium network / hub
const attachMaxFor = (node) => (isTreePremium(node) ? ATTACHMENT_MAX_BYTES_PREMIUM : ATTACHMENT_MAX_BYTES);
// Media per identity, as advertised in the Free vs Premium panel: 300 MB free,
// 500 MB on a Premium network (or hub).
const ATTACHMENT_OWNER_QUOTA = parseInt(process.env.MAX_ATTACHMENT_BYTES_PER_NODE || String(300 * 1024 * 1024), 10);
const ATTACHMENT_OWNER_QUOTA_PREMIUM = parseInt(process.env.MAX_ATTACHMENT_BYTES_PER_NODE_PREMIUM || String(500 * 1024 * 1024), 10);
const mediaQuotaFor = (node) => (isTreePremium(node) ? ATTACHMENT_OWNER_QUOTA_PREMIUM : ATTACHMENT_OWNER_QUOTA);
// Server-wide storage ceilings. Per-account quotas are ceilings, not reservations —
// these keep their SUM within the disk the server actually has. v71 had one for
// media only, off by default; v72 B4 adds messages (incl. queued scheduled sends)
// and state backups, and turns all three on with defaults sized for a ~58 GB disk
// (8 + 32 + 4 GB, leaving room for Postgres itself). Set them for your disk, in
// bytes; 0 = no limit. Totals are re-read at most once a minute and counted up on
// every accepted write in between.
const envBytes = (name, def) => { const v = process.env[name]; return v === undefined || v === '' ? def : (parseInt(v, 10) || 0); };
const GiB = 1024 ** 3;
const STORAGE_BUDGETS = {
  messages: { max: envBytes('MAX_MESSAGE_BYTES_TOTAL', 8 * GiB), read: () => messagesStore.totalBytes() },
  attachments: { max: envBytes('MAX_ATTACHMENT_BYTES_TOTAL', 32 * GiB), read: () => attachmentsStore.totalBytes() },
  backups: { max: envBytes('MAX_BACKUP_BYTES_TOTAL', 4 * GiB), read: () => backupsStore.totalBytes() },
};
const _budgetUsed = new Map();
/** Would storing `bytes` more exceed this server-wide budget? If not, counts them in. */
const budgetFull = async (kind, bytes) => {
  const b = STORAGE_BUDGETS[kind];
  if (!b.max) return false;
  let u = _budgetUsed.get(kind);
  if (!u || Date.now() - u.at > 60 * 1000) { u = { n: Number(await b.read()) || 0, at: Date.now(), logged: u ? u.logged : 0 }; _budgetUsed.set(kind, u); }
  if (u.n + bytes > b.max) {
    if (Date.now() - u.logged > 60 * 1000) { u.logged = Date.now(); console.error(`[storage] server-wide ${kind} budget reached (${b.max} bytes) — refusing new ${kind}`); }
    return true;
  }
  u.n += bytes;
  return false;
};
const STORAGE_FULL_MESSAGES = { error: 'This server’s message storage is full right now. Try again later.', code: 'server-storage-full' };
const ATTACHMENT_ACCOUNT_QUOTA = parseInt(process.env.MAX_ATTACHMENT_BYTES_PER_ACCOUNT || String(2 * 1024 * 1024 * 1024), 10); // v71 L1: 2 GB per account
const attachmentUpLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
const attachmentDownLimiter = rateLimit({ windowMs: 60 * 1000, max: 600, standardHeaders: true, legacyHeaders: false });

// v72 B4: refuse an oversized upload from its Content-Length BEFORE the body (up to
// 28 MB of JSON) is buffered and parsed, and cap the uploads one account can have in
// flight at once. The exact per-node limit is still checked after parsing.
const UPLOADS_IN_FLIGHT_MAX = parseInt(process.env.MAX_UPLOADS_IN_FLIGHT_PER_ACCOUNT || '3', 10);
const uploadsInFlight = new Map();
const attachmentPreflight = (req, res, next) => {
  const mine = dbCache.users.filter(u => u.accountId === req.accountId);
  const max = mine.some(n => attachMaxFor(n) === ATTACHMENT_MAX_BYTES_PREMIUM) ? ATTACHMENT_MAX_BYTES_PREMIUM : ATTACHMENT_MAX_BYTES;
  const len = parseInt(req.headers['content-length'] || '', 10);
  if (!Number.isFinite(len)) return res.status(411).json({ error: 'Length required' });
  if (len > Math.ceil(max * 4 / 3) + 4096) return res.status(413).json({ error: 'Attachment too large', max });
  const n = uploadsInFlight.get(req.accountId) || 0;
  if (n >= UPLOADS_IN_FLIGHT_MAX) return res.status(429).json({ error: 'Too many uploads at once — wait for the others to finish.' });
  uploadsInFlight.set(req.accountId, n + 1);
  let released = false;
  const release = () => {
    if (released) return; released = true;
    const c = (uploadsInFlight.get(req.accountId) || 1) - 1;
    if (c > 0) uploadsInFlight.set(req.accountId, c); else uploadsInFlight.delete(req.accountId);
  };
  res.on('finish', release); res.on('close', release);
  next();
};

// Upload: body is { nodeId, data (base64 ciphertext), expiresAt? }. Returns { id }.
app.post('/api/attachments', attachmentUpLimiter, attachmentPreflight, bigBody('28mb'), async (req, res) => {
  const { nodeId, data, expiresAt, scope } = req.body || {};
  if (!isStr(nodeId, 128) || !isB64(data, Math.ceil(ATTACHMENT_MAX_BYTES_PREMIUM * 4 / 3) + 16)) return bad(res, 'Invalid input');
  if (scope !== undefined && scope !== 'global' && scope !== 'main') return bad(res, 'Invalid scope');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (me.pending) return res.status(403).json({ error: 'Awaiting approval' });
  // Archived trees can't send messages, so they must not be able to park new
  // blobs either — uploads would otherwise be a free storage/relay channel
  // while the subscription is unpaid.
  if (isTreeArchived(me)) return res.status(402).json({ error: 'This network is archived — its subscription lapsed.' });
  let bytes;
  try { bytes = Buffer.from(data, 'base64'); } catch { return bad(res, 'Bad data'); }
  if (!bytes.length || bytes.length > attachMaxFor(me)) return res.status(413).json({ error: 'Attachment too large', max: attachMaxFor(me) });
  if ((await attachmentsStore.ownerBytes(me.id)) + bytes.length > mediaQuotaFor(me)) {
    return res.status(413).json({ error: 'Storage quota exceeded' });
  }
  if ((await attachmentsStore.ownersBytes(accountNodeIds(req.accountId))) + bytes.length > ATTACHMENT_ACCOUNT_QUOTA) {
    return res.status(413).json({ error: 'Storage quota exceeded' });
  }
  if (await budgetFull('attachments', bytes.length)) {
    return res.status(507).json({ error: 'This server’s media storage is full right now. Try again later, or send text.', code: 'server-storage-full' });
  }
  const id = getPublicId(uuid('a_')); // opaque, unguessable id
  // v71 L1: every blob expires — at the time the sender chose, but never later
  // than the message retention window (media outliving its message is dead weight).
  const retDaysFor = retentionDaysFor(me);
  const maxExp = retDaysFor > 0 ? Date.now() + retDaysFor * 864e5 : null;
  let exp = (typeof expiresAt === 'number' && expiresAt > Date.now()) ? expiresAt : null;
  if (maxExp && (!exp || exp > maxExp)) exp = maxExp;
  // v72 M2: a blob for a global-chat message (only while global chat is on).
  if (scope === 'global' && !globalChatOn(me)) return res.status(403).json({ error: 'Global chat is not enabled for this network.' });
  // A blob for a main Descendants/Ancestors chat message: downloadable by the
  // uploader's direct siblings too (mainChatPeers). The content key never leaves
  // the sealed message, so this only widens who may fetch the ciphertext.
  await attachmentsStore.insert(id, me.id, bytes, exp, scope === 'global' ? 'global' : scope === 'main' ? 'main' : null);
  res.json({ id });
});

// Download: any authenticated account in the same tree may fetch a blob by id.
// The id is an unguessable HMAC and the bytes are ciphertext the fetcher can
// only decrypt with the key from the (E2E) message — so this is safe. We also
// gate to same-tree to avoid cross-tree blob probing.
app.get('/api/attachments/:id', attachmentDownLimiter, async (req, res) => {
  const id = req.params.id;
  if (!isStr(id, 128)) return bad(res, 'Invalid id');
  const requesterNodes = dbCache.users.filter(u => u.accountId === req.accountId && !u.pending);
  if (!requesterNodes.length) return res.status(403).json({ error: 'No node' });
  const row = await attachmentsStore.get(id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  // Enforce the same-tree gate (the id being unguessable is defence-in-depth,
  // not the access control). Owner-deleted nodes leave orphan blobs readable by
  // nobody — the owner sweep removes them anyway.
  const owner = dbCache.users.find(u => u.id === row.ownerId);
  // v72 M2: across a compartment wall only a GLOBAL-chat blob, and only while global chat is on.
  const mayRead = (n) => relatedNodes(n, owner) && (!compartmentBlocked(n, owner) || (row.scope === 'global' && globalPeers(n, owner)) || (row.scope === 'main' && mainChatPeers(n, owner)));
  if (!owner || !requesterNodes.some(mayRead)) {
    return res.status(404).json({ error: 'Not found' }); // indistinguishable from absent
  }
  if (row.expiresAt && row.expiresAt <= Date.now()) return res.status(404).json({ error: 'Expired' });
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Cache-Control', 'private, max-age=31536000, immutable'); // ciphertext is immutable; cache hard
  res.send(row.bytes);
});

// ---------------------------------------------------------------------------
// Encrypted call signaling relay. The payload (SDP offers/answers, ICE
// candidates, ring/hangup control) is sealed CLIENT-SIDE through the callers'
// pairwise Signal ratchet sessions before it ever reaches us — the server
// relays opaque {kt,kb} blobs it cannot read, so it cannot tamper with the
// DTLS fingerprints inside the SDP (that is what makes the calls end-to-end:
// media is DTLS-SRTP keyed off fingerprints exchanged over the ratchet).
// Ephemeral: nothing is stored. Relaying is gated to same-tree members.
// ---------------------------------------------------------------------------
const rtcLimiter = rateLimit({ windowMs: 60 * 1000, max: 600, standardHeaders: true, legacyHeaders: false }); // ICE bursts are chatty

// In-memory buffer of undelivered/unanswered rings (TTL 40s — matches the ring
// timeout). SSE is ephemeral: if the callee's app was closed when the ring was
// relayed, tapping the push notification used to open the app into... nothing.
// Now the app fetches pending rings on open/wake and lands straight in the call.
let rtcSeq = 0;
const rtcBuffer = []; // { accountId, at, ev } — every relayed signal, 90s TTL
// Memory bounds: without these, one hostile client at the rate limit could park
// ~225MB of sealed blobs in RAM (600/min x 256KB x 90s). Oldest entries drop
// first — live SSE delivery is unaffected; only the replay buffer is bounded.
const RTC_BUF_MAX_PER_ACCOUNT = 200;
const RTC_BUF_MAX_TOTAL = 2000;
const sweepRtc = () => { const cut = Date.now() - 90000; while (rtcBuffer.length && rtcBuffer[0].at < cut) rtcBuffer.shift(); };
const pushRtc = (entry) => {
  rtcBuffer.push(entry);
  let mine = 0;
  for (const e of rtcBuffer) if (e.accountId === entry.accountId) mine++;
  if (mine > RTC_BUF_MAX_PER_ACCOUNT) {
    const i = rtcBuffer.findIndex(e => e.accountId === entry.accountId);
    if (i >= 0) rtcBuffer.splice(i, 1);
  }
  while (rtcBuffer.length > RTC_BUF_MAX_TOTAL) rtcBuffer.shift();
};

// ICE server config. STUN alone fails on symmetric-NAT/carrier-CGNAT networks
// (most phones on cellular), so a TURN relay is included. TURN only forwards
// already-encrypted DTLS-SRTP packets — it cannot read or alter call media, so
// end-to-end encryption is fully preserved. Operators can (and should, for
// reliability) supply their own relay via env: TURN_URL, TURN_USERNAME,
// TURN_CREDENTIAL. Without env config a free public relay (OpenRelay) is used
// as a best-effort fallback.
// V8 L-3: TURN credentials. With TURN_SECRET set (coturn `use-auth-secret`),
// every response mints a fresh short-lived credential — username
// "<unix-expiry>:<random>", password base64(HMAC-SHA1(secret, username)) — so a
// credential lifted from any client expires by itself (TURN_TTL_SEC, default 2h).
// The legacy static TURN_USERNAME/TURN_CREDENTIAL still works but is flagged at
// boot. The endpoint is rate-limited per account (it only needs calling per call).
const TURN_TTL_SEC = parseInt(process.env.TURN_TTL_SEC || '7200', 10);
const turnCredentials = () => {
  const secret = process.env.TURN_SECRET;
  if (secret) {
    const username = `${Math.floor(Date.now() / 1000) + TURN_TTL_SEC}:${crypto.randomBytes(8).toString('hex')}`;
    return { username, credential: crypto.createHmac('sha1', secret).update(username).digest('base64'), ttl: TURN_TTL_SEC };
  }
  return { username: process.env.TURN_USERNAME || '', credential: process.env.TURN_CREDENTIAL || '' };
};
const rtcConfigLimiter = accountLimiter(60 * 1000, 30);
app.get('/api/rtc/config', rtcConfigLimiter, (req, res) => {
  // STUN is configurable so an operator isn't forced onto a third party. The
  // default public Google STUN servers see the caller's reflexive (public) IP;
  // set STUN_URLS (comma-separated, e.g. your own coturn) for a call path that
  // reveals IPs to nobody outside your own infrastructure.
  const stunUrls = process.env.STUN_URLS
    ? process.env.STUN_URLS.split(',').map(u => u.trim()).filter(Boolean)
    : [
      'stun:stun.l.google.com:19302',
      'stun:stun1.l.google.com:19302',
      'stun:stun2.l.google.com:19302',
      'stun:stun3.l.google.com:19302',
      'stun:stun4.l.google.com:19302',
    ];
  const iceServers = [{ urls: stunUrls }];
  if (process.env.TURN_URL) {
    // Operator-provided relay (recommended). A self-hosted coturn keeps relayed
    // call traffic — and the IP exposure a relay inherently sees — in-house.
    const tc = turnCredentials();
    iceServers.push({
      urls: process.env.TURN_URL.split(',').map(u => u.trim()).filter(Boolean),
      username: tc.username,
      credential: tc.credential,
    });
    if (tc.ttl) res.setHeader('X-Arbor-Ice-Ttl', String(tc.ttl));
  } else if (process.env.ALLOW_PUBLIC_TURN === '1') {
    // Third-party free relay — OPT-IN ONLY. A TURN relay necessarily sees both
    // parties' IP addresses (it cannot read the DTLS-SRTP media, but the IP
    // exposure to that third party is real). This used to be the silent default;
    // it now requires ALLOW_PUBLIC_TURN=1 so IP exposure to an outside relay is
    // never enabled without an explicit choice. Prefer TURN_* (self-hosted).
    iceServers.push({
      urls: [
        'turn:openrelay.metered.ca:80',
        'turn:openrelay.metered.ca:443',
        'turn:openrelay.metered.ca:443?transport=tcp',
        'turns:openrelay.metered.ca:443?transport=tcp',
      ],
      username: 'openrelayproject',
      credential: 'openrelayproject',
    });
  }
  // No TURN at all: calls still work on most networks via STUN; they may fail
  // only on symmetric-NAT/CGNAT paths that require a relay. That's the private
  // default — configure TURN_* to fix reliability without a third party.
  res.json({ iceServers });
});

// v70 H8: rings are what wake a phone (push notification + ringing screen), so
// they get their own budget: per caller account → callee account, and per callee
// across all callers. Handshake signals (ICE etc.) stay on the chatty limiter.
const RING_PAIR_PER_MIN = 3, RING_PAIR_PER_10MIN = 10, RING_TARGET_PER_MIN = 20, RING_PUSH_TARGET_PER_MIN = 6;
const ringLog = new Map();               // key → timestamps (ms) of accepted rings
const ringHits = (key, windowMs) => { const cut = Date.now() - windowMs; return (ringLog.get(key) || []).filter(t => t > cut).length; };
const ringNote = (key) => { const a = (ringLog.get(key) || []).filter(t => t > Date.now() - 10 * 60 * 1000); a.push(Date.now()); ringLog.set(key, a); };
setInterval(() => { const cut = Date.now() - 10 * 60 * 1000; for (const [k, a] of ringLog) { const b = a.filter(t => t > cut); if (b.length) ringLog.set(k, b); else ringLog.delete(k); } }, 60 * 1000).unref();
const rtcAccountLimiter = accountLimiter(60 * 1000, 600);
const RTC_MAX_KB = 65536;                  // a sealed SDP is a few KB; 64 KB is ample
const CALL_TTL_MS = 6 * 60 * 60 * 1000;    // a call context lives 6 h after its last signal
const CALL_MAX_SIGNALS = 4000;             // ICE trickle + renegotiations, per call
const CALL_MAX_PARTIES = 12;
const MAX_OPEN_CALLS_PER_ACCOUNT = 20;
const calls = new Map();                   // callId -> { owner (account), parties: Set<pid>, at, n }
const sweepCalls = () => { const cut = Date.now() - CALL_TTL_MS; for (const [k, c] of calls) if (c.at < cut) calls.delete(k); };
setInterval(sweepCalls, 10 * 60 * 1000).unref();
const openCall = (callId, fromPid, toPid, accountId) => {
  let c = calls.get(callId);
  if (!c) {
    if ([...calls.values()].filter(x => x.owner === accountId).length >= MAX_OPEN_CALLS_PER_ACCOUNT) sweepCalls();
    if ([...calls.values()].filter(x => x.owner === accountId).length >= MAX_OPEN_CALLS_PER_ACCOUNT) return false;
    c = { owner: accountId, parties: new Set([fromPid]), at: Date.now(), n: 0 };
    calls.set(callId, c);
  } else if (!c.parties.has(fromPid)) return false;             // only someone already in the call rings more people
  if (!c.parties.has(toPid) && c.parties.size >= CALL_MAX_PARTIES) return false;
  c.parties.add(toPid); c.at = Date.now();
  return true;
};
const inCall = (callId, fromPid, toPid) => {
  const c = calls.get(callId);
  if (!c || !c.parties.has(fromPid) || !c.parties.has(toPid) || ++c.n > CALL_MAX_SIGNALS) return false;
  c.at = Date.now();
  return true;
};
app.post('/api/rtc/signal', rtcLimiter, rtcAccountLimiter, (req, res) => {
  const { fromNodeId, toNodeId, callId, kind, kt, kb } = req.body || {};
  if (!isStr(fromNodeId, 128) || !isStr(toNodeId, 128) || !isStr(callId, 64)) return bad(res, 'Invalid call ids');
  if (!['ring', 'accept', 'offer', 'answer', 'ice', 'decline', 'hangup'].includes(kind)) return bad(res, 'Invalid signal kind');
  const me = ownNodeOr403(req, res, fromNodeId);
  if (!me) return;
  if (isTreeArchived(me)) return res.status(402).json({ error: 'This network is archived — calls are suspended until the subscription is renewed.' });
  const targetInternal = resolveInternalId(toNodeId);
  const target = targetInternal && dbCache.users.find(u => u.id === targetInternal);
  if (!target || !relatedNodes(me, target) || compartmentBlocked(me, target)) return res.status(404).json({ error: 'Unknown recipient' });
  if (me.pending || target.pending) return res.status(404).json({ error: 'Unknown recipient' }); // join requests can't call/be called
  // decline/hangup carry no SDP; everything else — rings included (v70 H8: the
  // caller seals the participant list into every ring) — carries a sealed blob.
  if (kind !== 'decline' && kind !== 'hangup') {
    if (typeof kt !== 'number' || !isB64(kb, RTC_MAX_KB)) return bad(res, 'Missing sealed payload');
  }
  const fromPid = getPublicId(me.id), toPid = getPublicId(target.id);   // parties are always public ids
  if (kind === 'ring') {
    if (!openCall(callId, fromPid, toPid, req.accountId)) return res.status(409).json({ error: 'That call can’t be joined.' });
  } else if (!inCall(callId, fromPid, toPid)) {
    // Ending a call that isn't open is harmless — acknowledge it, relay nothing.
    if (kind === 'hangup' || kind === 'decline') return res.json({ ok: true, relayed: false });
    return res.status(404).json({ error: 'No such call' });
  }
  let pushRing = false;
  if (kind === 'ring') {
    const pair = 'p:' + req.accountId + '>' + target.accountId, tgt = 't:' + target.accountId, pushKey = 'n:' + target.accountId;
    if (ringHits(pair, 60 * 1000) >= RING_PAIR_PER_MIN || ringHits(pair, 10 * 60 * 1000) >= RING_PAIR_PER_10MIN || ringHits(tgt, 60 * 1000) >= RING_TARGET_PER_MIN) {
      return res.status(429).json({ error: 'Too many calls to this person — try again in a few minutes.' });
    }
    ringNote(pair); ringNote(tgt);
    if (ringHits(pushKey, 60 * 1000) < RING_PUSH_TARGET_PER_MIN) { ringNote(pushKey); pushRing = true; }
  }
  const ev = {
    type: 'RTC', callId, kind, sid: ++rtcSeq,
    from: getPublicId(me.id),
    to: toNodeId, kt: kt ?? null, kb: kb ?? null, ts: Date.now(),
  };
  notifyPayload(new Set([target.accountId]), ev);
  sweepRtc();
  // Buffer EVERY signal (not just rings): SSE is best-effort, and losing a single
  // accept/offer/answer/ice mid-handshake used to strand the call at "connecting".
  // Clients poll /api/rtc/pending during call setup and dedupe by sid.
  pushRtc({ accountId: target.accountId, at: Date.now(), ev });
  if (pushRing) {
    // Typed push so the service worker renders a call-style notification; the
    // metadata here (name, callId) is what the server already knows — the SDP
    // stays sealed.
    sendPushToAccount(target.accountId, 'Incoming encrypted call', "You have an incoming call on Arbor", { kind: 'call', callId });
  }
  res.json({ ok: true });
});

// Pending (still-ringing) calls for this account — fetched by the app on
// open/wake so a tapped notification lands in the ringing call.
const rtcPendingLimiter = accountLimiter(60 * 1000, 120);
app.get('/api/rtc/pending', rtcPendingLimiter, (req, res) => {
  sweepRtc();
  const mine = rtcBuffer.filter(p => p.accountId === req.accountId).map(p => p.ev);
  // signals = everything (ordered, with sids for client-side dedupe);
  // rings kept for backwards compatibility with older clients.
  res.json({ signals: mine, rings: mine.filter(e => e.kind === 'ring') });
});

// Read receipts: ephemeral, content-free (message ids are random UUIDs — they
// reveal nothing the server doesn't already see as delivery metadata). Relayed
// only to the original sender's account; nothing persisted server-side.
const receiptLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
app.post('/api/receipt', receiptLimiter, async (req, res) => {
  const { nodeId, toNodeId, mids } = req.body || {};
  if (!isStr(nodeId, 128) || !isStr(toNodeId, 128)) return bad(res, 'Invalid input');
  if (!Array.isArray(mids) || mids.length === 0 || mids.length > 100 || !mids.every(m => isStr(m, 64))) return bad(res, 'Invalid mids');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  // Archived: messaging is suspended, and that includes every user-to-user relay.
  // Receipts carry an array of caller-chosen strings (up to 100 x 64 chars per
  // call) — left open, that's a functioning covert messaging channel around the
  // paywall. Silent no-op (receipts are best-effort by design).
  if (isTreeArchived(me)) return res.json({ ok: true });
  const targetInternal = resolveInternalId(toNodeId);
  const target = targetInternal && dbCache.users.find(u => u.id === targetInternal);
  if (!target || !relatedNodes(me, target) || compartmentBlocked(me, target)) return res.status(404).json({ error: 'Unknown recipient' });
  if (me.pending || target.pending) return res.status(404).json({ error: 'Unknown recipient' }); // V8 M-15: same rule as typing/rtc
  // Reciprocal read receipts: delivered only when BOTH sides have them on.
  const readerAcc = accountById(req.accountId);
  const senderAcc = accountById(target.accountId);
  if (readerAcc?.settings?.readReceipts !== false && senderAcc?.settings?.readReceipts !== false) {
    // v71 L6: only messages the target SENT and this node RECEIVED can be marked
    // read — anyone related could otherwise mark any of the target's messages read.
    const myPid = getPublicId(me.id);
    const ok = [];
    for (const mid of new Set(mids)) {
      if (!isMid(mid)) continue;
      const row = await messagesStore.byMid(mid);
      if (row && row.senderId === target.id && (await messagesStore.isRecipient(row.id, myPid))) ok.push(mid);
    }
    if (ok.length) notifyPayload(new Set([target.accountId]), { type: 'RECEIPT', from: myPid, to: toNodeId, mids: ok, ts: Date.now() });
  }
  res.json({ ok: true });
});

const msgLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });

app.post('/api/messages', msgLimiter, bigBody('6mb'), async (req, res) => {
  const { nodeId, envelope: rawEnvelope, type, targets, targetCircle, ackRequested, targetGroup, mentions } = req.body || {};
  if (!isStr(nodeId, 128) || !['PEER', 'BROADCAST', 'GLOBAL'].includes(type)) return bad(res, 'Invalid input');
  if (isObj(rawEnvelope) && typeof rawEnvelope.ct === 'string' && rawEnvelope.ct.length > MSG_MAX_CT_CHARS) return res.status(413).json({ error: 'Message too large. Photos and videos are sent as attachments.' });
  const envelope = cleanEnvelope(rawEnvelope);   // v71 H1: known fields only, bounded
  if (!envelope) return bad(res, 'Invalid envelope');
  if (targetCircle !== undefined && !['UP', 'DOWN'].includes(targetCircle)) return bad(res, 'Invalid targetCircle');
  if (targetGroup !== undefined && targetGroup !== null && (!isStr(targetGroup, 64) || !isSafeKey(targetGroup))) return bad(res, 'Invalid targetGroup');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (me.pending) return res.status(403).json({ error: 'Awaiting approval' });
  if (type === 'BROADCAST' && !canAnnounce(me)) return res.status(403).json({ error: 'You have not been granted announcement rights.' });
  if (type === 'GLOBAL' && !globalChatOn(me)) return res.status(403).json({ error: 'Global chat is not enabled for this network.' });
  if (isTreeArchived(me)) return res.status(402).json({ error: 'This network is archived — its subscription lapsed. The network root can restore it from the Network Plan panel.' });

  // Envelope mids must be globally unique. Client mids are 128-bit random, so a
  // collision only ever happens on purpose — reusing another message's mid would
  // let a sender hijack/poison its acknowledgment entry (acks are keyed by mid)
  // or replay envelopes. Indexed lookup; rejecting is the correct behaviour.
  if (await messagesStore.byMid(envelope.mid)) return res.status(409).json({ error: 'Duplicate message id' });

  const allowedUsers = usersWhoCanRead(me, type, targetCircle, dbCache.users, resolveTargets(targets), targetGroup || null);
  const allowed = new Map(allowedUsers.map(u => [getPublicId(u.id), u]));
  const recips = envelope.recips.map(r => r.id);
  if (!recips.length || recips.some(id => !allowed.has(id))) return res.status(403).json({ error: 'Recipient set not permitted' });

  // TTL is taken from the SIGNED envelope (envelope.exp), so a server cannot extend
  // a message's lifetime without breaking the signature the recipient verifies.
  const expiresAt = typeof envelope.exp === 'number' ? envelope.exp : null;

  // v71 H1: per-account storage quota (every stored byte counts against the sender).
  if (await messageQuotaExceeded(req.accountId, envelopeBytes(envelope))) return res.status(413).json(QUOTA_413);
  if (await budgetFull('messages', envelopeBytes(envelope))) return res.status(507).json(STORAGE_FULL_MESSAGES);

  const message = {
    id: uuid('m_'), senderId: me.id, envelope, recipients: recips, timestamp: Date.now(),
    expiresAt, type, depthLimit: null, targetCircle: targetCircle || null,
    targetGroup: targetGroup || null, // group/link scope, so recipients can file it in the right chat
    ackRequested: ackRequested === true,
  };
  await messagesStore.insert(message); // row-level write; nothing else is rewritten

  const recipUsers = recips.map(id => allowed.get(id));   // resolved above — no per-user HMAC scan
  const recipAccounts = accountsForUsers(recipUsers);
  notify(recipAccounts);
  // Mention-aware push. The client resolves @alias / @group to the specific
  // recipient public ids they touch (constrained to the recipient set) and sends
  // them as { users, viaGroup }. We only see these opaque ids — never the text —
  // and use them with each recipient account's notifyPref to decide whether to
  // ping: 'all' = every message; 'mentions' = only if @-mentioned directly or via
  // a group; 'alias' = only a direct @alias. (Metadata note: this does reveal to
  // the server WHICH recipients a message mentioned — the minimum needed to route
  // push while the app is closed; message content stays end-to-end encrypted.)
  const recipSet = new Set(recips);
  const cap = (arr) => Array.isArray(arr) ? arr.filter(x => typeof x === 'string' && recipSet.has(x)).slice(0, 500) : [];
  const mUsers = new Set(cap(mentions && mentions.users));
  const mGroup = new Set(cap(mentions && mentions.viaGroup));
  for (const accId of recipAccounts) {
    if (accId === req.accountId) continue;
    const acc = accountById(accId);
    const pref = (acc && acc.settings && acc.settings.notifyPref) || 'all';
    if (pref === 'all') { pushMessageTo(accId, 'Incoming Signal', 'New secure transmission.'); continue; }
    const myNodePids = recipUsers.filter(u => u.accountId === accId).map(u => getPublicId(u.id));
    const direct = myNodePids.some(pid => mUsers.has(pid));
    const viaGrp = myNodePids.some(pid => mGroup.has(pid));
    if ((pref === 'alias' && direct) || (pref === 'mentions' && (direct || viaGrp))) {
      pushMessageTo(accId, 'You were mentioned', 'You were mentioned in a secure message.');
    }
  }

  res.json({ id: message.id });
});

// Delete-for-everyone: only the original sender may retract. The message is
// removed server-side and its recipients are notified to drop it locally. We
// keep a short-lived tombstone so a recipient who is briefly offline still
// learns the message was retracted on their next sync.
const deleteLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
// Acknowledge a broadcast: recipient taps "Acknowledge"; the sender sees who.
const ackLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
app.post('/api/messages/ack', ackLimiter, async (req, res) => {
  const { nodeId, mid } = req.body || {};
  if (!isStr(nodeId, 128) || !isMid(mid)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (isTreeArchived(me)) return res.status(402).json({ error: 'This network is archived — its subscription lapsed.' });
  const row = await messagesStore.byMid(mid);
  if (!row || !row.ackRequested) return res.status(404).json({ error: 'No such message' });
  const myPublicId = getPublicId(me.id);
  if (!(await messagesStore.isRecipient(row.id, myPublicId))) return res.status(403).json({ error: 'Not a recipient' });
  let ack;
  try { ack = await metaStore.addAck(mid, myPublicId); }
  catch { return res.status(404).json({ error: 'No such message' }); }   // deleted meanwhile (foreign key)
  if (ack.added) {
    const sender = dbCache.users.find(u => u.id === row.senderId);
    if (sender) notify(new Set([sender.accountId]));
  }
  res.json({ ok: true, count: ack.count });
});

// React to a message with an emoji (toggle). Reactions are lightweight metadata
// (a single emoji + who), relayed live over SSE and persisted so offline
// recipients pick them up on next sync. Only actual recipients (or the sender)
// of the message may react, and only supported emoji are accepted.
const REACTION_SET = ['👍', '❤️', '😂', '😮', '😢', '🙏', '🔥', '✅'];
const reactionLimiter = rateLimit({ windowMs: 60 * 1000, max: 240, standardHeaders: true, legacyHeaders: false });
app.post('/api/messages/react', reactionLimiter, async (req, res) => {
  const { nodeId, mid, emoji } = req.body || {};
  if (!isStr(nodeId, 128) || !isMid(mid) || !REACTION_SET.includes(emoji)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (isTreeArchived(me)) return res.status(402).json({ error: 'This network is archived.' });
  const row = await messagesStore.byMid(mid);
  if (!row) return res.status(404).json({ error: 'No such message' });
  const myPublicId = getPublicId(me.id);
  const isSenderOrRecipient = row.senderId === me.id || (await messagesStore.isRecipient(row.id, myPublicId));
  if (!isSenderOrRecipient) return res.status(403).json({ error: 'Not part of this conversation' });

  // Toggle: a person holds at most one of each emoji; tapping again removes it.
  // v72 B4: stored in the reactions table (a row per person and emoji).
  let forMid;
  try { forMid = await metaStore.toggleReaction(mid, emoji, myPublicId); }
  catch { return res.status(404).json({ error: 'No such message' }); }   // deleted meanwhile (foreign key)
  // The message's audience (sender + recipients, public ids) for the live event
  // (v70 read row.recipients, which rows never carry, so only the reactor and the
  // sender were notified).
  const audPids = [getPublicId(row.senderId), ...(await messagesStore.recipientsOf(row.id))];

  // Notify everyone in the message's audience (recipients + sender).
  const audience = new Set([req.accountId]);
  for (const pid of audPids) { const id = resolveInternalId(pid); const u = id && dbCache.users.find(x => x.id === id); if (u) audience.add(u.accountId); }
  notifyPayload(audience, { type: 'REACTION', mid, reactions: forMid, ts: Date.now() });
  res.json({ ok: true, reactions: forMid });
});

// ---------------------------------------------------------------------------
// Scheduled messages (server-side release, E2E-preserving). The CLIENT seals
// the envelope at schedule time exactly like a normal send — the server only
// ever holds ciphertext plus a fire time, and relays it through the ordinary
// message path when the time arrives. This works with the sender's device off.
// The recipient set is validated at SCHEDULE time and REVALIDATED at fire time,
// so someone pruned from the tree in between never receives the message.
// ---------------------------------------------------------------------------
const SCHEDULE_MAX_AHEAD_MS = 30 * 864e5;   // 30 days
const scheduleLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
// V8 M-13: scheduled envelopes get hard caps (v72 B4: stored in the scheduled
// table, not RAM; their bytes also count toward the message quota). Scheduled sends are TEXT only (the client never attaches
// media to them), so a padded text envelope is well under 256 KB of ciphertext.
const SCHEDULE_MAX_CT_CHARS = 256 * 1024;
const SCHEDULE_MAX_PER_NODE = 50;
const SCHEDULE_MAX_BYTES_PER_ACCOUNT = 4 * 1024 * 1024;
const scheduleAccountLimiter = accountLimiter(60 * 60 * 1000, 120);
const envelopeBytes = (e) => { try { return JSON.stringify(e).length; } catch { return Infinity; } };

app.post('/api/messages/schedule', scheduleLimiter, scheduleAccountLimiter, bigBody('6mb'), async (req, res) => {
  const { nodeId, envelope: rawEnvelope, type, targetCircle, ackRequested, fireAt, targetGroup } = req.body || {};
  if (!isStr(nodeId, 128) || !['PEER', 'BROADCAST'].includes(type)) return bad(res, 'Invalid input');
  if (isObj(rawEnvelope) && typeof rawEnvelope.ct === 'string' && rawEnvelope.ct.length > SCHEDULE_MAX_CT_CHARS) return res.status(413).json({ error: 'Scheduled messages are text only.' });
  const envelope = cleanEnvelope(rawEnvelope, SCHEDULE_MAX_CT_CHARS);   // v71: known fields only, bounded
  if (!envelope) return bad(res, 'Invalid envelope');
  if (targetCircle !== undefined && !['UP', 'DOWN'].includes(targetCircle)) return bad(res, 'Invalid targetCircle');
  if (targetGroup !== undefined && targetGroup !== null && (!isStr(targetGroup, 64) || !isSafeKey(targetGroup))) return bad(res, 'Invalid targetGroup');
  if (typeof fireAt !== 'number' || fireAt < Date.now() + 30_000 || fireAt > Date.now() + SCHEDULE_MAX_AHEAD_MS) {
    return bad(res, 'fireAt must be between 1 minute and 30 days from now.');
  }
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (me.pending) return res.status(403).json({ error: 'Awaiting approval' });
  if (type === 'BROADCAST' && !canAnnounce(me)) return res.status(403).json({ error: 'You have not been granted announcement rights.' });
  if (isTreeArchived(me)) return res.status(402).json({ error: 'This network is archived.' });
  // mid must be unique across delivered AND pending messages (same replay/hijack
  // reasoning as the live-send path).
  if (await messagesStore.byMid(envelope.mid)) return res.status(409).json({ error: 'Duplicate message id' });
  if (await scheduledStore.hasMid(envelope.mid)) return res.status(409).json({ error: 'Duplicate message id' });
  // Per-node count + per-account byte caps (V8 M-13).
  if ((await scheduledStore.countForNode(me.id)) >= SCHEDULE_MAX_PER_NODE) {
    return res.status(429).json({ error: `You can have at most ${SCHEDULE_MAX_PER_NODE} scheduled messages queued.` });
  }
  const myBytes = await scheduledStore.bytesForNodes(accountNodeIds(req.accountId));
  if (myBytes + envelopeBytes(envelope) > SCHEDULE_MAX_BYTES_PER_ACCOUNT) {
    return res.status(413).json({ error: 'Scheduled-message storage limit reached — cancel some queued messages first.' });
  }
  if (await messageQuotaExceeded(req.accountId, envelopeBytes(envelope))) return res.status(413).json(QUOTA_413);
  // Same recipient-set gate as a live send (incl. its group scope), evaluated
  // now and again at fire time.
  const allowed = new Set(usersWhoCanRead(me, type, targetCircle, dbCache.users, null, targetGroup || null).map(u => getPublicId(u.id)));
  const recips = envelope.recips.map(r => r && r.id).filter(Boolean);
  if (!recips.length || recips.some(id => !allowed.has(id))) return res.status(403).json({ error: 'Recipient set not permitted' });
  if (await budgetFull('messages', envelopeBytes(envelope))) return res.status(507).json(STORAGE_FULL_MESSAGES);

  const entry = {
    id: uuid('sch_'), nodeId: me.id, fireAt, createdAt: Date.now(),
    type, targetCircle: targetCircle || null, targetGroup: targetGroup || null, ackRequested: ackRequested === true, envelope,
  };
  if (!(await scheduledStore.add({ ...entry, size: envelopeBytes(envelope) }))) return res.status(409).json({ error: 'Duplicate message id' });
  res.json({ id: entry.id, fireAt });
});

app.post('/api/messages/scheduled/list', async (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const mine = (await scheduledStore.listForNode(me.id))
    .map(x => ({ id: x.id, fireAt: x.fireAt, mid: x.envelope?.mid, type: x.type, createdAt: x.createdAt }));
  res.json({ scheduled: mine });
});

app.post('/api/messages/scheduled/cancel', async (req, res) => {
  const { nodeId, id } = req.body || {};
  if (!isStr(nodeId, 128) || !isStr(id, 64)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  await scheduledStore.cancel(id, me.id);
  res.json({ ok: true });
});

// Fire due scheduled envelopes. Runs frequently; each release goes through the
// SAME insert + notify path as a live send. Recipients are revalidated against
// the tree as it exists NOW — slots for people no longer allowed are stripped,
// and the whole message is dropped if nobody eligible remains.
// v72 B4: read from the scheduled table; each item is removed only AFTER its turn,
// so a crash mid-run fires it again on restart (the unique mid prevents a duplicate).
let firingScheduled = false;
const fireDueScheduled = async () => {
  if (!dbLoaded || firingScheduled) return;
  firingScheduled = true;
  try {
    const now = Date.now();
    for (const item of await scheduledStore.due(now)) {
      try { await fireScheduledItem(item, now); }
      catch (e) { console.error('[scheduled] fire failed:', e?.message || e); }
      try { await scheduledStore.remove(item.id); } catch (e) { console.error('[scheduled] remove failed:', e?.message || e); }
    }
  } catch (e) { console.error('[scheduled] run failed:', e?.message || e); }
  finally { firingScheduled = false; }
};
const fireScheduledItem = async (item, now) => {
  const sender = dbCache.users.find(u => u.id === item.nodeId);
  if (!sender || sender.pending) return;                       // sender pruned/gone
  if (item.type === 'BROADCAST' && !canAnnounce(sender)) return; // rights revoked
  if (isTreeArchived(sender)) return;
  if (await messagesStore.byMid(item.envelope.mid)) return;          // paranoia: no dup
  const allowed = new Set(usersWhoCanRead(sender, item.type, item.targetCircle || undefined, dbCache.users, null, item.targetGroup || null).map(u => getPublicId(u.id)));
  const liveRecips = item.envelope.recips.filter(r => r && allowed.has(r.id));
  if (!liveRecips.length) return;                              // audience dissolved
  const envelope = { ...item.envelope, recips: liveRecips };
  const message = {
    id: uuid('m_'), senderId: sender.id, envelope, recipients: liveRecips.map(r => r.id),
    timestamp: now, expiresAt: typeof envelope.exp === 'number' ? envelope.exp : null,
    type: item.type, depthLimit: null, targetCircle: item.targetCircle,
    targetGroup: item.targetGroup || null,
    ackRequested: !!item.ackRequested,
  };
  await messagesStore.insert(message);
  // v72 M8: resolve the recipients once (v71 hashed every user's id per recipient).
  const recipIds = new Set(message.recipients.map(pid => resolveInternalId(pid)).filter(Boolean));
  const recipUsers = dbCache.users.filter(u => recipIds.has(u.id));
  const recipAccounts = accountsForUsers(recipUsers);
  recipAccounts.add(sender.accountId); // sender's devices learn it fired
  notify(recipAccounts);
  for (const accId of recipAccounts) if (accId !== sender.accountId) pushMessageTo(accId, 'Incoming Signal', 'New secure transmission.');
};
setInterval(fireDueScheduled, 10 * 1000);

// Typing indicator: pure ephemeral relay, nothing stored. Tells the people in a
// 1:1 (or a circle) that this node is composing. The client sends 'start'
// heartbeats every few seconds and a 'stop' when idle/sent.
const typingLimiter = rateLimit({ windowMs: 10 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
app.post('/api/typing', typingLimiter, (req, res) => {
  const { nodeId, toNodeId, state } = req.body || {};
  if (!isStr(nodeId, 128) || !isStr(toNodeId, 128) || !['start', 'stop'].includes(state)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  if (isTreeArchived(me)) return res.status(402).json({ error: 'This network is archived.' });
  const targetInternal = resolveInternalId(toNodeId);
  const target = targetInternal && dbCache.users.find(u => u.id === targetInternal);
  if (!target || !relatedNodes(me, target) || compartmentBlocked(me, target)) return res.status(404).json({ error: 'Unknown recipient' });
  if (me.pending || target.pending) return res.status(404).json({ error: 'Unknown recipient' });
  notifyPayload(new Set([target.accountId]), {
    type: 'TYPING', from: getPublicId(me.id), state, ts: Date.now(),
  });
  res.json({ ok: true });
});

app.post('/api/messages/delete', deleteLimiter, async (req, res) => {
  const { nodeId, mids } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  if (!Array.isArray(mids) || mids.length === 0 || mids.length > 200 || !mids.every(isMid)) return bad(res, 'Invalid mids');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  // v72: retract() also writes the tombstones (one row per recipient, so /tree-context
  // replays it only to that message's recipients, V8 L-1); reactions and acks go
  // with the message.
  const { removed, recipientPublicIds } = await messagesStore.retract(mids, me.id);
  const affectedAccounts = new Set();
  for (const rid of recipientPublicIds) {
    const id = resolveInternalId(rid);
    const u = id && dbCache.users.find(x => x.id === id);
    if (u) affectedAccounts.add(u.accountId);
  }
  if (removed.length) {
    const now = Date.now();
    affectedAccounts.add(req.accountId);
    notifyPayload(affectedAccounts, { type: 'RETRACT', mids: removed, ts: now });
  }
  res.json({ ok: true, removed });
});

// V8 H-5 / M-17: /api/register was uncapped — one account minted 100 roots in 3s
// and queued unlimited pending join requests. Now: IP + account rate limits, a
// per-account node cap, a per-account network (root) cap, and pending-request caps.
const MAX_NODES_PER_ACCOUNT = parseInt(process.env.MAX_NODES_PER_ACCOUNT || '60', 10);
const MAX_ROOTS_PER_ACCOUNT = parseInt(process.env.MAX_ROOTS_PER_ACCOUNT || '10', 10);
const MAX_PENDING_PER_ACCOUNT = 5;
const registerIpLimiter = rateLimit({ windowMs: 60 * 1000, max: parseInt(process.env.REGISTER_IP_PER_MIN || '20', 10), standardHeaders: true, legacyHeaders: false });
const registerAccountLimiter = accountLimiter(60 * 60 * 1000, 30);
app.post('/api/register', registerIpLimiter, registerAccountLimiter, (req, res) => {
  const { inviteCode, treeMode, treeNameVisible, monitorEnabled, referralOpen, globalChat, color, wrappedKeys } = req.body || {};
  const encPub = cleanJwk(req.body && req.body.encPub), sigPub = cleanJwk(req.body && req.body.sigPub);   // v71 M4: exact shapes
  if (!encPub || !sigPub || !isStr(wrappedKeys, MAX_WRAPPED_KEYS)) return bad(res, 'Invalid input');
  // V8 phase 2 (M-8): the display name and network name are NOT sent here any
  // more. Right after registering, the app uploads them end-to-end encrypted
  // (POST /api/profile/set); the account default photo/bio are applied by the
  // app too, only when the person opts in for this network.
  // Optional user-chosen icon color; fall back to a random hue when absent/invalid.
  const chosenColor = isHexColor(color) ? color : null;
  const mine = dbCache.users.filter(u => u.accountId === req.accountId);
  const reusingHub = !inviteCode && treeMode === 'HUB' && !!accountHubRoot(req.accountId);
  if (!reusingHub && mine.length >= MAX_NODES_PER_ACCOUNT) {
    return res.status(429).json({ error: `An account can hold at most ${MAX_NODES_PER_ACCOUNT} identities.` });
  }
  if (!inviteCode && treeMode !== 'HUB' && mine.filter(u => !String(u.path).includes('/') && (u.treeMode || '') !== 'HUB').length >= MAX_ROOTS_PER_ACCOUNT) {
    return res.status(429).json({ error: `An account can own at most ${MAX_ROOTS_PER_ACCOUNT} networks.` });
  }

  if (!inviteCode) {
    // One personal hub per account: creating a "second" hub just hands back the
    // existing one (its keys are the stored wrapped blob, not the fresh pair the
    // client generated for this request — hence wrappedKeys + existing flag).
    if (treeMode === 'HUB') {
      const existing = accountHubRoot(req.accountId);
      if (existing) return res.json({ ...sanitizeUser(existing, existing), wrappedKeys: existing.wrappedKeys, existing: true });
    }
    const id = uuid('u_');
    const user = {
      id, accountId: req.accountId, invitedBy: null, role: 'ROOT', level: 0,
      color: chosenColor || (treeMode === 'HUB' ? `hsl(${Math.floor(Math.random() * 360)}, 70%, 50%)` : 'hsl(210, 70%, 50%)'),
      path: id,
      treeMode: ['DM', 'HUB'].includes(treeMode) ? treeMode : 'HIERARCHICAL',
      treeNameVisible: treeNameVisible === true,
      monitorEnabled: monitorEnabled !== false,
      // Referral mode is a Direct-Only-only switch: let members invite too, with
      // every joiner re-parented straight to the root (a flat referral star).
      ...(treeMode === 'DM' ? { referralOpen: referralOpen === true } : {}),
      // Global chat: a network-wide channel any member can use once the root turns it on.
      ...(globalChat === true ? { globalChat: true } : {}),
      encPub, sigPub, wrappedKeys, permissions: {},
    };
    dbCache.users.push(user);
    if (treeMode === 'HUB') bindAccountHubInvites(user); // pick up any parked "add to hub" requests
    persistDB();
    notify(new Set([req.accountId]));
    return res.json(sanitizeUser(user, user));
  }

  if (!isStr(inviteCode, 64)) return bad(res, 'Invalid invite');
  const code = inviteCode.trim().toUpperCase();
  const idx = dbCache.invites.findIndex(i => i.code === code && !i.isUsed && (!i.expiresAt || i.expiresAt > Date.now()));
  if (idx === -1) return res.status(400).json({ error: 'Invalid or expired invite code.' });
  const invite = dbCache.invites[idx];
  const inviter = dbCache.users.find(u => u.id === invite.inviterId);
  if (!inviter) return res.status(400).json({ error: 'Inviter no longer exists.' });

  // ---- Personal hub invites: no joining, no hierarchy — a CONTACT REQUEST ----
  // Opening someone's hub link connects your OWN personal hub to theirs as a
  // symmetric pair (each appears in the other's chats). You never become a
  // member of their space, and you can't invite anyone into it — you only ever
  // add contacts to your own hub.
  if ((inviter.treeMode || '') === 'HUB') {
    if (inviter.accountId === req.accountId) return res.status(400).json({ error: 'That\u2019s your own invite link.' });
    if (hubContactsOf(inviter.id, true).length >= 2000) return res.status(402).json({ error: 'This person\u2019s contact list is full.' });
    let mine = accountHubRoot(req.accountId);
    let reused = false;
    if (mine) {
      reused = true;
    } else {
      const id = uuid('u_');
      mine = {
        id, accountId: req.accountId,
        invitedBy: null, role: 'ROOT', level: 0,
        color: chosenColor || `hsl(${Math.floor(Math.random() * 360)}, 70%, 50%)`,
        path: id, treeMode: 'HUB',
        encPub, sigPub, wrappedKeys, permissions: {},
      };
      dbCache.users.push(mine);
      bindAccountHubInvites(mine); // this account just got its hub — pick up any parked "add to hub" requests
    }
    const already = hubEdgeBetween(inviter.id, mine.id);
    if (!already) {
      hubEdges().push({ a: inviter.id, b: mine.id, pending: true, requestedBy: mine.id, addedAt: Date.now() });
      if (!invite.permanent) dbCache.invites[idx].isUsed = true;
      sendPushToAccount(inviter.accountId, 'Arbor', 'You have a new contact request on Arbor');
    }
    persistDB();
    notify(new Set([inviter.accountId, req.accountId]));
    const out = sanitizeUser(mine, mine);
    // Reused hub: the client generated throwaway keys for this request — hand it
    // the REAL wrapped blob so it unlocks the existing identity instead.
    return res.json(reused ? { ...out, wrappedKeys: mine.wrappedKeys, existing: true } : out);
  }

  // DM trees are hub-and-spoke. Normally ONLY the root invites (enforced here at
  // join time too, not just at code creation, so a stale member-minted code can
  // never grow a chain the root never approved). When the root turns on Referral
  // mode, ANY member may invite — but every joiner is re-parented directly under
  // the root, a flat referral star: the root ends up 1:1 with everyone, and
  // because no one is parented under a member, members still never see or reach
  // each other. The root's OWN invites in this mode activate immediately; anyone
  // a member refers stays pending until the root approves.
  let parent = inviter;      // node the newcomer attaches under
  let referredBy = null;     // the actual referrer, when a member (not the root) shared the link
  let dmAutoJoin = false;    // skip the pending step (root's own invites in a referral tree)
  if ((inviter.treeMode || '') === 'DM') {
    const root = treeRootUser(inviter);
    const inviterIsRoot = !!(root && inviter.id === root.id);
    if (!inviterIsRoot && !(root && root.referralOpen)) {
      return res.status(403).json({ error: 'Only the owner can invite people here.' });
    }
    if (root && root.referralOpen) {
      parent = root;                                   // flatten every referral onto the root
      if (!inviterIsRoot) referredBy = inviter.id;     // remember who actually brought them in
      dmAutoJoin = inviterIsRoot;                      // the root's own invites need no self-approval
    }
  }
  const gateMsg = growthGate(parent);
  if (gateMsg) return res.status(402).json({ error: gateMsg });

  // Auto-accept: if the network root has turned it on, an invite join is activated
  // on arrival instead of queued for approval (dmAutoJoin already covers the root's
  // own referral-tree invites). Applies to both hierarchical and Direct-Only trees.
  const troot = treeRootUser(parent);
  const autoAccept = dmAutoJoin || !!(troot && troot.autoAcceptInvites);

  // V8 M-17: sybil join spam. One outstanding request per inviter per account,
  // a small global cap on outstanding requests, and a cap on how many identities
  // one account may hold inside a single network (with auto-accept on, junk
  // identities would otherwise burn the network's free-tier member budget).
  const rootIdOfParent = String(parent.path).split('/')[0];
  const mineHere = mine.filter(u => String(u.path) === rootIdOfParent || String(u.path).startsWith(rootIdOfParent + '/'));
  if (mineHere.length >= 3) return res.status(429).json({ error: 'You already have the maximum number of identities in this network.' });
  if (!autoAccept) {
    const myPending = mine.filter(u => u.pending);
    if (myPending.some(u => u.invitedBy === parent.id)) return res.status(409).json({ error: 'You already have a request waiting here.' });
    if (myPending.length >= MAX_PENDING_PER_ACCOUNT) return res.status(429).json({ error: 'You have too many join requests waiting for approval.' });
  }

  const id = uuid('u_');
  const user = {
    id, accountId: req.accountId, invitedBy: parent.id,
    role: 'MEMBER', level: parent.level + 1, color: chosenColor || `hsl(${Math.floor(Math.random() * 360)}, 70%, 50%)`,
    path: `${parent.path}/${id}`, treeMode: parent.treeMode || 'HIERARCHICAL',
    encPub, sigPub, wrappedKeys, permissions: {},
    ...(referredBy ? { referredBy } : {}),
    // Every invite join normally starts as a REQUEST the inviter must accept. The
    // lone exception is the root's own invite in a DM referral tree, which is
    // active on arrival (joinedAt set, no pending flag).
    ...(autoAccept ? { joinedAt: Date.now() } : { pending: true, requestedAt: Date.now() }),
  };
  if (!invite.permanent) dbCache.invites[idx].isUsed = true; // permanent codes are reusable by design
  dbCache.users.push(user);
  // Group ("branch") link: pre-assign the newcomer to that group on the node that
  // owns it (their direct inviter), so it shows on the join request and they land
  // in the right compartment the moment they're accepted.
  if (invite.groupId && parent.id === user.invitedBy && parent.groupLabels && parent.groupLabels[invite.groupId]) {
    parent.inviteeGroups = { ...(parent.inviteeGroups || {}), [user.id]: invite.groupId };
  }
  persistDB();

  // Wake whoever needs to act: the parent (the root, who approves) and the
  // newcomer. In a referral, the member who shared the link also gets an FYI.
  const touched = new Set([parent.accountId, req.accountId]);
  if (referredBy && inviter.accountId) touched.add(inviter.accountId);
  notify(touched);
  if (autoAccept) {
    sendPushToAccount(parent.accountId, 'Arbor', 'Someone joined your network');
  } else {
    // Coalesce multiple outstanding requests into ONE notification that updates to
    // the current count (a stable per-inviter tag replaces the previous one).
    const pendingCount = dbCache.users.filter(u => u.invitedBy === parent.id && u.pending).length;
    const body = pendingCount > 1
      ? `${pendingCount} people are requesting to join your network`
      : 'Someone is requesting to join your network';
    sendPushToAccount(parent.accountId, 'Arbor', body, { tag: `arbor-join-${getPublicId(parent.id)}`, renotify: true });
  }
  res.json({ ...sanitizeUser(user, user), invitedBy: getPublicId(parent.id), pending: !autoAccept });
});

// Inviter reviews a join request. Accept activates the node; decline removes it
// entirely (node + prekeys + wrapped state), leaving the requester's account
// untouched so they can try again with a fresh invite.
const joinRespondLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
app.post('/api/join-requests/respond', joinRespondLimiter, async (req, res) => {
  const { inviterId, targetUserId, accept } = req.body || {};
  if (!isStr(inviterId, 128) || !isStr(targetUserId, 128) || typeof accept !== 'boolean') return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, inviterId);
  if (!me) return;
  const targetInternal = resolveInternalId(targetUserId);
  const target = targetInternal && dbCache.users.find(u => u.id === targetInternal);
  // Personal hub: the pending state lives on the CONTACT EDGE, not the node
  // (the requester's node is their own hub, possibly full of other chats).
  if ((me.treeMode || '') === 'HUB') {
    const edge = target && hubEdgeBetween(me.id, target.id);
    if (!edge || !edge.pending || edge.requestedBy !== target.id) return res.status(404).json({ error: 'No such request' });
    if (accept) {
      edge.pending = false;
      edge.addedAt = Date.now();
      delete edge.attest; delete edge.attestTo;   // only needed while pending
      persistDB();
      notify(new Set([me.accountId, target.accountId]));
      sendPushToAccount(target.accountId, 'Arbor', 'Your contact request was accepted');
    } else {
      dbCache.hubContacts = hubEdges().filter(e => e !== edge);
      persistDB();
      notify(new Set([me.accountId, target.accountId]));
    }
    return res.json({ ok: true });
  }
  if (!target || target.invitedBy !== me.id || !target.pending) return res.status(404).json({ error: 'No such request' });
  if (accept) {
    const gateMsg = growthGate(me);
    if (gateMsg) return res.status(402).json({ error: gateMsg });
    delete target.pending;
    target.joinedAt = Date.now();
    persistDB();
    notify(new Set([me.accountId, target.accountId]));
    sendPushToAccount(target.accountId, 'Arbor', 'You were accepted into the network');
  } else {
    dbCache.users = dbCache.users.filter(u => u.id !== target.id);
    dropMembershipFor(new Set([getPublicId(target.id)]));
    delete dbCache.prekeys[target.id];
    delete dbCache.signalIdentities[target.id];
    await backupsStore.delete(target.id);
    await attachmentsStore.deleteByOwner(target.id);
    persistDB();
    notify(new Set([me.accountId, target.accountId]));
  }
  res.json({ ok: true });
});

const inviteLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

// Permanent invite: one reusable code per node, rotatable on demand. Anyone with
// the code (typically via its QR) can join under this node until it's rotated.
app.post('/api/invites/permanent', inviteLimiter, (req, res) => {
  const { inviterId, rotate, groupId } = req.body || {};
  if (!isStr(inviterId, 128)) return bad(res, 'Invalid input');
  // You may mint an invite for your OWN node, for any node BELOW you on the tree
  // (an ancestor grabbing a group's join link), or — with TrueSight — for any node
  // in that tree. The invite still lands the joiner under `me` (the group owner).
  const me = dbCache.users.find(u => u.id === resolveInternalId(inviterId));
  if (!me) return res.status(404).json({ error: 'Node not found' });
  const ownsIt = me.accountId === req.accountId;
  const ownsAncestor = dbCache.users.some(a => a.accountId === req.accountId && me.path.startsWith(a.path + '/'));
  const tgtRootId = me.path.split('/')[0];
  const hasTrueSight = dbCache.users.some(a => a.accountId === req.accountId && (a.path === tgtRootId || a.path.startsWith(tgtRootId + '/')) && (a.role === 'ROOT' || (a.permissions && a.permissions.viewTrueLevel)));
  if (!ownsIt && !ownsAncestor && !hasTrueSight) return res.status(403).json({ error: 'You can only invite into your own network.' });
  if (me.pending) return res.status(403).json({ error: 'Awaiting approval' });
  // Optional group scoping: a per-group link drops the joiner straight into one
  // of my groups (a "branch"). The group must be a real label I own.
  let gid = null;
  if (groupId !== undefined && groupId !== null && groupId !== '') {
    if (typeof groupId !== 'string' || groupId.length > 64 || !isSafeKey(groupId) || !(me.groupLabels && hasOwn(me.groupLabels, groupId))) {
      return res.status(400).json({ error: 'Unknown group.' });
    }
    gid = groupId;
  }
  // Personal hubs are always root-only: a hub member's node IS their own hub, so
  // they can never mint codes into someone else's space.
  if ((me.treeMode || '') === 'HUB') {
    const root = treeRootUser(me);
    if (!root || me.id !== root.id) return res.status(403).json({ error: 'Only the owner can invite people here.' });
  }
  // Direct-Only networks are hub-and-spoke: ONLY the root invites — UNLESS the
  // root has turned on Referral mode, in which case any member may mint a code
  // (every joiner is re-parented to the root at /api/register).
  if ((me.treeMode || '') === 'DM') {
    const root = treeRootUser(me);
    const isRoot = !!(root && me.id === root.id);
    if (!isRoot && !(root && root.referralOpen)) return res.status(403).json({ error: 'Only the owner can invite people here.' });
  }
  // Same rule as one-time invites: at the free limit, no new invite codes exist
  // to hand out (joins through an old permanent code are still gated at
  // /api/register and at accept time — this just prevents stale codes).
  const permGateMsg = growthGate(me);
  if (permGateMsg) return res.status(402).json({ error: permGateMsg });
  let inv = dbCache.invites.find(i => i.permanent && i.inviterId === me.id && (i.groupId || null) === gid);
  if (inv && rotate) { dbCache.invites = dbCache.invites.filter(i => i !== inv); inv = null; }
  if (!inv) {
    inv = { code: inviteCode(), inviterId: me.id, recipientName: null, permanent: true, isUsed: false, createdAt: Date.now(), ...(gid ? { groupId: gid } : {}) };
    dbCache.invites.push(inv);
    persistDB();
  }
  res.json({ code: inv.code, permanent: true, ...(gid ? { groupId: gid } : {}) });
});

// Crockford base32 alphabet (uppercase, unambiguous) -> exact, lossless entropy.
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const inviteCode = () => {
  const bytes = crypto.randomBytes(20); // 160 bits of source entropy
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out.slice(0, 26); // 26 base32 chars ≈ 130 bits, lossless
};

// One-time named invites removed: the permanent QR invite (/api/invites/permanent)
// is the single join path. Fewer code types = smaller surface, and /api/register
// still validates + growth-gates every join.

app.post('/api/users/delete', async (req, res) => {
  const { targetUserId, initiatorId } = req.body || {};
  if (!isStr(targetUserId, 128) || !isStr(initiatorId, 128)) return bad(res, 'Invalid input');
  const initiator = ownNodeOr403(req, res, initiatorId);
  if (!initiator) return;
  const target = dbCache.users.find(u => u.id === resolveInternalId(targetUserId));
  if (!target) return res.status(404).json({ error: 'Target not found' });
  const isAncestorInitiator = target.path.startsWith(initiator.path + '/');
  if (!isAncestorInitiator) return res.status(403).json({ error: 'Only an ancestor may prune this node' });
  if (!(await reauthOr403(req, res))) return;                    // v72 M4

  const pruned = subtreeOf(target);
  const prunedIds = new Set(pruned.map(u => u.id));
  const prunedAccounts = accountsForUsers(pruned);
  const affected = new Set([...prunedAccounts, ...accountsForUsers(ancestorsOf(target)), req.accountId]);

  dbCache.users = dbCache.users.filter(u => !prunedIds.has(u.id));
  dropHubEdgesFor(prunedIds);
  const prunedPublicIds = new Set([...prunedIds].map(getPublicId));
  // V8 phase 2: the pruned held the network key — ask the root's app to rotate
  // it — and their membership certificates / key boxes are dropped.
  flagRotation(treeRootUser(initiator));
  dropMembershipFor(prunedPublicIds);
  // Their sent messages are deleted; their address rows drop out of everything
  // else. (Envelope recips lists keep the stale entry — harmless: those key slots
  // can no longer be fetched by anyone, and rewriting envelopes would break the
  // sender's signature that recipients verify.)
  await messagesStore.pruneNodes([...prunedIds], [...prunedPublicIds]);
  // Purge scheduled envelopes queued BY a pruned member. (Their slots in others'
  // queued envelopes are dropped at fire time, when the audience is re-checked —
  // they are no longer in the network by then.)
  await scheduledStore.deleteByNodes([...prunedIds]);
  dbCache.invites = dbCache.invites.filter(i => !prunedIds.has(i.inviterId));
  for (const id of prunedIds) { delete dbCache.prekeys[id]; delete dbCache.signalIdentities[id]; await backupsStore.delete(id); await attachmentsStore.deleteByOwner(id); }
  persistDB();
  notify(affected);
  res.json({ pruned: pruned.length });
});

// Inviter-only: partition your OWN direct invitees into groups that can't see
// or message each other. The grouping lives on your node and only you may set
// it. `assignments` maps invitee public ids -> group id (or null to ungroup);
// `labels` maps group id -> display name. We validate every target is actually
// your direct invitee, so you can never move someone else's node or reach
// outside your own circle.
// v71 H2: group structures are stored on the node (RAM + snapshot) and walked on
// hot paths, so each is bounded.
const MAX_GROUPS_PER_NODE = 200;
const MAX_GROUPS_PER_MEMBER = 20;
const MAX_LINKS_PER_NODE = 100;
const MAX_LINK_REFS = 50;
const MAX_VISITORS_PER_GROUP = 200;
const MAX_VISITORS_PER_NODE = 2000;
const groupsLimiter = accountLimiter(60 * 1000, 60);
app.post('/api/users/groups', groupsLimiter, bigBody('1mb'), (req, res) => {
  const { initiatorId, assignments, labels, parents, links, visitors } = req.body || {};
  if (!isStr(initiatorId, 128)) return bad(res, 'Invalid input');
  if (links !== undefined && !isObj(links)) return bad(res, 'Invalid links');
  if (visitors !== undefined && !isObj(visitors)) return bad(res, 'Invalid visitors');
  // You may manage a node's groups if you OWN it, or you own an ANCESTOR of it —
  // so the root (or any ancestor) can lay out groups anywhere in its own subtree.
  const initiator = dbCache.users.find(u => u.id === resolveInternalId(initiatorId));
  if (!initiator) return res.status(404).json({ error: 'Node not found' });
  const ownsIt = initiator.accountId === req.accountId;
  const ownsAncestor = dbCache.users.some(u => u.accountId === req.accountId && initiator.path.startsWith(u.path + '/'));
  if (!ownsIt && !ownsAncestor) return res.status(403).json({ error: 'You can only group nodes in your own network.' });
  if (assignments !== undefined && !isObj(assignments)) return bad(res, 'Invalid assignments');
  if (labels !== undefined && !isObj(labels)) return bad(res, 'Invalid labels');
  if (parents !== undefined && !isObj(parents)) return bad(res, 'Invalid parents');

  const prevLinks = initiator.groupLinks || {}, prevVisitors = initiator.groupVisitors || {};
  const map = { ...(initiator.inviteeGroups || {}) };
  if (isObj(assignments)) {
    for (const [pubId, rawGroup] of Object.entries(assignments)) {
      const childId = resolveInternalId(pubId);
      const child = dbCache.users.find(u => u.id === childId);
      // Must be a real, direct invitee of the initiator — never anyone else.
      if (!child || child.invitedBy !== initiator.id) {
        return res.status(403).json({ error: 'Can only group your own direct invitees' });
      }
      if (rawGroup == null || rawGroup === '') { delete map[childId]; continue; }
      // Accept a single group id (legacy) OR an array of ids (multi-group). Store
      // scalar when exactly one so existing single-group data keeps its shape;
      // store an array only when a member is genuinely in 2+ groups.
      let list;
      if (Array.isArray(rawGroup)) {
        list = [...new Set(rawGroup.filter(g => typeof g === 'string' && g))];
        if (list.some(g => g.length > 64 || !isSafeKey(g))) return bad(res, 'Invalid group id');
        if (list.length > MAX_GROUPS_PER_MEMBER) return bad(res, `A member can be in at most ${MAX_GROUPS_PER_MEMBER} groups.`);
      } else {
        if (typeof rawGroup !== 'string' || rawGroup.length > 64 || !isSafeKey(rawGroup)) return bad(res, 'Invalid group id');
        list = [rawGroup];
      }
      if (list.length === 0) delete map[childId];
      else if (list.length === 1) map[childId] = list[0];
      else map[childId] = list;
    }
  }

  const lbls = { ...(initiator.groupLabels || {}) };
  if (isObj(labels)) {
    for (const [gid, name] of Object.entries(labels)) {
      if (typeof gid !== 'string' || gid.length > 64 || !isSafeKey(gid)) return bad(res, 'Invalid group id');
      if (name == null || name === '') { delete lbls[gid]; continue; }
      if (typeof name !== 'string' || name.length > 80) return bad(res, 'Invalid label');
      lbls[gid] = name;
    }
  }

  // Nested groups: `parents` maps a groupId to its parent groupId (or null to make
  // it top-level). This lets groups cascade (a group inside a group) — purely an
  // organizational/display + join-routing hierarchy; the compartment a member
  // belongs to is still their EXACT leaf group (sameInviteeGroup is unchanged).
  const pars = { ...(initiator.groupParents || {}) };
  if (isObj(parents)) {
    for (const [gid, pid] of Object.entries(parents)) {
      if (typeof gid !== 'string' || gid.length > 64 || !isSafeKey(gid)) return bad(res, 'Invalid group id');
      if (pid == null || pid === '') { delete pars[gid]; continue; }
      if (typeof pid !== 'string' || pid.length > 64 || !isSafeKey(pid)) return bad(res, 'Invalid parent id');
      if (pid === gid) return bad(res, 'A group cannot be its own parent');
      pars[gid] = pid;
    }
  }
  // Cycle + depth guard: walking parents from any group must terminate.
  for (const start of Object.keys(pars)) {
    let cur = pars[start]; let hops = 0;
    while (cur) { if (cur === start || hops++ > 50) return res.status(400).json({ error: 'Groups can’t be nested in a loop.' }); cur = pars[cur]; }
  }
  // Drop parent links that point at a group with no label (a deleted parent).
  for (const gid of Object.keys(pars)) if (!lbls[pars[gid]]) delete pars[gid];

  // Group LINKS: a link joins two (or more) of this node's groups into one shared
  // channel — members of any linked group, plus this node, can message each other
  // there (and only there; their separate group chats stay walled off). Stored as
  // { linkId: { groups: [...], name } }; null clears a link.
  const lks = { ...(initiator.groupLinks || {}) };
  const keyOf = (groups) => [...groups].sort().join('|');
  if (isObj(links)) {
    for (const [lid, spec] of Object.entries(links)) {
      if (typeof lid !== 'string' || lid.length > 64 || !isSafeKey(lid)) return bad(res, 'Invalid link id');
      if (spec === null) { delete lks[lid]; continue; }         // hard delete (rare; unlink archives instead)
      if (!isObj(spec)) return bad(res, 'Invalid link');
      // Archive / un-archive an existing link WITHOUT touching its chat history.
      if (spec.groups === undefined && spec.refs === undefined && typeof spec.archived === 'boolean') {
        if (lks[lid]) lks[lid] = { ...lks[lid], archived: spec.archived };
        continue;
      }
      // CROSS-LEVEL link (ROOT only): join groups from ANYWHERE in the tree,
      // referenced by { o: ownerPublicId, g: groupId }. Deliberately spans
      // compartments, so only the network root may create one.
      // A link never changes kind: rewriting a same-level link as cross-level (or
      // back) would hand its chat and history to a different set of groups.
      if (lks[lid] && (Array.isArray(spec.refs) || Array.isArray(spec.groups)) && !!lks[lid].crossLevel !== Array.isArray(spec.refs)) {
        return res.status(409).json({ error: 'That chat is a different kind of link. Create a new link instead.', code: 'link-kind' });
      }
      if (Array.isArray(spec.refs)) {
        if (initiator.role !== 'ROOT') return res.status(403).json({ error: 'Only the network root can link groups across levels.' });
        if (spec.refs.length > MAX_LINK_REFS * 4) return bad(res, `A link can join at most ${MAX_LINK_REFS} groups.`);
        const refs = []; const seen = new Set();
        for (const r of spec.refs) {
          if (!isObj(r) || !isStr(r.o, 128) || !isStr(r.g, 64)) return bad(res, 'Invalid link ref');
          const owner = dbCache.users.find(u => u.id === resolveInternalId(r.o));
          if (!owner || !(owner.id === initiator.id || owner.path.startsWith(initiator.path + '/'))) return res.status(403).json({ error: 'A linked group is not in your network.' });
          if (!isSafeKey(r.g) || !hasOwn(owner.groupLabels || {}, r.g)) return bad(res, 'Unknown linked group.');
          const k = r.o + '|' + r.g; if (seen.has(k)) continue; seen.add(k);
          refs.push({ o: r.o, g: r.g });
        }
        if (refs.length < 2) return bad(res, 'A link needs at least two groups.');
        if (refs.length > MAX_LINK_REFS) return bad(res, `A link can join at most ${MAX_LINK_REFS} groups.`);
        const nm = typeof spec.name === 'string' && spec.name.trim() ? spec.name.slice(0, 80)
          : refs.map(r => ((dbCache.users.find(u => u.id === resolveInternalId(r.o)) || {}).groupLabels || {})[r.g]).join(' × ');
        lks[lid] = { refs, name: nm, crossLevel: true, ...(lks[lid] && lks[lid].archived ? { archived: true } : {}) };
        continue;
      }
      if (!Array.isArray(spec.groups)) return bad(res, 'Invalid link');
      const groups = [...new Set(spec.groups)].filter(g => typeof g === 'string' && hasOwn(lbls, g));
      if (groups.length < 2) return bad(res, 'A link needs at least two existing groups.');
      if (groups.length > MAX_LINK_REFS) return bad(res, `A link can join at most ${MAX_LINK_REFS} groups.`);
      const nm = typeof spec.name === 'string' && spec.name.trim() ? spec.name.slice(0, 80) : groups.map(g => lbls[g]).join(' × ');
      const key = keyOf(groups);
      // No duplicate ACTIVE link over the same set of groups (order-independent —
      // keyOf sorts, so "East×West" and "West×East" collide).
      const dupActive = Object.entries(lks).find(([id, s]) => id !== lid && !s.crossLevel && !s.archived && keyOf(s.groups) === key);
      if (dupActive) return res.status(409).json({ error: 'Those groups are already linked.', code: 'active-exists', linkId: dupActive[0], name: lks[dupActive[0]].name });
      // A previously-archived link over this exact pair already exists: DON'T
      // silently revive it and DON'T make a parallel duplicate. Report it so the
      // client can offer to restore that chat (with its history). The client
      // restores by POSTing { [linkId]: { archived: false } }.
      const archivedDup = Object.entries(lks).find(([id, s]) => !s.crossLevel && s.archived && keyOf(s.groups) === key);
      if (archivedDup) return res.status(409).json({ error: 'A previous chat between these groups is archived.', code: 'archived-exists', linkId: archivedDup[0], name: lks[archivedDup[0]].name });
      lks[lid] = { groups, name: nm };
    }
  }
  // Drop links referencing a group that no longer exists.
  for (const lid of Object.keys(lks)) {
    const L = lks[lid];
    if (L.crossLevel) {
      // A cross-level link references groups across the tree by { o, g }.
      L.refs = (L.refs || []).filter(r => { const o = dbCache.users.find(u => u.id === resolveInternalId(r.o)); return o && (o.groupLabels || {})[r.g]; });
      if (L.refs.length < 2) delete lks[lid];
    } else {
      L.groups = (L.groups || []).filter(g => lbls[g]);
      if (L.groups.length < 2) delete lks[lid];
    }
  }

  // Cross-level VISITORS: `visitors` maps one of initiator's group ids -> the FULL
  // set of visitor public ids for that group (replace semantics; [] or null clears).
  // Each must be a real, non-pending user; stored as internal ids on the owner node.
  const vis = { ...(initiator.groupVisitors || {}) };
  if (isObj(visitors)) {
    for (const [gid, arr] of Object.entries(visitors)) {
      if (typeof gid !== 'string' || gid.length > 64 || !isSafeKey(gid) || !hasOwn(lbls, gid)) return bad(res, 'Unknown group for visitors.');
      if (arr == null || (Array.isArray(arr) && arr.length === 0)) { delete vis[gid]; continue; }
      if (!Array.isArray(arr)) return bad(res, 'Invalid visitors list');
      if (arr.length > MAX_VISITORS_PER_GROUP) return bad(res, `A group can have at most ${MAX_VISITORS_PER_GROUP} visitors.`);
      const ids = [];
      for (const pub of arr) {
        if (!isStr(pub, 128)) return bad(res, 'Invalid visitor id');
        const uid = resolveInternalId(pub);
        const u = uid && dbCache.users.find(x => x.id === uid);
        if (!u || u.pending) return res.status(400).json({ error: 'Unknown visitor.' });
        // SECURITY: a cross-level visitor MUST belong to the same network as the
        // group owner. Without this, any member could staple an arbitrary node id
        // (even one in a different tree) into their own group and open a message
        // channel to it — breaking tree isolation and the compartment model.
        if (!sameTree(initiator, u)) return res.status(403).json({ error: 'A visitor must be in your network.' });
        // SECURITY: a member cannot add a node the inviter walled off from this
        // group owner (same inviter, disjoint groups) as a visitor — that would
        // let a member unilaterally rebuild a channel the inviter deliberately
        // severed. (Root/ancestor owners have no such inviter, so this never
        // blocks legitimate cross-level visitor setup by the network owner.)
        if (compartmentBlocked(initiator, u)) return res.status(403).json({ error: 'That member is in a different compartment of your network.' });
        if (u.id === initiator.id) continue;      // the owner isn't their own visitor
        if (!ids.includes(u.id)) ids.push(u.id);
      }
      if (ids.length) vis[gid] = ids; else delete vis[gid];
    }
  }
  for (const gid of Object.keys(vis)) if (!lbls[gid]) delete vis[gid]; // drop orphans

  // Keep labels as-is: a freshly created group is legitimately empty until the
  // inviter assigns members. Labels are only removed when explicitly cleared
  // (name set to null/empty above). This lets "create group, then add people"
  // work, and lets a group be abolished by clearing its label.
  // v71 H2: per-node totals (only an edit that GROWS past a cap is refused, so a
  // node already over one from older data can still be tidied up).
  const grew = (now, before, cap) => now > cap && now > before;
  if (grew(Object.keys(lbls).length, Object.keys(initiator.groupLabels || {}).length, MAX_GROUPS_PER_NODE)) return bad(res, `At most ${MAX_GROUPS_PER_NODE} groups per member.`);
  if (grew(Object.keys(lks).length, Object.keys(prevLinks).length, MAX_LINKS_PER_NODE)) return bad(res, `At most ${MAX_LINKS_PER_NODE} linked chats per member.`);
  const visCount = (v) => Object.values(v || {}).reduce((n, a) => n + (Array.isArray(a) ? a.length : 0), 0);
  if (grew(visCount(vis), visCount(prevVisitors), MAX_VISITORS_PER_NODE)) return bad(res, `At most ${MAX_VISITORS_PER_NODE} visitors per member.`);
  initiator.groupParents = pars;
  initiator.groupLinks = lks;
  initiator.groupVisitors = vis;
  initiator.inviteeGroups = map;
  initiator.groupLabels = lbls;
  persistDB();
  // Notify the inviter and every affected invitee's account so clients refresh
  // their view (a regrouped invitee's sibling set changes).
  const affected = new Set([initiator.accountId, req.accountId]);
  for (const u of dbCache.users) if (u.invitedBy === initiator.id) affected.add(u.accountId);
  // Cross-level links reach people all over the tree — refresh their clients too.
  for (const L of Object.values(lks)) {
    if (L && L.crossLevel) for (const id of crossLevelParticipants(initiator, L, dbCache.users)) {
      const u = dbCache.users.find(x => x.id === id); if (u && u.accountId) affected.add(u.accountId);
    }
  }
  // Cross-level visitors are elsewhere in the tree — refresh their clients too.
  for (const ids of Object.values(vis)) for (const id of ids) { const u = dbCache.users.find(x => x.id === id); if (u && u.accountId) affected.add(u.accountId); }
  notify(affected);
  // Respond with PUBLIC-keyed groups so any client using this response directly
  // matches its rendered nodes (tree-context/sanitizeUser already does the same).
  const pubKeyed = {};
  for (const [internalId, gid] of Object.entries(map)) pubKeyed[getPublicId(internalId)] = gid;
  const visPub = {};
  for (const [gid, ids] of Object.entries(vis)) visPub[gid] = ids.map(getPublicId);
  res.json({ ok: true, inviteeGroups: pubKeyed, groupLabels: lbls, groupParents: pars, groupLinks: lks, groupVisitors: visPub });
});

// Move a member (and its ENTIRE subtree) to become an invitee of another node,
// placed in one of that node's groups. Re-parents the node: its descendants and
// its own groups travel with it (they hang off the moved node), and every path/
// level in the moved subtree is recomputed. HIERARCHICAL trees only.
app.post('/api/nodes/move', (req, res) => {
  const { initiatorId, nodeId, targetOwnerId, targetGroupId } = req.body || {};
  if (!isStr(initiatorId, 128) || !isStr(nodeId, 128) || !isStr(targetOwnerId, 128)) return bad(res, 'Invalid input');
  if (targetGroupId != null && (typeof targetGroupId !== 'string' || targetGroupId.length > 64 || !isSafeKey(targetGroupId))) return bad(res, 'Invalid group');
  const initiator = dbCache.users.find(u => u.id === resolveInternalId(initiatorId));
  if (!initiator || initiator.accountId !== req.accountId) return res.status(403).json({ error: 'Access denied' });
  const node = dbCache.users.find(u => u.id === resolveInternalId(nodeId));
  const newOwner = dbCache.users.find(u => u.id === resolveInternalId(targetOwnerId));
  if (!node || !newOwner) return res.status(404).json({ error: 'Node not found' });
  const root = treeRootUser(node);
  if (!root) return res.status(404).json({ error: 'Tree not found' });
  if ((root.treeMode || 'HIERARCHICAL') !== 'HIERARCHICAL') return bad(res, 'Only hierarchical networks support moving members.');
  if (treeRootUser(newOwner)?.id !== root.id) return bad(res, 'Target is in a different network.');
  // The initiator must MANAGE both endpoints: own the network's root, or an ancestor
  // of each (v71 L8: owning the moved node itself is not enough). The destination
  // may also be one of the initiator's own nodes.
  const ownsRoot = root.accountId === req.accountId;
  const above = (n) => ownsRoot || dbCache.users.some(u => u.accountId === req.accountId && !u.pending && n.path.startsWith(u.path + '/'));
  if (node.pending || newOwner.pending) return res.status(400).json({ error: 'Pending requests can’t be moved.' });
  if (!above(node) || !(above(newOwner) || (newOwner.accountId === req.accountId && !newOwner.pending))) return res.status(403).json({ error: 'You can only move members within a branch you manage.' });
  if (node.id === root.id) return bad(res, 'The root cannot be moved.');
  // No cycles: cannot move a node under itself or one of its own descendants.
  if (newOwner.id === node.id || newOwner.path.startsWith(node.path + '/')) return bad(res, "Can't move a member into its own branch.");
  if (targetGroupId && !(newOwner.groupLabels && newOwner.groupLabels[targetGroupId])) return res.status(404).json({ error: 'That group no longer exists.' });
  // v72 (L): the member stays a visitor of their old groups (below) — that must fit
  // the same visitor caps as any other visitor change (v71 appended without checking).
  {
    const inv = dbCache.users.find(u => u.id === node.invitedBy);
    const cur = (inv && inv.groupVisitors) || {};
    const adds = inv ? memberGids(inv, node.id).filter(g => !(cur[g] || []).includes(node.id)) : [];
    const total = Object.values(cur).reduce((n, a) => n + (Array.isArray(a) ? a.length : 0), 0) + adds.length;
    if (adds.some(g => (cur[g] || []).length + 1 > MAX_VISITORS_PER_GROUP)) return bad(res, `Their current group already has ${MAX_VISITORS_PER_GROUP} visitors, so they couldn’t stay in it as a visitor after the move. Remove a visitor there first.`);
    if (adds.length && total > MAX_VISITORS_PER_NODE) return bad(res, `Their current inviter already has ${MAX_VISITORS_PER_NODE} visitors, so they couldn’t stay in their old group as a visitor after the move. Remove a visitor there first.`);
  }

  const oldPath = node.path;
  const oldLevel = typeof node.level === 'number' ? node.level : (oldPath.split('/').length - 1);
  const newLevel = (typeof newOwner.level === 'number' ? newOwner.level : (newOwner.path.split('/').length - 1)) + 1;
  const delta = newLevel - oldLevel;
  const newNodePath = newOwner.path + '/' + node.id;
  // Detach from the OLD inviter's group map — but KEEP the moved user connected to
  // those groups as a cross-level VISITOR, so moving doesn't strip their access to
  // the groups they were local to before the move.
  const oldInviter = dbCache.users.find(u => u.id === node.invitedBy);
  if (oldInviter) {
    const oldGids = memberGids(oldInviter, node.id);
    if (oldGids.length) {
      oldInviter.groupVisitors = oldInviter.groupVisitors || {};
      for (const g of oldGids) {
        const arr = oldInviter.groupVisitors[g] || [];
        if (!arr.includes(node.id)) arr.push(node.id);
        oldInviter.groupVisitors[g] = arr;
      }
    }
    if (oldInviter.inviteeGroups) delete oldInviter.inviteeGroups[node.id];
  }
  // Re-parent the node and cascade paths + levels across its whole subtree.
  for (const u of dbCache.users) {
    if (u.id === node.id) { u.path = newNodePath; u.level = newLevel; }
    else if (u.path.startsWith(oldPath + '/')) { u.path = newNodePath + u.path.slice(oldPath.length); u.level = (typeof u.level === 'number' ? u.level : (u.path.split('/').length - 1)) + delta; }
  }
  node.invitedBy = newOwner.id;
  // Place into the target group on the new owner (or leave ungrouped).
  if (!newOwner.inviteeGroups) newOwner.inviteeGroups = {};
  if (targetGroupId) newOwner.inviteeGroups[node.id] = targetGroupId; else delete newOwner.inviteeGroups[node.id];
  persistDB();
  const affected = new Set();
  for (const u of subtreeOf(root)) affected.add(u.accountId);
  notify(affected);
  res.json({ ok: true });
});

// Change a node's own icon color. Cosmetic, but it shows on everyone who can see
// this node, so we notify their accounts to refresh (tree members + hub contacts
// + the inviter). Others still pick it up on their next poll regardless.
// V8 L-4: profile-class writes (color/name/bio/photo) were unthrottled and each
// one fans out a whole-tree refresh — per-account cap. V8 M-6: an archived
// network's messaging is suspended, and these writes (readable by other members)
// were an open relay around that — same 402 guard as messages/typing/prekeys.
const profileLimiter = accountLimiter(60 * 1000, 20);
const ARCHIVED_402 = { error: 'This network is archived — its subscription lapsed. The network root can restore it from the Network Plan panel.' };
app.post('/api/users/color', profileLimiter, (req, res) => {
  const { nodeId, color } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  if (!isHexColor(color)) return bad(res, 'Invalid color');
  const node = ownNodeOr403(req, res, nodeId);
  if (!node) return;
  if (isTreeArchived(node)) return res.status(402).json(ARCHIVED_402);
  node.color = color;
  persistDB();
  const affected = new Set([node.accountId]);
  try {
    const root = treeRootUser(node);
    if (root) for (const u of subtreeOf(root)) affected.add(u.accountId);
    for (const { other } of hubContactsOf(node.id, true)) affected.add(other.accountId);
    if (node.invitedBy) { const inv = dbCache.users.find(u => u.id === node.invitedBy); if (inv) affected.add(inv.accountId); }
  } catch {}
  notify(affected);
  res.json({ ok: true, color });
});

// ---- Network Profile: per-node display name (+ change history), bio, avatar ----
// Same visibility tier as name/color (server-side, seen by anyone who can see the
// node) — only message CONTENT is E2E. Profile photos are metadata-scrubbed TWICE:
// on the client (canvas re-encode; only pixels leave the device) AND here on the
// server (structural strip in imageScrub.js — V8 M-3), so the guarantee no longer
// depends on the client being honest. Photos are stored content-addressed in the
// avatars table (V8 H-5), referenced from nodes/accounts by hash.
const MAX_BIO = 500;
const MAX_AVATAR_CHARS = 400000; // ~300KB data URL; the client downscales to ~256px
const avatarHashOf = (dataUrl) => crypto.createHash('sha256').update(dataUrl).digest('hex');
// Validate + strip + store. Returns the hash, or throws ImageRejected.
const storeAvatar = async (dataUrl) => {
  if (typeof dataUrl !== 'string' || dataUrl.length > MAX_AVATAR_CHARS) throw new ImageRejected('too large');
  const clean = scrubImageDataUrl(dataUrl);
  const hash = avatarHashOf(clean);
  await avatarsStore.put(hash, clean);
  return hash;
};
// Drop photos no node or account default references any more (hourly + at boot).
async function dropAvatarIfUnused(h) {
  const used = dbCache.users.some(u => u.avatarHash === h)
    || dbCache.accounts.some(a => a.defaultProfileRef === h || (a.defaultProfile && a.defaultProfile.avatarHash === h));
  if (!used) { try { await avatarsStore.delete(h); } catch (e) { console.error('[avatars] delete failed:', e.message); } }
}
const sweepAvatars = async () => {
  if (!dbLoaded) return;                 // v70: with no users loaded, every photo looks unused
  try {
    const liveNow = () => {
      const live = new Set();
      for (const u of dbCache.users) if (u.avatarHash) live.add(u.avatarHash);
      for (const a of dbCache.accounts) {
        if (a.defaultProfile && a.defaultProfile.avatarHash) live.add(a.defaultProfile.avatarHash);
        if (a.defaultProfileRef) live.add(a.defaultProfileRef);   // v71: sealed default profile
      }
      return live;
    };
    // v71: the deletes are async — if any write lands meanwhile (e.g. a new photo
    // stored and then referenced), rebuild the live set before deciding again.
    let live = liveNow(), seen = dataVersion;
    for (const h of await avatarsStore.allHashes()) {
      if (dataVersion !== seen) { live = liveNow(); seen = dataVersion; }
      if (!live.has(h)) await avatarsStore.delete(h);
    }
  } catch (e) { console.error('[avatars] sweep failed:', e.message); }
};
setInterval(sweepAvatars, 60 * 60 * 1000);

// Accounts to wake when a node's profile changes: its whole tree plus its hub
// contacts and inviter — the same fanout the color endpoint uses.
const profileWatchers = (node) => {
  const affected = new Set([node.accountId]);
  try {
    const root = treeRootUser(node);
    if (root) for (const u of subtreeOf(root)) affected.add(u.accountId);
    for (const { other } of hubContactsOf(node.id, true)) affected.add(other.accountId);
    if (node.invitedBy) { const inv = dbCache.users.find(u => u.id === node.invitedBy); if (inv) affected.add(inv.accountId); }
  } catch {}
  return affected;
};

// Can a node the requester owns see `target`'s profile? V8 M-2: this used to be
// "same tree or any hub edge", which let a walled sibling, a cousin across a wall,
// or an UNAPPROVED join-requester read bio, avatar and full name history of
// members hidden from them in /tree-context. It now mirrors the roster rules:
//  - a pending node sees only itself;
//  - a pending target is visible only to the inviter reviewing that request;
//  - hub contacts: active edges both ways; a pending request lets the RECIPIENT
//    view the requester (to decide) but not the other way round;
//  - tree members: root/True-Sight see the tree; everyone else sees their direct
//    line (ancestors/descendants), same-compartment siblings, and co-participants
//    of explicit cross-compartment channels (links, visitors, global chat).
const canSeeProfile = (viewer, target, { global = true } = {}) => {
  if (!viewer || !target) return false;
  if (viewer.id === target.id) return true;
  if (viewer.pending) return false;
  const edge = hubEdgeBetween(viewer.id, target.id);
  if (edge) return !edge.pending || edge.requestedBy === target.id;
  if (!sameTree(viewer, target)) return false;
  if (target.pending) return target.invitedBy === viewer.id;
  if (viewer.role === 'ROOT' || viewer.permissions?.viewTrueLevel) return true;
  if (target.path.startsWith(viewer.path + '/') || viewer.path.startsWith(target.path + '/')) return true;
  const root = treeRootUser(viewer);
  if (global && globalPeers(viewer, target)) return true;           // v72 M2: global chat participants see each other's full profile
  if (root && (root.treeMode || '') === 'DM') return sharesExplicitChannel(viewer, target);
  if (viewer.invitedBy && target.invitedBy === viewer.invitedBy && sameInviteeGroup(viewer, target, dbCache.users)) return true;
  if (mainChatPeers(viewer, target)) return true;                   // they share the main Ancestors chat
  return sharesExplicitChannel(viewer, target);
};
// True if the REQUESTER (any node on their account) shares a context with target.
// v72 M2: global chat alone doesn't count ("Add to my hub" keeps the wall).
const accountSharesContext = (accountId, target) =>
  dbCache.users.some(n => n.accountId === accountId && canSeeProfile(n, target, { global: false }));

// Plaintext profile writes are retired (V8 phase 2, M-8): names, bios, name
// history and photos are uploaded end-to-end encrypted via /api/profile/set.
// These answer 410 so a stale client can't reintroduce plaintext.
const PLAINTEXT_GONE = { error: 'Profiles are end-to-end encrypted now. Please reload Arbor.', code: 'update-required' };
app.post('/api/users/name', (req, res) => res.status(410).json(PLAINTEXT_GONE));

// V8 M-8: the server kept up to 50 prior names per node with no way to remove
// them — a permanent deanonymization trail. The owner can now clear it.
app.post('/api/users/name/history/clear', profileLimiter, (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const node = ownNodeOr403(req, res, nodeId);
  if (!node) return;
  if (Array.isArray(node.nameHistory) && node.nameHistory.length) {
    delete node.nameHistory;
    persistDB();
    notify(profileWatchers(node));
  }
  res.json({ ok: true, nameHistory: [] });
});

app.post('/api/users/profile', (req, res) => res.status(410).json(PLAINTEXT_GONE));

// Profile info-view data for a node the caller can see: the ENCRYPTED profile
// (name, bio, name history, photo key) plus the node's identity key, which the
// viewer checks against its membership certificates. Legacy plaintext only for a
// node whose owner hasn't opened an updated app yet.
app.get('/api/users/:publicId/profile', (req, res) => {
  const viewer = ownNodeOr403(req, res, req.query.viewerNodeId);
  if (!viewer) return;
  const target = dbCache.users.find(u => u.id === resolveInternalId(req.params.publicId));
  if (!target || !canSeeProfile(viewer, target)) return res.status(404).json({ error: 'Not found' });
  res.json({
    id: getPublicId(target.id), color: target.color, avatarAt: target.avatarAt || 0,
    ...(identityKeyOf(target) ? { ik: identityKeyOf(target) } : {}),
    ...(target.profileCt ? { profileCt: target.profileCt } : {
      name: target.name, bio: target.bio || '',
      nameHistory: Array.isArray(target.nameHistory) ? target.nameHistory : [],
    }),
  });
});

// Lazy avatar bytes for a visible node, cached client-side by avatarAt. Returned as
// a data URL in JSON. 404 when the node has no photo or the caller can't see it.
app.get('/api/users/:publicId/avatar', async (req, res) => {
  const viewer = ownNodeOr403(req, res, req.query.viewerNodeId);
  if (!viewer) return;
  const target = dbCache.users.find(u => u.id === resolveInternalId(req.params.publicId));
  if (!target || !canSeeProfile(viewer, target) || !target.avatarHash) return res.status(404).json({ error: 'No avatar' });
  const avatar = await avatarsStore.get(target.avatarHash);
  if (!avatar) return res.status(404).json({ error: 'No avatar' });
  res.set('Cache-Control', 'private, max-age=86400');
  res.json({ avatar, avatarAt: target.avatarAt || 0 });
});

// v72 B2: the statement an "Add to my hub" request carries (services/membership.ts
// 'hubreq'): my node `by` in the network I share with `to` signs, with its
// registered identity, that my hub `hub` has key `ik`. The accepting app verifies
// it against its OWN pin for that network (the server can't make one up); the
// server checks shape, parties and signature so no unverifiable request is stored.
const HUBREQ_FIELDS = ['k', 'v', 'tree', 'by', 'to', 'hub', 'ik', 'ts'];
function checkHubAttestIn(raw, mine, target, accountId) {
  if (!isStr(raw, CERT_MAX_CHARS)) return null;
  let o; try { o = JSON.parse(raw); } catch { return null; }
  if (!isObj(o) || Object.keys(o).some(k => k !== 'b' && k !== 's') || !isB64(o.s, 100)) return null;
  const b = o.b;
  if (!isObj(b) || b.k !== 'hubreq' || b.v !== 1 || Object.keys(b).some(k => !HUBREQ_FIELDS.includes(k))) return null;
  if (typeof b.ts !== 'number' || !Number.isFinite(b.ts) || b.ts <= 0 || b.ts > Date.now() + CERT_FUTURE_MS) return null;
  const byId = isStr(b.by, 128) && resolveInternalId(b.by);
  const by = byId && dbCache.users.find(u => u.id === byId);
  if (!by || by.accountId !== accountId || by.pending || (by.treeMode || '') === 'HUB' || !sameTree(by, target)) return null;
  if (b.tree !== treePidOf(target) || b.to !== getPublicId(target.id) || b.hub !== getPublicId(mine.id)) return null;
  if (!isIk(b.ik) || !sameIk(b.ik, identityKeyOf(mine))) return null;
  if (!certSigOk(b, o.s, identityKeyOf(by))) return null;
  return { raw, to: target.id };
}
// What the accepting hub owner needs to check it: the statement, the signer's
// certificate chain in that network, and the owner's own sealed pin copy for its
// node there. Only served when that node really is the owner's.
function hubAttestFor(edge, me) {
  const to = edge.attest && edge.attestTo && dbCache.users.find(u => u.id === edge.attestTo);
  if (!to || to.accountId !== me.accountId) return {};
  let by; try { by = JSON.parse(edge.attest).b.by; } catch { return {}; }
  return { attest: edge.attest, attestCerts: certChainsFor(treePidOf(to), [by]), ...(to.anchorCt ? { attestAnchorCt: to.anchorCt } : {}) };
}

// "Add to my hub": connect a user I can see to my personal hub as a symmetric
// contact — the same pending→accept edge that opening a hub link creates, but by
// node id from the profile info view. I must own a hub root (the client creates one
// first if needed). If the target has no hub yet the request is parked against
// their account and bound when they first open their own hub.
app.post('/api/hub/connect', (req, res) => {
  const { fromHubNodeId, targetPublicId } = req.body || {};
  if (!isStr(fromHubNodeId, 128) || !isStr(targetPublicId, 128)) return bad(res, 'Invalid input');
  const mine = ownNodeOr403(req, res, fromHubNodeId);
  if (!mine) return;
  if ((mine.treeMode || '') !== 'HUB' || mine.invitedBy) return res.status(400).json({ error: 'Use your personal hub to add contacts.' });
  const target = dbCache.users.find(u => u.id === resolveInternalId(targetPublicId));
  if (!target) return res.status(404).json({ error: 'Not found' });
  if (target.accountId === mine.accountId) return res.status(400).json({ error: 'That’s you.' });
  // You may only add someone you already share a context with (a tree member or an
  // existing contact) — never an arbitrary id. Prevents hub-spam / enumeration.
  if (!accountSharesContext(mine.accountId, target)) {
    // v72 M2: global chat alone doesn't count — say so instead of "no shared network".
    const viaGlobal = dbCache.users.some(n => n.accountId === mine.accountId && globalPeers(n, target));
    return res.status(403).json({ error: viaGlobal
      ? 'Global chat connects people only inside the global channel — you can add someone to your hub when you share a conversation with them elsewhere in the network.'
      : 'You can only add people you share a network or contact with.' });
  }
  // v72 B2: a NEW request must carry the requester's signed statement (see
  // checkHubAttestIn); without it the other side could never verify it.
  const att = checkHubAttestIn(req.body.attest, mine, target, req.accountId);
  const NEEDS_ATTEST = { error: 'Please reload Arbor, then try again.', code: 'update-required' };

  const targetHub = accountHubRoot(target.accountId);
  if (targetHub) {
    if (targetHub.id === mine.id) return res.status(400).json({ error: 'That’s you.' });
    const existing = hubEdgeBetween(mine.id, targetHub.id);
    if (existing) return res.json({ ok: true, status: existing.pending ? 'pending' : 'connected' });
    if (hubContactsOf(targetHub.id, true).length >= 2000) return res.status(402).json({ error: 'Their contact list is full.' });
    if (!att) return res.status(400).json(NEEDS_ATTEST);
    hubEdges().push({ a: targetHub.id, b: mine.id, pending: true, requestedBy: mine.id, addedAt: Date.now(), attest: att.raw, attestTo: att.to });
    persistDB();
    notify(new Set([mine.accountId, target.accountId]));
    sendPushToAccount(target.accountId, 'Arbor', 'You have a new contact request on Arbor');
    return res.json({ ok: true, status: 'requested' });
  }
  // Target has no hub yet: park the request on their account; bound when they first
  // open their personal hub (bindAccountHubInvites).
  dbCache.accountHubInvites = dbCache.accountHubInvites || [];
  if (!att) return res.status(400).json(NEEDS_ATTEST);
  const dup = dbCache.accountHubInvites.find(x => x.toAccount === target.accountId && x.fromHub === mine.id);
  if (dup) { dup.attest = att.raw; dup.attestTo = att.to; persistDB(); }
  if (!dup) {
    dbCache.accountHubInvites.push({ toAccount: target.accountId, fromHub: mine.id, at: Date.now(), attest: att.raw, attestTo: att.to });
    persistDB();
    sendPushToAccount(target.accountId, 'Arbor', 'Someone wants to connect with you on Arbor — open your Chats to accept.');
  }
  return res.json({ ok: true, status: 'invited' });
});

// ---- Account-level DEFAULT profile ----
// A template (display name, photo, bio) stored on the ACCOUNT that a new network
// can start from. V8 phase 2 (M-8): it is ONE blob encrypted under the account's
// password-derived key — only the account owner can read it; the server can't.
// The app applies it to a new network (encrypting a copy under that network's
// key) only when the person opts in for that network.
// Legacy plaintext defaults are handed back once so the app can re-encrypt them,
// then deleted when the encrypted blob is uploaded.
const MAX_DEFAULT_PROFILE_CT = 900000;
app.get('/api/account/profile', async (req, res) => {
  const acc = dbCache.accounts.find(a => a.id === req.accountId);
  if (!acc) return res.status(404).json({ error: 'Not found' });
  const d = acc.defaultProfile || {};
  const legacy = (d.name || d.bio || d.avatarHash)
    ? { name: d.name || '', bio: d.bio || '', avatar: d.avatarHash ? (await avatarsStore.get(d.avatarHash)) || '' : '' }
    : null;
  const ct = acc.defaultProfileRef ? await avatarsStore.get(acc.defaultProfileRef) : (acc.defaultProfileCt || null);
  res.json({ ct: ct || null, ...(legacy ? { legacy } : {}) });
});

app.post('/api/account/profile', profileLimiter, bigBody('1mb'), async (req, res) => {
  const acc = dbCache.accounts.find(a => a.id === req.accountId);
  if (!acc) return res.status(404).json({ error: 'Not found' });
  const { ct } = req.body || {};
  if (!(ct === null || isStr(ct, MAX_DEFAULT_PROFILE_CT))) return bad(res, 'Invalid input');
  // v71 M4: the (up to ~900 KB) sealed template lives in the content-addressed
  // blob table, referenced by hash — not inline in the in-memory accounts list.
  if (ct === null) delete acc.defaultProfileRef;
  else { const h = 'dp:' + avatarHashOf(ct); await avatarsStore.put(h, ct); acc.defaultProfileRef = h; }
  delete acc.defaultProfileCt;
  delete acc.defaultProfile; // plaintext template gone for good (its photo is swept)
  persistDB();
  res.json({ ok: true });
});

app.post('/api/users/permissions', (req, res) => {
  const { targetUserId, permissions, initiatorId } = req.body || {};
  if (!isStr(targetUserId, 128) || !isStr(initiatorId, 128) || !isObj(permissions)) return bad(res, 'Invalid input');
  const initiator = ownNodeOr403(req, res, initiatorId);
  if (!initiator) return;
  if (initiator.role !== 'ROOT') return res.status(403).json({ error: 'Only the root user may grant permissions' });
  const target = dbCache.users.find(u => u.id === resolveInternalId(targetUserId));
  if (!target) return res.status(404).json({ error: 'Target not found' });
  if (!target.path.startsWith(initiator.path + '/')) return res.status(403).json({ error: 'Target is not in your network' });
  target.permissions = { viewTrueLevel: !!permissions.viewTrueLevel, announce: !!permissions.announce };
  persistDB();
  notify(new Set([target.accountId, initiator.accountId]));
  res.json({ ok: true });
});

// Root-only: rename the network / 1:1 and toggle whether its name is visible to
// every member (a switch entirely separate from True Sight, which only governs
// visibility of the whole tree). Works for HIERARCHICAL and DM roots.
app.post('/api/tree/settings', (req, res) => {
  const { nodeId, treeName, treeNameVisible, monitorEnabled, referralOpen, globalChat, autoAcceptInvites } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const root = treeRootUser(me);
  if (!root || me.id !== root.id) return res.status(403).json({ error: 'Only the network root can change these settings.' });
  // The network NAME is end-to-end encrypted (V8 phase 2): renames go through
  // /api/profile/set { treeNameCt }. A plaintext name is refused — v72 (L): before
  // anything else in the request is applied (v71 had already changed some settings).
  if (treeName !== undefined) return res.status(410).json(PLAINTEXT_GONE);
  if (globalChat !== undefined) me.globalChat = !!globalChat;
  // Auto-accept invitations: when on, anyone who joins with a valid invite is
  // activated on arrival instead of waiting in the approval queue. Applies to the
  // invite-based tree networks (hierarchical + Direct-Only); off by default.
  if (autoAcceptInvites !== undefined && (me.treeMode || '') !== 'HUB') me.autoAcceptInvites = !!autoAcceptInvites;
  if (treeNameVisible !== undefined) me.treeNameVisible = !!treeNameVisible;
  if (monitorEnabled !== undefined) me.monitorEnabled = !!monitorEnabled;
  // Referral mode only applies to Direct-Only trees. Ignore it elsewhere so a
  // hierarchical/hub root can't set a flag that has no meaning for its topology.
  if (referralOpen !== undefined && (me.treeMode || '') === 'DM') me.referralOpen = !!referralOpen;
  persistDB();
  // Everyone in the tree may now see a different name — refresh the whole tree.
  const affected = new Set(subtreeOf(me).map(u => u.accountId));
  affected.add(req.accountId);
  notify(affected);
  res.json({ ok: true, treeNameVisible: !!me.treeNameVisible, monitorEnabled: me.monitorEnabled !== false, referralOpen: !!me.referralOpen, globalChat: !!me.globalChat, autoAcceptInvites: !!me.autoAcceptInvites });
});
// STRIPE_SECRET_KEY, STRIPE_PRICE_ID, STRIPE_WEBHOOK_SECRET). Monero runs
// through NOWPayments (NOWPAYMENTS_API_KEY, NOWPAYMENTS_IPN_SECRET) — a hosted
// payment processor that generates deposit addresses and tracks on-chain
// confirmations, so you don't need to run your own Monero node.
// ---------------------------------------------------------------------------
const billingLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const NP_API = process.env.NOWPAYMENTS_SANDBOX === 'true'
  ? 'https://api-sandbox.nowpayments.io/v1'
  : 'https://api.nowpayments.io/v1';

app.post('/api/billing/status', billingLimiter, async (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me) return;
  const root = treeRootUser(me);
  const rootAcc = root && accountById(root.accountId);
  const isRoot = !!(root && me.id === root.id && root.accountId === req.accountId);
  // Paid-through horizon for THIS network: its own paid time, or the root
  // account's admin comp if that runs longer (permanent comps have no horizon).
  const paidThrough = Math.max(root?.premiumUntil || 0, rootAcc?.compUntil || 0) || null;
  res.json({
    treeSize: treeMemberCount(me),
    limit: FREE_TREE_LIMIT,
    premiumLimit: NETWORK_MEMBER_MAX,                    // v72: Premium's member limit (enforced)
    // v72: relayed calls are available to EVERYONE when this server runs a relay
    // (not Premium-gated) — the plan panel shows what is actually true here.
    relayCalls: !!process.env.TURN_URL || process.env.ALLOW_PUBLIC_TURN === '1',
    priceUsd: PREMIUM_USD,
    premium: isTreePremium(me),
    premiumUntil: paidThrough,
    isRoot,
    archived: isTreeArchived(me),
    graceUntil: paidThrough ? paidThrough + GRACE_MS : null,
    // This identity's stored media: the byte count of its (end-to-end encrypted)
    // attachment blobs, against its quota. Sizes only — the server never sees content.
    media: { used: Number(await attachmentsStore.ownerBytes(me.id)) || 0, quota: mediaQuotaFor(me) },
    historyDays: retentionDaysFor(me),                     // 0 = kept forever
    limits: { freeMediaBytes: ATTACHMENT_OWNER_QUOTA, premiumMediaBytes: ATTACHMENT_OWNER_QUOTA_PREMIUM, freeHistoryDays: MESSAGE_RETENTION_DAYS, premiumHistoryDays: premiumRetentionDays(), attachmentBytes: ATTACHMENT_MAX_BYTES, premiumAttachmentBytes: ATTACHMENT_MAX_BYTES_PREMIUM },
    attachMax: attachMaxFor(me),                              // this identity's per-file limit
    // Payment-method availability is only actionable by the root (who pays), and
    // only the root can reach checkout — so don't surface it to other members.
    ...(isRoot ? {
      cardConfigured: !!(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_PRICE_ID),
      moneroConfigured: !!process.env.NOWPAYMENTS_API_KEY,
      cardSubscription: cardSubState(rootAcc, root.id),   // null | { renews }
    } : {}),
  });
});

const rootOnlyOr403 = (req, res, me) => {
  const root = treeRootUser(me);
  if (!root || me.id !== root.id || root.accountId !== req.accountId) {
    res.status(403).json({ error: 'Only the network root can upgrade this network.' });
    return false;
  }
  return true;
};

app.post('/api/billing/stripe/checkout', billingLimiter, async (req, res) => {
  const KEY = process.env.STRIPE_SECRET_KEY, PRICE = process.env.STRIPE_PRICE_ID;
  if (!KEY || !PRICE) return res.status(503).json({ error: 'Card payments are not configured yet.' });
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me || !rootOnlyOr403(req, res, me)) return;
  const origin = originFor(req);
  if (!origin) return res.status(500).json({ error: 'Server origin not configured — set PUBLIC_ORIGIN.' });
  // A card subscription that still renews already pays for this network.
  if (cardSubState(accountById(req.accountId), me.id)?.renews) return res.status(409).json({ error: 'This network already has a card subscription. Cancel it first to change how you pay.' });
  const form = new URLSearchParams({
    mode: 'subscription',
    'line_items[0][price]': PRICE,
    'line_items[0][quantity]': '1',
    // Stripe fills in {CHECKOUT_SESSION_ID}; the app confirms it on return.
    success_url: origin + '/launch?billing=success&session_id={CHECKOUT_SESSION_ID}',
    cancel_url: origin + '/launch?billing=cancel',
    // v71: an opaque one-time reference instead of the internal account id.
    client_reference_id: billingRef(req.accountId, getPublicId(me.id)),
    // Premium is per network: name the network being paid for (public id, opaque).
    'metadata[rootId]': getPublicId(me.id),
    'subscription_data[metadata][rootId]': getPublicId(me.id),
  });
  try {
    const r = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    const j = await r.json();
    if (!r.ok) return providerFailed(res, 'Stripe checkout', r.status, j?.error?.code || j?.error?.type, CARD_PAGE_FAILED);
    res.json({ url: j.url });
  } catch (e) { res.status(502).json({ error: 'Payment provider unreachable' }); }
});

// The buyer's return from checkout: look the session up at Stripe and credit it if
// paid. Premium then doesn't depend on the webhook arriving (it may be late,
// retried, or misconfigured); the two can't double-credit (applyCheckoutSession).
app.post('/api/billing/stripe/confirm', billingLimiter, async (req, res) => {
  const KEY = process.env.STRIPE_SECRET_KEY;
  if (!KEY) return res.status(503).json({ error: 'Card payments are not configured.' });
  const { sessionId } = req.body || {};
  if (typeof sessionId !== 'string' || !/^cs_[A-Za-z0-9_]{8,250}$/.test(sessionId)) return bad(res, 'Invalid input');
  let s;
  try {
    const r = await fetch(`https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(sessionId)}`, { headers: { Authorization: `Bearer ${KEY}` }, signal: AbortSignal.timeout(10000) });
    s = await r.json();
    if (!r.ok) return res.status(r.status === 404 ? 404 : 502).json({ error: r.status === 404 ? 'Unknown checkout session.' : 'Payment provider error' });
  } catch { return res.status(502).json({ error: 'Payment provider unreachable' }); }
  // Only the account that started this checkout can confirm it.
  const acc = checkoutAccount(s);
  if (!acc || acc.id !== req.accountId) return res.status(403).json({ error: 'Access denied' });
  if (s.payment_status !== 'paid') return res.json({ ok: true, paid: false });
  const root = applyCheckoutSession(s);
  res.json({ ok: true, paid: true, premiumUntil: root ? root.premiumUntil || null : null });
});

// Card subscriptions paying for THIS network (subscription id → root id, recorded
// at checkout), and whether each still renews.
const cardSubsFor = (acc, rootId) => (acc && acc.stripeSubs ? Object.keys(acc.stripeSubs).filter(s => acc.stripeSubs[s] === rootId) : []);
// v72 M5: end a card subscription NOW (not at period end). True when Stripe confirms
// it's cancelled (or it no longer exists); false when that couldn't be done.
const cancelStripeSubNow = async (subId) => {
  const KEY = process.env.STRIPE_SECRET_KEY;
  if (!KEY) return false;
  try {
    const r = await fetch(`https://api.stripe.com/v1/subscriptions/${encodeURIComponent(subId)}`, { method: 'DELETE', headers: { Authorization: `Bearer ${KEY}` } });
    const j = await r.json().catch(() => ({}));
    return (r.ok && j.status === 'canceled') || j?.error?.code === 'resource_missing';
  } catch { return false; }
};
const queueStripeCancel = (subId) => {
  dbCache.serverMeta = dbCache.serverMeta || {};
  const q = (dbCache.serverMeta.pendingStripeCancels = dbCache.serverMeta.pendingStripeCancels || []);
  if (!q.some(x => x.sub === subId)) q.push({ sub: subId, at: Date.now(), tries: 1 });
  console.error(`[billing] could not cancel Stripe subscription ${subId} now — queued, retrying every 10 minutes`);
  persistDB('serverMeta');
};
const retryStripeCancels = async () => {
  const q = dbCache.serverMeta && dbCache.serverMeta.pendingStripeCancels;
  if (!dbLoaded || !Array.isArray(q) || !q.length) return;
  const keep = [];
  for (const x of q) {
    if (await cancelStripeSubNow(x.sub)) { console.log(`[billing] queued Stripe cancel done: ${x.sub}`); continue; }
    x.tries = (x.tries || 0) + 1;
    if (Date.now() - x.at < 30 * 864e5) keep.push(x);
    else console.error(`[billing] GAVE UP cancelling Stripe subscription ${x.sub} after 30 days — cancel it in the Stripe dashboard`);
  }
  dbCache.serverMeta.pendingStripeCancels = keep;
  persistDB('serverMeta');
};
setInterval(retryStripeCancels, 10 * 60 * 1000);
const cardSubState = (acc, rootId) => {
  const subs = cardSubsFor(acc, rootId);
  if (!subs.length) return null;
  return { renews: subs.some(s => !(acc.stripeSubsCanceled && acc.stripeSubsCanceled[s])) };
};
// Cancel the card subscription: it stops renewing, and the time already paid for
// stays (Stripe's cancel_at_period_end).
app.post('/api/billing/stripe/cancel', billingLimiter, async (req, res) => {
  const KEY = process.env.STRIPE_SECRET_KEY;
  if (!KEY) return res.status(503).json({ error: 'Card payments are not configured.' });
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me || !rootOnlyOr403(req, res, me)) return;
  const acc = accountById(req.accountId);
  const subs = cardSubsFor(acc, me.id).filter(s => !(acc.stripeSubsCanceled && acc.stripeSubsCanceled[s]));
  if (!subs.length) return res.status(404).json({ error: 'There is no card subscription to cancel for this network.' });
  let ok = 0;
  for (const sub of subs) {
    try {
      const r = await fetch(`https://api.stripe.com/v1/subscriptions/${encodeURIComponent(sub)}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ cancel_at_period_end: 'true' }),
      });
      const j = await r.json().catch(() => ({}));
      // Counted as cancelled only when Stripe's own answer (the updated subscription)
      // says it won't renew — or it's already gone on Stripe's side.
      const stops = r.ok && (j.cancel_at_period_end === true || j.status === 'canceled' || j.cancel_at != null);
      if (!stops && r.ok) console.error(`[billing] Stripe accepted the cancel for ${sub} but still reports it renewing`);
      if (stops || j?.error?.code === 'resource_missing') { acc.stripeSubsCanceled = acc.stripeSubsCanceled || {}; acc.stripeSubsCanceled[sub] = true; ok++; }
    } catch { /* unreachable: reported below */ }
  }
  persistDB();
  if (!ok) return res.status(502).json({ error: 'Could not reach the payment provider. Try again in a moment.' });
  res.json({ ok: true, premiumUntil: me.premiumUntil || null });
});

// Undo a cancellation: the subscription renews again (possible until the paid
// period ends — after that it has ended at Stripe and the network subscribes anew).
app.post('/api/billing/stripe/resume', billingLimiter, async (req, res) => {
  const KEY = process.env.STRIPE_SECRET_KEY;
  if (!KEY) return res.status(503).json({ error: 'Card payments are not configured.' });
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me || !rootOnlyOr403(req, res, me)) return;
  const acc = accountById(req.accountId);
  const subs = cardSubsFor(acc, me.id).filter(s => acc.stripeSubsCanceled && acc.stripeSubsCanceled[s]);
  if (!subs.length) return res.status(404).json({ error: 'There is no cancelled card subscription to resume.' });
  let ok = 0, ended = 0;
  for (const sub of subs) {
    try {
      const r = await fetch(`https://api.stripe.com/v1/subscriptions/${encodeURIComponent(sub)}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ cancel_at_period_end: 'false' }),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.status !== 'canceled') { delete acc.stripeSubsCanceled[sub]; ok++; }
      else if (j?.error?.code === 'resource_missing' || j.status === 'canceled' || /canceled subscription/i.test(j?.error?.message || '')) {
        // Fully ended at Stripe: forget it, so a new checkout is allowed.
        delete acc.stripeSubsCanceled[sub]; delete acc.stripeSubs[sub]; ended++;
      }
    } catch { /* unreachable: reported below */ }
  }
  persistDB();
  if (ok) return res.json({ ok: true });
  if (ended) return res.status(409).json({ error: 'That subscription has already ended. Subscribe again to renew Premium.', code: 'ended' });
  res.status(502).json({ error: 'Could not reach the payment provider. Try again in a moment.' });
});

// ---- NOWPayments Monero integration -----------------------------------------
// Create: POST to NOWPayments to get a deposit address and XMR amount.
// Check:  GET payment status from NOWPayments (polling fallback).
// IPN:    NOWPayments POSTs to /api/billing/monero/ipn on status changes;
//         on "finished" or "confirmed" we grant premium automatically.

app.post('/api/billing/monero/create', billingLimiter, async (req, res) => {
  const NP_KEY = process.env.NOWPAYMENTS_API_KEY;
  if (!NP_KEY) return res.status(503).json({ error: 'Monero payments are not configured yet.' });
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me || !rootOnlyOr403(req, res, me)) return;
  const origin = originFor(req);
  if (!origin) return res.status(500).json({ error: 'Server origin not configured — set PUBLIC_ORIGIN.' });
  const prId = uuid('xmr_');   // v71: also the provider's order_id (opaque — not the account id)
  try {
    const r = await fetch(NP_API + '/payment', {
      method: 'POST',
      headers: { 'x-api-key': NP_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        price_amount: PREMIUM_USD,
        price_currency: 'usd',
        pay_currency: 'xmr',
        order_id: prId,
        order_description: 'Arbor Premium — 30 days',
        ipn_callback_url: origin + '/api/billing/monero/ipn',
        is_fixed_rate: false,
      }),
    });
    const j = await r.json();
    if (!r.ok) return providerFailed(res, 'NOWPayments payment', r.status, j?.code || j?.statusCode, MONERO_CREATE_FAILED);
    // Store locally so we can map the NOWPayments payment_id back to an account.
    // Keep the requester's most recent PENDING requests too (capped at 2 + the
    // new one): deleting them all meant a user who generated a fresh address but
    // then paid a previously issued one would never receive their premium days
    // (the IPN's payment_id would no longer map to anything).
    const fresh = (dbCache.xmrPayments || []).filter(p => Date.now() - p.createdAt < 90 * 864e5);
    const minePendingIds = new Set(fresh
      .filter(p => p.accountId === req.accountId && p.status !== 'paid')
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, 2).map(p => p.id));
    dbCache.xmrPayments = fresh.filter(p =>
      p.accountId !== req.accountId || p.status === 'paid' || minePendingIds.has(p.id));
    const pr = {
      id: prId, accountId: req.accountId, rootId: me.id, // the network this payment is for
      npPaymentId: String(j.payment_id),
      address: j.pay_address, amountXmr: j.pay_amount,
      createdAt: Date.now(), status: 'pending',
    };
    dbCache.xmrPayments.push(pr);
    persistDB();
    res.json({ requestId: pr.id, address: pr.address, amountXmr: pr.amountXmr, usd: PREMIUM_USD });
  } catch (e) { console.error('[billing] NOWPayments create:', e.message); res.status(502).json({ error: 'The Monero payment service is unreachable. Try again shortly.' }); }
});

app.post('/api/billing/monero/check', billingLimiter, async (req, res) => {
  const NP_KEY = process.env.NOWPAYMENTS_API_KEY;
  if (!NP_KEY) return res.status(503).json({ error: 'Monero payments are not configured yet.' });
  const { requestId } = req.body || {};
  if (!isStr(requestId, 128)) return bad(res, 'Invalid input');
  const pr = (dbCache.xmrPayments || []).find(p => p.id === requestId && p.accountId === req.accountId);
  if (!pr) return res.status(404).json({ error: 'Unknown payment request' });
  if (pr.status === 'paid') return res.json({ status: 'paid' });
  try {
    const r = await fetch(NP_API + '/payment/' + pr.npPaymentId, {
      headers: { 'x-api-key': NP_KEY },
    });
    const j = await r.json();
    // Re-check AFTER the await: the NOWPayments IPN can land while we were
    // waiting on this fetch and grant premium first. Without this re-check a
    // single payment could be granted twice (once by the IPN, once here).
    if (pr.status === 'paid') return res.json({ status: 'paid' });
    if (j.payment_status === 'finished' || j.payment_status === 'confirmed') {
      pr.status = 'paid';
      const root = rootForPayment(pr.accountId, pr.rootId);
      if (root) grantPremium(root.id, PREMIUM_DAYS_PER_PAYMENT);
      persistDB();
      return res.json({ status: 'paid' });
    }
    res.json({
      status: 'pending',
      paymentStatus: j.payment_status || 'waiting',
      receivedXmr: j.actually_paid || 0,
      neededXmr: j.pay_amount || pr.amountXmr,
    });
  } catch (e) { console.error('[billing] NOWPayments check:', e.message); res.status(502).json({ error: 'Could not check the payment right now. Try again shortly.' }); }
});

// Delete the entire network (root-only). Used from the archived panel, but
// works for any root. Removes every node, message, invite, prekey, identity,
// backup and attachment in the tree. Accounts themselves survive (they may
// own nodes in other trees).
// Remove a set of nodes and EVERYTHING keyed to them: their sent messages, their
// recipient rows, scheduled envelopes they sent (and their slots in others'),
// attachments, prekeys, Signal identities, state backups, invites, hub edges,
// acks/reactions they authored, visitor/group references to them. Shared by
// network deletion and account deletion (V8 M-7).
const purgeNodes = async (internalIds) => {
  const goneIds = new Set(internalIds);
  const publicIds = internalIds.map(getPublicId);
  const gonePub = new Set(publicIds);
  // Surviving networks these nodes belonged to should rotate their key (V8 phase 2).
  for (const id of internalIds) {
    const u = dbCache.users.find(x => x.id === id);
    const r = u && treeRootUser(u);
    if (r && !goneIds.has(r.id)) flagRotation(r);
  }
  dropMembershipFor(gonePub);
  await messagesStore.pruneNodes(internalIds, publicIds);
  await scheduledStore.deleteByNodes(internalIds);   // (slots in others' queued sends: dropped at fire time)
  for (const id of internalIds) {
    await attachmentsStore.deleteByOwner(id);
    delete dbCache.prekeys[id];
    delete dbCache.signalIdentities[id];
    await backupsStore.delete(id);
  }
  // (v72: their acks/reactions/tombstones are removed by messagesStore.pruneNodes above.)
  // Scrub references held on OTHER nodes (group membership / visitor lists).
  for (const u of dbCache.users) {
    if (goneIds.has(u.id)) continue;
    if (u.inviteeGroups) for (const id of Object.keys(u.inviteeGroups)) if (goneIds.has(id)) delete u.inviteeGroups[id];
    if (u.groupVisitors) for (const g of Object.keys(u.groupVisitors)) {
      u.groupVisitors[g] = (u.groupVisitors[g] || []).filter(id => !goneIds.has(id));
      if (!u.groupVisitors[g].length) delete u.groupVisitors[g];
    }
  }
  dbCache.users = dbCache.users.filter(u => !goneIds.has(u.id));
  dropHubEdgesFor(goneIds);
  dbCache.accountHubInvites = (dbCache.accountHubInvites || []).filter(x => !goneIds.has(x.fromHub));
  dbCache.invites = dbCache.invites.filter(i => !goneIds.has(i.inviterId));
};
// Delete an entire network. Returns the set of member accounts (to notify).
const purgeTree = async (rootId) => {
  const doomed = dbCache.users.filter(u => u.id === rootId || String(u.path).startsWith(rootId + '/') || u.path === rootId);
  const memberAccounts = new Set(doomed.map(u => u.accountId));
  await purgeNodes(doomed.map(u => u.id));
  return { memberAccounts, removed: doomed.length };
};

app.post('/api/tree/delete', billingLimiter, async (req, res) => {
  const { nodeId } = req.body || {};
  if (!isStr(nodeId, 128)) return bad(res, 'Invalid input');
  const me = ownNodeOr403(req, res, nodeId);
  if (!me || !rootOnlyOr403(req, res, me)) return;
  if (!(await reauthOr403(req, res))) return;                    // v72 M4
  const rootId = String(me.path || me.id).split('/')[0];
  // v72: a card subscription paying for this network ends WITH it (v71 left it
  // running: the owner kept being charged for a network that no longer existed).
  // Cancelled immediately, before anything is deleted — if Stripe can't be reached,
  // nothing is deleted and the owner is told to try again.
  const acc = accountById(req.accountId);
  const subs = cardSubsFor(acc, rootId);
  if (subs.length) {
    if (!process.env.STRIPE_SECRET_KEY) return res.status(503).json({ error: 'This network has a card subscription, and card payments aren’t configured on this server right now, so it can’t be stopped. Try again later.' });
    for (const sub of subs) {
      if (!(await cancelStripeSubNow(sub))) return res.status(502).json({ error: 'Couldn’t reach the payment provider to stop this network’s card subscription, so nothing was deleted. Try again in a moment.' });
      delete acc.stripeSubs[sub];
      if (acc.stripeSubsCanceled) delete acc.stripeSubsCanceled[sub];
    }
  }
  const { memberAccounts, removed } = await purgeTree(rootId);
  persistDB();
  notifyPayload(memberAccounts, { type: 'BILLING', reason: 'deleted', ts: Date.now() });
  for (const accId of memberAccounts) sendPushToAccount(accId, 'Arbor', 'This network was permanently deleted by its root.');
  res.json({ ok: true, removed });
});

// ---- Account deletion (V8 M-7) -------------------------------------------------
// The privacy policy promised account deletion but no path existed — deleting a
// network left the account row (username hash, password hash, wrap salt, default
// profile, billing linkage) behind forever. This endpoint erases the account:
//   - requires re-authentication (the account's auth value, not just a session);
//   - networks the account OWNS are deleted entirely — but only when the caller
//     explicitly confirms (deleteOwnedNetworks: true) if other people are in them;
//   - member nodes elsewhere are removed and their invitees are re-parented to
//     the removed node's own inviter, INHERITING its group, so the rest of that
//     tree keeps working and nobody is dropped across a compartment wall;
//   - sessions, recovery blob, push subscriptions, parked hub invites, pending
//     payment records and default-profile photo go with it; any live Stripe
//     subscription is cancelled (best effort) so a deleted user is never billed.
const accountDeleteLimiter = accountLimiter(60 * 60 * 1000, 10);
const reparentChildrenUp = (node) => {
  const parent = dbCache.users.find(u => u.id === node.invitedBy);
  if (!parent) return;
  const nodeGroups = parent.inviteeGroups ? parent.inviteeGroups[node.id] : undefined;
  for (const u of dbCache.users) {
    if (u.path.startsWith(node.path + '/')) {
      u.path = parent.path + u.path.slice(node.path.length);                 // drop the node's path segment
      u.level = u.path.split('/').length - 1;
      if (u.invitedBy === node.id) {
        u.invitedBy = parent.id;
        if (nodeGroups != null) { parent.inviteeGroups = parent.inviteeGroups || {}; parent.inviteeGroups[u.id] = nodeGroups; }
      }
    }
  }
};
app.post('/api/account/delete', accountDeleteLimiter, async (req, res) => {
  const { authHash, deleteOwnedNetworks } = req.body || {};
  if (!isStr(authHash, 512)) return bad(res, 'Invalid input');
  const acc = accountById(req.accountId);
  if (!acc) return res.status(404).json({ error: 'No account' });
  if (!(await verifyPassword(authHash, acc.passwordHash))) return res.status(403).json({ error: 'Password check failed.' });
  if (!accountById(acc.id)) return res.status(404).json({ error: 'No account' });

  const mine = dbCache.users.filter(u => u.accountId === acc.id);
  const ownedRoots = mine.filter(u => !String(u.path).includes('/'));
  const othersIn = (root) => dbCache.users.filter(u => u.accountId !== acc.id && (u.path === root.id || String(u.path).startsWith(root.id + '/'))).length;
  const shared = ownedRoots.filter(r => (r.treeMode || '') !== 'HUB' && othersIn(r) > 0);
  if (shared.length && deleteOwnedNetworks !== true) {
    return res.status(409).json({
      error: 'You own networks that other people are in. Deleting your account deletes those networks for everyone.',
      code: 'owns-networks',
      // Names are encrypted; the app labels these from its own decrypted copy.
      networks: shared.map(r => ({ id: getPublicId(r.id), members: othersIn(r) + 1 })),
    });
  }
  const affected = new Set();
  for (const r of ownedRoots) {
    const { memberAccounts } = await purgeTree(r.id);
    for (const a of memberAccounts) affected.add(a);
  }
  // Remaining (member) nodes: re-parent their invitees upward, then remove them —
  // deepest first so a node's own re-parenting sees a still-valid parent chain.
  const memberNodes = dbCache.users.filter(u => u.accountId === acc.id)
    .sort((a, b) => b.path.split('/').length - a.path.split('/').length);
  for (const n of memberNodes) {
    for (const a of accountsForUsers(ancestorsOf(n))) affected.add(a);
    for (const a of accountsForUsers(subtreeOf(n))) affected.add(a);
    reparentChildrenUp(n);
    await purgeNodes([n.id]);
  }
  // Stop every card subscription so a deleted user is never billed again. v72 M5:
  // v71 fired the request and forgot it — if Stripe was unreachable the charges
  // continued. Now each is cancelled before we answer; any that fail are kept in a
  // retry queue (serverMeta.pendingStripeCancels, retried every 10 minutes).
  for (const subId of Object.keys(acc.stripeSubs || {})) {
    if (!(await cancelStripeSubNow(subId))) queueStripeCancel(subId);
  }
  dbCache.sessions = dbCache.sessions.filter(s => s.accountId !== acc.id);
  dbCache.recovery = (dbCache.recovery || []).filter(r => r.accountId !== acc.id);
  dbCache.subscriptions = dbCache.subscriptions.filter(s => s.accountId !== acc.id);
  dbCache.accountHubInvites = (dbCache.accountHubInvites || []).filter(x => x.toAccount !== acc.id);
  dbCache.xmrPayments = (dbCache.xmrPayments || []).filter(p => p.accountId !== acc.id);
  // v72: open checkout references (account id ↔ network) go too.
  for (const [k, v] of Object.entries(dbCache.billingRefs || {})) if (v && v.accountId === acc.id) delete dbCache.billingRefs[k];
  dbCache.accounts = dbCache.accounts.filter(a => a.id !== acc.id);
  persistDB();
  // Drop this account's live event streams and its session cookie.
  for (const c of clients.filter(c => c.accountId === acc.id)) { try { c.res.end(); } catch {} }
  clients = clients.filter(c => c.accountId !== acc.id);
  affected.delete(acc.id);
  notify(affected);
  sweepAvatars();
  clearSessionCookies(res);
  res.json({ ok: true });
});

// NOWPayments IPN webhook is registered BEFORE the auth middleware (see above)
// so it can receive unauthenticated POSTs from NOWPayments servers.

// ---------------------------------------------------------------------------
// Liveness probe for systemd/uptime monitors — MUST be registered before the
// static SPA handler or its catch-all serves index.html for this path.
// Deliberately unauthenticated and content-free: a bare 200 leaks nothing.
app.get('/healthz', (req, res) => res.json({ ok: true }));

// Static SPA (served from dist only).
// ---------------------------------------------------------------------------
// The link-preview card is fetched by other apps (iMessage, Instagram, etc.), so it
// alone opts out of helmet's same-origin CORP. It's a public marketing image.
app.get('/og-image.png', (req, res, next) => { res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin'); res.setHeader('Cache-Control', 'public, max-age=86400'); next(); });
app.use(express.static(path.join(__dirname, 'public')));
// Serve the landing page and its script from /public
app.get(['/start', '/landing'], (req, res) => {
  res.set('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'start.html'), (err) => {
    if (err) { console.error('start.html:', err); res.status(500).send('Could not load page'); }
  });
});
app.get('/start.js', (req, res) => {
  res.set('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'start.js'), (err) => {
    if (err) { console.error('start.js:', err); res.status(404).end(); }
  });
});
// Root is the marketing site; the app lives at /launch (SPA catch-all). Installed
// home-screen PWAs launch '/' in standalone mode and launch-redirect.js forwards
// them to /launch. Must be registered BEFORE express.static(DIST_PATH) so dist's
// index.html no longer serves '/'.
app.get('/', (req, res) => {
  res.set('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'start.html'), (err) => {
    if (err) { console.error('start.html (root):', err); res.status(500).send('Could not load page'); }
  });
});
// Legal pages (static HTML in /public), served at clean URLs.
for (const [route, file] of [['/privacy', 'privacy.html'], ['/terms', 'terms.html']]) {
  app.get(route, (req, res) => {
    res.set('Cache-Control', 'no-cache');
    res.sendFile(path.join(__dirname, 'public', file), (err) => {
      if (err) { console.error(file + ':', err); res.status(404).end(); }
    });
  });
}
app.use(express.static(DIST_PATH));
app.get('*', (req, res) => {
  const indexPath = path.join(DIST_PATH, 'index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.status(404).send('Build not found. Run "npm run build".');
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  // body-parser faults carry a status (413 too-large, 400 bad JSON) — pass it through
  const status = err?.status || err?.statusCode;
  if (err?.type === 'entity.too.large' || status === 413) {
    return res.status(413).json({ error: 'Payload too large' });
  }
  if (err?.type === 'entity.parse.failed' || err?.type === 'entity.verify.failed' || (err instanceof SyntaxError && status === 400)) {
    return res.status(400).json({ error: 'Malformed request body' });
  }
  console.error('Unhandled error:', err?.message);
  res.status(500).json({ error: 'Internal error' });
});

// Background maintenance: expire messages (TTL) and prune dead sessions.
setInterval(async () => {
  const now = Date.now();
  const beforeSessions = dbCache.sessions.length;
  await messagesStore.sweepExpired(now);
  await attachmentsStore.sweepExpired(now);
  dbCache.sessions = dbCache.sessions.filter(s => s.expiresAt > now);
  // Opt-in retention: clients persist their own decrypted copies (decrypt-once
  // design), so the server only needs to hold ciphertext long enough for every
  // device to come online. Without a bound, db.json grows forever (every media
  // message's ciphertext) and each debounced persist rewrites all of it.
  // Set MESSAGE_RETENTION_DAYS (e.g. 30) to enable. Devices offline longer than
  // the window won't receive those messages — pick generously.
  // v71 H1: a retention bound is now ON by default (90 days) — without one the
  // table only ever grows. MESSAGE_RETENTION_DAYS=0 explicitly keeps forever.
  const retDays = MESSAGE_RETENTION_DAYS;
  if (retDays > 0) {
    // Free window for everyone except members of Premium networks, who keep theirs
    // for the Premium window (a year); then the Premium window for all.
    // v72 M8: one index pass (v71: isTreePremium per root, each scanning all users).
    const { byRoot, accounts } = networkIndex();
    const keep = [];
    for (const s of byRoot.values()) if (s.root && premiumGiven(s.root, accounts.get(s.root.accountId))) for (const id of s.ids) keep.push(id);
    await messagesStore.sweepOlderThan(now - retDays * 864e5, keep);
    await messagesStore.sweepOlderThan(now - premiumRetentionDays() * 864e5);
  }
  if (beforeSessions !== dbCache.sessions.length) persistDB('sessions');
}, 60 * 1000);

// Acks, reactions and tombstones must not outlive their message. On Postgres the
// first two cascade with the message row; this hourly sweep also covers a database
// without that cascade, and expires tombstones after 7 days. Runs at boot and hourly.
const sweepMessageMeta = async () => {
  if (!dbLoaded) return;
  try { await metaStore.sweep(); }
  catch (e) { console.error('[sweep] message metadata:', e.message); }
  // v72 M7: re-encrypted backups staged by a password change that never committed.
  try { await backupsStore.clearStaleStages(STAGE_MAX_AGE_MS); }
  catch (e) { console.error('[sweep] staged backups:', e.message); }
};
setInterval(sweepMessageMeta, 60 * 60 * 1000);

await initDB();
// One-time migration: hash any legacy cleartext usernames at rest. Idempotent —
// once an account carries usernameHash (and no `username`), this is a no-op.
{
  let migrated = 0;
  for (const a of dbCache.accounts || []) {
    if (a.username && !a.usernameHash) { a.usernameHash = usernameHash(a.username); delete a.username; migrated++; }
  }
  // Flush synchronously (not the debounced persistDB) so the hashing is durable
  // even if the process is restarted immediately after boot.
  if (migrated) { await persistSnapshots(dbCache); console.log(`[migrate] hashed ${migrated} legacy username(s) at rest`); }
}
// One-time V8 data migrations (idempotent; each is a no-op once applied).
{
  let premMoved = 0, avMoved = 0, avDropped = 0;
  // H-4: paid premium used to live on the ACCOUNT. Move any remaining balance
  // onto that account's primary network (the one it was, in practice, paying for).
  for (const a of dbCache.accounts || []) {
    if (a.premiumUntil) {
      const r = primaryRootOf(a.id);
      if (r) { r.premiumUntil = Math.max(r.premiumUntil || 0, a.premiumUntil); r.archiveNotifiedAt = a.archiveNotifiedAt || r.archiveNotifiedAt; premMoved++; }
      delete a.premiumUntil; delete a.archiveNotifiedAt;
    }
  }
  // H-5 + M-3: inline avatars move into the content-addressed avatars table,
  // passing through the server-side metadata strip on the way (so photos stored
  // by a pre-fix client are cleaned too). Anything that fails validation is dropped.
  const migrateAvatar = async (holder) => {
    if (!holder || typeof holder.avatar !== 'string') return;
    try { holder.avatarHash = await storeAvatar(holder.avatar); avMoved++; }
    catch { delete holder.avatarHash; delete holder.avatarAt; avDropped++; }
    delete holder.avatar;
  };
  for (const u of dbCache.users || []) await migrateAvatar(u);
  // v71 M4: inline sealed default profiles move to the blob table.
  for (const a of dbCache.accounts || []) {
    if (typeof a.defaultProfileCt === 'string') { const h = 'dp:' + avatarHashOf(a.defaultProfileCt); await avatarsStore.put(h, a.defaultProfileCt); a.defaultProfileRef = h; delete a.defaultProfileCt; avMoved++; }
  }
  for (const a of dbCache.accounts || []) await migrateAvatar(a.defaultProfile);
  if (premMoved || avMoved || avDropped) {
    await persistSnapshots(dbCache);
    console.log(`[migrate V8] premium→network: ${premMoved}; avatars moved+scrubbed: ${avMoved}, dropped (invalid): ${avDropped}`);
  }
  await sweepAvatars();
  await sweepMessageMeta();
}
// Grandfather: accounts that existed before the paywall launched keep free access
// for life. Set GRANDFATHER_BEFORE=YYYY-MM-DD (the launch date); safe to leave set.
if (process.env.GRANDFATHER_BEFORE) {
  const before = process.env.GRANDFATHER_BEFORE;
  let n = 0;
  for (const a of dbCache.accounts || []) {
    if (!a.compedPremium && (!a.createdDay || a.createdDay < before)) { a.compedPremium = true; n++; }
  }
  if (n) { await persistSnapshots(dbCache); console.log(`[grandfather] ${n} pre-launch account(s) set to lifetime free`); }
}
const httpServer = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Arbor server (V6) on port ${PORT}`);
  // Call-path privacy posture (see /api/rtc/config).
  if (!process.env.TURN_URL) {
    if (process.env.ALLOW_PUBLIC_TURN === '1') {
      console.warn('[rtc] No TURN_URL set and ALLOW_PUBLIC_TURN=1 — calls that need a relay will use a THIRD-PARTY public TURN server, which sees both parties\' IP addresses. Set TURN_URL to a self-hosted coturn to avoid this.');
    } else {
      console.warn('[rtc] No TURN_URL set — calls use STUN only and may fail on symmetric-NAT/CGNAT networks. Set TURN_URL (self-hosted coturn) for reliability, or ALLOW_PUBLIC_TURN=1 to accept a third-party relay that sees participant IPs.');
    }
  }
  if (process.env.TURN_URL && !process.env.TURN_SECRET && process.env.TURN_USERNAME) {
    console.warn('[rtc] TURN uses a STATIC long-term credential handed to every account and never expiring. Switch coturn to use-auth-secret and set TURN_SECRET for short-lived per-request credentials (see deploy/turnserver.conf).');
  }
  if (!process.env.STUN_URLS) {
    console.warn('[rtc] No STUN_URLS set — using public Google STUN, which sees callers\' reflexive IPs. Set STUN_URLS (e.g. your coturn) for a no-third-party call path.');
  }
});

// Graceful shutdown: persistDB() is debounced 150ms, so a bare exit on SIGTERM
// (every systemd restart/redeploy) could drop the most recent account/billing
// snapshot — including a just-granted premium payment. Flush synchronously,
// stop accepting connections, and give in-flight requests a moment to finish.
let shuttingDown = false;
const shutdown = async (sig) => {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`[shutdown] ${sig} received — flushing state`);
  if (dbLoaded) try { await flushPersist(); } catch (e) { console.error('[shutdown] snapshot flush failed:', e.message); }   // v72 B6: after any in-flight save
  httpServer.close(() => process.exit(0));
  // SSE streams hold connections open indefinitely — don't wait on them.
  setTimeout(() => process.exit(0), 3000).unref();
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

export { usersWhoCanRead, getPublicId, hashPassword, verifyPassword };
