// ---------------------------------------------------------------------------
// Outbound-request address guard (security review V8, finding M-16).
//
// web-push dials whatever endpoint URL a client registers, so that URL must never
// point the server at itself, the LAN, or a cloud metadata service. The V7 filter
// checked a deny-list of textual prefixes and was bypassed by the NAT64 prefix
// (https://[64:ff9b::7f00:1]/ → 127.0.0.1) and IPv4-compatible literals
// (https://[::127.0.0.1]/). This module replaces it with:
//   - isPublicIp: IPv4 by deny-list of every special-purpose range; IPv6 by
//     ALLOW-list (global unicast 2000::/3 only), minus the global ranges that
//     embed an IPv4 address (6to4, Teredo) or are reserved/documentation.
//   - isSafePushEndpoint: URL-level check at subscribe time.
//   - safeLookup: a DNS lookup for an https.Agent that refuses to CONNECT unless
//     every resolved address is public — closing the hostname → private-IP and
//     DNS-rebinding paths at connect time, with no check-then-use gap.
// Pure functions (except safeLookup's DNS call); unit-tested in security-tests.
// ---------------------------------------------------------------------------
import net from 'node:net';
import dns from 'node:dns';

export const ipv4Public = (ip) => {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some(x => !Number.isInteger(x) || x < 0 || x > 255)) return false;
  const [a, b, c] = o;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;            // this-net, private, loopback, multicast/reserved/broadcast
  if (a === 100 && b >= 64 && b <= 127) return false;                        // CGNAT 100.64/10
  if (a === 169 && b === 254) return false;                                  // link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return false;                         // private
  if (a === 192 && b === 168) return false;                                  // private
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;            // IETF protocol assignments, TEST-NET-1
  if (a === 192 && b === 88 && c === 99) return false;                       // 6to4 relay anycast
  if (a === 198 && (b === 18 || b === 19)) return false;                     // benchmarking
  if (a === 198 && b === 51 && c === 100) return false;                      // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return false;                       // TEST-NET-3
  return true;
};

// Expand any textual IPv6 (incl. "::" compression and a dotted-quad tail) to 16 bytes.
export const ipv6Bytes = (ip) => {
  let s = ip.toLowerCase().split('%')[0];
  const v4tail = s.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4tail) {
    const o = v4tail[1].split('.').map(Number);
    if (o.some(x => x > 255)) return null;
    s = s.slice(0, -v4tail[1].length) + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (h) => (h ? h.split(':') : []);
  const head = parse(halves[0]), tail = halves.length === 2 ? parse(halves[1]) : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill('0'), ...tail];
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => { const v = parseInt(g, 16); out[2 * i] = v >> 8; out[2 * i + 1] = v & 255; });
  return out;
};

export const ipv6Public = (ip) => {
  const b = ipv6Bytes(ip);
  if (!b) return false;
  if ((b[0] & 0xe0) !== 0x20) return false;                    // only 2000::/3 — rejects ::1, ::a.b.c.d, ::ffff:*, 64:ff9b::/96, fc00::/7, fe80::/10, ff00::/8
  if (b[0] === 0x20 && b[1] === 0x02) return false;            // 2002::/16 6to4 (embeds IPv4)
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] < 0x02) return false;  // 2001::/23 IETF special (incl. Teredo 2001::/32)
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return false; // 2001:db8::/32 documentation
  return true;
};

export const isPublicIp = (ip) => {
  const fam = net.isIP(ip);
  if (fam === 4) return ipv4Public(ip);
  if (fam === 6) return ipv6Public(ip);
  return false;
};

// v71 M5: push endpoints are an ALLOW-list of the browser vendors' push services.
// v70 accepted any public HTTPS host, so an account could register unlimited
// endpoints on arbitrary third-party hosts and have this server POST to all of
// them on every message it received. Every current browser pushes through one of
// these (Chromium browsers incl. Opera/Brave/Samsung → FCM; Firefox → Mozilla
// autopush; Safari/iOS → Apple; Edge on Windows → WNS). Operators can add hosts
// with PUSH_ENDPOINT_HOSTS (comma-separated; a leading dot allows subdomains).
export const PUSH_SERVICE_HOSTS = ['fcm.googleapis.com', 'updates.push.services.mozilla.com', 'web.push.apple.com', '.notify.windows.com', '.push.apple.com'];
const extraPushHosts = () => String(process.env.PUSH_ENDPOINT_HOSTS || '').split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
export const isPushServiceHost = (host, allow = [...PUSH_SERVICE_HOSTS, ...extraPushHosts()]) =>
  allow.some(h => (h.startsWith('.') ? host.endsWith(h) && host.length > h.length : host === h));

export const isSafePushEndpoint = (raw) => {
  let u; try { u = new URL(raw); } catch { return false; }
  if (u.protocol !== 'https:' || u.username || u.password || (u.port && u.port !== '443')) return false;
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost')) return false;
  // IP literals are never a push service. (The connect-time lookup guard below
  // still refuses any non-public address a listed name might resolve to.)
  if (net.isIP(host)) return false;
  if (!/^[a-z0-9.-]+$/.test(host) || !host.includes('.')) return false; // plain DNS names only
  return isPushServiceHost(host);
};

// Connect-time guard for an https.Agent: resolve, then refuse unless EVERY
// returned address is public. `lookupFn` is injectable for tests.
export const makeSafeLookup = (lookupFn = dns.lookup) => (hostname, options, callback) => {
  if (typeof options === 'function') { callback = options; options = {}; }
  lookupFn(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return callback(err);
    const list = Array.isArray(addrs) ? addrs : [{ address: addrs, family: options.family || 4 }];
    if (!list.length || list.some(a => !isPublicIp(a.address))) {
      const e = new Error(`${hostname} resolves to a non-public address`); e.code = 'ENOTPUBLIC';
      return callback(e);
    }
    if (options.all) return callback(null, list);
    callback(null, list[0].address, list[0].family);
  });
};
export const safeLookup = makeSafeLookup();
