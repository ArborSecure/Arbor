const CACHE_NAME = 'arbor-v22-cache'; // v72: bumped so caches that stored query-string URLs are deleted.
// (v21 note:) // bumped: evict the old root ('/') app-shell cache so '/' serves the new marketing page and the app moves to /launch
// Precache the app shell (now served at /launch) so an OFFLINE cold launch of an
// installed PWA still reaches the app after the '/' → /launch move. Best-effort:
// a failed precache (e.g. offline during the SW update) must not fail install.
const ASSETS = ['/launch'];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS).catch(() => {})));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Network-first so fresh code/data always win (old cache-first SW could pin a
// stale, potentially vulnerable bundle — finding M7). API responses are never
// cached, so authenticated/ciphertext payloads don't linger in the cache store.
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  if (req.method !== 'GET') return; // never intercept non-GET (POSTs to /api etc.)
  if (url.pathname.startsWith('/api/')) return; // bypass SW entirely for API

  event.respondWith(
    fetch(req)
      .then((res) => {
        // Cache only same-origin static GETs as an offline fallback.
        // v72: never a URL with a query string — those carry invite codes and payment
        // session ids (?invite=, ?session_id=), which must not sit in the cache.
        if (res && res.ok && url.origin === self.location.origin && !url.search) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, copy)).catch(() => {});
        }
        return res;
      })
      // Offline fallback: the exact request if cached, else the app shell (/launch,
      // its real cache key after the move), else legacy /index.html. The old code
      // only tried /index.html, which is never populated post-move → offline miss.
      .catch(async () => (await caches.match(req)) || (await caches.match('/launch')) || (await caches.match('/index.html')))
  );
});

self.addEventListener('push', (event) => {
  let data = { title: 'Arbor Network', body: 'New secure transmission received.' };
  if (event.data) {
    try { data = event.data.json(); } catch (e) { data.body = event.data.text(); }
  }
  const isCall = data.kind === 'call';
  const options = {
    body: data.body,
    icon: '/icon-192.png',
    badge: 'data:image/svg+xml,%3Csvg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" fill=\"%2310b981\"%3E%3Ccircle cx=\"12\" cy=\"12\" r=\"10\"/%3E%3C/svg%3E',
    tag: data.tag || (isCall ? `arbor-call-${data.callId || 'x'}` : 'arbor-message'),
    renotify: true,
    // Calls demand attention: stay on screen until acted on, long ring vibration.
    requireInteraction: isCall,
    vibrate: isCall ? [400, 200, 400, 200, 400, 800, 400, 200, 400] : [100, 50, 100],
    data: { url: self.registration.scope, kind: data.kind || 'message' }
  };
  // If the app is open and visible, the message is already appearing in the chat —
  // a system notification on top of it is just noise. Suppress it.
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((wins) => {
      const appVisible = wins.some(w => w.visibilityState === 'visible');
      if (appVisible && !isCall) return; // in-app chat already shows messages; calls always notify
      return self.registration.showNotification(data.title, options);
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const isCall = event.notification.data && event.notification.data.kind === 'call';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(async (clientList) => {
      for (const client of clientList) {
        if (client.url.startsWith(self.registration.scope) && 'focus' in client) {
          // Tell the running app to check for the pending call immediately.
          if (isCall) { try { client.postMessage({ type: 'OPEN_CALL' }); } catch (e) {} }
          return client.focus();
        }
      }
      // Cold open: flag the URL so the freshly-booted app fetches pending rings.
      if (clients.openWindow) {
        const base = event.notification.data.url || self.registration.scope;
        return clients.openWindow(isCall ? base + (base.includes('?') ? '&' : '?') + 'call=1' : base);
      }
    })
  );
});
