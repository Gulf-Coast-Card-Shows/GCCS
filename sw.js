/* Gulf Coast Card Shows — Service Worker
   Strategy:
   - HTML pages (navigations): network-first, falling back to cache when offline,
     so visitors online always see the latest show data, but the app still opens
     when there's no signal (spotty venue wifi, parking lots, etc).
   - Static assets (icons/manifest): cache-first, since they rarely change.
   - Cross-origin requests (fonts, map tiles, the interest-counter Worker) are left
     alone — never intercepted — so they always hit the network normally.

   Bump CACHE_VERSION any time you want to force-refresh what's precached below
   (e.g. after adding a new page). Routine show-data edits don't need a bump —
   the network-first strategy already picks those up on the next online visit. */

const CACHE_VERSION = 'gccs-v2'; // bumped: added louisiana-card-shows.html to precache
const PRECACHE_URLS = [
  '/index.html',
  '/florida-card-shows.html',
  '/alabama-card-shows.html',
  '/mississippi-card-shows.html',
  '/georgia-card-shows.html',
  '/louisiana-card-shows.html',
  '/vendors.html',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-maskable-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .catch((err) => console.warn('SW precache skipped some URLs:', err))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_VERSION).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // never touch cross-origin (Worker API, fonts, tiles)

  // Navigations (loading a page) — network-first so content stays fresh, cache as offline fallback.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(req, copy));
          return res;
        })
        .catch(() => caches.match(req).then((cached) => cached || caches.match('/index.html')))
    );
    return;
  }

  // Everything else same-origin (icons, manifest, css/js if ever split out) — cache-first.
  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(CACHE_VERSION).then((cache) => cache.put(req, copy));
        return res;
      });
    })
  );
});

// ===== Web Push — TBD show announcements =====
// The payload sent by the Worker is JSON: { title, body, url }.
self.addEventListener('push', (event) => {
  let data = { title: 'Gulf Coast Card Shows', body: 'A show you follow has an update.', url: '/' };
  try {
    if (event.data) data = { ...data, ...event.data.json() };
  } catch (e) { /* fall back to defaults above */ }

  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icons/icon-192.png',
      badge: '/icons/icon-192.png',
      data: { url: data.url || '/' },
      tag: data.url || 'gccs-notification', // replaces any earlier notification for the same show
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientsList) => {
      for (const client of clientsList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          client.navigate(targetUrl);
          return client.focus();
        }
      }
      return self.clients.openWindow(targetUrl);
    })
  );
});