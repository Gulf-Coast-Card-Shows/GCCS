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

const CACHE_VERSION = 'gccs-v1';
const PRECACHE_URLS = [
  '/index.html',
  '/florida-card-shows.html',
  '/alabama-card-shows.html',
  '/mississippi-card-shows.html',
  '/georgia-card-shows.html',
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
