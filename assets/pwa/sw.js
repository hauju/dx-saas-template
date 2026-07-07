// Minimal service worker: makes the app installable and gives previously
// fetched static assets an offline fallback — without ever getting between the
// app and the live network for navigations or server-function/API calls.
//
// Strategy: cache-first ONLY for same-origin static assets (Dioxus hashes their
// filenames, so a cached copy is never stale). HTML documents and /api requests
// are left to the network so auth state and server data are always fresh.
// On localhost the worker stays fully inert so `dx serve` hot-reload is untouched.

const CACHE = 'saas-template-v1';
const DEV =
  self.location.hostname === 'localhost' || self.location.hostname === '127.0.0.1';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('fetch', (event) => {
  if (DEV) return;

  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Never intercept page navigations or server-function/API calls.
  if (req.mode === 'navigate' || url.pathname.startsWith('/api')) return;

  event.respondWith(
    (async () => {
      const cached = await caches.match(req);
      if (cached) return cached;
      const res = await fetch(req);
      if (res && res.status === 200 && res.type === 'basic') {
        const cache = await caches.open(CACHE);
        cache.put(req, res.clone());
      }
      return res;
    })(),
  );
});
