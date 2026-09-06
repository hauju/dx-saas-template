// Minimal service worker: makes the app installable and gives previously
// fetched static assets an offline fallback — without ever getting between the
// app and the live network for navigations or server-function/API calls.
//
// Strategy: cache-first ONLY for an explicit allowlist of same-origin static
// assets: the hashed bundle under /assets/ (Dioxus renames on every change, so
// a cached copy is never stale) and the PWA manifest and icons. Everything
// else — HTML documents, /api and /auth calls, OAuth metadata, health — goes to
// the network untouched, so nothing an endpoint returns for one user can be
// served to the next from the cache, whatever path a future endpoint takes.
// On localhost the worker stays fully inert so `dx serve` hot-reload is untouched.

const CACHE_PREFIX = 'saas-template-';
const CACHE = CACHE_PREFIX + 'v2';
const STATIC_PREFIXES = ['/assets/', '/wasm/'];
const STATIC_PATHS = new Set([
  '/manifest.webmanifest',
  '/apple-touch-icon.png',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-maskable-512.png',
]);

function isStaticAsset(pathname) {
  return STATIC_PATHS.has(pathname) || STATIC_PREFIXES.some((p) => pathname.startsWith(p));
}
const DEV =
  self.location.hostname === 'localhost' || self.location.hostname === '127.0.0.1';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      // Only this app's own older caches; another app on the same origin
      // (or a dev tool) keeps its.
      const keys = await caches.keys();
      await Promise.all(
        keys.filter((k) => k.startsWith(CACHE_PREFIX) && k !== CACHE).map((k) => caches.delete(k)),
      );
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

  // Allowlist, not a blocklist: anything that is not a known static asset
  // is left to the network, navigations and server functions included.
  if (req.mode === 'navigate' || !isStaticAsset(url.pathname)) return;

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
