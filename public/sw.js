'use strict';

const CACHE = 'bullionpro-v1';

const PRECACHE = [
  '/',
  '/manifest.json',
  '/favicon.ico',
  '/favicon-192.png',
  '/favicon-512.png',
  '/login',
  '/register',
  '/pricing',
  'https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&display=swap'
];

// ── Install: precache app shell ──
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

// ── Activate: clean old caches ──
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// ── Fetch strategy ──
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // API calls: network-first, cache fallback
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkFirst(event.request));
    return;
  }

  // Google Fonts: cache-first
  if (url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com') {
    event.respondWith(cacheFirst(event.request));
    return;
  }

  // Static assets: cache-first
  if (url.origin === self.location.origin) {
    event.respondWith(cacheFirst(event.request));
    return;
  }

  // Everything else: network-only
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
});

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    return new Response('Offline', { status: 503 });
  }
}

async function networkFirst(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    const cached = await caches.match(request);
    if (cached) return cached;
    return new Response(JSON.stringify({ error: 'Offline' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
