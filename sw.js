const CACHE = 'esl154-v5';
const ASSETS = ['./index.html', './manifest.json', './icon-192.png', './icon-512.png', './apple-touch-icon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  // Navigations: always answer with the cached index.html itself,
  // never a redirect. Fixes Safari's "response served by service
  // worker has redirections" error.
  if (e.request.mode === 'navigate') {
    e.respondWith(
      caches.match('./index.html').then(hit =>
        hit || fetch('./index.html').then(r => {
          const clone = r.clone();
          caches.open(CACHE).then(c => c.put('./index.html', clone));
          return r;
        })
      )
    );
    return;
  }

  // Everything else: cache-first, and never cache redirected responses
  e.respondWith(
    caches.match(e.request).then(hit => hit || fetch(e.request).then(r => {
      if (r.ok && !r.redirected) {
        const clone = r.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
      }
      return r;
    }).catch(() => caches.match('./index.html')))
  );
});
