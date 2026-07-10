const CACHE = 'esl154-v1';
const ASSETS = ['./', './index.html', './manifest.json', './icon-192.png', './icon-512.png'];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
});
self.addEventListener('fetch', e => {
  e.respondWith(caches.match(e.request).then(hit => hit || fetch(e.request).then(r => {
    if (e.request.method === 'GET' && r.ok) {
      const clone = r.clone();
      caches.open(CACHE).then(c => c.put(e.request, clone));
    }
    return r;
  }).catch(() => caches.match('./index.html'))));
});
