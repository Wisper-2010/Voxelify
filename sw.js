// Service worker for Voxelify: the app opens and plays offline after the first visit.
// - app shell (index.html, manifest, icons) is cached on install;
// - page loads: network first (updates arrive at once), cache when offline;
// - other same-origin files: from cache instantly, refreshed in the background;
// - other sites (e.g. the lyrics search on lrclib.net) are never touched.
// To ship an update of the shell, bump VERSION: old caches are deleted on activate.
const VERSION='voxelify.v1.1-12';
const SHELL = ['./', 'index.html', 'firebase-config.js', 'manifest.json', 'icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'apple-touch-icon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== VERSION && k !== 'voxelify-share').map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  // "Share → Voxelify" (Android): keep the shared files for a moment, then open the app, which adds them to the library
  if (req.method === 'POST' && url.origin === self.location.origin && url.pathname.endsWith('/share-target')) {
    e.respondWith((async () => {
      try {
        const fd = await req.formData(), files = fd.getAll('audio').filter(f => f && f.size), c = await caches.open('voxelify-share');
        let i = 0;
        for (const f of files) await c.put(new Request('./__shared/' + Date.now() + '-' + (i++)), new Response(f, { headers: { 'content-type': f.type || 'application/octet-stream', 'x-name': encodeURIComponent(f.name || 'track') } }));
      } catch (err) {}
      return Response.redirect('./index.html?shared=1', 303);
    })());
    return;
  }
  if (req.method !== 'GET' || url.origin !== self.location.origin || req.headers.has('range')) return;

  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then(res => { const copy = res.clone(); caches.open(VERSION).then(c => c.put(req, copy)); return res; })
        .catch(() => caches.match(req, { ignoreSearch: true }).then(r => r || caches.match('index.html')))
    );
    return;
  }

  e.respondWith(
    caches.match(req).then(hit => {
      const net = fetch(req)
        .then(res => { if (res.ok) { const copy = res.clone(); caches.open(VERSION).then(c => c.put(req, copy)); } return res; })
        .catch(() => hit);
      return hit || net;
    })
  );
});
