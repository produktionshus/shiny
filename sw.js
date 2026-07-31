// Service worker for PokéBinder — offline på messer/byttemarkeder.
// Strategi: app-shell network-first (deploys vinder), kortbilleder cache-first,
// TCGdex-API network-first med cache-fallback. Egne /api/-kald caches ALDRIG
// (auth/synk-data). Requests der ikke matcher røres ikke (shiny påvirkes ikke).
const VERSION = 'tcg-v1';
const SHELL = ['/tcg', '/tcg-manifest.json', '/tcg-icon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== VERSION && k !== VERSION + '-img' && k !== VERSION + '-api')
        .map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET') return;

  // egne API-kald: altid netvaerk (auth, synk, priser)
  if (url.origin === location.origin && url.pathname.startsWith('/api/')) return;

  // app-shell: network-first, cache-fallback
  if (url.origin === location.origin && SHELL.includes(url.pathname)) {
    e.respondWith(
      fetch(e.request)
        .then(r => {
          const copy = r.clone();
          caches.open(VERSION).then(c => c.put(e.request, copy));
          return r;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  // kortbilleder: cache-first (de aendrer sig aldrig)
  if (url.hostname === 'assets.tcgdex.net') {
    e.respondWith(
      caches.match(e.request).then(hit => hit || fetch(e.request).then(r => {
        if (r.ok) {
          const copy = r.clone();
          caches.open(VERSION + '-img').then(c => c.put(e.request, copy));
        }
        return r;
      }))
    );
    return;
  }

  // TCGdex-API (soegning/saet/detaljer): network-first, cache-fallback offline
  if (url.hostname === 'api.tcgdex.net') {
    e.respondWith(
      fetch(e.request)
        .then(r => {
          if (r.ok) {
            const copy = r.clone();
            caches.open(VERSION + '-api').then(c => c.put(e.request, copy));
          }
          return r;
        })
        .catch(() => caches.match(e.request))
    );
  }
  // alt andet (shiny, fonts, …): roer det ikke
});
