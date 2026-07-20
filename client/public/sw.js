const CACHE_NAME = 'saree-one-v2';

// الملفات التي يجب تخزينها مؤقتاً في الإنتاج فقط
const STATIC_ASSETS = [
  '/',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch(() => {});
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // لا نتدخل في طلبات POST أو API أو WebSocket
  if (request.method !== 'GET') return;
  if (url.pathname.startsWith('/api/')) return;
  if (url.pathname.startsWith('/uploads/')) return;

  // نستخدم استراتيجية "الشبكة أولاً" - إذا فشلت، نرجع للكاش
  event.respondWith(
    fetch(request)
      .then((response) => {
        // لا نخزّن مؤقتاً إلا الردود الناجحة من نفس الأصل
        if (
          response &&
          response.status === 200 &&
          response.type === 'basic' &&
          (url.pathname === '/' || url.pathname.endsWith('.js') || url.pathname.endsWith('.css'))
        ) {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(request, responseToCache);
          });
        }
        return response;
      })
      .catch(() => {
        // عند فشل الشبكة، جرّب الكاش أولاً
        return caches.match(request).then((cached) => {
          if (cached) return cached;
          // للتنقل (navigate)، أرجع الصفحة الرئيسية المخزنة
          if (request.mode === 'navigate') {
            return caches.match('/');
          }
        });
      })
  );
});
