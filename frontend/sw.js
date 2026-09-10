// sw.js — عامل الخدمة (Service Worker) بتاع فَصلي
// بيخزّن "هيكل" التطبيق (CSS/JS/الأيقونات) للسرعة والعمل الجزئي بدون إنترنت
// لكن **مايخزّنش** أي طلب لـ Supabase (بيانات الطلاب/الدرجات/المدفوعات) — دي المفروض دايماً تيجي من الإنترنت مباشرة

const CACHE_VERSION = 'fasli-shell-v1';
const SHELL_ASSETS = [
  './style.css',
  './activity-format.js',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(SHELL_ASSETS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // ✅ أي طلب لسيرفر Supabase (بيانات حية) — بيروح للإنترنت مباشرة دايماً، مفيش تخزين مؤقت خالص
  if (url.hostname.includes('supabase.co')) {
    return; // نسيب المتصفح يتعامل مع الطلب عادي بدون تدخل
  }

  // الصفحات (HTML): نحاول الإنترنت الأول، ولو مفيش اتصال نرجع للنسخة المخزنة لو موجودة
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() => caches.match(event.request))
    );
    return;
  }

  // باقي الملفات الثابتة (CSS/JS/صور): نجرب الكاش الأول، ولو مش موجود نجيبها من الإنترنت ونخزّنها
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((response) => {
        if (response && response.status === 200 && event.request.method === 'GET') {
          const clone = response.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => cached);
    })
  );
});
