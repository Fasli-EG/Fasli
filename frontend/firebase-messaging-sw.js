// firebase-messaging-sw.js — عامل خدمة مستقل مخصص لإشعارات Firebase الحقيقية (Push) في الخلفية
// (منفصل عن sw.js اللي بيدير كاش التطبيق العادي — Firebase محتاج اسم ملف ثابت وسياق خاص بيه،
// وبيتسجّل على scope مستقل عشان ما يتعارضش مع sw.js على نفس الأصل)
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');

// نفس رابط المشروع المستخدم في كل صفحات الفرونت إند (مفيش استيراد مشترك بين الملفات في المشروع ده)
const PROJECT_URL = 'https://yxkyxxzcnxpxefodfxnl.supabase.co';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// نجيب إعدادات Firebase من السيرفر (مش مكتوبة هنا صريح) عشان لو الأدمن غيّرها من لوحة التحكم
// تتحدث تلقائياً من غير ما نرفع نسخة جديدة من الملف ده لكل المتصفحات
async function initFirebaseMessaging() {
  try {
    const res = await fetch(PROJECT_URL + '/functions/v1/get-system-settings');
    const result = await res.json();
    const data = (result && result.data) || {};
    if (!data.firebase_api_key || !data.firebase_project_id) return; // Firebase لسه مش متفعّل من لوحة التحكم

    firebase.initializeApp({
      apiKey: data.firebase_api_key,
      authDomain: data.firebase_auth_domain,
      projectId: data.firebase_project_id,
      storageBucket: data.firebase_storage_bucket,
      messagingSenderId: data.firebase_messaging_sender_id,
      appId: data.firebase_app_id,
    });

    const messaging = firebase.messaging();
    messaging.onBackgroundMessage((payload) => {
      const title = (payload.notification && payload.notification.title) || 'إشعار جديد من فَصلي';
      const body = (payload.notification && payload.notification.body) || '';
      self.registration.showNotification(title, {
        body,
        icon: './icons/icon-192.png',
        badge: './icons/icon-192.png',
      });
    });
  } catch (e) {
    // بهدوء — لو فشل تحميل الإعدادات لأي سبب، مفيش داعي نكسر عامل الخدمة كله
  }
}

initFirebaseMessaging();

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then((clientsArr) => {
      for (const c of clientsArr) {
        if ('focus' in c) return c.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow('./');
    })
  );
});
