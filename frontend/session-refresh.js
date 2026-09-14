// frontend/session-refresh.js
// ============================================
// تجديد تلقائي لتوكن Supabase Auth في الخلفية — من غير ده، الجلسة كانت هتنقطع فجأة بعد
// ساعة واحدة بس (الصلاحية الافتراضية لتوكن Supabase) بدل 7 أيام زي النظام القديم.
// بيشتغل بصمت في الخلفية: يهيّئ جلسة Supabase من التوكنات المخزّنة، وبعدين أي مرة
// Supabase يجدد التوكن تلقائيًا (قبل انتهائه بشوية) بيكتب القيم الجديدة في نفس المكان
// اللي كل صفحات النظام بتقرأ منه (sessionStorage/localStorage.jwtToken).
//
// ✅ ملاحظة: العميل هنا persistSession:false عمداً (إحنا بنتحكم في التخزين بأنفسنا).
// ده معناه مينفعش يُستخدم لبدء أو استكمال أي تدفق OAuth (زي ربط جوجل) لأن حالة PKCE
// (code_verifier) محتاجة تخزين حقيقي يعيش بعد التنقل الكامل لصفحة تانية ورجوعه —
// google-link.js بيعمل عميله المستقل بتخزين حقيقي لنفس السبب ده بالظبط.
// ============================================
(function () {
  const PROJECT_URL = 'https://yxkyxxzcnxpxefodfxnl.supabase.co';
  const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inl4a3l4eHpjbnhweGVmb2RmeG5sIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ3MTY0MTEsImV4cCI6MjEwMDI5MjQxMX0.oTWvUOrR7DBnhWQF7ym6PNRlucfsESSJovPhnkqvNZc';

  function getStored(key) {
    return sessionStorage.getItem(key) || localStorage.getItem(key) || null;
  }

  function isRemembered() {
    return localStorage.getItem('fasliRememberMe') === 'true';
  }

  function persist(key, value) {
    sessionStorage.setItem(key, value);
    if (isRemembered()) localStorage.setItem(key, value);
  }

  async function init() {
    if (!window.supabase) return; // فشل تحميل مكتبة Supabase من الـCDN — تجاهل بصمت

    const token = getStored('jwtToken');
    const refreshToken = getStored('refreshToken');
    if (!token || !refreshToken) return; // مفيش جلسة Supabase Auth كاملة (حساب لسه م اتهاجرش، أو مش مسجل دخول)

    try {
      const client = window.supabase.createClient(PROJECT_URL, SUPABASE_ANON_KEY, {
        auth: { autoRefreshToken: true, persistSession: false, detectSessionInUrl: false },
      });

      const { error } = await client.auth.setSession({ access_token: token, refresh_token: refreshToken });
      if (error) return; // توكن/refresh غير صالحين — نسيب باقي الصفحة تتعامل مع 401 زي ما هي

      client.auth.onAuthStateChange((event, session) => {
        if (event === 'TOKEN_REFRESHED' && session) {
          persist('jwtToken', session.access_token);
          persist('refreshToken', session.refresh_token);
        }
      });

      // ✅ لازم نفضل ماسكين مرجع للعميل ده — Supabase بيجدول التجديد التلقائي داخليًا
      // (setTimeout قبل انتهاء الصلاحية بشوية)، ولو العميل اتنضف من الذاكرة (garbage collected)
      // التجديد مش هيحصل خالص
      window.__fasliSessionClient = client;
    } catch (e) {
      // ✅ أي فشل هنا لازم يتجاهل بصمت — تحسين خلفي اختياري، مش لازم يعطّل الصفحة الأساسية
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
