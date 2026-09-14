// frontend/session-refresh.js
// ============================================
// تجديد تلقائي لتوكن Supabase Auth في الخلفية — من غير ده، الجلسة كانت هتنقطع فجأة بعد
// ساعة واحدة بس (الصلاحية الافتراضية لتوكن Supabase) بدل 7 أيام زي النظام القديم.
// بيشتغل بصمت في الخلفية: يهيّئ جلسة Supabase من التوكنات المخزّنة، وبعدين أي مرة
// Supabase يجدد التوكن تلقائيًا (قبل انتهائه بشوية) بيكتب القيم الجديدة في نفس المكان
// اللي كل صفحات النظام بتقرأ منه (sessionStorage/localStorage.jwtToken).
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

    // ✅ لو الصفحة دي راجعة من ربط جوجل (أو أي OAuth تاني)، الرابط بيحتوي على توكنات/كود
    // جديد لازم Supabase يعالجه بنفسه (detectSessionInUrl) — من غير ما نكتب فوقه بتوكن قديم
    // من التخزين قبل ما يتعالج، وإلا الربط يفشل بصمت (الصفحة بترجّع تحمّل من غير ما حاجة تتغيّر)
    const hasOAuthCallback = window.location.hash.includes('access_token=')
      || new URLSearchParams(window.location.search).has('code');

    try {
      const client = window.supabase.createClient(PROJECT_URL, SUPABASE_ANON_KEY, {
        auth: { autoRefreshToken: true, persistSession: false, detectSessionInUrl: hasOAuthCallback },
      });

      client.auth.onAuthStateChange((event, session) => {
        if ((event === 'TOKEN_REFRESHED' || event === 'SIGNED_IN' || event === 'INITIAL_SESSION') && session) {
          persist('jwtToken', session.access_token);
          persist('refreshToken', session.refresh_token);
        }
      });

      if (hasOAuthCallback) {
        // ✅ نستنى Supabase يخلص معالجة الرابط ويصدر الجلسة الجديدة — بتوصلنا عن طريق
        // onAuthStateChange فوق (SIGNED_IN)، فبنستخدم getSession() بس عشان نستنى الجاهزية
        await client.auth.getSession();
      } else {
        const token = getStored('jwtToken');
        const refreshToken = getStored('refreshToken');
        if (!token || !refreshToken) return; // مفيش جلسة Supabase Auth كاملة (حساب لسه م اتهاجرش، أو مش مسجل دخول)
        const { error } = await client.auth.setSession({ access_token: token, refresh_token: refreshToken });
        if (error) return; // توكن/refresh غير صالحين — نسيب باقي الصفحة تتعامل مع 401 زي ما هي
      }

      // ✅ لازم نفضل ماسكين مرجع للعميل ده — Supabase بيجدول التجديد التلقائي داخليًا
      // (setTimeout قبل انتهاء الصلاحية بشوية)، ولو العميل اتنضف من الذاكرة (garbage collected)
      // التجديد مش هيحصل خالص
      window.__fasliSessionClient = client;
    } catch (e) {
      // ✅ أي فشل هنا لازم يتجاهل بصمت — تحسين خلفي اختياري، مش لازم يعطّل الصفحة الأساسية
    }
  }

  // ✅ باقي السكريبتات (google-link.js) بتستنى الـpromise ده قبل ما تنشئ عميل Supabase خاص بيها،
  // عشان تستخدم نفس العميل ده بدل ما تعمل GoTrueClient تاني على نفس مفتاح التخزين
  if (document.readyState === 'loading') {
    window.__fasliSessionReady = new Promise((resolve) => {
      document.addEventListener('DOMContentLoaded', () => init().then(resolve));
    });
  } else {
    window.__fasliSessionReady = init();
  }
})();
