// frontend/google-link.js
// ============================================
// شريط "اربط حسابك بجوجل" الموحّد لكل الأدوار — بيظهر مرة واحدة كل جلسة تسجيل دخول لو الحساب
// لسه مش مربوط بجوجل، وبيختفي لو المستخدم ضغط "لاحقاً" أو ربط حسابه بالفعل.
// نفس المنطق يُستخدم بعدين لبانر البصمة (WebAuthn) بنفس التصميم.
// ============================================
(function () {
  const PROJECT_URL = 'https://yxkyxxzcnxpxefodfxnl.supabase.co';
  const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inl4a3l4eHpjbnhweGVmb2RmeG5sIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODQ3MTY0MTEsImV4cCI6MjEwMDI5MjQxMX0.oTWvUOrR7DBnhWQF7ym6PNRlucfsESSJovPhnkqvNZc';
  const DISMISS_KEY = 'googleLinkDismissed';

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
    // ✅ الطالب بيدخل امتحان إلكتروني ممكن يكون في نص وقت محدود — مش وقته المناسب لبانر زي ده
    if (document.body?.dataset?.suppressAccountBanners === 'true') return;
    if (sessionStorage.getItem(DISMISS_KEY)) return;
    if (!window.supabase) return; // فشل تحميل مكتبة Supabase من الـCDN — تجاهل بصمت

    try {
      // ✅ عميل مخصص بتخزين Supabase الحقيقي (persistSession: true) — ده أساسي عشان تدفق
      // OAuth (PKCE) محتاج "code_verifier" يفضل محفوظ في التخزين الحقيقي طول ما المتصفح
      // متنقل بالكامل لصفحة جوجل ورجوعه؛ لو استخدمنا عميل بدون تخزين حقيقي (زي عميل
      // session-refresh.js المشترك) بتتفقد الحالة دي تمامًا لما الصفحة تتقفل، فعملية الربط
      // كانت بتفشل بصمت بعد الرجوع من جوجل رغم إن الرابط بيرجع لصفحتنا عادي
      const client = window.supabase.createClient(PROJECT_URL, SUPABASE_ANON_KEY, {
        auth: { autoRefreshToken: false, persistSession: true, detectSessionInUrl: true },
      });

      client.auth.onAuthStateChange((event, session) => {
        if (session) {
          persist('jwtToken', session.access_token);
          persist('refreshToken', session.refresh_token);
        }
      });

      // ✅ getSession() بينتظر انتهاء أي معالجة تلقائية لرابط عائد من جوجل (detectSessionInUrl)
      // قبل ما يرجّع نتيجة — لو مفيش جلسة خالص (أول تحميل عادي، مش عودة من جوجل)، نزرعها
      // من تخزيننا الخاص (jwtToken/refreshToken) اللي باقي صفحات النظام بتقرأ منه
      const { data: existing } = await client.auth.getSession();
      if (!existing?.session) {
        const token = getStored('jwtToken');
        const refreshToken = getStored('refreshToken');
        if (!token || !refreshToken) return; // مفيش جلسة Supabase Auth كاملة أصلاً
        const { error } = await client.auth.setSession({ access_token: token, refresh_token: refreshToken });
        if (error) return;
      }

      const { data: userData, error: userError } = await client.auth.getUser();
      if (userError || !userData?.user) return;

      const identities = userData.user.identities || [];
      const hasGoogle = identities.some((i) => i.provider === 'google');
      if (hasGoogle) return;

      showBanner(client);
    } catch (e) {
      // ✅ أي فشل هنا (شبكة، توكن منتهي، إلخ) لازم يتجاهل بصمت — البانر ميزة إضافية اختيارية،
      // مش المفروض يعطّل أو يظهر أخطاء في صفحة المستخدم الأساسية
    }
  }

  function showBanner(client) {
    if (document.getElementById('googleLinkBanner')) return;

    const bar = document.createElement('div');
    bar.id = 'googleLinkBanner';
    bar.style.cssText = [
      'position:fixed', 'bottom:0', 'left:0', 'right:0', 'z-index:99999',
      'background:#0B1C33', 'color:#fff', 'padding:14px 18px',
      'display:flex', 'align-items:center', 'justify-content:center', 'gap:14px', 'flex-wrap:wrap',
      'font-family:"IBM Plex Sans Arabic","Cairo",sans-serif', 'font-size:14px',
      'box-shadow:0 -4px 16px rgba(0,0,0,.2)',
    ].join(';');

    const text = document.createElement('span');
    text.textContent = '🔗 اربط حسابك بجوجل عشان تسجّل دخولك بضغطة واحدة وتقدر تسترجع حسابك بسهولة';
    text.style.cssText = 'flex:1;min-width:200px;';

    const acceptBtn = document.createElement('button');
    acceptBtn.textContent = 'ربط الحساب بجوجل';
    acceptBtn.style.cssText = 'background:#F2B705;color:#0B1C33;border:none;padding:9px 18px;border-radius:8px;cursor:pointer;font-weight:700;font-family:inherit;font-size:14px;white-space:nowrap;';

    const dismissBtn = document.createElement('button');
    dismissBtn.textContent = 'لاحقاً';
    dismissBtn.style.cssText = 'background:transparent;color:#fff;border:1px solid rgba(255,255,255,.5);padding:9px 18px;border-radius:8px;cursor:pointer;font-family:inherit;font-size:14px;white-space:nowrap;';

    dismissBtn.onclick = () => {
      sessionStorage.setItem(DISMISS_KEY, '1');
      bar.remove();
    };

    acceptBtn.onclick = async () => {
      acceptBtn.disabled = true;
      acceptBtn.textContent = 'جارٍ التحويل لجوجل...';
      const { error } = await client.auth.linkIdentity({
        provider: 'google',
        options: { redirectTo: window.location.href },
      });
      if (error) {
        await (window.customAlert ? window.customAlert(error.message, { title: '⚠️ خطأ' }) : Promise.resolve(alert(error.message)));
        acceptBtn.disabled = false;
        acceptBtn.textContent = 'ربط الحساب بجوجل';
      }
      // ✅ لو نجح، Supabase بيحوّل المتصفح تلقائياً لصفحة جوجل ثم يرجع هنا تاني — مفيش داعي لأي كود بعد كده
    };

    bar.appendChild(text);
    bar.appendChild(acceptBtn);
    bar.appendChild(dismissBtn);
    document.body.appendChild(bar);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
