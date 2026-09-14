// frontend/google-link.js
// ============================================
// شريط "اربط حسابك بجوجل" الموحّد لكل الأدوار — بيظهر مرة واحدة كل جلسة تسجيل دخول لو الحساب
// لسه مش مربوط بجوجل، وبيختفي لو المستخدم ضغط "لاحقاً" أو ربط حسابه بالفعل.
// نفس المنطق يُستخدم بعدين لبانر البصمة (WebAuthn) بنفس التصميم.
//
// ✅ فيه console.log تشخيصية مؤقتة بادئة بـ [GoogleLink] عشان نلاقي بالظبط فين بيقف التدفق —
// تتشال بعد ما المشكلة تتحل نهائيًا.
// ============================================
(function () {
  const DISMISS_KEY = 'googleLinkDismissed';

  function log(...args) { console.log('[GoogleLink]', ...args); }

  /** لو Supabase رفض الربط (زي: حساب جوجل ده مربوط بحساب فَصلي تاني بالفعل)، بيرجّع
   * ?error=...&error_description=... في الرابط بدل ما يكمل الجلسة — من غيرها كنا بنتجاهلها
   * بصمت تمامًا (الصفحة تعمل reload عادي من غير أي إشارة للمشكلة) */
  function checkAndShowOAuthError() {
    const params = new URLSearchParams(window.location.search);
    const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    const err = params.get('error_description') || hashParams.get('error_description')
      || params.get('error') || hashParams.get('error');
    if (err) {
      log('OAuth error in URL:', decodeURIComponent(err));
      const message = decodeURIComponent(err).replace(/\+/g, ' ');
      if (window.customAlert) window.customAlert(message, { title: '⚠️ تعذّر الربط بجوجل' });
      else alert('تعذّر الربط بجوجل: ' + message);
      // ننضّف الرابط عشان الرسالة ميتكررش لو المستخدم عمل reload يدوي
      history.replaceState(null, '', window.location.pathname);
      return true;
    }
    return false;
  }

  async function init() {
    log('init start, href=', window.location.href);
    if (checkAndShowOAuthError()) return;

    if (document.body?.dataset?.suppressAccountBanners === 'true') { log('suppressed on this page'); return; }
    if (sessionStorage.getItem(DISMISS_KEY)) { log('dismissed earlier this session'); return; }
    if (!window.supabase) { log('window.supabase missing (CDN failed?)'); return; }

    if (window.__fasliSessionReady) {
      try { await window.__fasliSessionReady; } catch (e) { log('session-refresh init threw', e); }
    } else {
      log('window.__fasliSessionReady not found — session-refresh.js did not run?');
    }

    const client = window.__fasliSessionClient;
    if (!client) { log('no __fasliSessionClient available — no active session'); return; }
    log('reusing shared client');

    try {
      const { data: userData, error: userError } = await client.auth.getUser();
      log('getUser result', { error: userError, hasUser: !!userData?.user, identities: userData?.user?.identities });
      if (userError || !userData?.user) { log('getUser failed, stopping'); return; }

      const identities = userData.user.identities || [];
      const hasGoogle = identities.some((i) => i.provider === 'google');
      if (hasGoogle) { log('google already linked — not showing banner'); return; }

      log('no google identity yet — showing banner');
      showBanner(client);
    } catch (e) {
      log('unexpected error in init', e);
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
    acceptBtn.type = 'button';
    acceptBtn.textContent = 'ربط الحساب بجوجل';
    acceptBtn.style.cssText = 'background:#F2B705;color:#0B1C33;border:none;padding:9px 18px;border-radius:8px;cursor:pointer;font-weight:700;font-family:inherit;font-size:14px;white-space:nowrap;';

    const dismissBtn = document.createElement('button');
    dismissBtn.type = 'button';
    dismissBtn.textContent = 'لاحقاً';
    dismissBtn.style.cssText = 'background:transparent;color:#fff;border:1px solid rgba(255,255,255,.5);padding:9px 18px;border-radius:8px;cursor:pointer;font-family:inherit;font-size:14px;white-space:nowrap;';

    dismissBtn.onclick = () => {
      sessionStorage.setItem(DISMISS_KEY, '1');
      bar.remove();
    };

    acceptBtn.onclick = async () => {
      acceptBtn.disabled = true;
      acceptBtn.textContent = 'جارٍ التحويل لجوجل...';
      log('calling linkIdentity, redirectTo=', window.location.href);
      const { data, error } = await client.auth.linkIdentity({
        provider: 'google',
        options: { redirectTo: window.location.href },
      });
      log('linkIdentity result', { data, error });
      if (error) {
        await (window.customAlert ? window.customAlert(error.message, { title: '⚠️ خطأ' }) : Promise.resolve(alert(error.message)));
        acceptBtn.disabled = false;
        acceptBtn.textContent = 'ربط الحساب بجوجل';
      } else {
        log('linkIdentity call succeeded with no error — browser should now navigate to Google. If the page just reloaded instead, the redirect never happened.');
      }
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
