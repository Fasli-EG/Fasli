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

  /** بيحسب مساحة السايدبار (لو موجود وظاهر في وضع الديسكتوب) عشان البانر ميغطّيهوش —
   * السايدبار (240px) بيبقى overlay مخفي في الموبايل (أقل من 901px)، مش لازم نبعد عنه وقتها */
  function getSidebarInsetPx() {
    const sidebar = document.querySelector('.sidebar');
    if (sidebar && window.innerWidth > 900) return sidebar.offsetWidth;
    return 0;
  }

  function showBanner(client) {
    if (document.getElementById('googleLinkBanner')) return;

    const bar = document.createElement('div');
    bar.id = 'googleLinkBanner';
    bar.style.cssText = [
      'position:fixed', 'bottom:0', 'left:0', `right:${getSidebarInsetPx()}px`, 'z-index:99999',
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
      try {
        await startLinkFlow(client);
      } catch (e) {
        await notify(e.message, '⚠️ خطأ');
        acceptBtn.disabled = false;
        acceptBtn.textContent = 'ربط الحساب بجوجل';
      }
    };

    bar.appendChild(text);
    bar.appendChild(acceptBtn);
    bar.appendChild(dismissBtn);
    document.body.appendChild(bar);
  }

  function notify(message, title) {
    return window.customAlert ? window.customAlert(message, { title: title || 'تنبيه' }) : Promise.resolve(alert(message));
  }

  function confirmAction(message) {
    return window.customConfirm ? window.customConfirm(message) : Promise.resolve(confirm(message));
  }

  /** يبدأ تدفق ربط جوجل (تحويل فعلي للمتصفح) — يرمي خطأ لو Supabase رفض بدء التدفق نفسه */
  async function startLinkFlow(client) {
    log('calling linkIdentity, redirectTo=', window.location.href);
    const { data, error } = await client.auth.linkIdentity({
      provider: 'google',
      options: { redirectTo: window.location.href },
    });
    log('linkIdentity result', { data, error });
    if (error) throw new Error(error.message);
    // ✅ لو نجح، Supabase بيحوّل المتصفح تلقائياً لصفحة جوجل — مفيش داعي لأي كود بعد كده
  }

  // ============================================
  // واجهة الإدارة — عرض/إلغاء ربط/إعادة ربط حساب جوجل، تُستخدم في صفحات الإعدادات
  // ============================================
  async function getReadyClient() {
    if (!window.supabase) return null;
    if (window.__fasliSessionReady) {
      try { await window.__fasliSessionReady; } catch (e) { /* تجاهل */ }
    }
    return window.__fasliSessionClient || null;
  }

  async function renderManager(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const client = await getReadyClient();
    if (!client) { container.innerHTML = ''; return; }

    container.innerHTML = '<p style="color:#6B7280;font-size:13px;">جارٍ التحميل...</p>';
    try {
      const { data: userData, error } = await client.auth.getUser();
      if (error || !userData?.user) throw new Error(error?.message || 'فشل التحميل');
      const googleIdentity = (userData.user.identities || []).find((i) => i.provider === 'google');
      renderManagerContent(container, client, googleIdentity);
    } catch (e) {
      container.innerHTML = `<p style="color:#E5484D;font-size:13px;">⚠️ ${e.message}</p>`;
    }
  }

  function renderManagerContent(container, client, googleIdentity) {
    container.innerHTML = '';

    if (googleIdentity) {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 14px;border:1px solid #E1E4E9;border-radius:10px;flex-wrap:wrap;margin-bottom:10px;';

      const info = document.createElement('span');
      const email = googleIdentity.identity_data?.email || 'حساب جوجل مربوط';
      info.textContent = `🔗 مربوط بـ ${email}`;
      info.style.cssText = 'font-size:13.5px;color:#0B1C33;';

      const unlinkBtn = document.createElement('button');
      unlinkBtn.type = 'button';
      unlinkBtn.textContent = 'إلغاء الربط';
      unlinkBtn.style.cssText = 'background:#FDEEEE;color:#E5484D;border:none;padding:7px 16px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:700;font-family:inherit;white-space:nowrap;';
      unlinkBtn.onclick = async () => {
        const ok = await confirmAction('متأكد إنك عايز تلغي ربط حسابك بجوجل؟ تقدر تربطه تاني (بنفس الحساب أو حساب تاني) في أي وقت.');
        if (!ok) return;
        unlinkBtn.disabled = true;
        unlinkBtn.textContent = 'جارٍ الإلغاء...';
        try {
          const { error } = await client.auth.unlinkIdentity(googleIdentity);
          if (error) throw new Error(error.message);
          renderManagerContent(container, client, null);
        } catch (e) {
          await notify(e.message, '⚠️ خطأ');
          unlinkBtn.disabled = false;
          unlinkBtn.textContent = 'إلغاء الربط';
        }
      };

      row.appendChild(info);
      row.appendChild(unlinkBtn);
      container.appendChild(row);

      const hint = document.createElement('p');
      hint.textContent = 'تقدر تربط حساب جوجل تاني (بريد مختلف) بعد إلغاء الحالي.';
      hint.style.cssText = 'color:#6B7280;font-size:12.5px;margin:0;';
      container.appendChild(hint);
    } else {
      const p = document.createElement('p');
      p.textContent = 'حسابك مش مربوط بجوجل دلوقتي.';
      p.style.cssText = 'color:#6B7280;font-size:13px;margin:0 0 12px;';
      container.appendChild(p);

      const linkBtn = document.createElement('button');
      linkBtn.type = 'button';
      linkBtn.textContent = '🔗 ربط الحساب بجوجل';
      linkBtn.style.cssText = 'background:#0B1C33;color:#fff;border:none;padding:10px 18px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:700;font-family:inherit;';
      linkBtn.onclick = async () => {
        linkBtn.disabled = true;
        linkBtn.textContent = 'جارٍ التحويل لجوجل...';
        try {
          await startLinkFlow(client);
        } catch (e) {
          await notify(e.message, '⚠️ خطأ');
          linkBtn.disabled = false;
          linkBtn.textContent = '🔗 ربط الحساب بجوجل';
        }
      };
      container.appendChild(linkBtn);
    }
  }

  /** موديال جاهز بيعرض واجهة الإدارة — لنفس الصفحات اللي مستخدمة لموديال البصمة */
  function openManagerModal() {
    if (document.getElementById('googleLinkModalOverlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'googleLinkModalOverlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(11,28,51,.55);z-index:100010;display:flex;align-items:center;justify-content:center;padding:20px;';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    const card = document.createElement('div');
    card.style.cssText = 'background:#fff;border-radius:16px;max-width:420px;width:100%;max-height:80vh;overflow-y:auto;padding:24px;box-shadow:0 20px 50px rgba(0,0,0,.3);font-family:"IBM Plex Sans Arabic","Cairo",sans-serif;';

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;';
    const title = document.createElement('h3');
    title.textContent = '🔗 ربط حساب جوجل';
    title.style.cssText = 'font-size:16px;font-weight:800;color:#0B1C33;margin:0;';
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.textContent = '✕';
    closeBtn.setAttribute('aria-label', 'إغلاق');
    closeBtn.style.cssText = 'background:none;border:none;font-size:20px;line-height:1;cursor:pointer;color:#6B7280;';
    closeBtn.onclick = () => overlay.remove();
    header.appendChild(title);
    header.appendChild(closeBtn);

    const contentContainer = document.createElement('div');
    contentContainer.id = 'googleLinkModalContent';

    card.appendChild(header);
    card.appendChild(contentContainer);
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    renderManager('googleLinkModalContent');
  }

  window.FasliGoogleLink = { renderManager, openManagerModal };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
