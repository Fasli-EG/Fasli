// frontend/webauthn.js
// ============================================
// الدخول بالبصمة/الوجه (WebAuthn) — موحّد لكل الأدوار. الملف ده بيعمل حاجتين:
// 1) بانر تلقائي بعد الدخول يقترح تفعيل البصمة لو الحساب لسه مالوش أي بصمة مسجّلة.
// 2) واجهة إدارة (window.FasliWebauthn) تقدر أي صفحة إعدادات تستخدمها لعرض/حذف/إضافة بصمات
//    من غير حدود — "لاحقاً" في البانر بيأجّل الاقتراح بس، مش بديل عن صفحة الإعدادات.
// ============================================
(function () {
  const PROJECT_URL = 'https://yxkyxxzcnxpxefodfxnl.supabase.co';
  const DISMISS_KEY = 'webauthnDismissed';

  function getStored(key) {
    return sessionStorage.getItem(key) || localStorage.getItem(key) || null;
  }

  /** بترجّع {ok, reason} بدل true/false بس — عشان لو مش مدعوم نعرف السبب بالظبط
   * (مفيدة جداً في تشخيص مشاكل الدعم جوه تطبيق الموبايل، مش بس المتصفح العادي) */
  function checkWebAuthnSupport() {
    if (!window.PublicKeyCredential) return { ok: false, reason: 'المتصفح مفيهوش PublicKeyCredential (نسخة قديمة أو WebView مش بيدعم WebAuthn)' };
    if (!navigator.credentials) return { ok: false, reason: 'المتصفح مفيهوش navigator.credentials' };
    if (!window.SimpleWebAuthnBrowser) return { ok: false, reason: 'مكتبة SimpleWebAuthn مانفعتش تتحمّل (مشكلة اتصال بالإنترنت أو حظر تحميل سكريبت خارجي)' };
    return { ok: true, reason: '' };
  }

  function supportsWebAuthn() {
    return checkWebAuthnSupport().ok;
  }

  /** بديل موحّد لـ alert() بهوية النظام (customAlert من custom-dialogs.js)، مع تراجع آمن
   * لـalert() العادية لو الملف ده اتحمّل لأي سبب من غير custom-dialogs.js */
  function notify(message, opts) {
    return window.customAlert ? window.customAlert(message, opts) : Promise.resolve(alert(message));
  }

  function confirmAction(message) {
    return window.customConfirm ? window.customConfirm(message) : Promise.resolve(confirm(message));
  }

  function guessDeviceName() {
    const ua = navigator.userAgent || '';
    if (/iphone/i.test(ua)) return 'iPhone';
    if (/ipad/i.test(ua)) return 'iPad';
    if (/android/i.test(ua)) return 'أندرويد';
    if (/macintosh|mac os/i.test(ua)) return 'ماك';
    if (/windows/i.test(ua)) return 'ويندوز';
    return 'جهاز غير معروف';
  }

  async function listCredentials(token) {
    const res = await fetch(PROJECT_URL + '/functions/v1/webauthn-list-credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: '{}',
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.message || 'فشل تحميل البصمات المسجّلة');
    return data.credentials || [];
  }

  /** يبدأ تسجيل بصمة جديدة كاملة (options -> startRegistration -> verify). يرمي خطأ لو فشل أو اتلغى. */
  async function registerNewCredential(token) {
    const optRes = await fetch(PROJECT_URL + '/functions/v1/webauthn-register-options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: '{}',
    });
    const optData = await optRes.json();
    if (!optData.success) throw new Error(optData.message || 'فشل بدء التسجيل');

    const attResp = await window.SimpleWebAuthnBrowser.startRegistration({ optionsJSON: optData.options });

    const verifyRes = await fetch(PROJECT_URL + '/functions/v1/webauthn-register-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ ...attResp, challengeId: optData.challengeId, deviceName: guessDeviceName() }),
    });
    const verifyData = await verifyRes.json();
    if (!verifyData.success) throw new Error(verifyData.message || 'فشل التفعيل');
    return verifyData;
  }

  async function deleteCredential(token, credentialId) {
    const res = await fetch(PROJECT_URL + '/functions/v1/webauthn-delete-credential', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ credentialId }),
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.message || 'فشل الحذف');
    return data;
  }

  // ============================================
  // البانر التلقائي بعد الدخول
  // ============================================
  async function initBanner() {
    if (document.body?.dataset?.suppressAccountBanners === 'true') return;
    if (sessionStorage.getItem(DISMISS_KEY)) return;
    if (!supportsWebAuthn()) return;

    const token = getStored('jwtToken');
    if (!token) return;

    try {
      const creds = await listCredentials(token);
      if (creds.length > 0) return; // البصمة مفعّلة بالفعل
      showBanner(token);
    } catch (e) {
      // ✅ أي فشل هنا لازم يتجاهل بصمت — ميزة إضافية اختيارية، مش لازم تعطّل الصفحة الأساسية
    }
  }

  function showBanner(token) {
    if (document.getElementById('webauthnBanner')) return;

    const bar = document.createElement('div');
    bar.id = 'webauthnBanner';
    const googleBar = document.getElementById('googleLinkBanner');
    const bottomOffset = googleBar ? googleBar.offsetHeight + 4 : 0;
    bar.style.cssText = [
      'position:fixed', `bottom:${bottomOffset}px`, 'left:0', 'right:0', 'z-index:99998',
      'background:#0E8074', 'color:#fff', 'padding:14px 18px',
      'display:flex', 'align-items:center', 'justify-content:center', 'gap:14px', 'flex-wrap:wrap',
      'font-family:"IBM Plex Sans Arabic","Cairo",sans-serif', 'font-size:14px',
      'box-shadow:0 -4px 16px rgba(0,0,0,.2)',
    ].join(';');

    const text = document.createElement('span');
    text.textContent = '🔒 فعّل الدخول بالبصمة أو الوجه عشان تدخل بضغطة واحدة من غير ما تكتب كلمة المرور';
    text.style.cssText = 'flex:1;min-width:200px;';

    const acceptBtn = document.createElement('button');
    acceptBtn.textContent = 'تفعيل البصمة';
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
      acceptBtn.textContent = 'جارٍ التسجيل...';
      try {
        const verifyData = await registerNewCredential(token);
        await notify(verifyData.message, { title: '✅ تم بنجاح' });
        bar.remove();
      } catch (e) {
        if (e && e.name === 'InvalidStateError') {
          await notify('⚠️ الجهاز ده مسجّل بالفعل', { title: '⚠️ تنبيه' });
        } else if (e && e.name === 'NotAllowedError') {
          // ✅ المستخدم لغى العملية أو رفض الإذن — مفيش داعي نزعجه برسالة خطأ
        } else {
          await notify('تعذّر تفعيل البصمة: ' + (e && e.message ? e.message : e), { title: '⚠️ خطأ' });
        }
        acceptBtn.disabled = false;
        acceptBtn.textContent = 'تفعيل البصمة';
      }
    };

    bar.appendChild(text);
    bar.appendChild(acceptBtn);
    bar.appendChild(dismissBtn);
    document.body.appendChild(bar);
  }

  // ============================================
  // واجهة الإدارة — تُستخدم في صفحات الإعدادات لعرض/حذف/إضافة بصمات بلا حدود
  // ============================================
  async function renderManager(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const token = getStored('jwtToken');
    if (!token) { container.innerHTML = ''; return; }

    const support = checkWebAuthnSupport();
    if (!support.ok) {
      container.innerHTML = `<p style="color:#6B7280;font-size:13px;">المتصفح ده مش بيدعم الدخول بالبصمة/الوجه.<br><span style="color:#9CA3AF;font-size:11.5px;">(${support.reason})</span></p>`;
      return;
    }

    container.innerHTML = '<p style="color:#6B7280;font-size:13px;">جارٍ التحميل...</p>';
    try {
      const creds = await listCredentials(token);
      renderManagerList(container, token, creds);
    } catch (e) {
      container.innerHTML = `<p style="color:#E5484D;font-size:13px;">⚠️ ${e && e.message ? e.message : 'فشل التحميل'}</p>`;
    }
  }

  function renderManagerList(container, token, creds) {
    container.innerHTML = '';

    if (creds.length === 0) {
      const p = document.createElement('p');
      p.textContent = 'مفيش أي بصمة مسجّلة لحسابك دلوقتي.';
      p.style.cssText = 'color:#6B7280;font-size:13px;margin:0 0 12px;';
      container.appendChild(p);
    } else {
      const list = document.createElement('div');
      list.style.cssText = 'display:flex;flex-direction:column;gap:8px;margin-bottom:12px;';
      creds.forEach((c) => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 14px;border:1px solid #E1E4E9;border-radius:10px;flex-wrap:wrap;';

        const info = document.createElement('span');
        const addedDate = new Date(c.created_at).toLocaleDateString('ar-EG');
        const lastUsed = c.last_used_at ? `، آخر استخدام: ${new Date(c.last_used_at).toLocaleDateString('ar-EG')}` : '';
        info.textContent = `🔒 ${c.device_name || 'جهاز'} — أُضيف في ${addedDate}${lastUsed}`;
        info.style.cssText = 'font-size:13.5px;color:#0B1C33;';

        const delBtn = document.createElement('button');
        delBtn.textContent = 'حذف';
        delBtn.style.cssText = 'background:#FDEEEE;color:#E5484D;border:none;padding:7px 16px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:700;font-family:inherit;white-space:nowrap;';
        delBtn.onclick = async () => {
          const ok = await confirmAction('متأكد إنك عايز تحذف البصمة دي؟ هتحتاج تسجّلها تاني لو غيّرت رأيك.');
          if (!ok) return;
          delBtn.disabled = true;
          delBtn.textContent = 'جارٍ الحذف...';
          try {
            await deleteCredential(token, c.id);
            const remaining = await listCredentials(token);
            renderManagerList(container, token, remaining);
          } catch (e) {
            await notify(e && e.message ? e.message : 'فشل الحذف', { title: '⚠️ خطأ' });
            delBtn.disabled = false;
            delBtn.textContent = 'حذف';
          }
        };

        row.appendChild(info);
        row.appendChild(delBtn);
        list.appendChild(row);
      });
      container.appendChild(list);
    }

    const addBtn = document.createElement('button');
    addBtn.textContent = '➕ إضافة بصمة جهاز جديد';
    addBtn.style.cssText = 'background:#0E8074;color:#fff;border:none;padding:10px 18px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:700;font-family:inherit;';
    addBtn.onclick = async () => {
      addBtn.disabled = true;
      addBtn.textContent = 'جارٍ التسجيل...';
      try {
        await registerNewCredential(token);
        const remaining = await listCredentials(token);
        renderManagerList(container, token, remaining);
      } catch (e) {
        if (e && e.name === 'InvalidStateError') {
          await notify('⚠️ الجهاز ده مسجّل بالفعل', { title: '⚠️ تنبيه' });
        } else if (!(e && e.name === 'NotAllowedError')) {
          await notify('تعذّر تفعيل البصمة: ' + (e && e.message ? e.message : e), { title: '⚠️ خطأ' });
        }
      } finally {
        addBtn.disabled = false;
        addBtn.textContent = '➕ إضافة بصمة جهاز جديد';
      }
    };
    container.appendChild(addBtn);
  }

  /** موديال جاهز بيعرض واجهة الإدارة — للصفحات اللي مفيهاش تبويب/بانل إعدادات جاهز أصلاً
   * (المساعد، ولي الأمر، الطالب) بدل ما نعمل تعديل هيكلي في تصميم كل صفحة منهم */
  function openManagerModal() {
    if (document.getElementById('webauthnModalOverlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'webauthnModalOverlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(11,28,51,.55);z-index:100000;display:flex;align-items:center;justify-content:center;padding:20px;';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    const card = document.createElement('div');
    card.style.cssText = 'background:#fff;border-radius:16px;max-width:420px;width:100%;max-height:80vh;overflow-y:auto;padding:24px;box-shadow:0 20px 50px rgba(0,0,0,.3);font-family:"IBM Plex Sans Arabic","Cairo",sans-serif;';

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;';
    const title = document.createElement('h3');
    title.textContent = '🔒 الدخول بالبصمة/الوجه';
    title.style.cssText = 'font-size:16px;font-weight:800;color:#0B1C33;margin:0;';
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕';
    closeBtn.setAttribute('aria-label', 'إغلاق');
    closeBtn.style.cssText = 'background:none;border:none;font-size:20px;line-height:1;cursor:pointer;color:#6B7280;';
    closeBtn.onclick = () => overlay.remove();
    header.appendChild(title);
    header.appendChild(closeBtn);

    const hint = document.createElement('p');
    hint.textContent = 'الأجهزة المسجّلة للدخول ببصمتك أو وجهك بدل كلمة المرور.';
    hint.style.cssText = 'color:#6B7280;font-size:13px;margin:0 0 14px;';

    const contentContainer = document.createElement('div');
    contentContainer.id = 'webauthnModalContent';

    card.appendChild(header);
    card.appendChild(hint);
    card.appendChild(contentContainer);
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    renderManager('webauthnModalContent');
  }

  window.FasliWebauthn = { renderManager, openManagerModal };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initBanner);
  } else {
    initBanner();
  }
})();
