// frontend/webauthn.js
// ============================================
// شريط "فعّل الدخول بالبصمة/الوجه" الموحّد لكل الأدوار — نفس تصميم وسلوك بانر ربط جوجل بالظبط،
// بيظهر مرة كل جلسة لو الحساب لسه مالوش أي بصمة مسجّلة، وبيسجّل بصمة جديدة (WebAuthn) لو المستخدم وافق.
// ============================================
(function () {
  const PROJECT_URL = 'https://yxkyxxzcnxpxefodfxnl.supabase.co';
  const DISMISS_KEY = 'webauthnDismissed';

  function getStored(key) {
    return sessionStorage.getItem(key) || localStorage.getItem(key) || null;
  }

  function supportsWebAuthn() {
    return !!(window.PublicKeyCredential && navigator.credentials && window.SimpleWebAuthnBrowser);
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

  async function init() {
    if (document.body?.dataset?.suppressAccountBanners === 'true') return;
    if (sessionStorage.getItem(DISMISS_KEY)) return;
    if (!supportsWebAuthn()) return;

    const token = getStored('jwtToken');
    if (!token) return;

    try {
      const res = await fetch(PROJECT_URL + '/functions/v1/webauthn-list-credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: '{}',
      });
      const data = await res.json();
      if (!data.success) return;
      if ((data.credentials || []).length > 0) return; // البصمة مفعّلة بالفعل

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

        alert('✅ ' + verifyData.message);
        bar.remove();
      } catch (e) {
        if (e && e.name === 'InvalidStateError') {
          alert('⚠️ الجهاز ده مسجّل بالفعل');
        } else if (e && e.name === 'NotAllowedError') {
          // ✅ المستخدم لغى العملية أو رفض الإذن — مفيش داعي نزعجه برسالة خطأ
        } else {
          alert('⚠️ تعذّر تفعيل البصمة: ' + (e && e.message ? e.message : e));
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

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
