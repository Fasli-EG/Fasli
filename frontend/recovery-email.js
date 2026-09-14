// frontend/recovery-email.js
// ============================================
// إيميل الاسترجاع الاختياري — موحّد لكل الأدوار (مدرس/مساعد/ولي أمر/طالب). لو المستخدم
// ضايف إيميل استرجاع من هنا، هيقدر يستخدم "نسيت كلمة المرور" في صفحة الدخول عشان يوصله
// رابط تحديد كلمة مرور جديدة عليه (request-password-reset في الباك إند). نفس نمط
// webauthn.js بالظبط: window.FasliRecoveryEmail = { renderManager, openManagerModal }
// ============================================
(function () {
  const PROJECT_URL = 'https://yxkyxxzcnxpxefodfxnl.supabase.co';

  function getStored(key) {
    return sessionStorage.getItem(key) || localStorage.getItem(key) || null;
  }

  function notify(message, opts) {
    return window.customAlert ? window.customAlert(message, opts) : Promise.resolve(alert(message));
  }

  async function getRecoveryEmail(token) {
    const res = await fetch(PROJECT_URL + '/functions/v1/manage-recovery-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ action: 'get' }),
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.message || 'تعذّر جلب إيميل الاسترجاع');
    return data.recoveryEmail;
  }

  async function setRecoveryEmail(token, email) {
    const res = await fetch(PROJECT_URL + '/functions/v1/manage-recovery-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
      body: JSON.stringify({ action: 'set', recoveryEmail: email }),
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.message || 'تعذّر حفظ إيميل الاسترجاع');
    return data;
  }

  async function renderManagerContent(container, token, currentEmail) {
    container.innerHTML = `
      <p style="font-size:12.5px;color:var(--muted-text,#6B7280);margin-bottom:10px;">لو نسيت كلمة المرور، هنبعتلك رابط لتحديد واحدة جديدة على الإيميل ده.</p>
      ${currentEmail ? `<p style="font-size:13.5px;font-weight:600;margin-bottom:10px;">📧 مسجّل حاليًا: ${currentEmail}</p>` : ''}
      <input type="email" id="recoveryEmailInput" placeholder="example@email.com" value="${currentEmail || ''}" style="width:100%;padding:10px 14px;border:1.5px solid #E1E4E9;border-radius:10px;font-size:13.5px;font-family:inherit;margin-bottom:10px;">
      <div style="display:flex;gap:8px;">
        <button type="button" id="recoveryEmailSaveBtn" style="flex:1;padding:10px;border-radius:10px;border:none;background:var(--primary,#F2B705);color:#0B1C33;font-weight:700;font-size:13px;cursor:pointer;font-family:inherit;">💾 حفظ</button>
        ${currentEmail ? `<button type="button" id="recoveryEmailClearBtn" style="padding:10px 16px;border-radius:10px;border:1.5px solid #E5484D;background:#fff;color:#E5484D;font-weight:700;font-size:13px;cursor:pointer;font-family:inherit;">حذف</button>` : ''}
      </div>`;

    container.querySelector('#recoveryEmailSaveBtn').onclick = async () => {
      const input = container.querySelector('#recoveryEmailInput');
      const email = input.value.trim();
      if (!email) { notify('⚠️ اكتب إيميل الأول'); return; }
      try {
        await setRecoveryEmail(token, email);
        await notify('✅ اتحفظ إيميل الاسترجاع');
        await renderManagerContent(container, token, email);
      } catch (e) {
        notify('⚠️ ' + e.message);
      }
    };

    const clearBtn = container.querySelector('#recoveryEmailClearBtn');
    if (clearBtn) {
      clearBtn.onclick = async () => {
        try {
          await setRecoveryEmail(token, '');
          await notify('✅ اتشال إيميل الاسترجاع');
          await renderManagerContent(container, token, null);
        } catch (e) {
          notify('⚠️ ' + e.message);
        }
      };
    }
  }

  async function renderManager(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const token = getStored('jwtToken');
    if (!token) return;
    container.innerHTML = '<p style="font-size:13px;color:var(--muted-text,#6B7280);">جاري التحميل...</p>';
    try {
      const currentEmail = await getRecoveryEmail(token);
      await renderManagerContent(container, token, currentEmail);
    } catch (e) {
      container.innerHTML = `<p style="font-size:13px;color:#E5484D;">⚠️ ${e.message}</p>`;
    }
  }

  function openManagerModal() {
    if (document.getElementById('recoveryEmailModalOverlay')) return;
    const overlay = document.createElement('div');
    overlay.id = 'recoveryEmailModalOverlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(11,28,51,.55);z-index:100010;display:flex;align-items:center;justify-content:center;padding:20px;';
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

    const card = document.createElement('div');
    card.style.cssText = 'background:#fff;border-radius:16px;max-width:420px;width:100%;max-height:80vh;overflow-y:auto;padding:24px;box-shadow:0 20px 50px rgba(0,0,0,.3);font-family:"IBM Plex Sans Arabic","Cairo",sans-serif;';

    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;';
    header.innerHTML = '<h3 style="font-size:16px;font-weight:800;color:#0B1C33;">📧 إيميل الاسترجاع</h3><button type="button" style="background:none;border:none;font-size:20px;cursor:pointer;color:#9CA3AF;line-height:1;">×</button>';
    header.querySelector('button').onclick = () => overlay.remove();

    const body = document.createElement('div');
    body.id = 'recoveryEmailModalContent';

    card.appendChild(header);
    card.appendChild(body);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
    renderManager('recoveryEmailModalContent');
  }

  window.FasliRecoveryEmail = { renderManager, openManagerModal };
})();
