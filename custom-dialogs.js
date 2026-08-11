// custom-dialogs.js — بديل موحّد وأنيق لـ confirm() و prompt() الافتراضية بتاعة المتصفح
// بيستخدم نفس كلاسات المودال الموجودة في النظام (.modal-overlay, .modal-box) عشان يبقى متسق بصرياً تماماً

(function () {
  if (window.__customDialogsInstalled) return;
  window.__customDialogsInstalled = true;

  function injectDialogHtml() {
    if (document.getElementById('customDialogOverlay')) return;
    const div = document.createElement('div');
    div.innerHTML = `
      <div class="modal-overlay" id="customDialogOverlay">
        <div class="modal-box" style="max-width:420px;">
          <div class="modal-header">
            <h3 id="customDialogTitle">تأكيد</h3>
          </div>
          <div class="modal-body">
            <p id="customDialogMessage" style="white-space:pre-line;line-height:1.8;font-size:14px;color:var(--gray-700, #374151);margin-bottom:16px;"></p>
            <input type="text" id="customDialogInput" style="display:none;width:100%;padding:10px 12px;border:1.5px solid var(--gray-200,#e5e7eb);border-radius:10px;font-size:14px;font-family:inherit;margin-top:4px;">
          </div>
          <div class="modal-footer" style="display:flex;gap:10px;padding:16px 24px;">
            <button class="btn" id="customDialogCancel" style="flex:1;display:flex;align-items:center;justify-content:center;text-align:center;background:var(--gray-100,#f3f4f6);color:var(--gray-700,#374151);border:none;padding:11px;border-radius:10px;font-weight:600;cursor:pointer;font-family:inherit;font-size:14px;">إلغاء</button>
            <button class="btn btn-danger" id="customDialogConfirm" style="flex:1;display:flex;align-items:center;justify-content:center;text-align:center;background:#e53e3e;color:#fff;border:none;padding:11px;border-radius:10px;font-weight:600;cursor:pointer;font-family:inherit;font-size:14px;">تأكيد</button>
          </div>
        </div>
      </div>`;
    document.body.appendChild(div.firstElementChild);
  }

  function showDialog({ message, isPrompt = false, defaultValue = '', danger = true }) {
    injectDialogHtml();
    const overlay = document.getElementById('customDialogOverlay');
    const msgEl = document.getElementById('customDialogMessage');
    const inputEl = document.getElementById('customDialogInput');
    const confirmBtn = document.getElementById('customDialogConfirm');
    const cancelBtn = document.getElementById('customDialogCancel');

    msgEl.textContent = message;
    inputEl.style.display = isPrompt ? 'block' : 'none';
    inputEl.value = defaultValue || '';
    confirmBtn.style.background = danger ? '#e53e3e' : '#F2B705';
    confirmBtn.style.color = danger ? '#fff' : '#0B1C33';
    confirmBtn.textContent = isPrompt ? 'حفظ' : 'تأكيد';

    overlay.classList.add('open');
    if (isPrompt) setTimeout(() => inputEl.focus(), 50);

    return new Promise((resolve) => {
      function cleanup(result) {
        overlay.classList.remove('open');
        confirmBtn.onclick = null;
        cancelBtn.onclick = null;
        overlay.onclick = null;
        document.removeEventListener('keydown', onKeydown);

        // ✅ إجباري: نرجّع التركيز (focus) للصفحة صراحة بعد قفل النافذة.
        // في تطبيق سطح المكتب (Electron) تحديداً، التركيز أحياناً بيفضل "عالق" على الزرار المختفي
        // وده اللي كان بيسبب إحساس إن البرنامج "متجمد" (مؤشر الكتابة مش بيظهر، والأزرار مش بتستجيب)
        // لغاية ما المستخدم يدوس بالماوس على حاجة يدوي.
        setTimeout(() => {
          document.body.focus();
          if (window.electronAPI?.refocusWindow) window.electronAPI.refocusWindow();
        }, 30);

        resolve(result);
      }
      function onKeydown(e) {
        if (e.key === 'Escape') cleanup(isPrompt ? null : false);
        if (e.key === 'Enter' && isPrompt) cleanup(inputEl.value);
      }
      confirmBtn.onclick = () => cleanup(isPrompt ? inputEl.value : true);
      cancelBtn.onclick = () => cleanup(isPrompt ? null : false);
      overlay.onclick = (e) => { if (e.target === overlay) cleanup(isPrompt ? null : false); };
      document.addEventListener('keydown', onKeydown);
    });
  }

  // ✅ بديل async لـ confirm() — بترجع true/false زيها بالظبط، بس لازم await قبلها
  window.customConfirm = (message, opts = {}) => showDialog({ message, isPrompt: false, danger: opts.danger !== false });

  // ✅ بديل async لـ prompt() — بترجع النص أو null لو اتلغى، بس لازم await قبلها
  window.customPrompt = (message, defaultValue = '') => showDialog({ message, isPrompt: true, defaultValue, danger: false });
})();
