// frontend/session-restore.js
// ============================================
// لازم يتحمّل مبكرًا في <head> قبل أي كود تاني في الصفحة — بينسخ بيانات الجلسة من
// localStorage لـsessionStorage لو "تذكرني" كانت مفعّلة وقت الدخول. من غيره: قفل
// المتصفح/التطبيق تمامًا وفتحه تاني بيمسح sessionStorage تلقائيًا (سلوك المتصفح الطبيعي)،
// فالصفحة كانت بتعتبر المستخدم مسجّل خروج حتى لو "تذكرني" كانت متفعّلة، إلا لو دخوله
// عن طريق login.html بالظبط (اللي فيه نفس المنطق ده لوحده) — دلوقتي بقى شغال من أي صفحة.
// ============================================
(function () {
  try {
    if (!sessionStorage.getItem('jwtToken') && localStorage.getItem('fasliRememberMe') === 'true') {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key === 'fasliRememberMe') continue;
        const value = localStorage.getItem(key);
        if (value !== null) sessionStorage.setItem(key, value);
      }
    }
  } catch (e) {
    // ✅ أي فشل هنا (خصوصية متصفح، وضع تصفّح خفي، إلخ) لازم يتجاهل بصمت
  }
})();
