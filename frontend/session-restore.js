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

  // ============================================
  // ✅ (طلب) "تذكرني" كانت بترجّع التوكن القديم صح، لكن لو كان خلاص منتهي الصلاحية (توكنات
  // Supabase بتنتهي بعد ساعة تقريباً — أي فتح للتطبيق بعد غيبة أطول من كده)، أول نداء بيانات
  // في الصفحة (زي loadGroups) كان بيتنفّذ فورًا بنفس التوكن القديم قبل ما session-refresh.js
  // (اللي محمّل آخر الصفحة عادةً) يلحق يجدده — يرجع 401، والصفحة كانت بتعتبرها نهاية الجلسة
  // فعليًا وتسجّل خروج المستخدم، رغم إن الـrefresh token لسه صالح وكان ممكن يجدد التوكن عادي.
  // الحل: نغلّف window.fetch من هنا (بداية الصفحة، قبل أي نداء تاني) عشان أي 401 من دوال
  // Supabase نستنى بيه انتهاء محاولة التجديد (اللي session-refresh.js بيبلّغنا عليها عن طريق
  // window.__fasliSessionReady) ونعيد نفس الطلب مرة واحدة بالتوكن الجديد قبل ما نستسلم.
  // ============================================
  try {
    if (window.__fasliFetchRetryInstalled) return;
    window.__fasliFetchRetryInstalled = true;

    // ✅ بروميس مشترك: session-refresh.js (لو محمّل في نفس الصفحة) هيحلّه هو لما يخلص محاولة
    // التجديد، ناجحة كانت أو فاشلة. لو مش محمّل أصلاً (صفحة من غيره)، الـfallback تحت بيحلّه
    // فورًا عشان منستناش حاجة مش هتيجي أبداً.
    window.__fasliSessionReadyResolve = null;
    window.__fasliSessionReady = new Promise((resolve) => { window.__fasliSessionReadyResolve = resolve; });
    setTimeout(() => { if (window.__fasliSessionReadyResolve) window.__fasliSessionReadyResolve(); }, 6000);

    const originalFetch = window.fetch.bind(window);
    window.fetch = async function (input, init) {
      const response = await originalFetch(input, init);
      try {
        const urlStr = typeof input === 'string' ? input : input?.url || '';
        const hadAuthHeader = init?.headers && (init.headers.Authorization || init.headers.authorization);
        if (response.status === 401 && urlStr.includes('/functions/v1/') && hadAuthHeader && !(init && init.__fasliRetried)) {
          await window.__fasliSessionReady;
          const freshToken = sessionStorage.getItem('jwtToken');
          if (freshToken) {
            const retryInit = Object.assign({}, init, {
              __fasliRetried: true,
              headers: Object.assign({}, init.headers, { Authorization: 'Bearer ' + freshToken }),
            });
            return await originalFetch(input, retryInit);
          }
        }
      } catch (e) { /* أي خطأ هنا يتجاهل — نرجع الاستجابة الأصلية زي ما هي */ }
      return response;
    };
  } catch (e) {
    // ✅ تجاهل — لو فشل تركيب الـwrapper لأي سبب، الصفحة تفضل شغالة بسلوكها القديم
  }
})();
