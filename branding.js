// ✅ يطبّق شعار/لون المدرس أو السنتر المخصص (لو موجود) بعد تسجيل الدخول.
// بيتحفظ في sessionStorage وقت الدخول (login.html) عشان الصفحة الحالية تقرأه فوراً من غير نداء سيرفر إضافي.
// فشل التخصيص (أو عدم وجوده) لازم ميأثرش على باقي الصفحة — الشعار/اللون الافتراضي بيفضل شغال دايماً.
(function () {
  // ✅ يمزج لون hex مع الأبيض أو الأسود بنسبة معينة، لاشتقاق درجة أفتح/أغمق منه (بديل عن ألوان ثابتة)
  function shadeColor(hex, percent) {
    try {
      var h = hex.replace('#', '');
      if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
      var r = parseInt(h.substring(0, 2), 16);
      var g = parseInt(h.substring(2, 4), 16);
      var b = parseInt(h.substring(4, 6), 16);
      var t = percent < 0 ? 0 : 255;
      var p = Math.abs(percent);
      r = Math.round((t - r) * p) + r;
      g = Math.round((t - g) * p) + g;
      b = Math.round((t - b) * p) + b;
      var toHex = function (n) { return ('0' + n.toString(16)).slice(-2); };
      return '#' + toHex(r) + toHex(g) + toHex(b);
    } catch (e) {
      return hex;
    }
  }

  // ✅ يطبّق لون أساسي مخصص + الدرجات المشتقة منه (فاتحة/غامقة) على كل الصفحة فوراً
  // ✅ (طلب) التخصيص بقى أشمل: بيغطي كمان خلفية القائمة الجانبية وإطار الكروت في كل الصفحة،
  // مش بس زرار "الإجراء الأساسي" زي ما كان قبل كده — كله مشتق من نفس اللون الواحد اللي بيختاره المدرس
  function applyBrandColor(color) {
    if (!color) return;
    try {
      document.documentElement.style.setProperty('--primary', color);
      document.documentElement.style.setProperty('--primary-light', shadeColor(color, 0.75));
      document.documentElement.style.setProperty('--primary-dark', shadeColor(color, -0.28));
      // ✅ اللون الثانوي (accent) بياخد نفس اللون الأساسي افتراضياً لو مفيش لون ثانوي مخصص منفصل
      var accent = sessionStorage.getItem('brandAccentColor') || color;
      document.documentElement.style.setProperty('--accent', accent);
      // ✅ إطار الكروت: درجة فاتحة جداً من نفس اللون (يفضل هادي وواضح، مش لون قوي يبوّظ القراءة)
      document.documentElement.style.setProperty('--card-border', shadeColor(color, 0.55));
      // ✅ خلفية القائمة الجانبية: درجة غامقة جداً من نفس اللون (تفضل غامقة كفاية إن النص الأبيض فوقها يتقرا بوضوح)
      document.documentElement.style.setProperty('--sidebar-bg', shadeColor(color, -0.82));
    } catch (e) { /* تجاهل — التخصيص اختياري */ }
  }
  window.applyBrandColor = applyBrandColor;

  function applyBranding() {
    try {
      var logoUrl = sessionStorage.getItem('brandLogoUrl');
      var color = sessionStorage.getItem('brandColor');

      if (logoUrl) {
        var imgs = document.querySelectorAll('.logo-icon img');
        for (var i = 0; i < imgs.length; i++) imgs[i].src = logoUrl;
      }
      if (color) {
        applyBrandColor(color);
      }
    } catch (e) { /* تجاهل — التخصيص اختياري */ }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyBranding);
  } else {
    applyBranding();
  }
})();
