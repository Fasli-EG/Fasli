/* layout.js — الهيدر/السايدبار الموحّد لصفحات النظام
   ============================================================
   قبل كده كانت كل صفحة (15+ ملف) بتعمل copy-paste لنفس الـ <aside class="sidebar">
   بالكامل — أي تعديل في عنصر قائمة واحد كان محتاج تعديل يدوي في كل ملف على حدة.
   دلوقتي كل صفحة بتحط <div id="app-shell-sidebar-slot"></div> مكان الـ <aside>،
   وتستدعي renderShell({active:'...'}) — نفس الـ ids المستخدمة في كود كل صفحة
   (navFinancial, navActivityLog, navManageAssistants, navSettings, navResetSystem,
   userAvatar, userDisplayName, teacherBadge, permissionBadge, notifWrap, notifBtn,
   notifBadge, notifPanel, notifList, themeToggle) محفوظة بالظبط زي ما كانت —
   كود الصلاحيات/الإشعارات/الدارك-مود في كل صفحة يفضل شغال من غير أي تعديل فيه. */
(function () {
  var NAV_SECTIONS = [
    { items: [
      { key: 'home', href: '#', onclick: 'goBackToDashboard(); return false;', icon: 'fa-house', label: 'الرئيسية' },
      { key: 'messages', href: 'messages.html', id: 'navMessages', icon: 'fa-paper-plane', label: 'رسائل جماعية' }
    ]},
    { label: '🎓 الأكاديمية', items: [
      { key: 'students', href: 'students.html', id: 'navStudents', icon: 'fa-user-graduate', label: 'الطلاب' },
      { key: 'groups', href: 'groups.html', id: 'navGroups', icon: 'fa-layer-group', label: 'المجموعات' },
      { key: 'grades', href: 'grades.html', id: 'navGrades', icon: 'fa-file-pen', label: 'الاختبارات' }
    ]},
    { label: '💰 المالية', items: [
      { key: 'payments', href: 'payments.html', id: 'navPayments', icon: 'fa-sack-dollar', label: 'المدفوعات والمذكرات' },
      { key: 'financial', href: 'financial.html', id: 'navFinancial', icon: 'fa-coins', label: 'الدخل الشهري', gated: true }
    ]},
    { label: '📊 التقارير', items: [
      { key: 'reports', href: 'reports.html', id: 'navReports', icon: 'fa-chart-simple', label: 'التقارير' }
    ]},
    { label: '⚙️ الإعدادات', items: [
      { key: 'activityLog', href: 'activity-log.html', id: 'navActivityLog', icon: 'fa-clock-rotate-left', label: 'سجل النشاطات', gated: true },
      { key: 'staff', href: 'staff.html', id: 'navManageAssistants', icon: 'fa-users-gear', label: 'إدارة فريق العمل', gated: true },
      { key: 'settings', href: 'teacher-settings.html', id: 'navSettings', icon: 'fa-gear', label: 'إعدادات الحساب', gated: true },
      { key: 'assistantColor', href: '#', onclick: 'window.openAssistantColorModal && window.openAssistantColorModal(); return false;', id: 'navAssistantColor', icon: 'fa-palette', label: 'لون الواجهة', gated: true },
      // ✅ (طلب) المدرس بقاله تبويب مخصص لهم في إعدادات الحساب (teacher-settings.html)،
      // فاختصار السايدبار بقى تكرار عنده — لكن المساعد معندوش صفحة إعدادات منفصلة بتاعته
      // خالص، فده لسه الطريقة الوحيدة ليه يوصلهم. assistantOnly بيتفلتر في sidebarHtml() تحت.
      { key: 'passkeys', href: '#', onclick: 'window.FasliWebauthn && window.FasliWebauthn.openManagerModal(); return false;', icon: 'fa-bolt', label: 'دخول سريع', assistantOnly: true },
      { key: 'recoveryEmail', href: '#', onclick: 'window.FasliRecoveryEmail && window.FasliRecoveryEmail.openManagerModal(); return false;', icon: 'fa-envelope-circle-check', label: 'إيميل الاسترجاع', assistantOnly: true }
    ]}
  ];

  function escapeAttr(s) { return String(s).replace(/"/g, '&quot;'); }

  function navItemHtml(item, activeKey, gateMessages) {
    var isActive = item.key === activeKey;
    var isGated = item.gated || (gateMessages && item.key === 'messages');
    var idAttr = item.id ? ' id="' + item.id + '"' : (item.key === 'messages' ? ' id="navMessages"' : '');
    var styleAttr = isGated ? ' style="display:none;"' : '';
    var cls = 'sidebar-item' + (isActive ? ' active' : ' ');
    var onclickAttr = item.onclick ? ' onclick="' + escapeAttr(item.onclick) + '"' : '';
    return '<a href="' + item.href + '"' + onclickAttr + ' class="' + cls + '"' + idAttr + styleAttr + '>' +
           '<i class="fas ' + item.icon + '"></i> ' + item.label + '</a>';
  }

  function sidebarHtml(activeKey, gateMessages, notifStartsHidden, isAssistant) {
    var nav = NAV_SECTIONS.map(function (section) {
      var items = section.items.filter(function (it) { return !it.assistantOnly || isAssistant; });
      if (!items.length) return '';
      var label = section.label ? '<div class="sidebar-section-label">' + section.label + '</div>' : '';
      return label + items.map(function (it) { return navItemHtml(it, activeKey, gateMessages); }).join('');
    }).join('');
    var notifWrapStyle = notifStartsHidden ? ' style="display:none;"' : '';

    return (
      '<aside class="sidebar" id="sidebar">' +
        '<div class="sidebar-brand">' +
          '<div class="logo-icon"><img src="assets/logo-icon.svg" alt="شعار فَصلي"></div>' +
          '<h1>فَصلي</h1>' +
        '</div>' +
        '<nav class="sidebar-nav">' + nav + '</nav>' +
        '<div class="sidebar-footer">' +
          '<div class="sidebar-user">' +
            '<div class="avatar" id="userAvatar">م</div>' +
            '<div class="u-info">' +
              '<div class="u-name" id="userDisplayName">مرحباً، مدرس</div>' +
              '<div class="u-role" id="teacherBadge">حساب مدرس</div>' +
              '<span class="permission-badge" id="permissionBadge" style="display:none;font-size:10px;margin-top:4px;"></span>' +
            '</div>' +
          '</div>' +
          '<button class="sidebar-item" id="navResetSystem" onclick="openResetConfirm()" style="color:#FCA5A5;display:none;">' +
            '<i class="fas fa-triangle-exclamation"></i> إعادة تهيئة النظام' +
          '</button>' +
          '<div class="sidebar-footer-actions">' +
            '<div class="notif-wrap" id="notifWrap"' + notifWrapStyle + '>' +
              '<button class="btn btn-ghost btn-sm" onclick="toggleNotifPanel()" id="notifBtn" title="الإشعارات">' +
                '<i class="fas fa-bell"></i><span class="notif-badge" id="notifBadge" style="display:none;">0</span>' +
              '</button>' +
              '<div class="notif-panel" id="notifPanel">' +
                '<div class="notif-panel-header"><span>الإشعارات</span><button class="notif-mark-all" onclick="markAllRead()">تعليم الكل كمقروء</button></div>' +
                '<div class="notif-list" id="notifList"><div style="text-align:center;padding:24px;color:var(--gray-400);font-size:13px;">جاري التحميل...</div></div>' +
              '</div>' +
            '</div>' +
            '<button onclick="toggleDarkMode()" id="themeToggle" title="الوضع الليلي"><i class="fas fa-moon"></i></button>' +
            '<button onclick="logout()" title="تسجيل الخروج"><i class="fas fa-sign-out-alt"></i> خروج</button>' +
          '</div>' +
        '</div>' +
      '</aside>'
    );
  }

  window.renderShell = function (opts) {
    opts = opts || {};
    document.body.insertAdjacentHTML('afterbegin', '<div class="sidebar-backdrop" id="sidebarBackdrop" onclick="toggleSidebar()"></div>');
    var slot = document.getElementById('app-shell-sidebar-slot');
    var notifStartsHidden = opts.notifStartsHidden !== false; /* default true (teacher pages); pass false for assistant-dashboard */
    if (slot) slot.outerHTML = sidebarHtml(opts.active, !!opts.gateMessages, notifStartsHidden, !!opts.isAssistant);

    /* ✅ (طلب) على الشاشات الصغيرة، السايدبار كان بيفضل مفتوح فوق المحتوى بعد ما تختار
       أي عنصر منه (خصوصاً عناصر زي "الدخول السريع"/"إيميل الاسترجاع"/"إعادة تهيئة النظام"
       اللي بتفتح موديال من غير أي تنقل فعلي بين الصفحات) — نقفله تلقائيًا هنا بمستمع واحد
       مُفوَّض على كل السايدبار (مش .sidebar-nav بس) عشان يغطي navResetSystem كمان اللي
       عايش في .sidebar-footer، بدل ما نضيف onclick يدوي لكل عنصر في navItemHtml() */
    var sidebar = document.getElementById('sidebar');
    if (sidebar) {
      sidebar.addEventListener('click', function (e) {
        if (window.innerWidth <= 900 && e.target.closest('.sidebar-item') && window.toggleSidebar) {
          window.toggleSidebar();
        }
      });
    }
  };

})();
