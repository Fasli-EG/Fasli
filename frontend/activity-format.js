// activity-format.js
// موديول موحّد لتحويل سجل النشاط (action_type + details) لجملة عربية مقروءة وتفصيلية
// يُستخدم في: activity-log.html, dashboard.html, assistant-dashboard.html

const ACTIVITY_LABELS = {
  login: { text: 'سجّل دخول', badge: 'badge-info' },
  add_student: { text: 'أضاف طالب', badge: 'badge-success' },
  edit_student: { text: 'عدّل بيانات طالب', badge: 'badge-warning' },
  transfer_student: { text: 'نقل طالب لمجموعة تانية', badge: 'badge-warning' },
  link_rfid_card: { text: 'ربط كارت RFID بطالب', badge: 'badge-primary' },
  delete_student: { text: 'حذف طالب', badge: 'badge-danger' },
  add_grade: { text: 'رصد درجة', badge: 'badge-primary' },
  bulk_add_grade: { text: 'رصد درجة لعدة طلاب', badge: 'badge-primary' },
  edit_grade: { text: 'عدّل درجة', badge: 'badge-warning' },
  delete_grade: { text: 'حذف درجة', badge: 'badge-danger' },
  add_payment: { text: 'سجّل دفعة', badge: 'badge-success' },
  bulk_add_payment: { text: 'سجّل دفعة لعدة طلاب', badge: 'badge-success' },
  edit_payment: { text: 'عدّل دفعة', badge: 'badge-warning' },
  delete_payment: { text: 'حذف دفعة', badge: 'badge-danger' },
  add_book: { text: 'أضاف مذكرة', badge: 'badge-primary' },
  edit_book: { text: 'عدّل مذكرة', badge: 'badge-warning' },
  delete_book: { text: 'حذف مذكرة', badge: 'badge-danger' },
  pay_book: { text: 'سجّل سداد مذكرة', badge: 'badge-success' },
  bulk_pay_book: { text: 'سجّل سداد مذكرة لعدة طلاب', badge: 'badge-success' },
  update_book_payment: { text: 'عدّل سداد مذكرة', badge: 'badge-warning' },
  edit_book_payment: { text: 'عدّل سداد مذكرة', badge: 'badge-warning' },
  delete_book_payment: { text: 'حذف سداد مذكرة', badge: 'badge-danger' },
  record_attendance: { text: 'سجّل حضور', badge: 'badge-info' },
  create_group: { text: 'أنشأ مجموعة', badge: 'badge-success' },
  rename_group: { text: 'عدّل اسم مجموعة', badge: 'badge-warning' },
  delete_group: { text: 'حذف مجموعة', badge: 'badge-danger' },
  add_assistant: { text: 'أضاف مساعد', badge: 'badge-success' },
  update_assistant: { text: 'عدّل صلاحيات مساعد', badge: 'badge-warning' },
  delete_assistant: { text: 'حذف مساعد', badge: 'badge-danger' },
  reset_password: { text: 'أعاد تعيين كلمة مرور', badge: 'badge-warning' },
  reset_parent_password: { text: 'أعاد تعيين كلمة مرور ولي أمر', badge: 'badge-warning' },
  change_password: { text: 'غيّر كلمة المرور', badge: 'badge-info' },
  reset_system: { text: 'أعاد تهيئة النظام بالكامل', badge: 'badge-danger' },
  add_teacher: { text: 'أضاف مدرس جديد', badge: 'badge-success' },
  update_teacher: { text: 'عدّل بيانات مدرس', badge: 'badge-warning' },
  delete_teacher: { text: 'حذف مدرس', badge: 'badge-danger' },
  bulk_message: { text: 'أرسل رسالة جماعية', badge: 'badge-info' },
  export_backup: { text: 'صدّر نسخة احتياطية', badge: 'badge-info' },
  restore_backup: { text: 'استعاد نسخة احتياطية', badge: 'badge-warning' },
};

// أسماء عربية للحقول اللي بتظهر جوه أي "changes" (قبل/بعد)
const FIELD_LABELS = {
  name: 'الاسم',
  phone: 'رقم الهاتف',
  parent_phone: 'رقم ولي الأمر',
  score: 'الدرجة',
  amount: 'المبلغ',
  status: 'الحالة',
  is_active: 'الحالة (مفعّل)',
  isActive: 'الحالة (مفعّل)',
  permissions: 'الصلاحيات',
  expiry_date: 'تاريخ الانتهاء',
  expiryDate: 'تاريخ الانتهاء',
  max_students: 'الحد الأقصى للطلاب',
  maxStudents: 'الحد الأقصى للطلاب',
  group_name: 'المجموعة',
  device_secret: 'مفتاح الجهاز',
};

// أسماء عربية لصلاحيات المساعد (لعرض فرق التعديل بشكل مقروء بدل JSON خام)
const ASSISTANT_PERM_LABELS = {
  view_students: 'عرض الطلاب',
  add_students: 'إضافة طلاب',
  edit_students: 'تعديل طلاب',
  delete_students: 'حذف طلاب',
  record_grades: 'إدارة الدرجات',
  record_payments: 'إدارة المدفوعات',
  view_reports: 'عرض التقارير',
  manage_attendance: 'إدارة الحضور',
  manage_groups: 'إدارة المجموعات',
  reset_parent_password: 'إعادة تعيين كلمة مرور ولي الأمر',
  manage_books: 'إدارة المذكرات',
  send_messages: 'الرسائل الجماعية',
};

/** يقارن قبل/بعد object صلاحيات ويرجّع بس اللي اتغيّر بشكل مقروء */
function renderPermissionsDiff(oldPerms, newPerms) {
  oldPerms = oldPerms || {};
  newPerms = newPerms || {};
  const allKeys = new Set([...Object.keys(oldPerms), ...Object.keys(newPerms)]);
  const changed = [];
  allKeys.forEach(key => {
    const before = !!oldPerms[key];
    const after = !!newPerms[key];
    if (before !== after) {
      const label = ASSISTANT_PERM_LABELS[key] || key;
      changed.push(`${after ? '✅ فعّل' : '❌ ألغى'} ${label}`);
    }
  });
  return changed.length ? changed.join(' — ') : 'لا تغيير فعلي في الصلاحيات';
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function fmtVal(v) {
  if (v === null || v === undefined || v === '') return '—';
  if (typeof v === 'boolean') return v ? 'نعم' : 'لا';
  if (typeof v === 'object') return escapeHtml(JSON.stringify(v));
  return escapeHtml(String(v));
}

/** يرجّع نسخة من details بكل الحقول النصية معقّمة من أي كود HTML (بيانات دي ممكن يكتبها مستخدم زي مساعد وتتعرض لمستخدم تاني زي المدرس) */
function escapeDetailFields(obj) {
  const out = {};
  for (const key in obj) {
    const v = obj[key];
    out[key] = (typeof v === 'string') ? escapeHtml(v) : v;
  }
  return out;
}

/** يبني نص "قبل ← بعد" لكل حقل اتغيّر جوه details.changes */
function renderChanges(changes) {
  if (!changes || typeof changes !== 'object') return '';
  const parts = [];
  for (const key in changes) {
    const c = changes[key];
    if (!c || typeof c !== 'object') continue;
    if (key === 'permissions') {
      parts.push(`الصلاحيات: ${renderPermissionsDiff(c.old, c.new)}`);
      continue;
    }
    const label = FIELD_LABELS[key] || key;
    parts.push(`${label}: ${fmtVal(c.old)} ← ${fmtVal(c.new)}`);
  }
  return parts.join(' | ');
}

/** يرجّع { label, badgeClass, detailText, changesText } لسجل نشاط واحد */
function formatActivity(log) {
  const meta = ACTIVITY_LABELS[log.action_type] || { text: log.action_type, badge: 'badge-info' };

  let det = {};
  if (log.details) {
    try { det = typeof log.details === 'string' ? JSON.parse(log.details) : log.details; }
    catch (e) { det = {}; }
  }
  det = escapeDetailFields(det);

  const parts = [];

  switch (log.action_type) {
    case 'add_student':
    case 'edit_student':
    case 'delete_student':
      if (det.student_name) parts.push(`الطالب: ${det.student_name}`);
      break;
    case 'transfer_student':
      if (det.student_name) parts.push(`الطالب: ${det.student_name}`);
      if (det.old_group && det.new_group) parts.push(`من "${det.old_group}" إلى "${det.new_group}"`);
      break;
    case 'link_rfid_card':
      if (det.student_name) parts.push(`الطالب: ${det.student_name}`);
      if (det.new_uid) parts.push(`الكارت الجديد: ${det.new_uid}`);
      break;
    case 'add_grade':
    case 'edit_grade':
    case 'delete_grade':
      if (det.student_name) parts.push(`الطالب: ${det.student_name}`);
      if (det.exam_name) parts.push(`الامتحان: ${det.exam_name}`);
      if (log.action_type !== 'edit_grade' && det.score !== undefined && det.max_score !== undefined) {
        parts.push(`الدرجة: ${det.score}/${det.max_score}`);
      }
      break;
    case 'bulk_add_grade': {
      if (det.exam_name) parts.push(`الامتحان: ${det.exam_name}`);
      if (det.score !== undefined && det.max_score !== undefined) parts.push(`الدرجة: ${det.score}/${det.max_score}`);
      if (det.count) parts.push(`عدد الطلاب: ${det.count}`);
      if (Array.isArray(det.students)) {
        const names = det.students.map((s) => escapeHtml(s.name)).join('، ');
        parts.push(`الطلاب: ${names}`);
      }
      break;
    }
    case 'add_payment':
    case 'edit_payment':
    case 'delete_payment':
      if (det.student_name) parts.push(`الطالب: ${det.student_name}`);
      if (det.title) parts.push(`البند: ${det.title}`);
      if (log.action_type !== 'edit_payment' && det.amount !== undefined) parts.push(`المبلغ: ${det.amount} ج.م`);
      break;
    case 'bulk_add_payment': {
      if (det.title) parts.push(`البند: ${det.title}`);
      if (det.amount !== undefined) parts.push(`المبلغ: ${det.amount} ج.م`);
      if (det.count) parts.push(`عدد الطلاب: ${det.count}`);
      if (Array.isArray(det.students)) {
        const names = det.students.map((s) => escapeHtml(s.name)).join('، ');
        parts.push(`الطلاب: ${names}`);
      }
      break;
    }
    case 'add_book':
    case 'edit_book':
    case 'delete_book':
      if (det.book_name) parts.push(`المذكرة: ${det.book_name}`);
      if (det.price !== undefined) parts.push(`السعر: ${det.price} ج.م`);
      break;
    case 'pay_book':
    case 'update_book_payment':
    case 'edit_book_payment':
    case 'delete_book_payment':
      if (det.student_name) parts.push(`الطالب: ${det.student_name}`);
      if (det.book_name) parts.push(`المذكرة: ${det.book_name}`);
      if (det.new_amount !== undefined) parts.push(`المبلغ: ${det.new_amount} ج.م`);
      else if (det.amount_paid_now !== undefined) parts.push(`المبلغ: ${det.amount_paid_now} ج.م`);
      break;
    case 'bulk_pay_book': {
      if (det.book_name) parts.push(`المذكرة: ${det.book_name}`);
      if (det.count) parts.push(`عدد الطلاب: ${det.count}`);
      if (Array.isArray(det.students)) {
        const names = det.students.map((s) => `${escapeHtml(s.name)} (${s.amount} ج.م)`).join('، ');
        parts.push(`الطلاب: ${names}`);
      }
      break;
    }
    case 'record_attendance':
      if (det.student_name) parts.push(`الطالب: ${det.student_name}`);
      if (det.status) parts.push(`الحالة: ${det.status === 'present' ? 'حاضر' : 'غائب'}`);
      break;
    case 'create_group':
    case 'delete_group':
      if (det.group_name) parts.push(`المجموعة: ${det.group_name}`);
      break;
    case 'rename_group':
      if (det.old_name && det.new_name) parts.push(`من "${det.old_name}" إلى "${det.new_name}"`);
      break;
    case 'add_assistant':
    case 'update_assistant':
    case 'delete_assistant':
    case 'reset_password':
      if (det.name) parts.push(`المساعد: ${det.name}`);
      else if (det.username) parts.push(`المستخدم: ${det.username}`);
      break;
    case 'change_password':
      if (det.role) parts.push(`نوع الحساب: ${det.role === 'teacher' ? 'مدرس' : det.role === 'assistant' ? 'مساعد' : 'ولي أمر'}`);
      break;
    case 'reset_system':
      if (det.deleted_students !== undefined) parts.push(`تم حذف ${det.deleted_students} طالب وكل بياناتهم`);
      break;
    case 'add_teacher':
    case 'update_teacher':
    case 'delete_teacher':
      if (det.name) parts.push(`المدرس: ${det.name}`);
      break;
    case 'bulk_message':
      if (det.recipients !== undefined) parts.push(`المستلمين: ${det.recipients}`);
      if (det.target) parts.push(`النوع: ${det.target === 'absent_today' ? 'الغايبين' : det.target === 'assistants' ? 'مساعدين' : 'مجموعة'}`);
      break;
    default:
      if (det.student_name) parts.push(`الطالب: ${det.student_name}`);
      else if (det.name) parts.push(det.name);
      else if (det.message) parts.push(det.message);
  }

  // ✅ المجموعة تتذكر دايماً لو موجودة، بغض النظر عن نوع النشاط
  if (det.group_name && !parts.some(p => p.startsWith('المجموعة:') || p.startsWith('من "'))) {
    parts.push(`المجموعة: ${det.group_name}`);
  }

  const detailText = parts.join(' — ') || '—';
  const changesText = renderChanges(det.changes);

  let performer = escapeHtml(log.performer_name || 'مستخدم');
  if (log.performer_role === 'assistant') performer = '👤 ' + performer + ' (مساعد)';
  else if (log.performer_role === 'parent') performer = '👨‍👩‍👦 ' + performer + ' (ولي أمر)';
  else performer = '👨‍🏫 ' + performer + ' (مدرس)';

  return {
    label: meta.text,
    badgeClass: meta.badge,
    detailText,
    detailParts: parts,
    changesText,
    performerText: performer,
    sentence: `${performer} ${meta.text}${detailText !== '—' ? ' — ' + detailText : ''}${changesText ? ' (' + changesText + ')' : ''}`,
  };
}
