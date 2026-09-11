// supabase/functions/manage-backup/index.ts
// ✅ دالة موحّدة تجمع export-backup + restore-backup — action: export | restore
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
};

interface TokenPayload { sub: string; clientId?: string; teacherId?: string; role: string; name: string; }

class AuthError extends Error {
  status: number; code?: string;
  constructor(message: string, status = 401, code?: string) { super(message); this.status = status; this.code = code; }
}

async function verifyToken(req: Request): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) throw new AuthError("⚠️ التوكن مطلوب", 401);
  const token = authHeader.substring(7);
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) throw new Error("⚠️ JWT_SECRET غير مضبوط");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  try { return (await verify(token, key, "HS256")) as unknown as TokenPayload; }
  catch (_e) { throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401); }
}

function requireOwnClientId(payload: TokenPayload, requestedClientId?: string | null): string {
  const tokenClientId = payload.clientId || payload.teacherId;
  if (!tokenClientId) throw new AuthError("⚠️ التوكن لا يحتوي على clientId", 401);
  if (requestedClientId && requestedClientId !== tokenClientId) throw new AuthError("⛔ غير مصرح لك بمشاهدة بيانات هذا المدرس", 403);
  return tokenClientId;
}

async function requireTeacherPlanPermission(supabase: any, clientId: string, permKey: string): Promise<void> {
  if (clientId === "master_admin") return;
  const { data: teacher } = await supabase.from("teachers").select("permissions").eq("client_id", clientId).maybeSingle();
  const perms = teacher?.permissions || {};
  if (perms[permKey] === false) throw new AuthError("⛔ هذه الميزة غير متاحة في باقتك الحالية، تواصل مع الإدارة لتفعيلها", 403, "PLAN_RESTRICTED");
}

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// هاش وتحقق كلمات المرور (لازمة لـ restore بس، لكن مفيش ضرر من وجودها في export كمان)
// ============================================
const ITERATIONS = 100_000;
function toHex(bytes: Uint8Array): string { return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(""); }
function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}
async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, keyMaterial, 256);
  return new Uint8Array(bits);
}
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function legacySha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(hashBuffer));
}
async function verifyPassword(password: string, storedHash: string): Promise<{ valid: boolean }> {
  if (storedHash.startsWith("pbkdf2$")) {
    const parts = storedHash.split("$");
    if (parts.length !== 4) return { valid: false };
    const [, iterStr, saltHex, hashHex] = parts;
    const salt = fromHex(saltHex);
    const computed = await pbkdf2(password, salt, parseInt(iterStr, 10));
    return { valid: timingSafeEqual(toHex(computed), hashHex) };
  }
  const legacy = await legacySha256(password);
  return { valid: timingSafeEqual(legacy, storedHash) };
}

// ============================================
// حماية من التخمين المتكرر (نفس منطق _shared/rateLimit.ts الأصلي)
// ============================================
async function checkRateLimit(supabase: any, key: string): Promise<{ blocked: boolean; message?: string }> {
  const { data } = await supabase.from("login_attempts").select("attempts, locked_until").eq("username", key).maybeSingle();
  if (data?.locked_until && new Date(data.locked_until) > new Date()) {
    const minutes = Math.ceil((new Date(data.locked_until).getTime() - Date.now()) / 60000);
    return { blocked: true, message: `⛔ تم حظر المحاولات مؤقتاً، حاول بعد ${minutes} دقيقة` };
  }
  return { blocked: false };
}
async function registerFailedAttempt(supabase: any, key: string) {
  const { data } = await supabase.from("login_attempts").select("attempts").eq("username", key).maybeSingle();
  const attempts = (data?.attempts || 0) + 1;
  const lockedUntil = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000).toISOString() : null;
  await supabase.from("login_attempts").upsert({ username: key, attempts, locked_until: lockedUntil, last_attempt: new Date().toISOString() });
}
async function clearAttempts(supabase: any, key: string) {
  await supabase.from("login_attempts").delete().eq("username", key);
}

// ============================================
// ⭐ العملية 1: تصدير نسخة احتياطية
// ============================================
async function handleExport(supabase: any, payload: TokenPayload, body: any) {
  const { clientId } = body;
  if (!clientId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ clientId مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const finalClientId = requireOwnClientId(payload, clientId);
  if (payload.role === "assistant") {
    return new Response(JSON.stringify({ success: false, message: "⛔ النسخ الاحتياطي متاح للمدرس بس" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  await requireTeacherPlanPermission(supabase, finalClientId, "can_use_backup");

  // ✅ Batch 24 (بند 5): النسخة الاحتياطية كانت ناقصة كتير من بيانات المدرس (المصروفات،
  // حصص الحضور، أسماء المدرسين، المراحل التعليمية، عناوين الدرجات/الاختبارات الإلكترونية بالكامل،
  // ربط الطلاب بأكتر من مجموعة، ربط السنتر بالمدرسين، المحادثات، كروت NFC، أولياء الأمور،
  // والإشعارات) — بننزّل كل جداول بيانات المدرس دلوقتي عشان النسخة تبقى شاملة فعلاً
  const [
    teacherRes, studentsRes, groupsRes, gradesRes, paymentsRes, booksRes, bookPaymentsRes,
    attendanceRes, assistantsRes, attendanceSessionsRes, expensesRes, instructorNamesRes,
    educationLevelsRes, paymentTitlesRes, examTitlesRes, onlineExamsRes, studentGroupLinksRes,
    studentTeacherLinksRes, conversationMessagesRes, systemCardsRes, cardActionModeRes, notificationsRes,
  ] = await Promise.all([
    supabase.from("teachers").select("client_id, name, expiry_date, max_students, permissions, contact_whatsapp, contact_phone").eq("client_id", finalClientId).maybeSingle(),
    supabase.from("students").select("*").eq("teacher_id", finalClientId),
    supabase.from("groups").select("*").eq("teacher_id", finalClientId),
    supabase.from("grades").select("*").eq("teacher_id", finalClientId),
    supabase.from("payments").select("*").eq("teacher_id", finalClientId),
    supabase.from("books").select("*").eq("teacher_id", finalClientId),
    supabase.from("book_payments").select("*").eq("teacher_id", finalClientId),
    supabase.from("attendance").select("*").eq("teacher_id", finalClientId),
    supabase.from("assistants").select("id, username, name, permissions, is_active").eq("teacher_id", finalClientId),
    supabase.from("attendance_sessions").select("*").eq("teacher_id", finalClientId),
    supabase.from("expenses").select("*").eq("teacher_id", finalClientId),
    supabase.from("instructor_names").select("*").eq("teacher_id", finalClientId),
    supabase.from("education_levels").select("*").eq("teacher_id", finalClientId),
    supabase.from("payment_titles").select("*").eq("teacher_id", finalClientId),
    supabase.from("exam_titles").select("*").eq("teacher_id", finalClientId),
    supabase.from("online_exams").select("*").eq("teacher_id", finalClientId),
    supabase.from("student_group_links").select("*").eq("teacher_id", finalClientId),
    supabase.from("student_teacher_links").select("*").eq("teacher_id", finalClientId),
    supabase.from("conversation_messages").select("*").eq("teacher_id", finalClientId),
    supabase.from("system_cards").select("*").eq("teacher_id", finalClientId),
    supabase.from("card_action_mode").select("*").eq("teacher_id", finalClientId),
    supabase.from("notifications").select("*").eq("teacher_id", finalClientId),
  ]);

  // بيانات الاختبارات الإلكترونية بترتبط بـ exam_id/attempt_id مش teacher_id مباشرة
  const examIds = (onlineExamsRes.data || []).map((e: any) => e.id);
  const [examQuestionsRes, examTargetStudentsRes, examAttemptsRes] = examIds.length
    ? await Promise.all([
        supabase.from("exam_questions").select("*").in("exam_id", examIds),
        supabase.from("exam_target_students").select("*").in("exam_id", examIds),
        supabase.from("exam_attempts").select("*").in("exam_id", examIds),
      ])
    : [{ data: [] }, { data: [] }, { data: [] }];

  const attemptIds = (examAttemptsRes.data || []).map((a: any) => a.id);
  const examAnswersRes = attemptIds.length
    ? await supabase.from("exam_answers").select("*").in("attempt_id", attemptIds)
    : { data: [] };

  // أولياء الأمور مش مرتبطين بـ teacher_id، بيترتبطوا برقم تليفون الطالب
  const parentPhones = [...new Set((studentsRes.data || []).map((s: any) => s.parent_phone).filter(Boolean))];
  const parentsRes = parentPhones.length
    ? await supabase.from("parents").select("phone, name, is_active, must_change_password").in("phone", parentPhones)
    : { data: [] };

  const backup = {
    exported_at: new Date().toISOString(),
    teacher: teacherRes.data,
    students: studentsRes.data || [],
    groups: groupsRes.data || [],
    grades: gradesRes.data || [],
    payments: paymentsRes.data || [],
    books: booksRes.data || [],
    book_payments: bookPaymentsRes.data || [],
    attendance: attendanceRes.data || [],
    assistants: assistantsRes.data || [],
    attendance_sessions: attendanceSessionsRes.data || [],
    expenses: expensesRes.data || [],
    instructor_names: instructorNamesRes.data || [],
    education_levels: educationLevelsRes.data || [],
    payment_titles: paymentTitlesRes.data || [],
    exam_titles: examTitlesRes.data || [],
    online_exams: onlineExamsRes.data || [],
    exam_questions: examQuestionsRes.data || [],
    exam_target_students: examTargetStudentsRes.data || [],
    exam_attempts: examAttemptsRes.data || [],
    exam_answers: examAnswersRes.data || [],
    student_group_links: studentGroupLinksRes.data || [],
    student_teacher_links: studentTeacherLinksRes.data || [],
    conversation_messages: conversationMessagesRes.data || [],
    system_cards: systemCardsRes.data || [],
    card_action_mode: cardActionModeRes.data || [],
    parents: parentsRes.data || [],
    notifications: notificationsRes.data || [],
  };

  await supabase.from("activity_logs").insert({
    client_id: finalClientId, teacher_id: finalClientId, action_type: "export_backup",
    details: { students_count: backup.students.length, grades_count: backup.grades.length, payments_count: backup.payments.length },
    performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
  });

  return new Response(JSON.stringify({ success: true, data: backup }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 2: استعادة نسخة احتياطية
// ============================================
async function handleRestore(supabase: any, payload: TokenPayload, body: any) {
  const { clientId, password, backup } = body;
  if (!clientId || !password || !backup) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ clientId وكلمة المرور وملف النسخة الاحتياطية مطلوبين" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const finalClientId = requireOwnClientId(payload, clientId);
  if (payload.role === "assistant") {
    return new Response(JSON.stringify({ success: false, message: "⛔ النسخ الاحتياطي متاح للمدرس بس" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  await requireTeacherPlanPermission(supabase, finalClientId, "can_use_backup");

  const rateLimitKey = `restore-backup:${finalClientId}`;
  const rateLimit = await checkRateLimit(supabase, rateLimitKey);
  if (rateLimit.blocked) {
    return new Response(JSON.stringify({ success: false, message: rateLimit.message }),
      { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: teacherRow, error: teacherError } = await supabase.from("teachers").select("password_hash").eq("client_id", finalClientId).maybeSingle();
  if (teacherError || !teacherRow) {
    return new Response(JSON.stringify({ success: false, message: "تعذر التحقق من الحساب" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { valid } = await verifyPassword(password, teacherRow.password_hash);
  if (!valid) {
    await registerFailedAttempt(supabase, rateLimitKey);
    return new Response(JSON.stringify({ success: false, message: "⛔ كلمة المرور غير صحيحة" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  await clearAttempts(supabase, rateLimitKey);

  if (backup.teacher && backup.teacher.client_id && backup.teacher.client_id !== finalClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه النسخة الاحتياطية ليست تابعة لحسابك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // 1) مسح البيانات الحالية بالكامل
  const { data: currentStudents } = await supabase.from("students").select("uid").eq("teacher_id", finalClientId);
  const currentUids = (currentStudents || []).map((s: any) => s.uid);

  const { data: currentExams } = await supabase.from("online_exams").select("id").eq("teacher_id", finalClientId);
  const currentExamIds = (currentExams || []).map((e: any) => e.id);
  if (currentExamIds.length > 0) {
    const { data: currentAttempts } = await supabase.from("exam_attempts").select("id").in("exam_id", currentExamIds);
    const currentAttemptIds = (currentAttempts || []).map((a: any) => a.id);
    if (currentAttemptIds.length > 0) await supabase.from("exam_answers").delete().in("attempt_id", currentAttemptIds);
    await supabase.from("exam_attempts").delete().in("exam_id", currentExamIds);
    await supabase.from("exam_target_students").delete().in("exam_id", currentExamIds);
    await supabase.from("exam_questions").delete().in("exam_id", currentExamIds);
  }
  await supabase.from("online_exams").delete().eq("teacher_id", finalClientId);
  await supabase.from("exam_titles").delete().eq("teacher_id", finalClientId);

  await supabase.from("attendance").delete().eq("teacher_id", finalClientId);
  await supabase.from("attendance_sessions").delete().eq("teacher_id", finalClientId);
  await supabase.from("book_payments").delete().eq("teacher_id", finalClientId);
  await supabase.from("books").delete().eq("teacher_id", finalClientId);
  await supabase.from("expenses").delete().eq("teacher_id", finalClientId);
  await supabase.from("payment_titles").delete().eq("teacher_id", finalClientId);
  await supabase.from("card_action_mode").delete().eq("teacher_id", finalClientId);
  await supabase.from("conversation_messages").delete().eq("teacher_id", finalClientId);
  await supabase.from("notifications").delete().eq("teacher_id", finalClientId);
  await supabase.from("student_teacher_links").delete().eq("teacher_id", finalClientId);
  await supabase.from("system_cards").update({ student_uid: null, linked_at: null }).eq("teacher_id", finalClientId);
  if (currentUids.length > 0) {
    await supabase.from("payments").delete().in("student_uid", currentUids);
    await supabase.from("grades").delete().in("student_uid", currentUids);
    await supabase.from("student_group_links").delete().in("student_uid", currentUids);
  }
  await supabase.from("students").delete().eq("teacher_id", finalClientId);
  try {
    const { error: checkError } = await supabase.from("groups").select("id").limit(1);
    if (!checkError) await supabase.from("groups").delete().eq("teacher_id", finalClientId);
  } catch (_) { /* جدول groups قد لا يكون موجوداً */ }
  await supabase.from("instructor_names").delete().eq("teacher_id", finalClientId);
  await supabase.from("education_levels").delete().eq("teacher_id", finalClientId);

  // 2) إعادة إدراج بيانات النسخة الاحتياطية
  const clean = (rows: any[]) => (rows || []).map((r: any) => { const { id, ...rest } = r; return rest; });
  let restoredCounts: Record<string, number> = {};

  // ✅ Batch 24 (بند 5): أسماء المدرسين والمراحل التعليمية بيترجع لهم id جديد عند الإدراج،
  // ومجموعات/حضور/حصص قديمة بتشاور على الـ id القديم (instructor_name_id / level_id) —
  // لازم نعمل mapping من القديم للجديد قبل ما نرجّع الجداول اللي بتشاور عليهم
  const instructorIdMap: Record<string, string> = {};
  if (backup.instructor_names?.length) {
    const { data, error } = await supabase.from("instructor_names").insert(clean(backup.instructor_names)).select("id, name");
    if (error) console.error("⚠️ فشل استعادة أسماء المدرسين:", error.message);
    else (data || []).forEach((row: any, idx: number) => { instructorIdMap[String(backup.instructor_names[idx].id)] = row.id; });
    restoredCounts.instructor_names = backup.instructor_names.length;
  }
  const levelIdMap: Record<string, string> = {};
  if (backup.education_levels?.length) {
    const { data, error } = await supabase.from("education_levels").insert(clean(backup.education_levels)).select("id, name");
    if (error) console.error("⚠️ فشل استعادة المراحل التعليمية:", error.message);
    else (data || []).forEach((row: any, idx: number) => { levelIdMap[String(backup.education_levels[idx].id)] = row.id; });
    restoredCounts.education_levels = backup.education_levels.length;
  }

  if (backup.groups?.length) {
    const remapped = backup.groups.map((g: any) => {
      const { id, ...rest } = g;
      return {
        ...rest,
        instructor_name_id: g.instructor_name_id ? (instructorIdMap[String(g.instructor_name_id)] ?? null) : null,
        level_id: g.level_id ? (levelIdMap[String(g.level_id)] ?? null) : null,
      };
    });
    const { error } = await supabase.from("groups").insert(remapped);
    if (error) console.error("⚠️ فشل استعادة المجموعات:", error.message);
    restoredCounts.groups = backup.groups.length;
  }
  if (backup.students?.length) {
    let restored = 0;
    for (const student of backup.students) {
      const { error } = await supabase.from("students").insert(student);
      if (error) console.error(`⚠️ فشل استعادة الطالب ${student.name || student.uid}:`, error.message);
      else restored++;
    }
    restoredCounts.students = restored;
  }
  if (backup.grades?.length) {
    const { error } = await supabase.from("grades").insert(clean(backup.grades));
    if (error) console.error("⚠️ فشل استعادة الدرجات:", error.message);
    restoredCounts.grades = backup.grades.length;
  }
  if (backup.payments?.length) {
    const { error } = await supabase.from("payments").insert(clean(backup.payments));
    if (error) console.error("⚠️ فشل استعادة المدفوعات:", error.message);
    restoredCounts.payments = backup.payments.length;
  }
  if (backup.books?.length) {
    const { error } = await supabase.from("books").insert(backup.books);
    if (error) console.error("⚠️ فشل استعادة المذكرات:", error.message);
    restoredCounts.books = backup.books.length;
  }
  if (backup.book_payments?.length) {
    const { error } = await supabase.from("book_payments").insert(clean(backup.book_payments));
    if (error) console.error("⚠️ فشل استعادة سدادات المذكرات:", error.message);
    restoredCounts.book_payments = backup.book_payments.length;
  }
  if (backup.attendance?.length) {
    const remapped = backup.attendance.map((a: any) => {
      const { id, ...rest } = a;
      return { ...rest, instructor_name_id: a.instructor_name_id ? (instructorIdMap[String(a.instructor_name_id)] ?? null) : null };
    });
    const { error } = await supabase.from("attendance").insert(remapped);
    if (error) console.error("⚠️ فشل استعادة الحضور:", error.message);
    restoredCounts.attendance = backup.attendance.length;
  }
  if (backup.attendance_sessions?.length) {
    const remapped = backup.attendance_sessions.map((s: any) => {
      const { id, ...rest } = s;
      return { ...rest, instructor_name_id: s.instructor_name_id ? (instructorIdMap[String(s.instructor_name_id)] ?? null) : null };
    });
    const { error } = await supabase.from("attendance_sessions").insert(remapped);
    if (error) console.error("⚠️ فشل استعادة حصص اليوم:", error.message);
    restoredCounts.attendance_sessions = backup.attendance_sessions.length;
  }
  if (backup.expenses?.length) {
    const { error } = await supabase.from("expenses").insert(clean(backup.expenses));
    if (error) console.error("⚠️ فشل استعادة المصروفات:", error.message);
    restoredCounts.expenses = backup.expenses.length;
  }
  if (backup.payment_titles?.length) {
    const { error } = await supabase.from("payment_titles").insert(clean(backup.payment_titles));
    if (error) console.error("⚠️ فشل استعادة عناوين المدفوعات:", error.message);
    restoredCounts.payment_titles = backup.payment_titles.length;
  }
  if (backup.exam_titles?.length) {
    const { error } = await supabase.from("exam_titles").insert(clean(backup.exam_titles));
    if (error) console.error("⚠️ فشل استعادة عناوين الاختبارات:", error.message);
    restoredCounts.exam_titles = backup.exam_titles.length;
  }
  if (backup.card_action_mode?.length) {
    const { error } = await supabase.from("card_action_mode").insert(clean(backup.card_action_mode));
    if (error) console.error("⚠️ فشل استعادة وضع بطاقات NFC:", error.message);
    restoredCounts.card_action_mode = backup.card_action_mode.length;
  }
  if (backup.conversation_messages?.length) {
    const { error } = await supabase.from("conversation_messages").insert(clean(backup.conversation_messages));
    if (error) console.error("⚠️ فشل استعادة رسائل المحادثات:", error.message);
    restoredCounts.conversation_messages = backup.conversation_messages.length;
  }
  if (backup.student_group_links?.length) {
    const { error } = await supabase.from("student_group_links").insert(clean(backup.student_group_links));
    if (error) console.error("⚠️ فشل استعادة روابط المجموعات المتعددة:", error.message);
    restoredCounts.student_group_links = backup.student_group_links.length;
  }
  if (backup.student_teacher_links?.length) {
    const { error } = await supabase.from("student_teacher_links").insert(clean(backup.student_teacher_links));
    if (error) console.error("⚠️ فشل استعادة روابط السنتر:", error.message);
    restoredCounts.student_teacher_links = backup.student_teacher_links.length;
  }
  if (backup.parents?.length) {
    let restored = 0;
    for (const parent of backup.parents) {
      const { error } = await supabase.from("parents").upsert(parent, { onConflict: "phone" });
      if (!error) restored++;
    }
    restoredCounts.parents = restored;
  }
  if (backup.notifications?.length) {
    const { error } = await supabase.from("notifications").insert(clean(backup.notifications));
    if (error) console.error("⚠️ فشل استعادة الإشعارات:", error.message);
    restoredCounts.notifications = backup.notifications.length;
  }
  // ✅ كروت الـ NFC مش بتتحذف/تتعاد إنشاؤها (مخزون فعلي)، بس بنعيد ربطها بالطلاب حسب النسخة
  if (backup.system_cards?.length) {
    let relinked = 0;
    for (const card of backup.system_cards) {
      if (!card.card_uid) continue;
      const { error } = await supabase.from("system_cards")
        .update({ student_uid: card.student_uid || null, linked_at: card.linked_at || null })
        .eq("card_uid", card.card_uid).eq("teacher_id", finalClientId);
      if (!error) relinked++;
    }
    restoredCounts.system_cards = relinked;
  }

  // ✅ الاختبارات الإلكترونية: online_exams -> exam_questions/exam_target_students/exam_attempts -> exam_answers
  // كل مرحلة بتاخد id جديد ولازم نعمل mapping قبل ما نرجّع الجداول اللي بتشاور عليها
  const examIdMap: Record<string, string> = {};
  if (backup.online_exams?.length) {
    const { data, error } = await supabase.from("online_exams").insert(clean(backup.online_exams)).select("id");
    if (error) console.error("⚠️ فشل استعادة الاختبارات الإلكترونية:", error.message);
    else (data || []).forEach((row: any, idx: number) => { examIdMap[String(backup.online_exams[idx].id)] = row.id; });
    restoredCounts.online_exams = backup.online_exams.length;
  }
  const questionIdMap: Record<string, string> = {};
  if (backup.exam_questions?.length) {
    const remapped = backup.exam_questions.map((q: any) => ({ ...q, exam_id: examIdMap[String(q.exam_id)] ?? q.exam_id }));
    const clean2 = remapped.map((r: any) => { const { id, ...rest } = r; return rest; });
    const { data, error } = await supabase.from("exam_questions").insert(clean2).select("id");
    if (error) console.error("⚠️ فشل استعادة أسئلة الاختبارات:", error.message);
    else (data || []).forEach((row: any, idx: number) => { questionIdMap[String(backup.exam_questions[idx].id)] = row.id; });
    restoredCounts.exam_questions = backup.exam_questions.length;
  }
  if (backup.exam_target_students?.length) {
    const remapped = backup.exam_target_students.map((t: any) => {
      const { id, ...rest } = t;
      return { ...rest, exam_id: examIdMap[String(t.exam_id)] ?? t.exam_id };
    });
    const { error } = await supabase.from("exam_target_students").insert(remapped);
    if (error) console.error("⚠️ فشل استعادة الطلاب المستهدفين بالاختبار:", error.message);
    restoredCounts.exam_target_students = backup.exam_target_students.length;
  }
  const attemptIdMap: Record<string, string> = {};
  if (backup.exam_attempts?.length) {
    const remapped = backup.exam_attempts.map((a: any) => {
      const { id, ...rest } = a;
      return { ...rest, exam_id: examIdMap[String(a.exam_id)] ?? a.exam_id };
    });
    const { data, error } = await supabase.from("exam_attempts").insert(remapped).select("id");
    if (error) console.error("⚠️ فشل استعادة محاولات الاختبارات:", error.message);
    else (data || []).forEach((row: any, idx: number) => { attemptIdMap[String(backup.exam_attempts[idx].id)] = row.id; });
    restoredCounts.exam_attempts = backup.exam_attempts.length;
  }
  if (backup.exam_answers?.length) {
    const remapped = backup.exam_answers.map((ans: any) => ({
      attempt_id: attemptIdMap[String(ans.attempt_id)] ?? ans.attempt_id,
      question_id: questionIdMap[String(ans.question_id)] ?? ans.question_id,
      selected_answer: ans.selected_answer, is_correct: ans.is_correct, points_earned: ans.points_earned,
    }));
    const { error } = await supabase.from("exam_answers").insert(remapped);
    if (error) console.error("⚠️ فشل استعادة إجابات الاختبارات:", error.message);
    restoredCounts.exam_answers = backup.exam_answers.length;
  }

  await supabase.from("teachers").update({ student_count: backup.students?.length || 0 }).eq("client_id", finalClientId);

  await supabase.from("activity_logs").insert({
    client_id: finalClientId, teacher_id: finalClientId, action_type: "restore_backup",
    details: { ...restoredCounts, restored_at: new Date().toISOString() },
    performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
  });

  return new Response(JSON.stringify({ success: true, message: "✅ تم استعادة النسخة الاحتياطية بنجاح", data: restoredCounts }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const body = await req.json();
    const action = body.action;

    if (action === "export") return await handleExport(supabase, payload, body);
    if (action === "restore") return await handleRestore(supabase, payload, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في manage-backup:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
