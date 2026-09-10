// supabase/functions/get-parent-children/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

// ============================================
// (من _shared/auth.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// ============================================
// ============================================
// موديول موحّد للتحقق من هوية المستخدم (JWT)
// يُستورد في كل دالة تحتاج تأكيد هوية بدل تكرار الكود
// ============================================
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
  "Access-Control-Max-Age": "86400",
};

export interface TokenPayload {
  sub: string;
  clientId?: string;
  teacherId?: string;
  username?: string;
  phone?: string;
  role: "teacher" | "assistant" | "parent";
  name: string;
  exp: number;
}

export class AuthError extends Error {
  status: number;
  code?: string;
  constructor(message: string, status = 401, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function getKey() {
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) {
    throw new Error("⚠️ JWT_SECRET غير مضبوط في متغيرات البيئة");
  }
  return await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

/** عميل Supabase بصلاحيات كاملة، مخصص لفحص الترخيص فقط (بدون تكرار الاستيراد في كل دالة) */
async function licenseCheckClient() {
  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2.38.4");
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

/**
 * يتحقق من حالة ترخيص المدرس (نشط + لم تنتهِ صلاحيته).
 * يُستخدم تلقائياً جوه verifyToken لكل توكن مدرس/مساعد، فيغطي المساعدين تلقائياً
 * (توكن المساعد بيتحقق من ترخيص المدرس بتاعه نفسه).
 */
async function checkLicenseActive(teacherClientId: string): Promise<{ active: boolean; reason?: string }> {
  if (teacherClientId === "master_admin") return { active: true };

  const supabase = await licenseCheckClient();
  const { data: teacher, error } = await supabase
    .from("teachers")
    .select("is_active, expiry_date")
    .eq("client_id", teacherClientId)
    .maybeSingle();

  if (error || !teacher) return { active: false, reason: "الحساب غير موجود" };
  if (teacher.is_active === false) return { active: false, reason: "الحساب معطّل" };

  if (teacher.expiry_date) {
    const todayCLA = new Date().toISOString().split("T")[0];
    if (teacher.expiry_date < todayCLA) return { active: false, reason: "انتهت صلاحية الترخيص" };
  }

  return { active: true };
}

/**
 * يتحقق من صحة الـ Authorization header ويرجّع بيانات التوكن.
 * يرمي AuthError (401) لو التوكن غير موجود/غير صالح/منتهي.
 * يرمي AuthError (402, code=LICENSE_EXPIRED) لو ترخيص المدرس (أو مدرس المساعد) منتهي/معطّل.
 * مرّر skipLicenseCheck:true فقط للدوال العامة اللي المفروض تشتغل حتى لو الترخيص منتهي (نادر جداً).
 */
export async function verifyToken(req: Request, opts?: { skipLicenseCheck?: boolean }): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new AuthError("⚠️ التوكن مطلوب", 401);
  }
  const token = authHeader.substring(7);
  const key = await getKey();
  let payload: TokenPayload;
  try {
    payload = (await verify(token, key, "HS256")) as unknown as TokenPayload;
  } catch (_e) {
    throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401);
  }

  if (!opts?.skipLicenseCheck && (payload.role === "teacher" || payload.role === "assistant")) {
    const ownerId = payload.clientId || payload.teacherId;
    if (ownerId) {
      const license = await checkLicenseActive(ownerId);
      if (!license.active) {
        throw new AuthError(
          `⛔ ${license.reason || "انتهت صلاحية الترخيص"} — يرجى التواصل مع الإدارة`,
          402,
          "LICENSE_EXPIRED"
        );
      }
    }
  }

  return payload;
}

/**
 * يتحقق من هوية جهاز قارئ الكروت (ESP32) عن طريق سر خاص بكل مدرس،
 * بديل عن التوكن العادي لأن الجهاز مش عنده تسجيل دخول. يرجّع بيانات المدرس لو صح.
 */
export async function verifyDeviceSecret(clientId: string, deviceSecret: string): Promise<void> {
  if (!clientId || !deviceSecret) {
    throw new AuthError("⚠️ بيانات الجهاز ناقصة (clientId أو deviceSecret)", 401);
  }
  const supabase = await licenseCheckClient();
  const { data: teacher, error } = await supabase
    .from("teachers")
    .select("device_secret, is_active, expiry_date")
    .eq("client_id", clientId)
    .maybeSingle();

  if (error || !teacher || !teacher.device_secret) {
    throw new AuthError("⛔ جهاز غير معروف", 401);
  }
  if (teacher.device_secret !== deviceSecret) {
    throw new AuthError("⛔ سر الجهاز غير صحيح", 401);
  }
  if (teacher.is_active === false) {
    throw new AuthError("⛔ حساب المدرس معطّل", 402, "LICENSE_EXPIRED");
  }
  if (teacher.expiry_date) {
    const today = new Date().toISOString().split("T")[0];
    if (teacher.expiry_date < today) {
      throw new AuthError("⛔ انتهت صلاحية الترخيص", 402, "LICENSE_EXPIRED");
    }
  }
}

/** يرجّع معرّف "المدرس المالك" للحساب (نفس clientId للمدرس، أو teacherId للمساعد) */
export function ownerClientId(payload: TokenPayload): string {
  const id = payload.clientId || payload.teacherId;
  if (!id) throw new AuthError("⚠️ التوكن لا يحتوي على clientId", 401);
  return id;
}

/** يتأكد إن التوكن (مدرس أو مساعد تابع له) مصرح له بالوصول لبيانات clientId المطلوب */
export function requireOwnClientId(payload: TokenPayload, requestedClientId?: string | null) {
  const tokenClientId = ownerClientId(payload);
  if (requestedClientId && requestedClientId !== tokenClientId) {
    throw new AuthError("⛔ غير مصرح لك بمشاهدة بيانات هذا المدرس", 403);
  }
  return tokenClientId;
}

/** يتأكد إن التوكن ده لحساب المشرف الرئيسي (master_admin) */
export function requireAdmin(payload: TokenPayload) {
  if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
    throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
  }
}

/** يتأكد إن التوكن لحساب ولي أمر برقم هاتف محدد */
export function requireParentPhone(payload: TokenPayload, requestedPhone?: string | null) {
  if (payload.role !== "parent" || !payload.phone) {
    throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
  }
  if (requestedPhone && requestedPhone !== payload.phone) {
    throw new AuthError("⛔ غير مصرح لك بمشاهدة بيانات هذا الطالب", 403);
  }
  return payload.phone;
}

/**
 * يتأكد إن باقة المدرس (المُحدّدة من الأدمن) فيها الميزة المطلوبة.
 * لو المفتاح مش موجود في permissions (مدرس قديم قبل إضافة الميزة دي) بنسمح افتراضياً (توافق مع الحسابات القديمة).
 * لا تُستدعى لحساب master_admin.
 */
export async function requireTeacherPlanPermission(clientId: string, permKey: string): Promise<void> {
  if (clientId === "master_admin") return;
  const supabase = await licenseCheckClient();
  const { data: teacher } = await supabase
    .from("teachers").select("permissions").eq("client_id", clientId).maybeSingle();
  const perms = teacher?.permissions || {};
  if (perms[permKey] === false) {
    throw new AuthError("⛔ هذه الميزة غير متاحة في باقتك الحالية، تواصل مع الإدارة لتفعيلها", 403, "PLAN_RESTRICTED");
  }
}

/**
 * يتأكد إن المساعد عنده صلاحية محددة منحها له المدرس. لا تأثير على المدرس نفسه (دايماً مسموح له).
 */
export async function requireAssistantPermission(payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const supabase = await licenseCheckClient();
  const { data: assistant } = await supabase
    .from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) {
    throw new AuthError("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس", 403);
  }
}

/** يحوّل AuthError لـ Response جاهزة */
export function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(
    JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة"); // ✅ رفض واضح بدل السقوط الصامت لصلاحيات anon
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطريقة غير مسموحة" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  try {
    const payload = await verifyToken(req);
    const { parentPhone } = await req.json();

    if (!parentPhone) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ رقم الهاتف مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // ✅ لازم توكن ولي أمر بنفس رقم الهاتف المطلوب
    requireParentPhone(payload, parentPhone);

    const { data: students, error: studentError } = await supabase
      .from("students").select("uid, name, group_name, teacher_id").eq("parent_phone", parentPhone);

    if (studentError) {
      return new Response(JSON.stringify({ success: false, message: studentError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (!students || students.length === 0) {
      return new Response(JSON.stringify({ success: true, data: [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const today = new Date().toISOString().split("T")[0];
    const result: any[] = [];

    const groupsMap = new Map<string, any[]>();
    students.forEach((s: any) => {
      const group = s.group_name || "بدون مجموعة";
      if (!groupsMap.has(group)) groupsMap.set(group, []);
      groupsMap.get(group)!.push(s);
    });

    const workingDaysCache = new Map<string, Set<string>>();
    const presentDatesByStudent = new Map<string, Set<string>>();

    for (const [groupName, groupStudents] of groupsMap) {
      const uids = groupStudents.map((s: any) => s.uid);
      const { data: attendanceData, error: attError } = await supabase
        .from("attendance").select("date, student_uid").in("student_uid", uids).eq("status", "present").not("date", "is", null);

      if (attError) { console.error(`خطأ في جلب أيام العمل للمجموعة ${groupName}:`, attError); continue; }

      const workingDaysSet = new Set<string>();
      attendanceData?.forEach((record: any) => {
        if (!record.date) return;
        workingDaysSet.add(record.date);
        if (!presentDatesByStudent.has(record.student_uid)) presentDatesByStudent.set(record.student_uid, new Set());
        presentDatesByStudent.get(record.student_uid)!.add(record.date);
      });
      workingDaysCache.set(groupName, workingDaysSet);
    }

    // ✅ دفعة واحدة بدل استعلام منفصل لكل طالب: المدرسين، درجات كل الطلاب، وحضور اليوم لكل الطلاب
    const allUids = students.map((s: any) => s.uid);
    const uniqueTeacherIds = [...new Set(students.map((s: any) => s.teacher_id).filter(Boolean))];

    const [{ data: teachers }, { data: allGrades }, { data: todayAttendance }, { data: allPayments }, { data: allExamAttempts }] = await Promise.all([
      uniqueTeacherIds.length > 0
        ? supabase.from("teachers").select("client_id, name, contact_whatsapp, contact_phone, conversations_enabled, whatsapp_visible, phone_visible").in("client_id", uniqueTeacherIds)
        : Promise.resolve({ data: [] as any[] }),
      supabase.from("grades").select("student_uid, score, max_score").in("student_uid", allUids),
      supabase.from("attendance").select("student_uid, status").in("student_uid", allUids).eq("date", today),
      // ✅ Batch 22 (بند 2): إجمالي المدفوعات كان غايب تماماً من كارت الطالب عند ولي الأمر
      supabase.from("payments").select("student_uid, amount, total_amount").in("student_uid", allUids),
      // ✅ Batch 23 (بند 2): "عدد الامتحانات" في الكارت كان فعليًا بيعدّ صفوف جدول grades بس
      // (يشمل الاختبار الإلكتروني لو counts_toward_grade فقط) — مش كل الاختبارات الإلكترونية اللي
      // الطالب فعلاً دخلها. exam_attempts (mode='official') هو السجل الحقيقي لكل محاولة اختبار
      // إلكتروني رسمية بغض النظر عن احتسابها في الدرجة من عدمه
      supabase.from("exam_attempts").select("student_uid").in("student_uid", allUids).eq("mode", "official"),
    ]);

    const teacherMap = new Map<string, any>((teachers || []).map((t: any) => [t.client_id, t]));
    const gradesByStudent = new Map<string, any[]>();
    (allGrades || []).forEach((g: any) => {
      if (!gradesByStudent.has(g.student_uid)) gradesByStudent.set(g.student_uid, []);
      gradesByStudent.get(g.student_uid)!.push(g);
    });
    // ✅ Batch 24 (بند 1): طالب ممكن يحضر أكتر من حصة في نفس اليوم دلوقتي — لو معاه أكتر من صف
    // حضور النهاردة (حاضر لحصة وغايب عن حصة تانية مثلاً)، بيتعرض "حاضر" لولي الأمر طالما حضر
    // ولو حصة واحدة، بدل ما يعتمد على آخر صف وصل بترتيب عشوائي
    const todayAttendanceMap = new Map<string, string>();
    (todayAttendance || []).forEach((a: any) => {
      const prev = todayAttendanceMap.get(a.student_uid);
      if (prev !== "present") todayAttendanceMap.set(a.student_uid, a.status);
    });
    const paymentsByStudent = new Map<string, any[]>();
    (allPayments || []).forEach((p: any) => {
      if (!paymentsByStudent.has(p.student_uid)) paymentsByStudent.set(p.student_uid, []);
      paymentsByStudent.get(p.student_uid)!.push(p);
    });
    const examAttemptsCountByStudent = new Map<string, number>();
    (allExamAttempts || []).forEach((e: any) => {
      examAttemptsCountByStudent.set(e.student_uid, (examAttemptsCountByStudent.get(e.student_uid) || 0) + 1);
    });

    for (const student of students as any[]) {
      const group = student.group_name || "بدون مجموعة";
      const workingDaysSet = workingDaysCache.get(group) || new Set<string>();
      const totalWorkingDays = workingDaysSet.size;

      const teacher = teacherMap.get(student.teacher_id);
      const grades = gradesByStudent.get(student.uid) || [];

      let gradesCount = grades.length;
      let avgGrade = 0;
      if (grades.length > 0) {
        let totalScore = 0, totalMax = 0;
        grades.forEach((g: any) => { totalScore += Number(g.score); totalMax += Number(g.max_score) || 100; });
        avgGrade = totalMax > 0 ? (totalScore / totalMax) * 100 : 0;
      }

      const presentDays = presentDatesByStudent.get(student.uid)?.size || 0;
      const absentDays = totalWorkingDays - presentDays;
      const attendancePercent = totalWorkingDays > 0 ? Math.round((presentDays / totalWorkingDays) * 100) : 0;

      // ✅ Batch 22 (بند 2): إجمالي المدفوع + إجمالي المطلوب لكل طالب
      const payments = paymentsByStudent.get(student.uid) || [];
      let totalPaid = 0, totalDue = 0;
      payments.forEach((p: any) => { totalPaid += Number(p.amount) || 0; totalDue += Number(p.total_amount) || 0; });

      result.push({
        uid: student.uid, name: student.name, group_name: group,
        teacher_name: teacher?.name || "غير محدد",
        // ✅ (طلب) المدرس يقدر يخفي رقم الواتساب عن أولياء الأمور — منفصل تماماً عن محادثات داخل التطبيق
        teacher_whatsapp: (teacher?.whatsapp_visible !== false) ? (teacher?.contact_whatsapp || null) : null,
        // ✅ (طلب) نفس منطق إخفاء الواتساب بالظبط — كان رقم الهاتف بيتعرض دايماً من غير أي تحكم،
        // ودلوقتي بقى المدرس يقدر يخفيه عن أولياء الأمور برضه (phone_visible)
        teacher_phone: (teacher?.phone_visible !== false) ? (teacher?.contact_phone || null) : null,
        conversations_enabled: teacher?.conversations_enabled !== false,
        today_attendance: todayAttendanceMap.get(student.uid) || "absent",
        grades_count: gradesCount, avg_grade: Math.round(avgGrade),
        attendance_percent: attendancePercent, present_days: presentDays,
        total_working_days: totalWorkingDays, absent_days: absentDays,
        total_paid: totalPaid, total_due: totalDue,
        // ✅ Batch 23 (بند 2): عدد الاختبارات الإلكترونية الرسمية الفعلية اللي الطالب دخلها
        exams_count: examAttemptsCountByStudent.get(student.uid) || 0
      });
    }

    return new Response(JSON.stringify({ success: true, data: result }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ عام:", error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
