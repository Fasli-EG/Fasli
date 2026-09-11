// supabase/functions/get-dashboard/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// ============================================
// (من _shared/auth.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// ============================================
// ============================================
// موديول موحّد للتحقق من هوية المستخدم (JWT)
// يُستورد في كل دالة تحتاج تأكيد هوية بدل تكرار الكود
// ============================================
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

export const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
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

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const payload = await verifyToken(req);

    const tokenClientId = payload.clientId || payload.teacherId;
    if (!tokenClientId) {
      console.error("❌ التوكن لا يحتوي على clientId");
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ التوكن لا يحتوي على clientId" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }


    const { clientId } = await req.json();

    if (clientId && clientId !== tokenClientId) {
      console.error(`❌ clientId غير متطابق: ${clientId} != ${tokenClientId}`);
      return new Response(
        JSON.stringify({ success: false, message: "⛔ غير مصرح لك بمشاهدة بيانات هذا المدرس" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const finalClientId = tokenClientId;

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    const today = new Date().toISOString().split("T")[0];
    const sevenDaysAgoPre = new Date();
    sevenDaysAgoPre.setDate(sevenDaysAgoPre.getDate() - 6);
    const sevenDaysAgoStrPre = sevenDaysAgoPre.toISOString().split("T")[0];
    const oneHourAgoPre = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    // ✅ تحسين أداء: الاستعلامات السبعة دي مستقلة عن بعض (مفيش واحد محتاج نتيجة التاني)
    // فكانت بتتنفذ واحد ورا التاني بالتتابع (7 round-trips) رغم إنهم يقدروا يتنفذوا مع بعض.
    // Promise.all بيبعتهم كلهم مرة واحدة، فزمن التنفيذ الكلي بقى = أبطأ استعلام لوحده
    // بدل مجموع الكل — get-dashboard ده بيتنادى في كل تحميل للوحة التحكم.
    const [
      { data: teacher, error: teacherError },
      { count: totalStudents, error: countError },
      { data: todayAttendance, error: attendanceError },
      { data: groupsData, error: groupsError },
      { data: groupRows, error: groupRowsError },
      { data: weekAttendance, error: weekAttError },
      { data: activities, error: activitiesError },
    ] = await Promise.all([
      supabase.from("teachers").select("*").eq("client_id", finalClientId).single(),
      supabase.from("students").select("id", { count: "exact", head: true })
        .eq("teacher_id", finalClientId).is("archived_at", null),
      supabase.from("attendance").select("student_uid, status")
        .eq("teacher_id", finalClientId).eq("date", today),
      supabase.from("students").select("group_name")
        .eq("teacher_id", finalClientId).not("group_name", "is", null).is("archived_at", null),
      supabase.from("groups").select("name").eq("teacher_id", finalClientId),
      supabase.from("attendance").select("date")
        .eq("teacher_id", finalClientId).eq("status", "present").gte("date", sevenDaysAgoStrPre),
      supabase.from("activity_logs")
        .select(`id, action_type, details, performer_id, performer_role, performer_name, created_at`)
        .eq("client_id", finalClientId)
        .gte("created_at", oneHourAgoPre)
        .or("performer_role.is.null,performer_role.neq.admin")
        .or("performer_id.is.null,performer_id.neq.master_admin")
        .order("created_at", { ascending: false })
        .limit(50),
    ]);

    if (teacherError || !teacher) {
      console.error("❌ المدرس غير موجود:", teacherError);
      return new Response(
        JSON.stringify({ success: false, message: "المدرس غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
    if (countError) throw new Error(`فشل جلب عدد الطلاب: ${countError.message}`);
    if (attendanceError) throw new Error(`فشل جلب حضور اليوم: ${attendanceError.message}`);
    if (groupsError) throw new Error(`فشل جلب المجموعات: ${groupsError.message}`);
    if (groupRowsError) throw new Error(`فشل جلب جدول المجموعات: ${groupRowsError.message}`);
    if (weekAttError) console.error("خطأ في جلب حضور آخر 7 أيام:", weekAttError);
    if (activitiesError) console.error("❌ خطأ في جلب النشاطات:", activitiesError);

    // ✅ Batch 24 (بند 1): بعد ما بقى مسموح للطالب يحضر أكتر من حصة في نفس اليوم (كل حصة صف
    // حضور منفصل)، عدّ الصفوف الخام هنا كان بيضخّم الرقم — طالب حضر حصتين النهاردة كان بيتحسب
    // 2 في "حضور اليوم" بدل 1. دلوقتي بنعدّ الطلاب المتفرّدين، وأي طالب حضر ولو حصة واحدة
    // النهاردة بيتحسب "حاضر" حتى لو معاه صف غياب لحصة تانية في نفس اليوم
    const statusByStudent = new Map<string, string>();
    (todayAttendance || []).forEach((a: any) => {
      const prev = statusByStudent.get(a.student_uid);
      if (prev !== "present") statusByStudent.set(a.student_uid, a.status);
    });
    const presentToday = Array.from(statusByStudent.values()).filter((s) => s === "present").length;
    const absentToday = Array.from(statusByStudent.values()).filter((s) => s === "absent").length;

    const groupCounts: Record<string, number> = {};
    (groupsData || []).forEach((s: any) => {
      const name = s.group_name || "بدون مجموعة";
      groupCounts[name] = (groupCounts[name] || 0) + 1;
    });

    // ✅ إصلاح (Aug 2026): عدد المجموعات كان بيتحسب من أسماء مجموعات الطلاب بس، فأي مجموعة اتعملت
    // فعلاً في جدول groups بس لسه معندهاش طلاب (زي مجموعة جديدة فاضية) كانت مش بتتحسب خالص —
    // نضيفها هنا بعدد 0 طالب، بنفس منطق الدمج المستخدم في manage-group's handleListDetailed
    (groupRows || []).forEach((g: any) => {
      if (!(g.name in groupCounts)) groupCounts[g.name] = 0;
    });

    const groups = Object.keys(groupCounts);
    const groupCountsArray = Object.values(groupCounts);

    const dayCounts: Record<string, number> = {};
    (weekAttendance || []).forEach((r: any) => {
      dayCounts[r.date] = (dayCounts[r.date] || 0) + 1;
    });

    const weeklyData = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split("T")[0];
      weeklyData.push({ date: dateStr, count: dayCounts[dateStr] || 0 });
    }

    const formattedActivities = activities || [];

    // ✅ مقارنة تاريخ بتاريخ بس (بدون وقت)، عشان المدرس يفضل له اليوم كامل لحد آخره
    // — مقارنة timestamp كانت بتعتبره منتهي من أول ثانية في يوم الانتهاء نفسه
    const todayDashStr = new Date().toISOString().split("T")[0];
    const in7DaysStr = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];

    const responseData = {
      teacher: {
        ...teacher,
        licenseStatus: teacher.is_active 
          ? (teacher.expiry_date && teacher.expiry_date < todayDashStr
              ? "expired" 
              : teacher.expiry_date && teacher.expiry_date < in7DaysStr
                ? "expiring_soon" 
                : "active")
          : "inactive",
        daysRemaining: teacher.expiry_date 
          ? Math.ceil((new Date(teacher.expiry_date + "T00:00:00Z").getTime() - new Date(todayDashStr + "T00:00:00Z").getTime()) / (1000 * 60 * 60 * 24))
          : null,
      },
      totalStudents: totalStudents || 0,
      todayAttendance: presentToday,
      absentToday: absentToday,
      groupsCount: groups.length,
      groups: groups,
      groupCounts: groupCountsArray,
      weeklyAttendance: weeklyData,
      recentActivities: formattedActivities,
    };

    return new Response(
      JSON.stringify({ success: true, data: responseData }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في get-dashboard:", error);
    return new Response(
      JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

