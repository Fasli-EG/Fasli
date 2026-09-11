// supabase/functions/transfer-student/index.ts
// ينقل طالب من مجموعة لمجموعة تانية، وينقل معاه كل بياناته المرتبطة (درجات، مدفوعات، سداد مذكرات، حضور)
// لأن اسم المجموعة متكرر (denormalized) في كذا جدول لأسباب أداء الفلترة
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

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

// ✅ (طلب) نقل طالب لمجموعة جديدة هو "إضافة" ضمنية للمجموعة الجديدة — لازم يترفض لو المجموعة
// الجديدة وصلت لحدها الأقصى (max_students). العدد الحالي = مجموعة أساسية (students.group_name)
// + مجموعات إضافية (student_group_links)، نفس منطق العدّ في باقي الدوال. من غير حد أقصى = بلا رفض.
async function checkGroupCapacity(teacherId: string, groupName: string): Promise<{ ok: boolean; message?: string }> {
  const { data: group } = await supabase.from("groups").select("max_students").eq("teacher_id", teacherId).eq("name", groupName).maybeSingle();
  const maxStudents = group?.max_students;
  if (!maxStudents || maxStudents <= 0) return { ok: true };

  const { count: primaryCount } = await supabase
    .from("students").select("uid", { count: "exact", head: true }).eq("teacher_id", teacherId).eq("group_name", groupName);
  const { count: linkedCount } = await supabase
    .from("student_group_links").select("id", { count: "exact", head: true }).eq("teacher_id", teacherId).eq("group_name", groupName);
  const currentCount = (primaryCount || 0) + (linkedCount || 0);

  if (currentCount >= maxStudents) {
    return { ok: false, message: `⚠️ المجموعة "${groupName}" وصلت للحد الأقصى لعدد الطلاب (${maxStudents}) — لازم تزود الحد الأقصى أو تختار مجموعة تانية` };
  }
  return { ok: true };
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;
    await requireTeacherPlanPermission(tokenClientId, "can_manage_students");
    await requireAssistantPermission(payload, "edit_students");

    const { clientId, studentUid, newGroupName } = await req.json();

    if (!clientId || !studentUid || !newGroupName) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ clientId و studentUid و newGroupName مطلوبين" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (tokenClientId !== clientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: student, error: studentError } = await supabase
      .from("students").select("name, group_name, teacher_id").eq("uid", studentUid).maybeSingle();

    if (studentError || !student) {
      return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (student.teacher_id !== clientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const oldGroupName = student.group_name;
    if (oldGroupName === newGroupName) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب أصلاً في نفس المجموعة دي" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const capacity = await checkGroupCapacity(clientId, newGroupName);
    if (!capacity.ok) {
      return new Response(JSON.stringify({ success: false, message: capacity.message }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ نحدّث المجموعة في كل الجداول المرتبطة بالطالب مع بعض
    const [studentsUpdate, gradesUpdate, paymentsUpdate, bookPaymentsUpdate, attendanceUpdate] = await Promise.all([
      supabase.from("students").update({ group_name: newGroupName }).eq("uid", studentUid),
      supabase.from("grades").update({ group_name: newGroupName }).eq("student_uid", studentUid),
      supabase.from("payments").update({ group_name: newGroupName }).eq("student_uid", studentUid),
      supabase.from("book_payments").update({ group_name: newGroupName }).eq("student_uid", studentUid),
      supabase.from("attendance").update({ group_name: newGroupName }).eq("student_uid", studentUid),
    ]);

    const failedUpdates = [studentsUpdate, gradesUpdate, paymentsUpdate, bookPaymentsUpdate, attendanceUpdate]
      .filter((r) => r.error)
      .map((r) => r.error?.message);

    if (studentsUpdate.error) {
      console.error("❌ فشل نقل الطالب:", studentsUpdate.error);
      return new Response(JSON.stringify({ success: false, message: "فشل نقل الطالب: " + studentsUpdate.error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (failedUpdates.length > 0) {
      console.error("⚠️ نجح نقل الطالب لكن فشل تحديث بعض بياناته المرتبطة:", failedUpdates);
    }

    await supabase.from("activity_logs").insert({
      client_id: clientId, teacher_id: clientId,
      action_type: "transfer_student", entity_type: "student", entity_id: studentUid,
      details: { student_name: student.name, student_uid: studentUid, old_group: oldGroupName, new_group: newGroupName },
      performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
    });

    return new Response(JSON.stringify({
      success: true,
      message: `✅ تم نقل ${student.name} من "${oldGroupName}" إلى "${newGroupName}" بنجاح، مع كل بياناته`,
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
