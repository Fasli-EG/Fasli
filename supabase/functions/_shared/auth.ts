// supabase/functions/_shared/auth.ts
// ============================================
// موديول موحّد للتحقق من هوية المستخدم (JWT)
// يُستورد في كل دالة تحتاج تأكيد هوية بدل تكرار الكود
// ============================================
// ✅ (هجرة Supabase Auth) verifyToken بقى بيتحقق من توكن Supabase Auth الحقيقي بدل التوكن
// المخصص القديم (djwt + JWT_SECRET يدوي). بيانات الدور (role/clientId/sub/...) بقت متخزّنة
// في app_metadata بتاعة مستخدم Supabase (بتتحط وقت إنشاء الحساب)، ونفس شكل TokenPayload
// اتحافظ عليه بالظبط عشان الـ80+ فانكشن اللي بتستورد الملف ده متحتاجش أي تعديل خالص.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

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
  role: "teacher" | "assistant" | "parent" | "student";
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

/** عميل Supabase بصلاحيات كاملة — مستخدم لفحص الترخيص، وكمان للتحقق من توكنات Supabase Auth */
export async function licenseCheckClient() {
  // ✅ ترتيب المتغيرات هنا لازم يطابق باقي المشروع (SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY الأول) —
  // كان معكوس هنا تحديدًا (نفس فئة الباج التاريخي اللي كسر الأوث قبل كده)
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

/** يفك تشفير جزء الـpayload من JWT من غير أي تحقق من التوقيع — يُستخدم بس لقراءة exp
 * (قيمة عرض/توثيق مش منطق أمان، التحقق الحقيقي بيحصل عن طريق supabase.auth.getUser أصلاً) */
function decodeJwtExpUnsafe(token: string): number {
  try {
    const payloadPart = token.split(".")[1];
    const json = JSON.parse(atob(payloadPart.replace(/-/g, "+").replace(/_/g, "/")));
    return typeof json.exp === "number" ? json.exp : 0;
  } catch (_e) {
    return 0;
  }
}

/**
 * يتحقق من حالة ترخيص المدرس (نشط + لم تنتهِ صلاحيته).
 * يُستخدم تلقائياً جوه verifyToken لكل توكن مدرس/مساعد، فيغطي المساعدين تلقائياً
 * (توكن المساعد بيتحقق من ترخيص المدرس بتاعه نفسه).
 */
async function checkLicenseActive(teacherClientId: string): Promise<{ active: boolean; reason?: string }> {
  if (teacherClientId === "Fasli-admin") return { active: true };

  const supabase = await licenseCheckClient();
  const { data: teacher, error } = await supabase
    .from("teachers")
    .select("is_active, expiry_date")
    .eq("client_id", teacherClientId)
    .maybeSingle();

  if (error || !teacher) return { active: false, reason: "الحساب غير موجود" };
  if (teacher.is_active === false) return { active: false, reason: "الحساب معطّل" };

  if (teacher.expiry_date) {
    const today = new Date().toISOString().split("T")[0];
    if (teacher.expiry_date < today) return { active: false, reason: "انتهت صلاحية الترخيص" };
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

  const supabase = await licenseCheckClient();
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) {
    throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401);
  }

  // ✅ بيانات دورنا احنا (role/clientId/sub الحقيقي/...) متخزّنة في app_metadata، مش في
  // مستوى الـclaims الأعلى بتاعة Supabase نفسها — دي بتتحط وقت إنشاء كل حساب (منطق منفصل)
  const meta = (data.user.app_metadata || {}) as Record<string, unknown>;
  if (!meta.role || meta.sub === undefined || meta.sub === null) {
    throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401);
  }
  const payload: TokenPayload = {
    sub: String(meta.sub),
    clientId: meta.clientId as string | undefined,
    teacherId: meta.teacherId as string | undefined,
    username: meta.username as string | undefined,
    phone: meta.phone as string | undefined,
    role: meta.role as TokenPayload["role"],
    name: meta.name as string,
    exp: decodeJwtExpUnsafe(token),
  };

  // ✅ Batch 27 (أمان حرج): لو المدرس عطّل/فصل مساعد، التوكن بتاعه كان يفضل شغال بالكامل لحد
  // ما ينتهي بطبيعته (~ساعة، وممكن يتجدد لو معاه refresh token) — محدش كان بيتحقق أبداً من
  // assistants.is_active في أي مكان (لا هنا ولا في requireAssistantPermission، واللي أصلاً
  // مش كل الدوال بتنادي عليها زي get-students). التحقق ده لازم يبقى هنا، نقطة العبور الوحيدة
  // لكل الدوال، وغير مرتبط بـskipLicenseCheck (فصل المساعد أخطر وأشمل من مجرد انتهاء ترخيص)
  if (payload.role === "assistant") {
    const supabaseForAssistant = await licenseCheckClient();
    const { data: assistantRow } = await supabaseForAssistant
      .from("assistants").select("is_active").eq("id", payload.sub).maybeSingle();
    if (!assistantRow || assistantRow.is_active === false) {
      throw new AuthError("⛔ تم إلغاء تفعيل حسابك، تواصل مع المدرس", 403);
    }
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

/** يتأكد إن التوكن ده لحساب المشرف الرئيسي (Fasli-admin) */
export function requireAdmin(payload: TokenPayload) {
  if (payload.role !== "teacher" || payload.clientId !== "Fasli-admin") {
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
 * لا تُستدعى لحساب Fasli-admin.
 */
export async function requireTeacherPlanPermission(clientId: string, permKey: string): Promise<void> {
  if (clientId === "Fasli-admin") return;
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
