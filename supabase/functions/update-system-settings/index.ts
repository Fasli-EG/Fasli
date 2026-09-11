// supabase/functions/update-system-settings/index.ts
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

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const payload = await verifyToken(req);
    requireAdmin(payload);

    const body = await req.json();
    const {
      whatsappNumber, phoneNumber, facebookUrl, youtubeUrl, tiktokUrl, desktopDownloadUrl, mobileAppUrl,
      requireRegisteredCards, adminName, adminWhatsapp,
      portalBannerUrl, portalBannerLinkUrl, portalBannerShowStudent, portalBannerShowParent,
      portalBannerParentUrl, portalBannerParentLinkUrl,
      portalBannerStudentUrl, portalBannerStudentLinkUrl,
      portalBannerTeacherUrl, portalBannerTeacherLinkUrl, portalBannerShowTeacher,
      portalBannerAssistantUrl, portalBannerAssistantLinkUrl, portalBannerShowAssistant,
      loginCreditShow, loginCreditText,
      firebaseApiKey, firebaseAuthDomain, firebaseProjectId, firebaseStorageBucket,
      firebaseMessagingSenderId, firebaseAppId, firebaseVapidKey,
      showDownloadSection,
    } = body;

    // ✅ نبني كائن التحديث بس من الحقول اللي فعلاً اتبعتت، عشان مانمسحش إعدادات تانية بالغلط
    // لو حد استدعى الدالة دي بحقل واحد بس (زي تبديل خاصية الكروت من تاب تاني)
    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if ("whatsappNumber" in body) updates.whatsapp_number = whatsappNumber ?? null;
    if ("phoneNumber" in body) updates.phone_number = phoneNumber ?? null;
    if ("facebookUrl" in body) updates.facebook_url = facebookUrl ?? null;
    if ("youtubeUrl" in body) updates.youtube_url = youtubeUrl ?? null;
    if ("tiktokUrl" in body) updates.tiktok_url = tiktokUrl ?? null;
    if ("adminName" in body) updates.admin_name = adminName ?? null;
    if ("adminWhatsapp" in body) updates.admin_whatsapp = adminWhatsapp ?? null;
    if ("desktopDownloadUrl" in body) updates.desktop_download_url = desktopDownloadUrl ?? null;
    if ("mobileAppUrl" in body) updates.mobile_app_url = mobileAppUrl ?? null;
    if ("requireRegisteredCards" in body) updates.require_registered_cards = !!requireRegisteredCards;
    // ✅ Batch 24 (بند 8): اللافتة الإعلانية أعلى صفحة الطالب/ولي الأمر (حقول قديمة، لسه
    // متاحة للتوافق لكن الواجهة بقت بتستخدم الحقول المنفصلة بالأسفل لكل جمهور على حدة)
    if ("portalBannerUrl" in body) updates.portal_banner_url = portalBannerUrl ?? null;
    if ("portalBannerLinkUrl" in body) updates.portal_banner_link_url = portalBannerLinkUrl ?? null;
    if ("portalBannerShowStudent" in body) updates.portal_banner_show_student = !!portalBannerShowStudent;
    if ("portalBannerShowParent" in body) updates.portal_banner_show_parent = !!portalBannerShowParent;
    // ✅ Batch 28 (بند 1): لافتة إعلانية منفصلة بالكامل لكل جمهور (ولي أمر/طالب/مدرس/مساعد) —
    // كل واحدة عندها صورة ورابط وخيار إظهار مستقل، عشان الماستر يقدر يخصص إعلان مختلف لكل واحد
    if ("portalBannerParentUrl" in body) updates.portal_banner_parent_url = portalBannerParentUrl ?? null;
    if ("portalBannerParentLinkUrl" in body) updates.portal_banner_parent_link_url = portalBannerParentLinkUrl ?? null;
    if ("portalBannerStudentUrl" in body) updates.portal_banner_student_url = portalBannerStudentUrl ?? null;
    if ("portalBannerStudentLinkUrl" in body) updates.portal_banner_student_link_url = portalBannerStudentLinkUrl ?? null;
    if ("portalBannerTeacherUrl" in body) updates.portal_banner_teacher_url = portalBannerTeacherUrl ?? null;
    if ("portalBannerTeacherLinkUrl" in body) updates.portal_banner_teacher_link_url = portalBannerTeacherLinkUrl ?? null;
    if ("portalBannerShowTeacher" in body) updates.portal_banner_show_teacher = !!portalBannerShowTeacher;
    if ("portalBannerAssistantUrl" in body) updates.portal_banner_assistant_url = portalBannerAssistantUrl ?? null;
    if ("portalBannerAssistantLinkUrl" in body) updates.portal_banner_assistant_link_url = portalBannerAssistantLinkUrl ?? null;
    if ("portalBannerShowAssistant" in body) updates.portal_banner_show_assistant = !!portalBannerShowAssistant;
    // ✅ Batch 25 (بند 2): إظهار/إخفاء نص فوتر صفحة تسجيل الدخول، أو استبداله بنص مخصص كامل
    if ("loginCreditShow" in body) updates.login_credit_show = !!loginCreditShow;
    if ("loginCreditText" in body) updates.login_credit_text = loginCreditText ?? null;
    // ✅ Batch 32: إعدادات Firebase العامة (Web Config) — عشان تفعيل الإشعارات الحقيقية
    // (Push) لولي الأمر/الطالب/المدرس/المساعد. قيم عامة (public) بتصميم Firebase، مش أسرار
    if ("firebaseApiKey" in body) updates.firebase_api_key = firebaseApiKey ?? null;
    if ("firebaseAuthDomain" in body) updates.firebase_auth_domain = firebaseAuthDomain ?? null;
    if ("firebaseProjectId" in body) updates.firebase_project_id = firebaseProjectId ?? null;
    if ("firebaseStorageBucket" in body) updates.firebase_storage_bucket = firebaseStorageBucket ?? null;
    if ("firebaseMessagingSenderId" in body) updates.firebase_messaging_sender_id = firebaseMessagingSenderId ?? null;
    if ("firebaseAppId" in body) updates.firebase_app_id = firebaseAppId ?? null;
    if ("firebaseVapidKey" in body) updates.firebase_vapid_key = firebaseVapidKey ?? null;
    // ✅ Batch 33 (بند 2): تحكم الماستر في إظهار/إخفاء قسم روابط التحميل بالكامل في صفحة
    // تسجيل الدخول، مستقل عن كون الروابط نفسها متسجّلة أو لأ
    if ("showDownloadSection" in body) updates.show_download_section = !!showDownloadSection;

    const { error } = await supabase
      .from("system_settings")
      .update(updates)
      .eq("id", 1);

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ تم تحديث بيانات التواصل بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
