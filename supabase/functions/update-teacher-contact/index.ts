// supabase/functions/update-teacher-contact/index.ts
// يسمح للمدرس بتحديث بيانات التواصل الخاصة بيه (تظهر لمساعديه وأولياء أمور طلابه عند المشاكل)
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
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const payload = await verifyToken(req);
    const body = await req.json();
    const action = body.action;
    // ✅ (طلب) المساعد ملوش صلاحية يغيّر أي من بيانات تواصل/براندنج المدرس — إلا فعل واحد بس:
    // توليد رابط تسجيل جديد، ولو معاه صلاحية manage_registration الجديدة اللي المدرس يمنحها له
    // صراحة (نفس منطق باقي الصلاحيات — مفيش وصول تلقائي لحد ما المدرس يفعّلها)
    if (payload.role !== "teacher") {
      if (payload.role === "assistant" && action === "regenerateRegistrationToken") {
        await requireAssistantPermission(payload, "manage_registration");
      } else {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح إلا للمدرس نفسه" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }
    const tokenClientId = ownerClientId(payload);

    // ✅ رفع شعار فعلي (صورة) لتخزين Supabase Storage، بدل رابط نصي يدوي
    if (action === "uploadLogo") {
      const { imageBase64, fileExt } = body;
      if (!imageBase64 || !fileExt) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const cleanExt = String(fileExt).toLowerCase().replace(/^\./, "");
      const allowedExts: Record<string, string> = {
        png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp", svg: "image/svg+xml",
      };
      if (!allowedExts[cleanExt]) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ صيغة الصورة غير مدعومة (المسموح: png, jpg, jpeg, webp, svg)" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const base64Data = imageBase64.includes(",") ? imageBase64.split(",")[1] : imageBase64;
      const binaryData = Uint8Array.from(atob(base64Data), (c) => c.charCodeAt(0));
      const MAX_LOGO_SIZE_BYTES = 2 * 1024 * 1024;
      if (binaryData.length > MAX_LOGO_SIZE_BYTES) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ حجم الصورة أكبر من الحد المسموح (2 ميجا)" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ لو فيه شعار قديم مرفوع، نحاول نحذفه (best-effort — مش بيوقف العملية لو فشل)
      const { data: existingTeacher } = await supabase
        .from("teachers").select("brand_logo_url").eq("client_id", tokenClientId).maybeSingle();
      if (existingTeacher?.brand_logo_url) {
        try {
          const oldPath = existingTeacher.brand_logo_url.split("/teacher-logos/")[1];
          if (oldPath) await supabase.storage.from("teacher-logos").remove([oldPath]);
        } catch (_e) { /* تجاهل — حذف الشعار القديم اختياري */ }
      }

      const storagePath = `${tokenClientId}/logo-${Date.now()}.${cleanExt}`;
      const { error: uploadError } = await supabase.storage.from("teacher-logos").upload(storagePath, binaryData, {
        contentType: allowedExts[cleanExt], upsert: true,
      });
      if (uploadError) {
        // ✅ (طلب) لو الـ bucket نفسه مش موجود (لسه ما اتعملش يدوي في Supabase Storage)، بنوضح
        // ده صراحة بدل رسالة عامة زي "Bucket not found" — نفس نمط الحل المستخدم في manage-login-ad
        const rawMessage = (uploadError as any)?.message || "";
        const bucketMissing = /bucket/i.test(rawMessage) && /not found|does not exist/i.test(rawMessage);
        const friendlyMessage = bucketMissing
          ? "⚠️ مساحة تخزين شعارات المدرسين (teacher-logos) لسه مش متعملة على السيرفر — لازم تتعمل يدوياً من Supabase Storage كـ bucket عام (Public) الأول"
          : `⚠️ فشل رفع الشعار: ${rawMessage || "حاول مرة أخرى"}`;
        return new Response(JSON.stringify({ success: false, message: friendlyMessage }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: publicUrlData } = supabase.storage.from("teacher-logos").getPublicUrl(storagePath);

      const { error: updateError } = await supabase
        .from("teachers").update({ brand_logo_url: publicUrlData.publicUrl }).eq("client_id", tokenClientId);
      if (updateError) throw new Error(updateError.message);

      return new Response(JSON.stringify({ success: true, brand_logo_url: publicUrlData.publicUrl }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ Aug 2026: توليد رابط تسجيل جديد (registration_token عشوائي) — مفيد لو الرابط القديم
    // اتسرّب أو المدرس عايز يوقف اللي كان شغال بالرابط القديم من غير ما يعطّل حسابه كله.
    // بنحاول 3 مرات لو حصل تصادم نادر جداً (unique index على registration_token).
    if (action === "regenerateRegistrationToken") {
      let newToken = "";
      let saved = false;
      for (let attempt = 0; attempt < 3 && !saved; attempt++) {
        newToken = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
        const { error: tokenError } = await supabase
          .from("teachers").update({ registration_token: newToken }).eq("client_id", tokenClientId);
        if (!tokenError) { saved = true; break; }
        // ✅ لو الخطأ مش تصادم unique (23505)، مفيش داعي نكرر المحاولة
        if ((tokenError as any).code !== "23505") throw new Error(tokenError.message);
      }
      if (!saved) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ تعذّر توليد رابط جديد، حاول تاني" }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ success: true, message: "✅ تم توليد رابط تسجيل جديد", registrationToken: newToken }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { contactWhatsapp, contactPhone, absenceThresholdMinutes, brandLogoUrl, brandColor, conversationsEnabled, whatsappVisible, phoneVisible } = body;

    const updates: any = {};
    if (contactWhatsapp !== undefined) updates.contact_whatsapp = contactWhatsapp || null;
    if (contactPhone !== undefined) updates.contact_phone = contactPhone || null;
    if (absenceThresholdMinutes !== undefined) updates.absence_threshold_minutes = Number(absenceThresholdMinutes);
    if (brandLogoUrl !== undefined) updates.brand_logo_url = brandLogoUrl || null;
    if (brandColor !== undefined) updates.brand_color = brandColor || null;
    // ✅ (طلب) تفعيل/تعطيل محادثات أولياء الأمور — لما تتعطّل، تبويب "محادثات أولياء الأمور"
    // يختفي من messages.html عند المدرس، وتبويب "تواصل" يختفي من صفحة الطالب عند ولي الأمر
    if (conversationsEnabled !== undefined) updates.conversations_enabled = !!conversationsEnabled;
    // ✅ (طلب) إظهار/إخفاء رقم واتساب المدرس لأولياء الأمور — مستقل عن محادثات داخل التطبيق
    if (whatsappVisible !== undefined) updates.whatsapp_visible = !!whatsappVisible;
    // ✅ (طلب) إظهار/إخفاء رقم الهاتف للمدرس لأولياء الأمور — رقم مستقل تمامًا عن الواتساب
    if (phoneVisible !== undefined) updates.phone_visible = !!phoneVisible;

    const { error } = await supabase
      .from("teachers")
      .update(updates)
      .eq("client_id", tokenClientId);

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ تم حفظ بيانات التواصل بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
