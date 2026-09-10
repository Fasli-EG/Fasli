// supabase/functions/submit-rfid-scan/index.ts
// يستقبل قراية الكارت من جهاز ESP32 مباشرة (بدل الكتابة المباشرة في جدول rfid_scans بالـ anon key)
// التوثيق هنا بسر خاص بكل مدرس (device_secret) مش بتوكن عادي، لأن الجهاز مالوش تسجيل دخول
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
    const { clientId, uid, deviceSecret } = await req.json();

    if (!clientId || !uid || !deviceSecret) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ clientId و uid و deviceSecret مطلوبين" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ التحقق من إن الجهاز ده فعلاً بتاع المدرس صاحب clientId ده
    await verifyDeviceSecret(clientId, deviceSecret);
    await requireTeacherPlanPermission(clientId, "can_use_rfid");

    // ✅ أولاً: هل فيه طلب تسجيل كارت جديد معلّق لنفس المدرس ده؟ لو أيوه، الكارت ده يتسجّل كارت رسمي للطالب المطلوب
    // بدل ما يتسجّل كحضور عادي
    const NEW_STUDENT_SENTINEL = "__NEW_STUDENT__";
    const { data: pending } = await supabase
      .from("pending_card_registrations")
      .select("*")
      .eq("teacher_id", clientId)
      .is("registered_card_uid", null)
      .maybeSingle();

    if (pending) {
      const { data: card } = await supabase
        .from("system_cards").select("id, status, teacher_id, is_active, student_uid").eq("card_uid", uid).maybeSingle();

      let errorMsg: string | null = null;
      if (!card) {
        errorMsg = "⚠️ الكارت ده مش مسجّل في مخزون النظام خالص";
      } else if (card.status !== "assigned" || card.teacher_id !== clientId) {
        errorMsg = "⛔ الكارت ده مش متخصص لحسابك — كلّمي إدارة النظام";
      } else if (!card.is_active) {
        errorMsg = "⛔ الكارت ده متخصص لحسابك بس لسه مش مفعّل — كلّمي إدارة النظام";
      } else if (card.student_uid && card.student_uid !== pending.student_uid) {
        // ✅ لو الكارت مرتبط بطالب تاني بالفعل (وده مش نفس الطالب اللي بنحاول نربطه دلوقتي) — نجيب اسمه عشان الرسالة تبقى واضحة
        const { data: linkedStudent } = await supabase.from("students").select("name").eq("uid", card.student_uid).maybeSingle();
        errorMsg = `⚠️ الكارت ده متسجّل بالفعل للطالب: ${linkedStudent?.name || "غير معروف"}`;
      }

      if (errorMsg) {
        await supabase.from("pending_card_registrations").update({ error_message: errorMsg }).eq("teacher_id", clientId);
        return new Response(JSON.stringify({ success: false, message: errorMsg }),
          { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      if (pending.student_uid === NEW_STUDENT_SENTINEL) {
        // ✅ ده كارت لطالب لسه ما اتسجّلش أصلاً — نخزّن رقم الكارت بس ونسيب باقي التسجيل للفورم
        // (الربط الفعلي بـ system_cards هيحصل وقت إضافة الطالب نفسه في add-student)
        await supabase.from("pending_card_registrations").update({ registered_card_uid: uid, error_message: null }).eq("teacher_id", clientId);
        return new Response(JSON.stringify({ success: true, message: "✅ تم قراءة الكارت", registered: true }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ ربط كارت بطالب موجود بالفعل.
      // ✅ (طلب) كان ده بيتم عن طريق دالة قاعدة بيانات (`link_card_to_student` RPC) مش متتبّعة في
      // أي migration محلي عندنا (اتعملت مباشرة على السيرفر من غير ما تتسجّل في الكود) — يعني
      // سلوكها الفعلي مش موثّق ومش قابل للمراجعة، وكان فيه احتمال حقيقي إنها بتـ"سيب" أي كارت
      // تاني مربوط بنفس الطالب (اسم الدالة والتعليق القديم "تبديل الكارت" بيرجّحوا كده)، وده كان
      // هيمنع الطالب من إنه يتربط بأكتر من كارت في نفس الوقت. استبدلناها بتحديث مباشر وواضح على
      // صف الكارت المطلوب بس — من غير أي مسّ لأي كارت تاني، فالطالب يقدر يكون ليه أكتر من كارت
      // شغال في نفس الوقت من غير ما ربط كارت جديد يفصل كارت قديم كان شغال بالفعل
      const studentUidToLink = pending.student_uid;
      const newCardUid = uid;

      const { error: swapError, count: linkedCount } = await supabase
        .from("system_cards")
        .update({ student_uid: studentUidToLink, linked_at: new Date().toISOString() }, { count: "exact" })
        .eq("id", card.id)
        .eq("teacher_id", clientId);

      if (swapError || !linkedCount) {
        console.error("❌ فشل ربط الكارت:", swapError);
        const errMsg = "⚠️ حدث خطأ أثناء ربط الكارت، حاول مرة أخرى";
        await supabase.from("pending_card_registrations").update({ error_message: errMsg }).eq("teacher_id", clientId);
        return new Response(JSON.stringify({ success: false, message: errMsg }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ سجل تدقيق: نوثّق عملية ربط الكارت في سجل النشاطات
      const { data: teacherInfo } = await supabase.from("teachers").select("name").eq("client_id", clientId).maybeSingle();

      await supabase.from("activity_logs").insert({
        client_id: clientId,
        teacher_id: clientId,
        action_type: "link_rfid_card",
        entity_type: "system_card",
        entity_id: String(card.id),
        details: { student_name: pending.student_name, student_uid: studentUidToLink, card_uid: newCardUid },
        performer_id: clientId,
        performer_role: "teacher",
        performer_name: teacherInfo?.name || "مدرس",
      });

      await supabase.from("pending_card_registrations").update({ registered_card_uid: uid, error_message: null }).eq("teacher_id", clientId);

      return new Response(JSON.stringify({ success: true, message: "✅ تم ربط الكارت بالطالب بنجاح", registered: true }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ لو الكارت ده مسجّل في النظام (سواء الخاصية العامة مفعّلة ولا لأ) ومعطّل، نرفضه دايماً —
    // التعطيل لازم يشتغل فوري بغض النظر عن إعداد "التحقق الإجباري"، عشان لو المدرس عطّل كارت لطالب يفضل معطّل فعلاً
    const { data: knownCard } = await supabase
      .from("system_cards").select("id, is_active, teacher_id").eq("card_uid", uid).maybeSingle();

    if (knownCard && knownCard.teacher_id === clientId && !knownCard.is_active) {
      return new Response(JSON.stringify({ success: false, message: "⛔ الكارت ده معطّل حالياً" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ لو مفيش طلب تسجيل معلّق: نتحقق هل النظام مضبوط يرفض أي كارت مش مسجّل رسمياً ومفعّل
    const { data: settings } = await supabase.from("system_settings").select("require_registered_cards").eq("id", 1).maybeSingle();

    if (settings?.require_registered_cards) {
      const isRegisteredAndActive = knownCard && knownCard.teacher_id === clientId && knownCard.is_active;
      if (!isRegisteredAndActive) {
        return new Response(JSON.stringify({ success: false, message: "⛔ الكارت ده مش مسجّل رسمياً أو مش مفعّل في النظام" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }

    const { error } = await supabase.from("rfid_scans").insert({
      uid,
      client_id: clientId, // موثّق فعلياً دلوقتي، مش نص عادي أي حد يقدر يبعته
    });

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: error.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
