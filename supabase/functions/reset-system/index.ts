// supabase/functions/reset-system/index.ts
// أخطر دالة في النظام: تمسح كل بيانات المدرس (طلاب، مجموعات، مدفوعات، درجات، مذكرات، كروت، إشعارات، سجل نشاطات)
// وتُبقي على حساب المدرس نفسه وحسابات المساعدين بتوعه فقط
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

// ============================================
// (من _shared/password.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// ============================================
// ============================================
// هاش كلمات المرور: PBKDF2-SHA256 (native Web Crypto API)
// اخترنا PBKDF2 بدل bcrypt لأنه مدعوم أصلاً في Deno/Supabase Edge Functions
// بدون أي مكتبة WASM خارجية قد تفشل في بيئة الإنتاج.
// ============================================

const ITERATIONS = 100_000;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

/** مقارنة بزمن ثابت لمنع timing attacks */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** هاش SHA-256 بسيط (النظام القديم) — لأغراض التوافق الخلفي فقط */
async function legacySha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(hashBuffer));
}

/** ينشئ هاش جديد بصيغة pbkdf2$<iterations>$<salt>$<hash> */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2(password, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${toHex(salt)}$${toHex(hashBytes)}`;
}

/**
 * يتحقق من كلمة المرور مقابل الهاش المخزّن (يدعم الصيغة الجديدة pbkdf2 والقديمة sha256 hex).
 * needsRehash=true تعني إن كلمة المرور صحيحة لكن مخزّنة بالصيغة القديمة الأضعف،
 * فيُستحسن استبدالها بهاش pbkdf2 جديد فوراً (ترقية شفافة تلقائية عند أول تسجيل دخول ناجح).
 */
export async function verifyPassword(
  password: string,
  storedHash: string
): Promise<{ valid: boolean; needsRehash: boolean }> {
  if (storedHash.startsWith("pbkdf2$")) {
    const parts = storedHash.split("$");
    if (parts.length !== 4) return { valid: false, needsRehash: false };
    const [, iterStr, saltHex, hashHex] = parts;
    const iterations = parseInt(iterStr, 10);
    const salt = fromHex(saltHex);
    const computed = await pbkdf2(password, salt, iterations);
    const valid = timingSafeEqual(toHex(computed), hashHex);
    return { valid, needsRehash: false };
  }

  // صيغة قديمة: SHA-256 hex بدون salt
  const legacy = await legacySha256(password);
  const valid = timingSafeEqual(legacy, storedHash);
  return { valid, needsRehash: valid }; // لو صحّت، نرقّيها فوراً بعد الاستخدام
}

// ============================================
// (من _shared/rateLimit.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// ============================================
// ============================================
// حماية عامة من الاستخدام المتكرر/التخمين (rate limiting)
// يعتمد على جدول login_attempts (key, attempts, locked_until, last_attempt)
// نفس الجدول يُستخدم لأي مفتاح (login أو change-password...) بادئة مختلفة فقط
// ============================================
// اسم مستعار فريد عمداً لتفادي أي تعارض مع "createClient" في الملفات اللي بتدمج هذا الموديول
import { createClient as _createRateLimitClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

export interface RateLimitOptions {
  maxAttempts?: number;   // الحد الأقصى للمحاولات قبل الحظر (افتراضي 5)
  lockMinutes?: number;   // مدة الحظر بالدقائق (افتراضي 15)
}

function adminClient() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return _createRateLimitClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

/** يتحقق هل المفتاح محظور حالياً. يرجّع رسالة عربية جاهزة لو محظور. */
export async function checkRateLimit(
  key: string,
  opts: RateLimitOptions = {}
): Promise<{ blocked: boolean; message?: string }> {
  const supabase = adminClient();
  const { data } = await supabase
    .from("login_attempts")
    .select("attempts, locked_until")
    .eq("username", key)
    .maybeSingle();

  if (data?.locked_until && new Date(data.locked_until) > new Date()) {
    const minutes = Math.ceil((new Date(data.locked_until).getTime() - Date.now()) / 60000);
    return { blocked: true, message: `⛔ تم حظر المحاولات مؤقتاً، حاول بعد ${minutes} دقيقة` };
  }
  return { blocked: false };
}

/** يسجّل محاولة فاشلة، ويحظر المفتاح تلقائياً لو تخطى الحد الأقصى */
export async function registerFailedAttempt(key: string, opts: RateLimitOptions = {}) {
  const maxAttempts = opts.maxAttempts ?? 5;
  const lockMinutes = opts.lockMinutes ?? 15;

  const supabase = adminClient();
  const { data } = await supabase
    .from("login_attempts")
    .select("attempts")
    .eq("username", key)
    .maybeSingle();

  const attempts = (data?.attempts || 0) + 1;
  const lockedUntil = attempts >= maxAttempts ? new Date(Date.now() + lockMinutes * 60 * 1000).toISOString() : null;

  await supabase.from("login_attempts").upsert({
    username: key,
    attempts,
    locked_until: lockedUntil,
    last_attempt: new Date().toISOString(),
  });
}

/** يصفّر عداد المحاولات عند النجاح */
export async function clearAttempts(key: string) {
  const supabase = adminClient();
  await supabase.from("login_attempts").delete().eq("username", key);
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    // ✅ أخطر دالة في النظام (حذف كل بيانات المدرس نهائياً) — لازم توكن + تأكيد صريح
    const payload = await verifyToken(req);
    if (payload.role === "assistant") {
      return new Response(JSON.stringify({ success: false, message: "⛔ العملية دي للمدرس نفسه بس، مش متاحة للمساعد خالص" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { clientId, password, options } = await req.json();

    // ✅ يحدد أي فئات بيانات تتحذف. لو "options" مش موجودة خالص (كود فرونت قديم مخزّن كاش)
    // نحذف كل حاجة زي الوضع القديم (توافق خلفي). لو موجودة، نحترمها بالظبط فئة فئة.
    const opts: Record<string, boolean> = options && typeof options === "object" ? options : {};
    const hasOptions = options && typeof options === "object";
    const want = (key: string) => (hasOptions ? opts[key] === true : true);

    if (!clientId) {
      return new Response(JSON.stringify({ success: false, message: "clientId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (!password) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ يجب إدخال كلمة المرور لتأكيد هذه العملية" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const finalClientId = requireOwnClientId(payload, clientId);

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    // ✅ حماية من محاولات تخمين الباسورد على هذه الدالة تحديداً
    const rateLimitKey = `reset-system:${finalClientId}`;
    const rateLimit = await checkRateLimit(rateLimitKey);
    if (rateLimit.blocked) {
      return new Response(JSON.stringify({ success: false, message: rateLimit.message }),
        { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ التحقق الفعلي من كلمة مرور المدرس نفسه (بدل كلمة تأكيد نصية ثابتة)
    const { data: teacherRow, error: teacherError } = await supabase
      .from("teachers").select("password_hash").eq("client_id", finalClientId).maybeSingle();

    if (teacherError || !teacherRow) {
      return new Response(JSON.stringify({ success: false, message: "تعذر التحقق من الحساب" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { valid } = await verifyPassword(password, teacherRow.password_hash);
    if (!valid) {
      await registerFailedAttempt(rateLimitKey);
      return new Response(JSON.stringify({ success: false, message: "⛔ كلمة المرور غير صحيحة" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    await clearAttempts(rateLimitKey);

    const { data: students, error: studentsError } = await supabase
      .from("students").select("uid").eq("teacher_id", finalClientId);

    if (studentsError) throw new Error(`فشل جلب الطلاب: ${studentsError.message}`);
    const uids = (students || []).map((s: any) => s.uid);

    // ✅ بيانات الطلاب الأكاديمية (الحضور، المدفوعات، الدرجات، سداد المذكرات) — كل فئة حسب اختيار المستخدم
    if (want("attendance")) {
      await supabase.from("attendance").delete().eq("teacher_id", finalClientId);
      // ✅ جلسات الحضور (attendance_sessions) تابعة لنفس فئة "سجلات الحضور"
      await supabase.from("attendance_sessions").delete().eq("teacher_id", finalClientId);
    }
    if (uids.length > 0) {
      if (want("payments")) await supabase.from("payments").delete().in("student_uid", uids);
      if (want("grades")) await supabase.from("grades").delete().in("student_uid", uids);
      if (want("bookPayments")) await supabase.from("book_payments").delete().in("student_uid", uids);
    }

    // ✅ كروت RFID: بما إنها ملك المدرس فعلياً (باعها الماستر له)، تفضل عنده لكن تتفصل عن الطلاب المحذوفين
    // (بيحصل بس لو هيتحذف الطلاب أنفسهم، عشان الكروت متتفصلش من طلاب لسه موجودين)
    if (want("students")) {
      await supabase.from("system_cards")
        .update({ student_uid: null, linked_at: null })
        .eq("teacher_id", finalClientId);
      await supabase.from("pending_card_registrations").delete().eq("teacher_id", finalClientId);

      // ✅ الطلاب أنفسهم
      await supabase.from("students").delete().eq("teacher_id", finalClientId).select("parent_phone").then(async ({ data: deletedStudents }) => {
        const parentPhones = [...new Set((deletedStudents || []).map((s: any) => s.parent_phone).filter(Boolean))];
        for (const phone of parentPhones) {
          const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("parent_phone", phone);
          if (!count || count === 0) {
            await supabase.from("parents").delete().eq("phone", phone);
          }
        }
      });

      await supabase.from("teachers").update({ student_count: 0 }).eq("client_id", finalClientId);
    }

    // ✅ المجموعات (وأسماء المدرسين التابعين للسنتر، بيانات تنظيمية مرتبطة بنفس فئة "المجموعات")
    if (want("groups")) {
      await supabase.from("groups").delete().eq("teacher_id", finalClientId);
      await supabase.from("instructor_names").delete().eq("teacher_id", finalClientId);
    }

    // ✅ المذكرات نفسها + ملفات الـ PDF المرفوعة لها في التخزين (Storage)
    if (want("books")) {
      await supabase.from("books").delete().eq("teacher_id", finalClientId);
      try {
        const { data: storageFiles } = await supabase.storage.from("book-files").list(finalClientId);
        if (storageFiles && storageFiles.length > 0) {
          const paths = storageFiles.map((f: any) => `${finalClientId}/${f.name}`);
          await supabase.storage.from("book-files").remove(paths);
        }
      } catch (storageErr) {
        // ✅ فشل حذف ملفات التخزين مش لازم يوقف باقي عملية إعادة التهيئة
        console.error("⚠️ تعذر حذف ملفات المذكرات من التخزين:", storageErr);
      }
    }

    // ✅ بنود السداد الثابتة
    if (want("paymentTitles")) {
      await supabase.from("payment_titles").delete().eq("teacher_id", finalClientId);
    }

    // ✅ أسماء الامتحانات المحفوظة (بنود ثابتة تُستخدم في إدخال الدرجات، غير مرتبطة بالامتحانات الإلكترونية)
    if (want("examTitles")) {
      await supabase.from("exam_titles").delete().eq("teacher_id", finalClientId);
    }

    // ✅ الامتحانات الإلكترونية: أسئلتها، الطلاب المستهدفين بيها، محاولات الطلاب وإجاباتهم
    if (want("onlineExams")) {
      const { data: onlineExams } = await supabase.from("online_exams").select("id").eq("teacher_id", finalClientId);
      const examIds = (onlineExams || []).map((e: any) => e.id);
      if (examIds.length > 0) {
        const { data: attempts } = await supabase.from("exam_attempts").select("id").in("exam_id", examIds);
        const attemptIds = (attempts || []).map((a: any) => a.id);
        if (attemptIds.length > 0) {
          await supabase.from("exam_answers").delete().in("attempt_id", attemptIds);
        }
        await supabase.from("exam_attempts").delete().in("exam_id", examIds);
        await supabase.from("exam_target_students").delete().in("exam_id", examIds);
        await supabase.from("exam_questions").delete().in("exam_id", examIds);
      }
      await supabase.from("online_exams").delete().eq("teacher_id", finalClientId);
    }

    // ✅ الإشعارات
    if (want("notifications")) {
      await supabase.from("notifications").delete().eq("teacher_id", finalClientId);
    }

    // ✅ مسح كل سجل النشاطات القديم الخاص بالمدرس (كما طُلب)
    if (want("activityLogs")) {
      await supabase.from("activity_logs").delete().eq("teacher_id", finalClientId);
    }

    // ✅ تسجيل واحد فقط يوثّق حدوث عملية إعادة التهيئة نفسها (دليل بعد الحذف)
    await supabase.from("activity_logs").insert({
      client_id: finalClientId, teacher_id: finalClientId, action_type: "reset_system",
      entity_type: "teacher", entity_id: finalClientId,
      details: { deleted_students: uids.length, deleted_at: new Date().toISOString(), options: hasOptions ? opts : "all (legacy)" },
      performer_id: finalClientId, performer_role: payload.role, performer_name: payload.name,
    });

    return new Response(JSON.stringify({ success: true, message: "✅ تم حذف البيانات اللي حددتها بنجاح (عدا حسابك وحسابات المساعدين)" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في reset-system:", error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
