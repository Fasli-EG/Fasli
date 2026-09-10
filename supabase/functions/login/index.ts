// supabase/functions/login/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";
import { create, getNumericDate } from "https://deno.land/x/djwt@v2.8/mod.ts";

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

const JWT_SECRET = Deno.env.get("JWT_SECRET");
if (!JWT_SECRET) {
  throw new Error("⚠️ JWT_SECRET غير مضبوط في متغيرات البيئة");
}

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SUPABASE_SERVICE_ROLE_KEY غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

async function generateToken(payload: {
  clientId?: string;
  teacherId?: string;
  username?: string;
  phone?: string;
  role: string;
  userId: string;
  name: string;
}) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const jwtPayload = {
    sub: payload.userId,
    clientId: payload.clientId || null,
    teacherId: payload.teacherId || null,
    username: payload.username || null,
    phone: payload.phone || null,
    role: payload.role,
    name: payload.name,
    exp: getNumericDate(60 * 60 * 24 * 7),
  };
  return await create({ alg: "HS256", typ: "JWT" }, jwtPayload, key);
}

// ✅ اكتشاف نوع الحساب تلقائياً، بدل ما المستخدم يحدد الدور بنفسه — يقلل عدد الاختيارات في صفحة الدخول
// "staff": نجرب سنتر، ثم مدرس، ثم مساعد (بالترتيب). "family": نجرب ولي أمر، ثم طالب.
async function detectRole(group: string, username: string): Promise<string | null> {
  if (group === "staff") {
    // ✅ Aug 2026 (تعديل جوهري): جدول centers ومفهوم "حساب سنتر منفصل" اتلغى تماماً —
    // السنتر بقى مجرد صف في جدول teachers عليه علامة is_center، فبيتكشف عادي هنا زي أي مدرس.
    const { data: teacher } = await supabase.from("teachers").select("client_id").eq("client_id", username).maybeSingle();
    if (teacher) return "teacher";
    const { data: assistant } = await supabase.from("assistants").select("username").eq("username", username).maybeSingle();
    if (assistant) return "assistant";
    return null;
  }
  if (group === "family") {
    const { data: parent } = await supabase.from("parents").select("phone").eq("phone", username).maybeSingle();
    if (parent) return "parent";
    const { data: student } = await supabase.from("students").select("uid").eq("uid", username).maybeSingle();
    if (student) return "student";
    return null;
  }
  return null;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ success: false, message: "⚠️ الطريقة غير مسموحة" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    const body = await req.json();
    const { username, password } = body;
    let role = body.role;

    if (!username || !password || (!role && !body.group)) {
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ✅ لو الواجهة الجديدة بعتت "group" بدل "role" الصريحة، نكتشف نوع الحساب تلقائياً
    if (!role && body.group) {
      role = await detectRole(body.group, username);
      if (!role) {
        return new Response(
          JSON.stringify({ success: false, message: "⚠️ الحساب غير مسجّل في المنظومة" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
    }

    // ✅ حماية من محاولات التخمين المتكررة
    const rateLimit = await checkRateLimit(`${role}:${username}`);
    if (rateLimit.blocked) {
      return new Response(
        JSON.stringify({ success: false, message: rateLimit.message }),
        { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    let table = "";
    let idField = "";
    if (role === "teacher") { table = "teachers"; idField = "client_id"; }
    else if (role === "assistant") { table = "assistants"; idField = "username"; }
    else if (role === "parent") { table = "parents"; idField = "phone"; }
    else if (role === "student") { table = "students"; idField = "uid"; }
    else {
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ دور غير معروف" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { data: user, error: userError } = await supabase
      .from(table)
      .select("*")
      .eq(idField, username)
      .maybeSingle();

    // ✅ رسالة موحّدة سواء المستخدم مش موجود أو كلمة المرور غلط، عشان محدش يقدر يكتشف
    // أكواد مدرسين/مساعدين حقيقية بمجرد تجربة تسجيل الدخول (Account Enumeration)
    if (userError || !user) {
      await registerFailedAttempt(`${role}:${username}`);
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ بيانات الدخول غير صحيحة" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ✅ دخول الطالب أول مرة: مفيش كلمة مرور متسجّلة لسه (password_hash فاضية) — بيدخل بكود الكارت
    // (UID) كاسم مستخدم وكلمة مرور مع بعض. لو مطابقين، نعتبره دخول ناجح ونسجّل الهاش دلوقتي.
    if (role === "student" && !user.password_hash) {
      if (password !== username) {
        await registerFailedAttempt(`${role}:${username}`);
        return new Response(
          JSON.stringify({ success: false, message: "⚠️ بيانات الدخول غير صحيحة" }),
          { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      const firstHash = await hashPassword(password);
      await supabase.from("students").update({ password_hash: firstHash, must_change_password: true }).eq("uid", username);
      user.password_hash = firstHash;
      user.must_change_password = true;
    }

    const { valid, needsRehash } = await verifyPassword(password, user.password_hash);
    if (!valid) {
      await registerFailedAttempt(`${role}:${username}`);
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ بيانات الدخول غير صحيحة" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ✅ ترقية شفافة: لو الهاش لسه بالصيغة القديمة الأضعف (SHA-256 بدون salt)، نستبدله بهاش pbkdf2 جديد فوراً
    if (needsRehash) {
      const newHash = await hashPassword(password);
      await supabase.from(table).update({ password_hash: newHash }).eq(idField, username);
    }

    // التحقق من حالة الترخيص للمدرس — بدل رفض الدخول، نسمح بيه ونعلّم الاستجابة
    // عشان الفرونت إند يحوّله لصفحة قفل مخصصة (بدل رسالة خطأ عادية)
    let licenseExpired = false;
    let licenseReason = "";
    let contactWhatsapp: string | null = null;
    let contactPhone: string | null = null;
    let contactAudience = "admin"; // admin = تواصل مع الإدارة | teacher = تواصل مع المدرس نفسه

    const loadAdminContact = async () => {
      const { data } = await supabase
        .from("system_settings").select("whatsapp_number, phone_number").eq("id", 1).maybeSingle();
      contactWhatsapp = data?.whatsapp_number || null;
      contactPhone = data?.phone_number || null;
      contactAudience = "admin";
    };

    const loadTeacherContact = async (teacherClientId: string) => {
      const { data } = await supabase
        .from("teachers").select("contact_whatsapp, contact_phone").eq("client_id", teacherClientId).maybeSingle();
      contactWhatsapp = data?.contact_whatsapp || null;
      contactPhone = data?.contact_phone || null;
      contactAudience = "teacher";
    };

    if (role === "teacher") {
      if (!user.is_active) {
        licenseExpired = true;
        licenseReason = "الحساب غير مفعل";
      } else if (user.expiry_date) {
        // ✅ مقارنة نصية بين تاريخين فقط (بدون وقت)، عشان المدرس يفضل له اليوم كامل لحد آخره
        // مهما كان فرق التوقيت — مقارنة timestamp كانت بتعتبره منتهي من أول ثانية في يوم الانتهاء نفسه
        const todayStr = new Date().toISOString().split("T")[0];
        if (user.expiry_date < todayStr) {
          licenseExpired = true;
          licenseReason = "انتهت صلاحية الترخيص";
        }
      }
      if (licenseExpired) await loadAdminContact();
    }

    if (role === "assistant" && !user.is_active) {
      if (user.teacher_id) await loadTeacherContact(user.teacher_id);
      return new Response(
        JSON.stringify({ success: false, message: "⛔ الحساب غير مفعل", contactWhatsapp, contactPhone, contactAudience }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (role === "parent" && !user.is_active) {
      const { data: linkedStudent } = await supabase
        .from("students").select("teacher_id").eq("parent_phone", username).limit(1).maybeSingle();
      if (linkedStudent?.teacher_id) await loadTeacherContact(linkedStudent.teacher_id);
      return new Response(
        JSON.stringify({ success: false, message: "⛔ الحساب غير مفعل", contactWhatsapp, contactPhone, contactAudience }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ✅ نجح تسجيل الدخول: نصفّر محاولات الفشل
    await clearAttempts(`${role}:${username}`);

    let teacherName = "";
    let assistantBrandLogoUrl: string | null = null;
    let assistantBrandColor: string | null = null;
    let assistantIsCenter = false;
    if (role === "assistant" && user.teacher_id) {
      const { data: teacher, error: teacherError } = await supabase
        .from("teachers")
        .select("name, is_active, expiry_date, contact_whatsapp, contact_phone, brand_logo_url, brand_color, center_id, is_center")
        .eq("client_id", user.teacher_id)
        .maybeSingle();
      if (!teacherError && teacher) {
        teacherName = teacher.name;
        if (!teacher.is_active) {
          licenseExpired = true;
          licenseReason = "حساب المدرس غير مفعل";
        } else if (teacher.expiry_date) {
          const todayStr2 = new Date().toISOString().split("T")[0];
          if (teacher.expiry_date < todayStr2) {
            licenseExpired = true;
            licenseReason = "انتهت صلاحية ترخيص المدرس";
          }
        }
        if (licenseExpired) {
          contactWhatsapp = teacher.contact_whatsapp || null;
          contactPhone = teacher.contact_phone || null;
          contactAudience = "teacher";
        }
        assistantBrandLogoUrl = teacher.brand_logo_url || null;
        assistantBrandColor = teacher.brand_color || null;
        // ✅ Batch 22: كانت isCenter بترجع للمدرس بس (role === "teacher") — المساعد ماكانش بيوصله
        // العلَم ده خالص، فتبويب "مدرّسو السنتر" في staff.html كان بيفضل مختفي للمساعد حتى لو
        // معاه صلاحية "عرض/إضافة/تعديل فريق العمل" الكاملة، لأن isCenterAccount في الفرونت إند
        // كانت دايماً false للمساعد (sessionStorage.isCenter مكانش بيتحط أصلاً)
        assistantIsCenter = teacher.is_center === true;
        if ((!assistantBrandLogoUrl || !assistantBrandColor) && teacher.center_id) {
          const { data: centerBrand } = await supabase.from("centers").select("brand_logo_url, brand_color").eq("id", teacher.center_id).maybeSingle();
          if (centerBrand) {
            if (!assistantBrandLogoUrl) assistantBrandLogoUrl = centerBrand.brand_logo_url || null;
            if (!assistantBrandColor) assistantBrandColor = centerBrand.brand_color || null;
          }
        }
      }
    }

    const forceChange = user.must_change_password || false;

    const responseData: any = { name: user.name };
    if (role === "teacher") {
      responseData.clientId = user.client_id;
      responseData.maxStudents = user.max_students;
      responseData.expiryDate = user.expiry_date;
      responseData.isActive = user.is_active;
      responseData.studentCount = user.student_count || 0;
      responseData.isAdmin = user.client_id === "master_admin";

      // ✅ لو المدرس عنده شعار/لون خاص بيه بيتقدّم على شعار السنتر (لو تابع لسنتر)
      let brandLogoUrl = user.brand_logo_url || null;
      let brandColor = user.brand_color || null;
      if ((!brandLogoUrl || !brandColor) && user.center_id) {
        const { data: centerBrand } = await supabase.from("centers").select("brand_logo_url, brand_color").eq("id", user.center_id).maybeSingle();
        if (centerBrand) {
          if (!brandLogoUrl) brandLogoUrl = centerBrand.brand_logo_url || null;
          if (!brandColor) brandColor = centerBrand.brand_color || null;
        }
      }
      responseData.brandLogoUrl = brandLogoUrl;
      responseData.brandColor = brandColor;
      // ✅ Aug 2026 (تعديل جوهري): بديل مفهوم "حساب السنتر المنفصل" — الفرونت إند بيستخدم العلَم ده
      // عشان يعرض للمدرس (اللي هو سنتر) إدارة "أسماء المدرسين" التابعين له
      responseData.isCenter = user.is_center === true;
    } else if (role === "assistant") {
      responseData.id = user.id;
      responseData.username = user.username;
      responseData.permissions = user.permissions || {};
      responseData.teacherId = user.teacher_id;
      responseData.teacherName = teacherName || "مدرس";
      responseData.brandLogoUrl = assistantBrandLogoUrl;
      responseData.brandColor = assistantBrandColor;
      responseData.isCenter = assistantIsCenter;
    } else if (role === "parent") {
      responseData.phone = user.phone;
    } else if (role === "student") {
      responseData.uid = user.uid;
      responseData.groupName = user.group_name;
      responseData.teacherId = user.teacher_id;
    }

    const tokenPayload = {
      userId: role === "student" ? user.uid : user.id,
      clientId: role === "teacher" ? user.client_id : (role === "student" ? user.teacher_id : undefined),
      teacherId: role === "assistant" ? user.teacher_id : undefined,
      username: role === "assistant" ? user.username : undefined,
      phone: role === "parent" ? user.phone : undefined,
      role: role,
      name: user.name,
    };
    const token = await generateToken(tokenPayload);

    // ✅ تسجيل نشاط الدخول — كان مفقود بالكامل رغم إن الفلتر بيسمح باختياره
    if (role === "teacher" || role === "assistant") {
      const logTeacherId = role === "teacher" ? user.client_id : user.teacher_id;
      supabase.from("activity_logs").insert({
        client_id: logTeacherId,
        teacher_id: logTeacherId,
        action_type: "login",
        entity_type: role,
        entity_id: role === "teacher" ? user.client_id : String(user.id),
        assistant_id: role === "assistant" ? user.id : null,
        performer_id: role === "teacher" ? user.client_id : String(user.id),
        performer_role: role,
        performer_name: user.name,
      }).then(({ error }: any) => { if (error) console.error("⚠️ فشل تسجيل نشاط الدخول:", error.message); });
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: "✅ تم تسجيل الدخول بنجاح",
        role,
        forceChange,
        licenseExpired,
        licenseReason,
        contactWhatsapp,
        contactPhone,
        contactAudience,
        token,
        data: responseData,
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("❌ خطأ عام:", error);
    return new Response(
      JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
