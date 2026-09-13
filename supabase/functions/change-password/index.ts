// supabase/functions/change-password/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, AuthError, verifyToken, authErrorResponse } from "../_shared/auth.ts";
import { updateAuthUserPassword } from "../_shared/authProvision.ts";

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
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    // ✅ لازم توكن صالح — الشخص يقدر يغيّر كلمة مروره هو فقط
    const payload = await verifyToken(req);

    const { username, newPassword, role } = await req.json();

    if (!username || !newPassword || !role) {
      return new Response(
        JSON.stringify({ success: false, message: "جميع الحقول مطلوبة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (role !== payload.role) {
      throw new AuthError("⛔ غير مصرح لك بتغيير كلمة مرور حساب من نوع مختلف", 403);
    }

    // ✅ التأكد إن صاحب التوكن هو نفسه صاحب الحساب المطلوب تغيير كلمة مروره
    let ownIdentity: string | undefined;
    if (role === "teacher") ownIdentity = payload.clientId;
    else if (role === "assistant") ownIdentity = payload.username;
    else if (role === "parent") ownIdentity = payload.phone;
    else if (role === "student") ownIdentity = payload.sub;
    else if (role === "center_owner") ownIdentity = payload.clientId;

    if (!ownIdentity || ownIdentity !== username) {
      throw new AuthError("⛔ غير مصرح لك بتغيير كلمة مرور هذا الحساب", 403);
    }

    // ✅ حماية من الاستخدام المتكرر لنفس الحساب (حد أقصى 5 محاولات كل 15 دقيقة)
    const rateLimitKey = `changepw:${role}:${username}`;
    const rateLimit = await checkRateLimit(rateLimitKey);
    if (rateLimit.blocked) {
      return new Response(
        JSON.stringify({ success: false, message: rateLimit.message }),
        { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
    await registerFailedAttempt(rateLimitKey);

    if (newPassword.length < 4) {
      return new Response(
        JSON.stringify({ success: false, message: "كلمة المرور يجب أن تكون 4 أحرف على الأقل" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    let table = "";
    let idField = "";
    if (role === "teacher") { table = "teachers"; idField = "client_id"; }
    else if (role === "assistant") { table = "assistants"; idField = "username"; }
    else if (role === "student") { table = "students"; idField = "uid"; }
    else if (role === "center_owner") { table = "centers"; idField = "client_id"; }
    else { table = "parents"; idField = "phone"; }

    const { data: user, error: userError } = await supabase
      .from(table)
      .select("*")
      .eq(idField, username)
      .maybeSingle();

    if (userError || !user) {
      return new Response(
        JSON.stringify({ success: false, message: "المستخدم غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!user.auth_user_id) {
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ الحساب ده من النظام القديم — تواصل مع الإدارة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    try {
      await updateAuthUserPassword(user.auth_user_id, newPassword);
    } catch (e) {
      return new Response(
        JSON.stringify({ success: false, message: e instanceof Error ? e.message : "فشل تحديث كلمة المرور" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { error: updateError } = await supabase
      .from(table)
      .update({ must_change_password: false })
      .eq(idField, username);

    if (updateError) {
      return new Response(
        JSON.stringify({
          success: false,
          message: `فشل تحديث كلمة المرور: ${updateError.message}`
        }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    await clearAttempts(rateLimitKey);

    // ✅ متعمّدين مانسجّلش نشاط "تغيير كلمة المرور" في سجل النشاطات (حاجة شخصية بحتة، مالهاش داعي تظهر في السجل)

    return new Response(
      JSON.stringify({
        success: true,
        message: "تم تغيير كلمة المرور بنجاح",
        data: { username, role }
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(
      JSON.stringify({
        success: false,
        message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" || "حدث خطأ داخلي في الخادم"
      }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
