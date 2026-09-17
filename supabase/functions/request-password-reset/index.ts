// supabase/functions/request-password-reset/index.ts
// ============================================
// استرجاع كلمة المرور الذاتي لكل الأدوار غير الماستر أدمن (كود مدرس/اسم مستخدم مساعد/
// رقم هاتف ولي أمر/كود كارت طالب) — نفس منطق التعرّف على الدور المستخدم في login/index.ts
// (group + identifier، مش إيميل، لأن باقي الأدوار مالهاش إيميل حقيقي في auth.users أصلاً).
// لو الحساب مسجّل له "إيميل استرجاع" اختياري (من إعدادات حسابه)، بنولّد توكن لمرة واحدة
// صالح ساعة ونبعته عن طريق Resend مباشرة — من غير أي حاجة لصلاحية Supabase Auth الجاهزة.
// ============================================
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";
import { corsHeaders } from "../_shared/auth.ts";
import { sendEmail } from "../_shared/email.ts";
import { checkRateLimit, registerFailedAttempt } from "../_shared/rateLimit.ts";

function supabaseAdmin() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function hashToken(raw: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const { identifier } = await req.json();
    if (!identifier) {
      return jsonResponse({ success: false, message: "⚠️ بيانات ناقصة" }, 400);
    }

    // ✅ حماية من التخمين/الإرسال المتكرر — نفس جدول login_attempts المستخدم في تسجيل الدخول،
    // ببادئة مختلفة، وحد أقل (3 محاولات) لأن ده بيبعت إيميل فعلي مش مجرد فحص باسورد
    const rateLimitKey = `pwreset:${identifier}`;
    const rateLimit = await checkRateLimit(rateLimitKey, { maxAttempts: 3, lockMinutes: 30 });
    if (rateLimit.blocked) return jsonResponse({ success: false, message: rateLimit.message }, 429);
    await registerFailedAttempt(rateLimitKey, { maxAttempts: 3, lockMinutes: 30 });

    const supabase = supabaseAdmin();

    // ✅ بعد إلغاء تبويبي "الطاقم"/"الأسرة"، بنجرب الجداول الأربعة كلها بنفس ترتيب detectRole()
    // في login/index.ts (مدرس → مساعد → ولي أمر → طالب) — شامل الماستر أدمن كمان، لأن حسابه
    // مجرد صف عادي في جدول teachers بـclient_id='master_admin'
    let row: { auth_user_id: string | null; recovery_email: string | null; name?: string } | null = null;
    const { data: teacher } = await supabase.from("teachers").select("auth_user_id, recovery_email, name").eq("client_id", identifier).maybeSingle();
    row = teacher ?? null;
    if (!row) {
      const { data: assistant } = await supabase.from("assistants").select("auth_user_id, recovery_email, name").eq("username", identifier).maybeSingle();
      row = assistant ?? null;
    }
    if (!row) {
      const { data: parent } = await supabase.from("parents").select("auth_user_id, recovery_email, name").eq("phone", identifier).maybeSingle();
      row = parent ?? null;
    }
    if (!row) {
      const { data: student } = await supabase.from("students").select("auth_user_id, recovery_email, name").eq("uid", identifier).maybeSingle();
      row = student ?? null;
    }

    // ✅ (أمان) الثلاث حالات دي (حساب مش موجود / حساب قديم من غير auth_user_id / حساب موجود
    // بس من غير إيميل استرجاع) كانت بترجع status code ورسالة مختلفة لكل حالة — ده بيسرّب معلومة
    // "الحساب ده موجود ولا لأ" لأي حد بيجرّب أكواد/أرقام عشوائية (enumeration)، بالظبط زي المنطق
    // اللي login نفسها بتتجنبه عمداً برسالة فشل موحّدة. بنرجّع نفس الرسالة العامة في الحالات
    // التلاتة، وترجع نجاح فعلي بس لو فعلاً هيتبعت إيميل
    const genericResponse = { success: true, message: "لو الحساب ده موجود ومسجّل له إيميل استرجاع، هيوصله رابط لتحديد كلمة مرور جديدة خلال دقايق. لو معملتش إيميل استرجاع لسه، تواصل مع الشخص المسؤول عن حسابك." };
    if (!row || !row.auth_user_id || !row.recovery_email) {
      return jsonResponse(genericResponse, 200);
    }

    const rawToken = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
    const tokenHash = await hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    const { error: insertError } = await supabase.from("password_reset_tokens").insert({
      auth_user_id: row.auth_user_id, token_hash: tokenHash, expires_at: expiresAt,
    });
    if (insertError) return jsonResponse({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }, 500);

    const resetLink = `https://fasli-eg.github.io/Fasli/login.html?resetToken=${rawToken}`;
    const greeting = row.name ? `مرحباً ${row.name}،` : "مرحباً،";
    // ✅ الرابط لازم يظهر كنص واضح في نسخة الـplain-text مش بس جوه زرار HTML — أي عميل
    // إيميل بيعرض النسخة النصية العادية (أو ما بيعرفش يرندر الـHTML) يفضل شايف الرابط كامل
    const plainText = `${greeting}\n\nوصلنا طلب لاسترجاع كلمة المرور بتاعة حسابك في فَصلي.\nافتح الرابط ده لتحديد كلمة مرور جديدة (صالح لمدة ساعة واحدة بس):\n\n${resetLink}\n\nلو معملتش الطلب ده، تقدر تتجاهل الإيميل ده بأمان — حسابك في أمان.\n\n—\nفَصلي`;
    const html = `
<div dir="rtl" style="background:#F3F4F6;padding:32px 16px;font-family:Arial,Tahoma,sans-serif;">
  <table role="presentation" width="100%" style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #E5E7EB;">
    <tr>
      <td style="background:#0B1C33;padding:22px 32px;text-align:center;">
        <span style="color:#F2B705;font-size:20px;font-weight:800;">فَصلي</span>
      </td>
    </tr>
    <tr>
      <td style="padding:32px;">
        <p style="margin:0 0 16px;font-size:16px;color:#0B1C33;font-weight:700;">${greeting}</p>
        <p style="margin:0 0 24px;font-size:14.5px;color:#374151;line-height:1.8;">وصلنا طلب لاسترجاع كلمة المرور بتاعة حسابك في فَصلي. اضغط على الزرار ده لتحديد كلمة مرور جديدة — الرابط صالح لمدة ساعة واحدة بس.</p>
        <table role="presentation" align="center" style="margin:0 auto 22px;">
          <tr>
            <td style="border-radius:10px;background:#F2B705;">
              <a href="${resetLink}" style="display:inline-block;padding:14px 34px;font-size:15px;font-weight:700;color:#0B1C33;text-decoration:none;">تحديد كلمة مرور جديدة</a>
            </td>
          </tr>
        </table>
        <p style="margin:0 0 6px;font-size:12px;color:#9CA3AF;">لو الزرار ما اشتغلش، انسخ الرابط ده والصقه في المتصفح:</p>
        <p style="margin:0 0 24px;font-size:12px;word-break:break-all;"><a href="${resetLink}" style="color:#0E8074;">${resetLink}</a></p>
        <p style="margin:0;font-size:12.5px;color:#9CA3AF;line-height:1.7;">لو معملتش الطلب ده، تقدر تتجاهل الإيميل ده بأمان — حسابك في أمان ومفيش حاجة اتغيّرت.</p>
      </td>
    </tr>
    <tr>
      <td style="background:#F9FAFB;padding:14px 32px;text-align:center;border-top:1px solid #E5E7EB;">
        <span style="font-size:11px;color:#9CA3AF;">فَصلي — نظام إدارة السناتر والدروس الخصوصية</span>
      </td>
    </tr>
  </table>
</div>`;
    try {
      await sendEmail({ to: row.recovery_email, subject: "Password Reset - Fasli", text: plainText, html });
    } catch (e) {
      return jsonResponse({ success: false, message: e instanceof Error ? e.message : "⚠️ فشل إرسال الإيميل" }, 500);
    }

    return jsonResponse({ success: true, message: "✅ اتبعت رابط تحديد كلمة مرور جديدة على الإيميل المسجّل عندك" });
  } catch (error) {
    return jsonResponse({ success: false, message: error instanceof Error ? error.message : "⚠️ خطأ غير متوقع" }, 500);
  }
});
