// supabase/functions/manage-recovery-email/index.ts
// ============================================
// يسمح لأي مستخدم (مدرس/مساعد/ولي أمر/طالب) يشوف/يحفظ إيميل الاسترجاع الاختياري بتاعه —
// نفس الإيميل ده بيُستخدم بعدين في request-password-reset لبعت رابط استرجاع كلمة المرور.
// كمان بيدير رمز التأكيد (6 أرقام) اللي بيتبعت على الإيميل ده للتحقق منه — إجباري لأي حساب
// جديد قبل ما يقدر يكمل استخدام النظام عادي (action: sendCode / verifyCode).
// ============================================
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";
import { corsHeaders, AuthError, verifyToken, authErrorResponse, TokenPayload } from "../_shared/auth.ts";
import { sendEmail } from "../_shared/email.ts";
import { checkRateLimit, registerFailedAttempt, clearAttempts } from "../_shared/rateLimit.ts";

function supabaseAdmin() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

function tableAndFilter(payload: TokenPayload): { table: string; column: string; value: string; role: string } {
  if (payload.role === "teacher") return { table: "teachers", column: "client_id", value: payload.clientId!, role: "teacher" };
  if (payload.role === "assistant") return { table: "assistants", column: "id", value: payload.sub, role: "assistant" };
  if (payload.role === "parent") return { table: "parents", column: "phone", value: payload.phone!, role: "parent" };
  return { table: "students", column: "uid", value: payload.sub, role: "student" };
}

async function hashCode(code: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function generateCode(): string {
  return String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, "0");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const payload = await verifyToken(req, { skipLicenseCheck: true });
    const body = await req.json();
    const { table, column, value, role } = tableAndFilter(payload);
    const supabase = supabaseAdmin();

    if (body.action === "get") {
      const { data } = await supabase.from(table).select("recovery_email, recovery_email_verified").eq(column, value).maybeSingle();
      return jsonResponse({
        success: true,
        recoveryEmail: data?.recovery_email || null,
        recoveryEmailVerified: data?.recovery_email_verified === true,
      });
    }

    if (body.action === "set") {
      const email = String(body.recoveryEmail || "").trim();
      if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return jsonResponse({ success: false, message: "⚠️ الإيميل غير صحيح" }, 400);
      }
      // ✅ لو الإيميل اتغيّر فعليًا، لازم يتأكد تاني من الأول — نمسح علامة التأكيد القديمة
      // عشان محدش يقدر يغيّر إيميل الاسترجاع لإيميل تاني من غير ما يثبت إنه بيملكه
      const { data: current } = await supabase.from(table).select("recovery_email").eq(column, value).maybeSingle();
      const emailChanged = (current?.recovery_email || null) !== (email || null);
      const { error } = await supabase.from(table)
        .update({ recovery_email: email || null, ...(emailChanged ? { recovery_email_verified: false } : {}) })
        .eq(column, value);
      if (error) return jsonResponse({ success: false, message: error.message }, 500);
      return jsonResponse({ success: true, message: email ? "✅ اتحفظ إيميل الاسترجاع" : "✅ اتشال إيميل الاسترجاع" });
    }

    // ============================================
    // ✅ إيميل الاسترجاع الإجباري: بعت رمز تأكيد (6 أرقام، صالح 10 دقايق) على الإيميل
    // ============================================
    if (body.action === "sendCode") {
      const email = String(body.recoveryEmail || "").trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return jsonResponse({ success: false, message: "⚠️ الإيميل غير صحيح" }, 400);
      }

      const rateLimitKey = `recovery-code-send:${role}:${value}`;
      const rateLimit = await checkRateLimit(rateLimitKey, { maxAttempts: 5, lockMinutes: 15 });
      if (rateLimit.blocked) return jsonResponse({ success: false, message: rateLimit.message }, 429);
      await registerFailedAttempt(rateLimitKey, { maxAttempts: 5, lockMinutes: 15 });

      // ✅ الإيميل بيتحفظ فورًا (بعلامة "غير مؤكد") عشان لو المستخدم قفل الصفحة قبل ما يدخّل
      // الرمز، يرجع تاني مرة يلاقي نفس الإيميل محفوظ وبس يطلب رمز جديد بدل ما يكتبه تاني
      await supabase.from(table).update({ recovery_email: email, recovery_email_verified: false }).eq(column, value);

      const code = generateCode();
      const codeHash = await hashCode(code);
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

      // ✅ نمسح أي رموز سابقة لنفس الحساب قبل ما نضيف رمز جديد — رمز واحد صالح بس في أي وقت
      await supabase.from("recovery_email_codes").delete().eq("role", role).eq("identifier", value);
      const { error: insertError } = await supabase.from("recovery_email_codes").insert({
        role, identifier: value, email, code_hash: codeHash, expires_at: expiresAt,
      });
      if (insertError) return jsonResponse({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }, 500);

      const plainText = `مرحباً،\n\nكود تأكيد إيميل الاسترجاع بتاعك في فَصلي هو: ${code}\n\nالكود صالح لمدة 10 دقايق بس. لو مطلبتش الكود ده، تقدر تتجاهل الإيميل ده بأمان.\n\n—\nفَصلي`;
      const html = `
<div dir="rtl" style="background:#F3F4F6;padding:32px 16px;font-family:Arial,Tahoma,sans-serif;">
  <table role="presentation" width="100%" style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #E5E7EB;">
    <tr><td style="background:#0B1C33;padding:22px 32px;text-align:center;"><span style="color:#F2B705;font-size:20px;font-weight:800;">فَصلي</span></td></tr>
    <tr>
      <td style="padding:32px;text-align:center;">
        <p style="margin:0 0 20px;font-size:14.5px;color:#374151;line-height:1.8;">كود تأكيد إيميل الاسترجاع بتاعك:</p>
        <div style="display:inline-block;padding:16px 32px;border-radius:10px;background:#F3F4F6;border:1px dashed #D1D5DB;font-size:32px;font-weight:800;letter-spacing:8px;color:#0B1C33;">${code}</div>
        <p style="margin:20px 0 0;font-size:12.5px;color:#9CA3AF;line-height:1.7;">الكود صالح لمدة 10 دقايق بس. لو مطلبتش الكود ده، تقدر تتجاهل الإيميل ده بأمان.</p>
      </td>
    </tr>
    <tr><td style="background:#F9FAFB;padding:14px 32px;text-align:center;border-top:1px solid #E5E7EB;"><span style="font-size:11px;color:#9CA3AF;">فَصلي — نظام إدارة السناتر والدروس الخصوصية</span></td></tr>
  </table>
</div>`;
      try {
        await sendEmail({ to: email, subject: "Confirmation Code - Fasli", text: plainText, html });
      } catch (e) {
        return jsonResponse({ success: false, message: e instanceof Error ? e.message : "⚠️ فشل إرسال الإيميل" }, 500);
      }

      return jsonResponse({ success: true, message: "✅ اتبعت رمز التأكيد على الإيميل" });
    }

    // ============================================
    // ✅ تأكيد الرمز المرسل — لو صح، نعلّم الإيميل كـ"مؤكد" ونمسح الرمز
    // ============================================
    if (body.action === "verifyCode") {
      const code = String(body.code || "").trim();
      if (!code) return jsonResponse({ success: false, message: "⚠️ من فضلك أدخل رمز التأكيد" }, 400);

      const rateLimitKey = `recovery-code-verify:${role}:${value}`;
      const rateLimit = await checkRateLimit(rateLimitKey, { maxAttempts: 6, lockMinutes: 15 });
      if (rateLimit.blocked) return jsonResponse({ success: false, message: rateLimit.message }, 429);

      const { data: codeRow } = await supabase.from("recovery_email_codes")
        .select("id, code_hash, expires_at").eq("role", role).eq("identifier", value)
        .order("created_at", { ascending: false }).limit(1).maybeSingle();

      if (!codeRow || new Date(codeRow.expires_at) < new Date()) {
        await registerFailedAttempt(rateLimitKey, { maxAttempts: 6, lockMinutes: 15 });
        return jsonResponse({ success: false, message: "⚠️ الرمز غير صحيح أو منتهي الصلاحية، اطلب رمز جديد" }, 400);
      }

      const codeHash = await hashCode(code);
      if (codeHash !== codeRow.code_hash) {
        await registerFailedAttempt(rateLimitKey, { maxAttempts: 6, lockMinutes: 15 });
        return jsonResponse({ success: false, message: "⛔ الرمز غير صحيح" }, 400);
      }

      await clearAttempts(rateLimitKey);
      await supabase.from("recovery_email_codes").delete().eq("id", codeRow.id);
      const { error } = await supabase.from(table).update({ recovery_email_verified: true }).eq(column, value);
      if (error) return jsonResponse({ success: false, message: error.message }, 500);

      return jsonResponse({ success: true, message: "✅ تم تأكيد إيميل الاسترجاع" });
    }

    return jsonResponse({ success: false, message: "⚠️ action غير معروفة" }, 400);
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return jsonResponse({ success: false, message: error instanceof Error ? error.message : "⚠️ خطأ غير متوقع" }, 500);
  }
});
