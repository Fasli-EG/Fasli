// supabase/functions/confirm-password-reset/index.ts
// ============================================
// الخطوة الثانية من استرجاع كلمة المرور الذاتي — بتاخد التوكن اللي وصل بالإيميل
// (request-password-reset) وكلمة المرور الجديدة، وتتحقق منه (موجود/معملوش استخدام قبل
// كده/معدّاش ساعة)، ولو تمام بتغيّر كلمة مرور الحساب مباشرة عن طريق auth.admin API.
// ============================================
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";
import { corsHeaders } from "../_shared/auth.ts";
import { updateAuthUserPassword } from "../_shared/authProvision.ts";

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
    const { token, newPassword } = await req.json();
    if (!token || !newPassword) return jsonResponse({ success: false, message: "⚠️ بيانات ناقصة" }, 400);
    if (newPassword.length < 6) return jsonResponse({ success: false, message: "⚠️ كلمة المرور لازم تكون 6 أحرف على الأقل" }, 400);

    const supabase = supabaseAdmin();
    const tokenHash = await hashToken(token);
    const { data: row } = await supabase
      .from("password_reset_tokens")
      .select("id, auth_user_id, expires_at, used_at")
      .eq("token_hash", tokenHash)
      .maybeSingle();

    if (!row) return jsonResponse({ success: false, message: "❌ الرابط غير صالح" }, 400);
    if (row.used_at) return jsonResponse({ success: false, message: "⚠️ الرابط ده اتستخدم قبل كده — اطلب رابط جديد" }, 400);
    if (new Date(row.expires_at) < new Date()) return jsonResponse({ success: false, message: "⚠️ الرابط ده منتهي الصلاحية، اطلب رابط جديد" }, 400);

    try {
      await updateAuthUserPassword(row.auth_user_id, newPassword);
    } catch (e) {
      return jsonResponse({ success: false, message: e instanceof Error ? e.message : "⚠️ حدث خطأ غير متوقع" }, 500);
    }
    await supabase.from("password_reset_tokens").update({ used_at: new Date().toISOString() }).eq("id", row.id);

    return jsonResponse({ success: true, message: "✅ اتحفظت كلمة المرور الجديدة" });
  } catch (error) {
    return jsonResponse({ success: false, message: error instanceof Error ? error.message : "⚠️ خطأ غير متوقع" }, 500);
  }
});
