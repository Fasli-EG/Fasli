// supabase/functions/manage-recovery-email/index.ts
// ============================================
// يسمح لأي مستخدم (مدرس/مساعد/ولي أمر/طالب) يشوف/يحفظ إيميل الاسترجاع الاختياري بتاعه —
// نفس الإيميل ده بيُستخدم بعدين في request-password-reset لبعت رابط استرجاع كلمة المرور.
// ============================================
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";
import { corsHeaders, AuthError, verifyToken, authErrorResponse, TokenPayload } from "../_shared/auth.ts";

function supabaseAdmin() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

function tableAndFilter(payload: TokenPayload): { table: string; column: string; value: string } {
  if (payload.role === "teacher") return { table: "teachers", column: "client_id", value: payload.clientId! };
  if (payload.role === "assistant") return { table: "assistants", column: "id", value: payload.sub };
  if (payload.role === "parent") return { table: "parents", column: "phone", value: payload.phone! };
  return { table: "students", column: "uid", value: payload.sub };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const payload = await verifyToken(req, { skipLicenseCheck: true });
    const body = await req.json();
    const { table, column, value } = tableAndFilter(payload);
    const supabase = supabaseAdmin();

    if (body.action === "get") {
      const { data } = await supabase.from(table).select("recovery_email").eq(column, value).maybeSingle();
      return jsonResponse({ success: true, recoveryEmail: data?.recovery_email || null });
    }

    if (body.action === "set") {
      const email = String(body.recoveryEmail || "").trim();
      if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return jsonResponse({ success: false, message: "⚠️ الإيميل غير صحيح" }, 400);
      }
      const { error } = await supabase.from(table).update({ recovery_email: email || null }).eq(column, value);
      if (error) return jsonResponse({ success: false, message: error.message }, 500);
      return jsonResponse({ success: true, message: email ? "✅ اتحفظ إيميل الاسترجاع" : "✅ اتشال إيميل الاسترجاع" });
    }

    return jsonResponse({ success: false, message: "⚠️ action غير معروفة" }, 400);
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return jsonResponse({ success: false, message: error instanceof Error ? error.message : "⚠️ خطأ غير متوقع" }, 500);
  }
});
