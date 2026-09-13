// supabase/functions/webauthn-list-credentials/index.ts
// ============================================
// بترجّع عدد/قائمة بصمات المستخدم الحالي المسجّلة — تُستخدم بس عشان نقرر نعرض بانر "فعّل
// الدخول بالبصمة" ولا لأ، من غير ما نبدأ عملية تسجيل جديدة فعلية (زي webauthn-register-options).
// ============================================
import { corsHeaders, AuthError, verifyToken, authErrorResponse } from "../_shared/auth.ts";
import { getRealAuthUserId } from "../_shared/authProvision.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

function adminClient() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    await verifyToken(req);
    const authUserId = await getRealAuthUserId(req);
    const supabase = adminClient();

    const { data, error } = await supabase
      .from("webauthn_credentials")
      .select("id, device_name, created_at, last_used_at")
      .eq("auth_user_id", authUserId)
      .order("created_at", { ascending: false });

    if (error) throw new Error(error.message);

    return new Response(JSON.stringify({ success: true, credentials: data || [] }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "⚠️ حدث خطأ غير متوقع";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
