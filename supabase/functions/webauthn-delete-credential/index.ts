// supabase/functions/webauthn-delete-credential/index.ts
// ============================================
// حذف بصمة/جهاز مسجَّل — بيتأكد إن البصمة دي فعلاً بتاعة صاحب التوكن قبل الحذف
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

    const body = await req.json();
    const { credentialId } = body;
    if (!credentialId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ credentialId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: cred, error: fetchError } = await supabase
      .from("webauthn_credentials")
      .select("id, auth_user_id")
      .eq("id", credentialId)
      .maybeSingle();

    if (fetchError || !cred) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ البصمة غير موجودة" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (cred.auth_user_id !== authUserId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بحذف هذه البصمة" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { error: deleteError } = await supabase.from("webauthn_credentials").delete().eq("id", credentialId);
    if (deleteError) {
      return new Response(JSON.stringify({ success: false, message: deleteError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ تم حذف البصمة بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "⚠️ حدث خطأ غير متوقع";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
