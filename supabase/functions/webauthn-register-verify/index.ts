// supabase/functions/webauthn-register-verify/index.ts
// ============================================
// الخطوة 2 من تسجيل بصمة/وجه جديدة: بتستقبل رد المصادق (من startRegistration() في المتصفح)
// وتتحقق منه مقابل الـchallenge المحفوظ، وتخزّن المفتاح العام لو التحقق نجح.
// ============================================
import { corsHeaders, AuthError, verifyToken, authErrorResponse } from "../_shared/auth.ts";
import { getRealAuthUserId } from "../_shared/authProvision.ts";
import { verifyRegistrationResponse, ORIGIN, RP_ID, bufferToBase64url, CHALLENGE_MAX_AGE_MS } from "../_shared/webauthn.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

function adminClient() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const authUserId = await getRealAuthUserId(req);
    const supabase = adminClient();

    const body = await req.json();
    const { challengeId, deviceName, ...attestationResponse } = body;

    if (!challengeId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ challengeId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: challengeRow } = await supabase
      .from("webauthn_challenges")
      .select("id, challenge, created_at")
      .eq("id", challengeId)
      .eq("auth_user_id", authUserId)
      .eq("purpose", "register")
      .maybeSingle();

    if (!challengeRow) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ طلب التسجيل غير موجود أو استُخدم بالفعل" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // ✅ استخدام لمرة واحدة — نمسحه فورًا بغض النظر عن نتيجة التحقق تحت
    await supabase.from("webauthn_challenges").delete().eq("id", challengeRow.id);

    if (Date.now() - new Date(challengeRow.created_at).getTime() > CHALLENGE_MAX_AGE_MS) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ انتهت صلاحية طلب التسجيل، حاول من جديد" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: attestationResponse,
        expectedChallenge: challengeRow.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
      });
    } catch (verifyErr) {
      const msg = verifyErr instanceof Error ? verifyErr.message : "فشل التحقق";
      return new Response(JSON.stringify({ success: false, message: `⚠️ فشل التحقق من البصمة: ${msg}` }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (!verification.verified || !verification.registrationInfo) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ تعذّر التحقق من البصمة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

    const { error: insertError } = await supabase.from("webauthn_credentials").insert({
      auth_user_id: authUserId,
      credential_id: credential.id,
      public_key: bufferToBase64url(credential.publicKey),
      counter: credential.counter,
      device_type: credentialDeviceType,
      backed_up: credentialBackedUp,
      transports: credential.transports || null,
      device_name: typeof deviceName === "string" && deviceName.trim() ? deviceName.trim().slice(0, 100) : null,
    });

    if (insertError) {
      return new Response(JSON.stringify({ success: false, message: insertError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ تم تفعيل الدخول بالبصمة بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "⚠️ حدث خطأ غير متوقع";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
