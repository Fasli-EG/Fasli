// supabase/functions/webauthn-login-verify/index.ts
// ============================================
// الخطوة 2 من الدخول بالبصمة: بتستقبل رد المصادق (من startAuthentication() في المتصفح)،
// تتحقق من التوقيع مقابل المفتاح العام المخزّن، وبعد النجاح "تصدر" جلسة Supabase Auth حقيقية
// لصاحب الحساب عن طريق generateLink (Admin API) + verifyOtp (من المتصفح مباشرة) — بديل آمن
// ومدعوم رسميًا لأي دخول بلا باسورد، من غير ما نحتاج نعرف/نصدر توكنات يدويًا.
// ============================================
import { corsHeaders } from "../_shared/auth.ts";
import { verifyAuthenticationResponse, ORIGIN, RP_ID, base64urlToBuffer, CHALLENGE_MAX_AGE_MS } from "../_shared/webauthn.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

function adminClient() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const supabase = adminClient();
    const body = await req.json();
    const { challengeId, ...assertionResponse } = body;

    if (!challengeId || !assertionResponse?.id) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ بيانات الطلب ناقصة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: challengeRow } = await supabase
      .from("webauthn_challenges")
      .select("id, challenge, created_at")
      .eq("id", challengeId)
      .eq("purpose", "login")
      .maybeSingle();

    if (!challengeRow) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ طلب الدخول غير موجود أو استُخدم بالفعل" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // ✅ استخدام لمرة واحدة — نمسحه فورًا بغض النظر عن نتيجة التحقق تحت
    await supabase.from("webauthn_challenges").delete().eq("id", challengeRow.id);

    if (Date.now() - new Date(challengeRow.created_at).getTime() > CHALLENGE_MAX_AGE_MS) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ انتهت صلاحية طلب الدخول، حاول من جديد" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: cred } = await supabase
      .from("webauthn_credentials")
      .select("id, auth_user_id, public_key, counter, transports")
      .eq("credential_id", assertionResponse.id)
      .maybeSingle();

    if (!cred) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ هذه البصمة غير مسجّلة في النظام" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge: challengeRow.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        credential: {
          id: cred.credential_id,
          publicKey: base64urlToBuffer(cred.public_key),
          counter: Number(cred.counter),
          transports: cred.transports || undefined,
        },
      });
    } catch (verifyErr) {
      const msg = verifyErr instanceof Error ? verifyErr.message : "فشل التحقق";
      return new Response(JSON.stringify({ success: false, message: `⚠️ فشل التحقق من البصمة: ${msg}` }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (!verification.verified) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ تعذّر التحقق من البصمة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    await supabase.from("webauthn_credentials").update({
      counter: verification.authenticationInfo.newCounter,
      last_used_at: new Date().toISOString(),
    }).eq("id", cred.id);

    // ✅ إصدار جلسة Supabase حقيقية من غير باسورد: نولّد "رابط دخول" عن طريق Admin API
    // (من غير ما نبعته فعليًا كإيميل — بنستخدم الـtoken الراجع مباشرة)، والمتصفح بعدين بيحوّله
    // لجلسة حقيقية بـauth.verifyOtp() — نفس الأسلوب الموصى بيه رسميًا من Supabase لأي نظام
    // دخول مخصص (custom auth) عايز يصدر جلسات حقيقية بلا باسورد.
    const { data: userData, error: getUserError } = await supabase.auth.admin.getUserById(cred.auth_user_id);
    if (getUserError || !userData?.user?.email) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ تعذّر إصدار جلسة الدخول لهذا الحساب" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: linkData, error: linkError } = await supabase.auth.admin.generateLink({
      type: "magiclink",
      email: userData.user.email,
    });
    if (linkError || !linkData?.properties?.hashed_token) {
      return new Response(JSON.stringify({ success: false, message: linkError?.message || "⚠️ تعذّر إصدار جلسة الدخول" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(
      JSON.stringify({ success: true, tokenHash: linkData.properties.hashed_token, email: userData.user.email }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "⚠️ حدث خطأ غير متوقع";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
