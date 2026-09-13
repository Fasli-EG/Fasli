// supabase/functions/webauthn-register-options/index.ts
// ============================================
// الخطوة 1 من تسجيل بصمة/وجه جديدة: بترجّع خيارات WebAuthn (challenge + rpID + ...) عشان
// المتصفح يمررها للمصادق (بصمة/وجه/مفتاح أمان)، ونخزّن الـchallenge مؤقتاً للتحقق بعدين.
// ============================================
import { corsHeaders, AuthError, verifyToken, authErrorResponse } from "../_shared/auth.ts";
import { getRealAuthUserId } from "../_shared/authProvision.ts";
import { generateRegistrationOptions, RP_NAME, RP_ID } from "../_shared/webauthn.ts";
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

    const { data: existingCreds } = await supabase
      .from("webauthn_credentials")
      .select("credential_id, transports")
      .eq("auth_user_id", authUserId);

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: payload.username || payload.clientId || payload.phone || payload.sub,
      userDisplayName: payload.name || "مستخدم",
      attestationType: "none",
      excludeCredentials: (existingCreds || []).map((c: any) => ({
        id: c.credential_id,
        transports: c.transports || undefined,
      })),
      authenticatorSelection: {
        residentKey: "required",
        // ✅ "required" بدل "preferred" — بيفرض تحقق حقيقي من هوية المستخدم (بصمة/وجه/PIN
        // الجهاز) بدل ما يكتفي بمجرد "لمسة" بلا أي تحقق فعلي
        userVerification: "required",
        // ✅ "platform" يقصر الاختيار على المصادق المدمج في الجهاز نفسه (بصمة/وجه/Windows
        // Hello) ويمنع خيارات زي "مفتاح أمان خارجي" أو "استخدم جهاز تاني عن طريق QR" اللي
        // مالهاش علاقة بالبصمة أو الوجه خالص
        authenticatorAttachment: "platform",
      },
    });

    const { data: challengeRow, error: challengeError } = await supabase
      .from("webauthn_challenges")
      .insert({ challenge: options.challenge, auth_user_id: authUserId, purpose: "register" })
      .select("id")
      .single();

    if (challengeError || !challengeRow) {
      throw new Error("⚠️ فشل تجهيز طلب التسجيل");
    }

    return new Response(
      JSON.stringify({ success: true, options, challengeId: challengeRow.id }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "⚠️ حدث خطأ غير متوقع";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
