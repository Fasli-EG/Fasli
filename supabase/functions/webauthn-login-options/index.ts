// supabase/functions/webauthn-login-options/index.ts
// ============================================
// الخطوة 1 من الدخول بالبصمة: بترجّع خيارات WebAuthn لتسجيل دخول "بلا اسم مستخدم" (discoverable
// credentials) — المتصفح بيدوّر بنفسه على أي بصمة مسجَّلة لهذا الموقع، من غير ما المستخدم يكتب
// أي معرّف الأول. دالة عامة تمامًا (قبل تسجيل الدخول، مفيش توكن أصلاً).
// ============================================
import { corsHeaders } from "../_shared/auth.ts";
import { generateAuthenticationOptions, RP_ID } from "../_shared/webauthn.ts";
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

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: "preferred",
      // ✅ مفيش allowCredentials عمداً — ده اللي بيخلي تسجيل الدخول "بلا اسم مستخدم"،
      // المتصفح بيعرض أي بصمة/مفتاح متسجّل لهذا الموقع بس
    });

    const { data: challengeRow, error: challengeError } = await supabase
      .from("webauthn_challenges")
      .insert({ challenge: options.challenge, auth_user_id: null, purpose: "login" })
      .select("id")
      .single();

    if (challengeError || !challengeRow) {
      throw new Error("⚠️ فشل تجهيز طلب الدخول");
    }

    return new Response(
      JSON.stringify({ success: true, options, challengeId: challengeRow.id }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "⚠️ حدث خطأ غير متوقع";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
