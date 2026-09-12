// supabase/functions/get-teacher-contact/index.ts
// يرجّع بيانات تواصل المدرس نفسه (لصفحة إعدادات الواي فاي/التواصل)
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, ownerClientId, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const payload = await verifyToken(req);
    const tokenClientId = ownerClientId(payload);

    // ✅ Aug 2026: بنرجّع registration_token كمان — صفحة إعدادات الحساب بتبني بيه رابط
    // التسجيل العام الآمن (register.html?token=...) بدل كود المدرس القابل للتخمين
    const { data, error } = await supabase
      .from("teachers")
      .select("contact_whatsapp, contact_phone, brand_logo_url, brand_color, registration_token, conversations_enabled, whatsapp_visible, phone_visible, electronic_payment_enabled, payment_instapay, payment_wallet, payment_bank_details")
      .eq("client_id", tokenClientId)
      .maybeSingle();

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, data: data || {} }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
