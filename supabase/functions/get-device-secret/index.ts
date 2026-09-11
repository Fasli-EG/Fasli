// supabase/functions/get-device-secret/index.ts
// يرجّع (أو يولّد أول مرة) مفتاح الجهاز الخاص بالمدرس، لاستخدامه في كود ESP32 بتاعه
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, ownerClientId, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

function generateSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const payload = await verifyToken(req);
    if (payload.role !== "teacher") {
      return new Response(JSON.stringify({ success: false, message: "⛔ متاح للمدرس نفسه بس" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const tokenClientId = ownerClientId(payload);
    const body = await req.json().catch(() => ({}));
    const forceRegenerate = body?.regenerate === true;

    const { data: teacher, error } = await supabase
      .from("teachers").select("device_secret").eq("client_id", tokenClientId).maybeSingle();

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    let secret = teacher?.device_secret;
    if (!secret || forceRegenerate) {
      secret = generateSecret();
      const { error: updateError } = await supabase
        .from("teachers").update({ device_secret: secret }).eq("client_id", tokenClientId);
      if (updateError) {
        return new Response(JSON.stringify({ success: false, message: updateError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }

    return new Response(JSON.stringify({ success: true, data: { deviceSecret: secret, clientId: tokenClientId } }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
