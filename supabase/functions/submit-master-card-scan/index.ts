// supabase/functions/submit-master-card-scan/index.ts
// بورد الماستر بيستدعيها لما كارت يتمرّغ عليه — لو وضع الاستقبال مفعّل، الكارت يتسجّل في المخزون تلقائياً
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const { uid, deviceSecret } = await req.json();

    if (!uid || !deviceSecret) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ uid و deviceSecret مطلوبين" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: device, error: deviceError } = await supabase
      .from("master_device").select("device_secret").eq("id", 1).maybeSingle();

    if (deviceError || !device || device.device_secret !== deviceSecret) {
      return new Response(JSON.stringify({ success: false, message: "⛔ سر الجهاز غير صحيح" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: scanMode } = await supabase.from("master_scan_mode").select("is_active").eq("id", 1).maybeSingle();
    if (!scanMode?.is_active) {
      // ✅ مش في وضع استقبال، نتجاهل الكارت بهدوء (البورد ممكن يفضل شغّال حتى لو مفيش استقبال دلوقتي)
      return new Response(JSON.stringify({ success: true, ignored: true }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ نسجّل الكارت في المخزون لو مش مسجّل بالفعل (نتجاهل التكرار بهدوء لو نفس الكارت اتمرّغ تاني)
    await supabase.from("system_cards").upsert(
      { card_uid: uid, status: "in_stock" },
      { onConflict: "card_uid", ignoreDuplicates: true }
    );

    await supabase.from("master_scan_mode").update({ last_scanned_uid: uid, last_scanned_at: new Date().toISOString() }).eq("id", 1);

    return new Response(JSON.stringify({ success: true }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
