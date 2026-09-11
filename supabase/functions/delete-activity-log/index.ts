// supabase/functions/delete-activity-log/index.ts
// يسمح للمدرس بحذف أي نشاط من سجل النشاطات بتاعه (المساعد ملوش الصلاحية دي)
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, requireOwnClientId, authErrorResponse } from "../_shared/auth.ts";

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

    // ✅ حذف سجل النشاطات متاح للمدرس نفسه بس، مش المساعد
    if (payload.role !== "teacher") {
      return new Response(JSON.stringify({ success: false, message: "⛔ حذف النشاطات متاح للمدرس بس" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { clientId, logId } = await req.json();
    if (!clientId || !logId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ clientId و logId مطلوبين" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const finalClientId = requireOwnClientId(payload, clientId);

    // ✅ التأكد إن النشاط ده فعلاً بتاع نفس المدرس قبل الحذف
    const { data: logRow, error: fetchError } = await supabase
      .from("activity_logs")
      .select("id, teacher_id")
      .eq("id", logId)
      .maybeSingle();

    if (fetchError || !logRow) {
      return new Response(JSON.stringify({ success: false, message: "النشاط غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (logRow.teacher_id !== finalClientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ هذا النشاط ليس تابعاً لك" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { error: deleteError } = await supabase.from("activity_logs").delete().eq("id", logId);
    if (deleteError) {
      return new Response(JSON.stringify({ success: false, message: deleteError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ تم حذف النشاط بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
