// supabase/functions/admin-get-teacher/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, requireAdmin, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة"); // ✅ رفض واضح بدل السقوط الصامت لصلاحيات anon
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطريقة غير مسموحة" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  try {
    const payload = await verifyToken(req);
    requireAdmin(payload);

    const { clientId } = await req.json();
    if (!clientId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ clientId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: teacher, error } = await supabase
      .from("teachers").select("*").eq("client_id", clientId).maybeSingle();

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (!teacher) {
      return new Response(JSON.stringify({ success: false, message: "❌ المدرس غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { count } = await supabase
      .from("students").select("*", { count: "exact", head: true }).eq("teacher_id", clientId);

    const today = new Date().toISOString().split("T")[0];
    let calculatedStatus = "active";
    let daysRemaining = null;

    if (teacher.client_id === "Fasli-admin") calculatedStatus = "admin";
    else if (teacher.is_active === false) calculatedStatus = "inactive";
    else if (teacher.expiry_date && teacher.expiry_date < today) calculatedStatus = "expired";

    if (teacher.expiry_date && teacher.expiry_date >= today) {
      daysRemaining = Math.ceil((new Date(teacher.expiry_date).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    }

    return new Response(JSON.stringify({
      success: true,
      data: { ...teacher, student_count: count || 0, calculated_status: calculatedStatus, days_remaining: daysRemaining }
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
