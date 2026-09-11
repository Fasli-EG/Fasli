// supabase/functions/teacher-start-new-student-scan/index.ts
// المدرس نفسه: يبدأ وضع "انتظار كارت" أثناء إضافة طالب جديد (قبل ما الطالب يتسجّل أصلاً)
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, AuthError, verifyToken, requireTeacherPlanPermission, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

const NEW_STUDENT_SENTINEL = "__NEW_STUDENT__";

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;
    if ((payload.role !== "teacher" && payload.role !== "assistant") || !tokenClientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ متاح للمدرس أو المساعد بس" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    await requireTeacherPlanPermission(tokenClientId, "can_use_rfid");
    if (payload.role === "assistant") {
      await requireAssistantPermission(payload, "add_students");
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    const { count: activeCount } = await supabase
      .from("system_cards").select("id", { count: "exact", head: true })
      .eq("teacher_id", tokenClientId).eq("status", "assigned").eq("is_active", true);

    if (!activeCount || activeCount === 0) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ مفيش أي كروت مفعّلة ليك دلوقتي، تواصل مع الإدارة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { error } = await supabase
      .from("pending_card_registrations")
      .upsert(
        { teacher_id: tokenClientId, student_uid: NEW_STUDENT_SENTINEL, student_name: null, requested_at: new Date().toISOString(), registered_card_uid: null, error_message: null },
        { onConflict: "teacher_id" }
      );

    if (error) {
      console.error("❌ فشل بدء وضع الانتظار:", error);
      return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ في انتظار تمريغ الكارت" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
