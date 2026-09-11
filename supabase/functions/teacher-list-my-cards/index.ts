// supabase/functions/teacher-list-my-cards/index.ts
// المدرس نفسه: يشوف الكروت المفعّلة له، ومربوطة بمين لو مربوطة
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, AuthError, verifyToken, authErrorResponse } from "../_shared/auth.ts";

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;
    if (payload.role !== "teacher") {
      return new Response(JSON.stringify({ success: false, message: "⛔ متاح للمدرس نفسه بس" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    const { data: cards, error } = await supabase
      .from("system_cards")
      .select("id, card_uid, student_uid, is_active, linked_at")
      .eq("teacher_id", tokenClientId)
      .eq("status", "assigned")
      .order("assigned_at", { ascending: false });

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const studentUids = [...new Set((cards || []).map((c: any) => c.student_uid).filter(Boolean))];
    const { data: students } = studentUids.length > 0
      ? await supabase.from("students").select("uid, name").in("uid", studentUids)
      : { data: [] };
    const studentNames: Record<string, string> = {};
    (students || []).forEach((s: any) => { studentNames[s.uid] = s.name; });

    const result = (cards || []).map((c: any) => ({
      id: c.id,
      cardUid: c.card_uid,
      isActive: c.is_active,
      studentUid: c.student_uid,
      studentName: c.student_uid ? (studentNames[c.student_uid] || "طالب محذوف") : null,
    }));

    return new Response(JSON.stringify({ success: true, data: result }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
