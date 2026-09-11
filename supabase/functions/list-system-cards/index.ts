// supabase/functions/list-system-cards/index.ts
// الأدمن بس: يعرض الكروت — إما كل كروت المخزون (status=in_stock) أو كروت مدرس معيّن (بأي حالة)
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, AuthError, verifyToken, requireAdmin, authErrorResponse } from "../_shared/auth.ts";

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const payload = await verifyToken(req);
    requireAdmin(payload);

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    const body = await req.json().catch(() => ({}));
    const { teacherId, statusFilter, cardUid } = body; // statusFilter: 'in_stock' | undefined (يبقى كل حاجة)

    let query = supabase
      .from("system_cards")
      .select("id, card_uid, status, teacher_id, student_uid, is_active, scanned_at, assigned_at, linked_at")
      .order("scanned_at", { ascending: false });

    if (teacherId) query = query.eq("teacher_id", teacherId);
    if (statusFilter) query = query.eq("status", statusFilter);
    if (cardUid) query = query.ilike("card_uid", cardUid.trim()); // مطابقة تامة بدون حساسية لحالة الأحرف

    const { data: cards, error } = await query;

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const studentUids = [...new Set((cards || []).map((c: any) => c.student_uid).filter(Boolean))];
    const teacherIds = [...new Set((cards || []).map((c: any) => c.teacher_id).filter(Boolean))];

    const [{ data: students }, { data: teachers }] = await Promise.all([
      studentUids.length > 0
        ? supabase.from("students").select("uid, name").in("uid", studentUids)
        : Promise.resolve({ data: [] }),
      teacherIds.length > 0
        ? supabase.from("teachers").select("client_id, name").in("client_id", teacherIds)
        : Promise.resolve({ data: [] }),
    ]);

    const studentNames: Record<string, string> = {};
    (students || []).forEach((s: any) => { studentNames[s.uid] = s.name; });
    const teacherNames: Record<string, string> = {};
    (teachers || []).forEach((t: any) => { teacherNames[t.client_id] = t.name; });

    const result = (cards || []).map((c: any) => ({
      id: c.id,
      cardUid: c.card_uid,
      status: c.status,
      isActive: c.is_active,
      teacherId: c.teacher_id,
      teacherName: c.teacher_id ? (teacherNames[c.teacher_id] || c.teacher_id) : null,
      studentUid: c.student_uid,
      studentName: c.student_uid ? (studentNames[c.student_uid] || "طالب محذوف") : null,
      scannedAt: c.scanned_at,
      assignedAt: c.assigned_at,
      linkedAt: c.linked_at,
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
