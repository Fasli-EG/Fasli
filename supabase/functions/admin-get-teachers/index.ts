// supabase/functions/admin-get-teachers/index.ts
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

    const { data: teachers, error } = await supabase
      .from("teachers").select("*").order("created_at", { ascending: false });

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ (أداء) كان بيجيب عمود teacher_id من جدول students كله (كل مدرسي المنصة، من غير حد
    // أقصى) بس عشان يعدّ الطلاب لكل مدرس في الكود — بقى العدّ نفسه جاهز من قاعدة البيانات
    const { data: studentCounts } = await supabase.rpc("get_student_counts_by_teacher");
    const countByTeacher = new Map<string, number>();
    (studentCounts || []).forEach((row: any) => {
      countByTeacher.set(row.teacher_id, Number(row.student_count));
    });

    const staleUpdates: Promise<any>[] = [];
    const teachersWithCount = (teachers || []).map((teacher) => {
      const count = countByTeacher.get(teacher.client_id) || 0;

      if (count !== teacher.student_count) {
        staleUpdates.push(supabase.from("teachers").update({ student_count: count }).eq("client_id", teacher.client_id));
      }

      const now = Date.now();
      let calculatedStatus = "active";
      let daysRemaining = null;

      // ✅ نقارن كائنات تواريخ حقيقية بدل النصوص مباشرة، عشان لو expiry_date راجعة بصيغة فيها وقت
      // (زي "2026-08-09T00:00:00.000Z") المقارنة النصية ممكن تدّي نتيجة غلط في حالات معيّنة
      const expiryTime = teacher.expiry_date ? new Date(teacher.expiry_date).getTime() : null;

      if (teacher.client_id === "master_admin") calculatedStatus = "admin";
      else if (teacher.is_active === false) calculatedStatus = "inactive";
      else if (expiryTime !== null && expiryTime < now) calculatedStatus = "expired";

      if (expiryTime !== null && expiryTime >= now) {
        daysRemaining = Math.ceil((expiryTime - now) / (1000 * 60 * 60 * 24));
      }

      return { ...teacher, student_count: count, calculated_status: calculatedStatus, days_remaining: daysRemaining };
    });
    if (staleUpdates.length > 0) await Promise.all(staleUpdates);

    return new Response(JSON.stringify({ success: true, data: teachersWithCount }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
