// supabase/functions/transfer-student/index.ts
// ينقل طالب من مجموعة لمجموعة تانية، وينقل معاه كل بياناته المرتبطة (درجات، مدفوعات، سداد مذكرات، حضور)
// لأن اسم المجموعة متكرر (denormalized) في كذا جدول لأسباب أداء الفلترة
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, requireTeacherPlanPermission, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

// ✅ (طلب) نقل طالب لمجموعة جديدة هو "إضافة" ضمنية للمجموعة الجديدة — لازم يترفض لو المجموعة
// الجديدة وصلت لحدها الأقصى (max_students). العدد الحالي = مجموعة أساسية (students.group_name)
// + مجموعات إضافية (student_group_links)، نفس منطق العدّ في باقي الدوال. من غير حد أقصى = بلا رفض.
async function checkGroupCapacity(teacherId: string, groupName: string): Promise<{ ok: boolean; message?: string }> {
  const { data: group } = await supabase.from("groups").select("max_students").eq("teacher_id", teacherId).eq("name", groupName).maybeSingle();
  const maxStudents = group?.max_students;
  if (!maxStudents || maxStudents <= 0) return { ok: true };

  const { count: primaryCount } = await supabase
    .from("students").select("uid", { count: "exact", head: true }).eq("teacher_id", teacherId).eq("group_name", groupName);
  const { count: linkedCount } = await supabase
    .from("student_group_links").select("id", { count: "exact", head: true }).eq("teacher_id", teacherId).eq("group_name", groupName);
  const currentCount = (primaryCount || 0) + (linkedCount || 0);

  if (currentCount >= maxStudents) {
    return { ok: false, message: `⚠️ المجموعة "${groupName}" وصلت للحد الأقصى لعدد الطلاب (${maxStudents}) — لازم تزود الحد الأقصى أو تختار مجموعة تانية` };
  }
  return { ok: true };
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;
    await requireTeacherPlanPermission(tokenClientId, "can_manage_students");
    await requireAssistantPermission(payload, "edit_students");

    const { clientId, studentUid, newGroupName } = await req.json();

    if (!clientId || !studentUid || !newGroupName) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ clientId و studentUid و newGroupName مطلوبين" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (tokenClientId !== clientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: student, error: studentError } = await supabase
      .from("students").select("name, group_name, teacher_id").eq("uid", studentUid).maybeSingle();

    if (studentError || !student) {
      return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (student.teacher_id !== clientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const oldGroupName = student.group_name;
    if (oldGroupName === newGroupName) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب أصلاً في نفس المجموعة دي" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const capacity = await checkGroupCapacity(clientId, newGroupName);
    if (!capacity.ok) {
      return new Response(JSON.stringify({ success: false, message: capacity.message }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ نحدّث المجموعة في كل الجداول المرتبطة بالطالب مع بعض
    const [studentsUpdate, gradesUpdate, paymentsUpdate, bookPaymentsUpdate, attendanceUpdate] = await Promise.all([
      supabase.from("students").update({ group_name: newGroupName }).eq("uid", studentUid),
      supabase.from("grades").update({ group_name: newGroupName }).eq("student_uid", studentUid),
      supabase.from("payments").update({ group_name: newGroupName }).eq("student_uid", studentUid),
      supabase.from("book_payments").update({ group_name: newGroupName }).eq("student_uid", studentUid),
      supabase.from("attendance").update({ group_name: newGroupName }).eq("student_uid", studentUid),
    ]);

    const failedUpdates = [studentsUpdate, gradesUpdate, paymentsUpdate, bookPaymentsUpdate, attendanceUpdate]
      .filter((r) => r.error)
      .map((r) => r.error?.message);

    if (studentsUpdate.error) {
      console.error("❌ فشل نقل الطالب:", studentsUpdate.error);
      return new Response(JSON.stringify({ success: false, message: "فشل نقل الطالب: " + studentsUpdate.error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (failedUpdates.length > 0) {
      console.error("⚠️ نجح نقل الطالب لكن فشل تحديث بعض بياناته المرتبطة:", failedUpdates);
    }

    await supabase.from("activity_logs").insert({
      client_id: clientId, teacher_id: clientId,
      action_type: "transfer_student", entity_type: "student", entity_id: studentUid,
      details: { student_name: student.name, student_uid: studentUid, old_group: oldGroupName, new_group: newGroupName },
      performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
    });

    return new Response(JSON.stringify({
      success: true,
      message: `✅ تم نقل ${student.name} من "${oldGroupName}" إلى "${newGroupName}" بنجاح، مع كل بياناته`,
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
