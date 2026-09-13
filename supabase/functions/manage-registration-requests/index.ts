// supabase/functions/manage-registration-requests/index.ts
// ✅ إدارة طلبات الانضمام (جانب المدرس) — action: list | approve | reject
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, TokenPayload, AuthError, verifyToken } from "../_shared/auth.ts";
import { provisionAuthUser, deleteAuthUser } from "../_shared/authProvision.ts";

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ✅ (طلب) صلاحية جديدة manage_registration — يتأكد إن المساعد عنده صلاحية إدارة طلبات
// التسجيل المُمنوحة له من المدرس. لا تأثير على المدرس نفسه (دايماً مسموح له).
async function requireAssistantPermission(supabase: any, payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const { data: assistant } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) {
    throw new AuthError("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس", 403);
  }
}

// ✅ (طلب) قبول طلب تسجيل هو "إضافة" طالب جديد للمجموعة المختارة — لازم يترفض لو المجموعة دي
// وصلت لحدها الأقصى (max_students). العدد الحالي = مجموعة أساسية (students.group_name) +
// مجموعات إضافية (student_group_links)، نفس منطق العدّ في باقي الدوال. من غير حد أقصى = بلا رفض.
async function checkGroupCapacity(supabase: any, teacherId: string, groupName: string): Promise<{ ok: boolean; message?: string }> {
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

// ✅ نفس مولّد كود UID مؤقت مستخدم في باقي النظام (حروف+أرقام)
function generateTempUid(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let uid = "";
  for (let i = 0; i < 8; i++) uid += chars.charAt(Math.floor(Math.random() * chars.length));
  return uid;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  try {
    const payload = await verifyToken(req);
    if (payload.role !== "teacher" && payload.role !== "assistant") {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const tokenClientId = payload.clientId || payload.teacherId;
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");
    // ✅ (طلب) كل الأفعال هنا (list/approve/reject) بقت مربوطة بصلاحية manage_registration
    // للمساعد — قبل كده أي مساعد كان يقدر يستخدم الدالة دي من غير أي فحص صلاحية خالص لو وصلها
    await requireAssistantPermission(supabase, payload, "manage_registration");

    const body = await req.json();
    const action = body.action;

    if (action === "list") {
      const { data, error } = await supabase.from("registration_requests").select("*").eq("teacher_id", tokenClientId).order("created_at", { ascending: false });
      if (error) throw new Error(error.message);
      const rows = data || [];

      // ✅ Aug 2026: نجيب أسماء المدرسين (instructor_names) المرتبطين بالطلبات دي عشان صاحب
      // السنتر يميّز كل طلب اتقدّم لمين من مدرسيه — طلب من غير instructor_name_id يبقى لمدرس
      // عادي (مش سنتر) أو للسنتر نفسه من غير تحديد مدرس معيّن
      const instructorIds = [...new Set(rows.map((r: any) => r.instructor_name_id).filter((id: any) => id !== null && id !== undefined))];
      let instructorById: Record<number, string> = {};
      if (instructorIds.length > 0) {
        const { data: instructors } = await supabase.from("instructor_names").select("id, name").in("id", instructorIds);
        (instructors || []).forEach((i: any) => { instructorById[i.id] = i.name; });
      }

      // ✅ (المرحلة الدراسية) نفس أسلوب instructorById بالظبط — بُعد مستقل يظهر جنب بادج المدرس
      const levelIds = [...new Set(rows.map((r: any) => r.level_id).filter((id: any) => id !== null && id !== undefined))];
      let levelById: Record<number, string> = {};
      if (levelIds.length > 0) {
        const { data: levels } = await supabase.from("education_levels").select("id, name").in("id", levelIds);
        (levels || []).forEach((l: any) => { levelById[l.id] = l.name; });
      }

      const enriched = rows.map((r: any) => ({
        ...r,
        instructorName: r.instructor_name_id ? (instructorById[r.instructor_name_id] || null) : null,
        levelName: r.level_id ? (levelById[r.level_id] || null) : null,
      }));

      return new Response(JSON.stringify({ success: true, data: enriched }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "reject") {
      const { requestId } = body;
      const { data: reqRow } = await supabase.from("registration_requests").select("teacher_id").eq("id", requestId).maybeSingle();
      if (!reqRow || reqRow.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      await supabase.from("registration_requests").update({ status: "rejected", reviewed_at: new Date().toISOString() }).eq("id", requestId);
      return new Response(JSON.stringify({ success: true, message: "✅ تم رفض الطلب" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "approve") {
      const { requestId, groupName } = body;
      if (!groupName) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ حدد المجموعة اللي هيتضاف لها الطالب" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: reqRow } = await supabase.from("registration_requests").select("*").eq("id", requestId).maybeSingle();
      if (!reqRow || reqRow.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (reqRow.status !== "pending") {
        return new Response(JSON.stringify({ success: false, message: "⚠️ تم التعامل مع الطلب ده بالفعل" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const capacity = await checkGroupCapacity(supabase, tokenClientId, groupName);
      if (!capacity.ok) {
        return new Response(JSON.stringify({ success: false, message: capacity.message }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ نتأكد إن ولي الأمر عنده حساب بالفعل، وإلا ننشئ واحد جديد (نفس منطق إضافة طالب عادي)
      const { data: existingParent } = await supabase.from("parents").select("phone").eq("phone", reqRow.parent_phone).maybeSingle();
      let newParentAuthUserId: string | null = null;
      if (!existingParent) {
        const parentName = reqRow.parent_name || `ولي أمر ${reqRow.student_name}`;
        newParentAuthUserId = await provisionAuthUser({
          phone: reqRow.parent_phone,
          password: reqRow.parent_phone,
          appMetadata: { role: "parent", phone: reqRow.parent_phone, sub: reqRow.parent_phone, name: parentName },
        });
        const { error: insertParentError } = await supabase.from("parents").insert({
          phone: reqRow.parent_phone, name: parentName,
          auth_user_id: newParentAuthUserId, must_change_password: true, is_active: true,
        });
        if (insertParentError) {
          await deleteAuthUser(newParentAuthUserId);
          return new Response(JSON.stringify({ success: false, message: `⚠️ فشل إنشاء ولي الأمر: ${insertParentError.message}` }),
            { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }

      const uid = generateTempUid();
      const { error: insertError } = await supabase.from("students").insert({
        uid, name: reqRow.student_name, parent_phone: reqRow.parent_phone, group_name: groupName, teacher_id: tokenClientId,
      });
      if (insertError) {
        if (newParentAuthUserId) {
          await deleteAuthUser(newParentAuthUserId);
          await supabase.from("parents").delete().eq("phone", reqRow.parent_phone);
        }
        return new Response(JSON.stringify({ success: false, message: `⚠️ فشلت إضافة الطالب: ${insertError.message}` }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", tokenClientId);
      await supabase.from("teachers").update({ student_count: count }).eq("client_id", tokenClientId);

      await supabase.from("registration_requests").update({ status: "approved", reviewed_at: new Date().toISOString() }).eq("id", requestId);

      return new Response(JSON.stringify({ success: true, message: `✅ تم قبول الطلب وإضافة ${reqRow.student_name} بكود كارت مؤقت: ${uid}`, studentUid: uid }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
