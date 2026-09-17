// supabase/functions/manage-instructor-names/index.ts
// ✅ Aug 2026 (تعديل جوهري): دالة جديدة — إدارة "أسماء المدرسين" التابعين لحساب سنتر (teachers.is_center = true).
// الاسم هنا مجرد تاج/علامة بدون تسجيل دخول خاص بيه (مش حساب مستقل زي المساعد)، بيستخدمه صاحب
// حساب السنتر وقت تسجيل حضور طلابه لتحديد مين من "مدرسينه" الطالب حاضر عنده، وعشان تقدر تطلع
// تقارير/إحصائيات منفصلة لكل اسم لاحقاً (عدد الطلاب اللي معلَّمين عليه، الحضور، المدفوعات).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, TokenPayload, AuthError, verifyToken, ownerClientId, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

/** يتأكد إن صاحب التوكن حساب سنتر فعلاً (is_center = true) قبل ما يدير أي اسم مدرس */
async function requireIsCenter(supabase: any, clientId: string): Promise<void> {
  const { data: teacher } = await supabase.from("teachers").select("is_center").eq("client_id", clientId).maybeSingle();
  if (!teacher?.is_center) {
    throw new AuthError("⛔ هذه الميزة متاحة لحسابات السنتر فقط", 403);
  }
}

/**
 * ✅ Batch 21: يتأكد إن المساعد عنده صلاحية محددة منحها له المدرس — بدل الرفض القاطع لأي مساعد
 * اللي كان معمول بيه في كل handler هنا قبل كده. "أسماء المدرسين" جزء من نفس تبويب "فريق العمل"
 * في staff.html، فبتستخدم نفس صلاحيات view_staff/add_staff/edit_staff/delete_staff.
 */

function jsonRes(body: any, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleList(supabase: any, payload: TokenPayload) {
  await requireAssistantPermission(payload, "view_staff");
  const clientId = ownerClientId(payload);
  await requireIsCenter(supabase, clientId);
  const { data, error } = await supabase.from("instructor_names").select("*").eq("teacher_id", clientId).order("created_at", { ascending: true });
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, data: data || [] });
}

async function handleAdd(supabase: any, payload: TokenPayload, body: any) {
  await requireAssistantPermission(payload, "add_staff");
  const clientId = ownerClientId(payload);
  await requireIsCenter(supabase, clientId);
  const name = (body.name || "").trim();
  if (!name) return jsonRes({ success: false, message: "⚠️ اسم المدرس مطلوب" }, 400);

  const { data: existing } = await supabase.from("instructor_names").select("id").eq("teacher_id", clientId).eq("name", name).maybeSingle();
  if (existing) return jsonRes({ success: false, message: `⚠️ الاسم "${name}" موجود بالفعل` }, 400);

  const { data, error } = await supabase.from("instructor_names").insert({ teacher_id: clientId, name, is_active: true }).select();
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, message: `✅ تم إضافة "${name}"`, data: data[0] });
}

async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  await requireAssistantPermission(payload, "edit_staff");
  const clientId = ownerClientId(payload);
  await requireIsCenter(supabase, clientId);
  const { id, name, isActive } = body;
  if (!id) return jsonRes({ success: false, message: "⚠️ id مطلوب" }, 400);

  const { data: row } = await supabase.from("instructor_names").select("teacher_id").eq("id", id).maybeSingle();
  if (!row) return jsonRes({ success: false, message: "❌ الاسم غير موجود" }, 404);
  if (row.teacher_id !== clientId) return jsonRes({ success: false, message: "⛔ غير مصرح لك بتعديل هذا الاسم" }, 403);

  const updateData: any = {};
  if (name !== undefined && name !== null && String(name).trim()) updateData.name = String(name).trim();
  if (isActive !== undefined) updateData.is_active = isActive;

  const { error } = await supabase.from("instructor_names").update(updateData).eq("id", id);
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, message: "✅ تم التحديث" });
}

async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  await requireAssistantPermission(payload, "delete_staff");
  const clientId = ownerClientId(payload);
  await requireIsCenter(supabase, clientId);
  const { id } = body;
  if (!id) return jsonRes({ success: false, message: "⚠️ id مطلوب" }, 400);

  const { data: row } = await supabase.from("instructor_names").select("teacher_id, name").eq("id", id).maybeSingle();
  if (!row) return jsonRes({ success: false, message: "❌ الاسم غير موجود" }, 404);
  if (row.teacher_id !== clientId) return jsonRes({ success: false, message: "⛔ غير مصرح لك بحذف هذا الاسم" }, 403);

  // ✅ الحذف بيشيل التاج بس — الحضور القديم المسجّل عليه بيفضل زي ما هو (اسم نصي محفوظ وقت التسجيل)
  // لكن instructor_name_id بيرجع NULL تلقائياً (ON DELETE SET NULL في الـ migration)
  const { error } = await supabase.from("instructor_names").delete().eq("id", id);
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, message: `✅ تم حذف "${row.name}"` });
}

/**
 * إحصائيات منفصلة لكل اسم مدرس — تلبية لطلب "تقارير/إحصائيات منفصلة لكل اسم".
 * ✅ مبنية على جدول attendance فقط (اللي فيه instructor_name_id) — أي اسم مدرس بياخد سجلات
 * حضور بيتحدد له تلقائياً، وده اللي بيمكّن فصل الحضور والطلاب الفريدين لكل اسم عن التاني.
 */
async function handleStats(supabase: any, payload: TokenPayload) {
  await requireAssistantPermission(payload, "view_staff");
  const clientId = ownerClientId(payload);
  await requireIsCenter(supabase, clientId);

  const attendanceLookbackDays = 14;
  const cutoffDate = new Date(Date.now() - attendanceLookbackDays * 24 * 60 * 60 * 1000).toISOString().split("T")[0];

  // ✅ (أداء) الاستعلامات السبعة دي كانت متسلسلة (await واحد ورا التاني) رغم إنها مستقلة تمامًا
  // عن بعضها — بقت متوازية عن طريق Promise.all
  const [
    { data: names }, { data: attendance },
    // ✅ Aug 2026 (Phase I follow-up): تفاصيل أكتر لكل مدرس — مجموعاته المربوطة بيه (groups.instructor_name_id)
    // وعدد الطلاب الفعلي في المجموعات دي (المجموعة الأساسية + المربوطين بيها كمجموعة إضافية عن طريق
    // student_group_links)، مش بس إحصائيات الحضور القديمة — عشان تظهر تفاصيل أوضح في لوحة تحكم السنتر
    { data: groups }, { data: allStudents }, { data: allLinks },
    // ✅ Aug 2026 (Phase I follow-up): نظرة مالية وأكاديمية ونسبة حضور لكل مدرس — بيوصلوا كلهم عن طريق
    // group_name (المدفوعات والدرجات بتاخده وقت التسجيل)، فمش لازم كل صف يكون فيه instructor_name_id
    { data: allPayments }, { data: allGrades }, { data: recentAttendance },
  ] = await Promise.all([
    supabase.from("instructor_names").select("*").eq("teacher_id", clientId),
    supabase.from("attendance").select("instructor_name_id, student_uid").eq("teacher_id", clientId),
    supabase.from("groups").select("name, instructor_name_id").eq("teacher_id", clientId),
    supabase.from("students").select("uid, group_name").eq("teacher_id", clientId).is("archived_at", null),
    supabase.from("student_group_links").select("student_uid, group_name").eq("teacher_id", clientId),
    supabase.from("payments").select("group_name, amount, total_amount").eq("teacher_id", clientId),
    supabase.from("grades").select("group_name, score, max_score").eq("teacher_id", clientId),
    supabase.from("attendance").select("group_name, is_absent, date").eq("teacher_id", clientId).gte("date", cutoffDate),
  ]);

  const list = names || [];

  // ✅ (أداء حرج) كانت بتعمل .filter() على المصفوفات الكاملة دي لكل اسم مدرس على حدة —
  // يعني O(عدد المدرسين × عدد كل صفوف السنتر) في مركز فيه سنين من البيانات. بدل كده، بنجمّع
  // كل حاجة في خرائط حسب اسم المجموعة مرة واحدة بس (O(عدد الصفوف))، وكل مدرس بعد كده بيقرا
  // بس من مجموعاته هو (O(مجموعات المدرس))
  const attendanceByInstructor = new Map<number, { student_uid: string }[]>();
  (attendance || []).forEach((a: any) => {
    if (a.instructor_name_id == null) return;
    if (!attendanceByInstructor.has(a.instructor_name_id)) attendanceByInstructor.set(a.instructor_name_id, []);
    attendanceByInstructor.get(a.instructor_name_id)!.push(a);
  });

  const groupsByInstructor = new Map<number, string[]>();
  (groups || []).forEach((g: any) => {
    if (g.instructor_name_id == null) return;
    if (!groupsByInstructor.has(g.instructor_name_id)) groupsByInstructor.set(g.instructor_name_id, []);
    groupsByInstructor.get(g.instructor_name_id)!.push(g.name);
  });

  const rosterUidsByGroup = new Map<string, Set<string>>();
  (allStudents || []).forEach((s: any) => {
    if (!rosterUidsByGroup.has(s.group_name)) rosterUidsByGroup.set(s.group_name, new Set());
    rosterUidsByGroup.get(s.group_name)!.add(s.uid);
  });
  (allLinks || []).forEach((l: any) => {
    if (!rosterUidsByGroup.has(l.group_name)) rosterUidsByGroup.set(l.group_name, new Set());
    rosterUidsByGroup.get(l.group_name)!.add(l.student_uid);
  });

  const paymentsByGroup = new Map<string, { collected: number; expected: number }>();
  (allPayments || []).forEach((p: any) => {
    const cur = paymentsByGroup.get(p.group_name) || { collected: 0, expected: 0 };
    cur.collected += Number(p.amount || 0);
    cur.expected += Number(p.total_amount || 0);
    paymentsByGroup.set(p.group_name, cur);
  });

  const gradesByGroup = new Map<string, { sumPercent: number; count: number }>();
  (allGrades || []).forEach((g: any) => {
    if (!(Number(g.max_score) > 0)) return;
    const cur = gradesByGroup.get(g.group_name) || { sumPercent: 0, count: 0 };
    cur.sumPercent += (Number(g.score) / Number(g.max_score)) * 100;
    cur.count += 1;
    gradesByGroup.set(g.group_name, cur);
  });

  const attendanceRateByGroup = new Map<string, { present: number; absent: number }>();
  (recentAttendance || []).forEach((a: any) => {
    const cur = attendanceRateByGroup.get(a.group_name) || { present: 0, absent: 0 };
    if (a.is_absent === true) cur.absent += 1; else cur.present += 1;
    attendanceRateByGroup.set(a.group_name, cur);
  });

  const stats = list.map((n: any) => {
    const related = attendanceByInstructor.get(n.id) || [];
    const uniqueStudents = new Set(related.map((a: any) => a.student_uid)).size;

    const groupNames = groupsByInstructor.get(n.id) || [];
    const rosterUids = new Set<string>();
    groupNames.forEach((g: string) => { (rosterUidsByGroup.get(g) || new Set<string>()).forEach((uid) => rosterUids.add(uid)); });

    let paymentsCollected = 0, paymentsExpected = 0;
    groupNames.forEach((g: string) => {
      const p = paymentsByGroup.get(g);
      if (p) { paymentsCollected += p.collected; paymentsExpected += p.expected; }
    });
    const collectionRate = paymentsExpected > 0 ? Math.round((paymentsCollected / paymentsExpected) * 100) : null;

    let gradeSum = 0, gradeCount = 0;
    groupNames.forEach((g: string) => {
      const gr = gradesByGroup.get(g);
      if (gr) { gradeSum += gr.sumPercent; gradeCount += gr.count; }
    });
    const avgGradePercent = gradeCount > 0 ? Math.round(gradeSum / gradeCount) : null;

    let presentCount = 0, absentCount = 0;
    groupNames.forEach((g: string) => {
      const ar = attendanceRateByGroup.get(g);
      if (ar) { presentCount += ar.present; absentCount += ar.absent; }
    });
    const attendanceRatePercent = (presentCount + absentCount) > 0 ? Math.round((presentCount / (presentCount + absentCount)) * 100) : null;

    return {
      ...n,
      attendanceCount: related.length,
      uniqueStudentsCount: uniqueStudents,
      groupNames,
      groupsCount: groupNames.length,
      rosterStudentsCount: rosterUids.size,
      paymentsCollected,
      paymentsExpected,
      collectionRate,
      avgGradePercent,
      attendanceRatePercent,
      attendanceLookbackDays,
    };
  });

  return jsonRes({ success: true, data: stats });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  if (req.method !== "POST") {
    return jsonRes({ success: false, message: "⚠️ الطريقة غير مسموحة" }, 405);
  }

  try {
    const payload = await verifyToken(req);
    const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
    const supabase = createClient(supabaseUrl, supabaseKey);

    let body: any = {};
    try { body = await req.json(); }
    catch (_e) {
      return jsonRes({ success: false, message: "الطلب يجب أن يحتوي على JSON صالح" }, 400);
    }

    const action = body.action;
    if (action === "list") return await handleList(supabase, payload);
    if (action === "add") return await handleAdd(supabase, payload, body);
    if (action === "update") return await handleUpdate(supabase, payload, body);
    if (action === "delete") return await handleDelete(supabase, payload, body);
    if (action === "stats") return await handleStats(supabase, payload);

    return jsonRes({ success: false, message: "⚠️ action غير معروفة" }, 400);
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return jsonRes({ success: false, message }, 500);
  }
});
