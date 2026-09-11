// supabase/functions/manage-instructor-names/index.ts
// ✅ Aug 2026 (تعديل جوهري): دالة جديدة — إدارة "أسماء المدرسين" التابعين لحساب سنتر (teachers.is_center = true).
// الاسم هنا مجرد تاج/علامة بدون تسجيل دخول خاص بيه (مش حساب مستقل زي المساعد)، بيستخدمه صاحب
// حساب السنتر وقت تسجيل حضور طلابه لتحديد مين من "مدرسينه" الطالب حاضر عنده، وعشان تقدر تطلع
// تقارير/إحصائيات منفصلة لكل اسم لاحقاً (عدد الطلاب اللي معلَّمين عليه، الحضور، المدفوعات).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

export const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
  "Access-Control-Max-Age": "86400",
};

export interface TokenPayload {
  sub: string; clientId?: string; teacherId?: string; role: "teacher" | "assistant" | "parent"; name: string; exp: number;
}

export class AuthError extends Error {
  status: number; code?: string;
  constructor(message: string, status = 401, code?: string) { super(message); this.status = status; this.code = code; }
}

async function getKey() {
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) throw new Error("⚠️ JWT_SECRET غير مضبوط في متغيرات البيئة");
  return await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
}

async function licenseCheckClient() {
  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2.38.4");
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

async function checkLicenseActive(teacherClientId: string): Promise<{ active: boolean; reason?: string }> {
  if (teacherClientId === "master_admin") return { active: true };
  const supabase = await licenseCheckClient();
  const { data: teacher, error } = await supabase.from("teachers").select("is_active, expiry_date").eq("client_id", teacherClientId).maybeSingle();
  if (error || !teacher) return { active: false, reason: "الحساب غير موجود" };
  if (teacher.is_active === false) return { active: false, reason: "الحساب معطّل" };
  if (teacher.expiry_date) {
    const todayCLA = new Date().toISOString().split("T")[0];
    if (teacher.expiry_date < todayCLA) return { active: false, reason: "انتهت صلاحية الترخيص" };
  }
  return { active: true };
}

export async function verifyToken(req: Request): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) throw new AuthError("⚠️ التوكن مطلوب", 401);
  const token = authHeader.substring(7);
  const key = await getKey();
  let payload: TokenPayload;
  try { payload = (await verify(token, key, "HS256")) as unknown as TokenPayload; }
  catch (_e) { throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401); }
  if (payload.role === "teacher" || payload.role === "assistant") {
    const ownerId = payload.clientId || payload.teacherId;
    if (ownerId) {
      const license = await checkLicenseActive(ownerId);
      if (!license.active) throw new AuthError(`⛔ ${license.reason || "انتهت صلاحية الترخيص"} — يرجى التواصل مع الإدارة`, 402, "LICENSE_EXPIRED");
    }
  }
  return payload;
}

export function ownerClientId(payload: TokenPayload): string {
  const id = payload.clientId || payload.teacherId;
  if (!id) throw new AuthError("⚠️ التوكن لا يحتوي على clientId", 401);
  return id;
}

export function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

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
async function requireAssistantPermission(payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const supabase = await licenseCheckClient();
  const { data: assistant } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) throw new AuthError("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس", 403);
}

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

  const { data: names } = await supabase.from("instructor_names").select("*").eq("teacher_id", clientId);
  const list = names || [];

  const { data: attendance } = await supabase.from("attendance").select("instructor_name_id, student_uid").eq("teacher_id", clientId);

  // ✅ Aug 2026 (Phase I follow-up): تفاصيل أكتر لكل مدرس — مجموعاته المربوطة بيه (groups.instructor_name_id)
  // وعدد الطلاب الفعلي في المجموعات دي (المجموعة الأساسية + المربوطين بيها كمجموعة إضافية عن طريق
  // student_group_links)، مش بس إحصائيات الحضور القديمة — عشان تظهر تفاصيل أوضح في لوحة تحكم السنتر
  const { data: groups } = await supabase.from("groups").select("name, instructor_name_id").eq("teacher_id", clientId);
  const { data: allStudents } = await supabase.from("students").select("uid, group_name").eq("teacher_id", clientId).is("archived_at", null);
  const { data: allLinks } = await supabase.from("student_group_links").select("student_uid, group_name").eq("teacher_id", clientId);

  // ✅ Aug 2026 (Phase I follow-up): نظرة مالية وأكاديمية ونسبة حضور لكل مدرس — بيوصلوا كلهم عن طريق
  // group_name (المدفوعات والدرجات بتاخده وقت التسجيل)، فمش لازم كل صف يكون فيه instructor_name_id
  const { data: allPayments } = await supabase.from("payments").select("group_name, amount, total_amount").eq("teacher_id", clientId);
  const { data: allGrades } = await supabase.from("grades").select("group_name, score, max_score").eq("teacher_id", clientId);
  const attendanceLookbackDays = 14;
  const cutoffDate = new Date(Date.now() - attendanceLookbackDays * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
  const { data: recentAttendance } = await supabase
    .from("attendance").select("group_name, is_absent, date").eq("teacher_id", clientId).gte("date", cutoffDate);

  const stats = list.map((n: any) => {
    const related = (attendance || []).filter((a: any) => a.instructor_name_id === n.id);
    const uniqueStudents = new Set(related.map((a: any) => a.student_uid)).size;

    const groupNames = (groups || []).filter((g: any) => g.instructor_name_id === n.id).map((g: any) => g.name);
    const rosterUids = new Set<string>();
    (allStudents || []).forEach((s: any) => { if (groupNames.includes(s.group_name)) rosterUids.add(s.uid); });
    (allLinks || []).forEach((l: any) => { if (groupNames.includes(l.group_name)) rosterUids.add(l.student_uid); });

    const instructorPayments = (allPayments || []).filter((p: any) => groupNames.includes(p.group_name));
    const paymentsCollected = instructorPayments.reduce((sum: number, p: any) => sum + Number(p.amount || 0), 0);
    const paymentsExpected = instructorPayments.reduce((sum: number, p: any) => sum + Number(p.total_amount || 0), 0);
    const collectionRate = paymentsExpected > 0 ? Math.round((paymentsCollected / paymentsExpected) * 100) : null;

    const instructorGrades = (allGrades || []).filter((g: any) => groupNames.includes(g.group_name) && Number(g.max_score) > 0);
    const avgGradePercent = instructorGrades.length > 0
      ? Math.round(instructorGrades.reduce((sum: number, g: any) => sum + (Number(g.score) / Number(g.max_score)) * 100, 0) / instructorGrades.length)
      : null;

    const instructorAttendance = (recentAttendance || []).filter((a: any) => groupNames.includes(a.group_name));
    const presentCount = instructorAttendance.filter((a: any) => a.is_absent !== true).length;
    const absentCount = instructorAttendance.filter((a: any) => a.is_absent === true).length;
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
