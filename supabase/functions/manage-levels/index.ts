// supabase/functions/manage-levels/index.ts
// ✅ Aug 2026 (تعديل جوهري): دالة جديدة — إدارة "المراحل الدراسية" (زي "الصف الأول الثانوي")
// اللي كل مدرس (سنتر أو مش سنتر) يقدر يعرّفها، يربطها بمجموعاته، ورابط التسجيل العام
// يستخدمها عشان ولي الأمر يختار مرحلة دراسية بدل ما يختار/يكتب اسم مجموعة مباشرة —
// المدرس أو المساعد بيحدد المجموعة الفعلية وقت الموافقة على الطلب.
// ✅ الفرق الأساسي عن manage-instructor-names: الميزة دي مش مقصورة على حسابات السنتر —
// أي مدرس عنده صلاحية إدارة المجموعات (can_manage_groups / manage_groups) يقدر يستخدمها،
// فبنستخدم نفس نمط الصلاحيات اللي في manage-group بدل requireIsCenter.
// نفس شكل CRUD بالظبط (list/add/update/delete) — manage-instructor-names هو القالب الأصلي لنفس
// الفكرة ("كيان مسمّى صغير مربوط بحساب المدرس")، فدالة جديدة هنا متسقة مع سابقة موجودة فعلاً،
// مش مخالفة لقاعدة "تجنب إنشاء دوال جديدة".
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, TokenPayload, AuthError, verifyToken, ownerClientId, requireTeacherPlanPermission, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

// ✅ نفس صلاحية إدارة المجموعات المستخدمة في manage-group — مش مقصورة على حسابات السنتر

function jsonRes(body: any, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleList(supabase: any, payload: TokenPayload) {
  const clientId = ownerClientId(payload);
  await requireTeacherPlanPermission(clientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");
  const { data, error } = await supabase.from("education_levels").select("*").eq("teacher_id", clientId).order("created_at", { ascending: true });
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, data: data || [] });
}

async function handleAdd(supabase: any, payload: TokenPayload, body: any) {
  const clientId = ownerClientId(payload);
  await requireTeacherPlanPermission(clientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");
  const name = (body.name || "").trim();
  if (!name) return jsonRes({ success: false, message: "⚠️ اسم المرحلة الدراسية مطلوب" }, 400);

  const { data: existing } = await supabase.from("education_levels").select("id").eq("teacher_id", clientId).eq("name", name).maybeSingle();
  if (existing) return jsonRes({ success: false, message: `⚠️ المرحلة "${name}" موجودة بالفعل` }, 400);

  const { data, error } = await supabase.from("education_levels").insert({ teacher_id: clientId, name, is_active: true }).select();
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, message: `✅ تم إضافة "${name}"`, data: data[0] });
}

async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  const clientId = ownerClientId(payload);
  await requireTeacherPlanPermission(clientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");
  const { id, name, isActive } = body;
  if (!id) return jsonRes({ success: false, message: "⚠️ id مطلوب" }, 400);

  const { data: row } = await supabase.from("education_levels").select("teacher_id").eq("id", id).maybeSingle();
  if (!row) return jsonRes({ success: false, message: "❌ المرحلة غير موجودة" }, 404);
  if (row.teacher_id !== clientId) return jsonRes({ success: false, message: "⛔ غير مصرح لك بتعديل هذه المرحلة" }, 403);

  const updateData: any = {};
  if (name !== undefined && name !== null && String(name).trim()) updateData.name = String(name).trim();
  if (isActive !== undefined) updateData.is_active = isActive;

  const { error } = await supabase.from("education_levels").update(updateData).eq("id", id);
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, message: "✅ تم التحديث" });
}

async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  const clientId = ownerClientId(payload);
  await requireTeacherPlanPermission(clientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");
  const { id } = body;
  if (!id) return jsonRes({ success: false, message: "⚠️ id مطلوب" }, 400);

  const { data: row } = await supabase.from("education_levels").select("teacher_id, name").eq("id", id).maybeSingle();
  if (!row) return jsonRes({ success: false, message: "❌ المرحلة غير موجودة" }, 404);
  if (row.teacher_id !== clientId) return jsonRes({ success: false, message: "⛔ غير مصرح لك بحذف هذه المرحلة" }, 403);

  // ✅ الحذف بيشيل المرحلة بس — level_id في groups/registration_requests بيرجع NULL تلقائياً
  // (ON DELETE SET NULL في الـ migration)، فمفيش بيانات تاريخية بتتفقد
  const { error } = await supabase.from("education_levels").delete().eq("id", id);
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, message: `✅ تم حذف "${row.name}"` });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  if (req.method !== "POST") {
    return jsonRes({ success: false, message: "⚠️ الطريقة غير مسموحة" }, 405);
  }

  try {
    const payload = await verifyToken(req);
    const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
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

    return jsonRes({ success: false, message: "⚠️ action غير معروفة — لازم تكون list أو add أو update أو delete" }, 400);
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return jsonRes({ success: false, message }, 500);
  }
});
