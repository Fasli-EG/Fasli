// supabase/functions/manage-assistant/index.ts
// ✅ دالة موحّدة تجمع add-assistant + update-assistant + delete-assistant بـ "action" parameter
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, TokenPayload, AuthError, verifyToken, ownerClientId, requireOwnClientId, requireTeacherPlanPermission, requireAssistantPermission, authErrorResponse, licenseCheckClient } from "../_shared/auth.ts";
import { provisionAuthUser, deleteAuthUser, syntheticEmailFor } from "../_shared/authProvision.ts";

/**
 * ✅ Batch 21: يتأكد إن المساعد عنده صلاحية محددة منحها له المدرس. لا تأثير على المدرس نفسه
 * (دايماً مسموح له). دي أول مرة الدالة دي تتعرّف في manage-assistant — الملف ده كان دايماً
 * بيرفض أي مساعد بشكل قاطع (role check مش permission check)، فاحتجنا نعرّفها هنا زي باقي
 * الدوال اللي بتستخدمها.
 */

/**
 * ✅ Batch 21: حماية ضد تصعيد الصلاحيات — مساعد معاه "إضافة/تعديل فريق عمل" ميقدرش يمنح مساعد
 * (نفسه أو حد تاني) صلاحية هو نفسه مش حاصل عليها من المدرس. من غير الحماية دي، مساعد كان
 * هيقدر يمنح نفسه أي صلاحية في النظام (زي "حذف طلاب" أو "الدخل الشهري") لمجرد إن معاه صلاحية
 * تعديل فريق العمل. المدرس نفسه معفى من الفحص ده (بيقدر يمنح أي صلاحية زي ما كان دايماً).
 */
async function assertNoPermissionEscalation(payload: TokenPayload, requestedPermissions: Record<string, unknown> | undefined): Promise<void> {
  if (payload.role !== "assistant" || !requestedPermissions) return;
  const supabase = await licenseCheckClient();
  const { data: caller } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const callerPerms = caller?.permissions || {};
  const escalated = Object.keys(requestedPermissions).filter(
    (key) => requestedPermissions[key] === true && callerPerms[key] !== true
  );
  if (escalated.length > 0) {
    throw new AuthError(`⛔ لا يمكنك منح صلاحية لا تملكها أنت نفسك (${escalated.join("، ")})`, 403);
  }
}

async function handleAdd(supabase: any, payload: TokenPayload, body: any) {
  // ✅ Batch 21: بدل الرفض القاطع لأي مساعد، بقى مربوط بصلاحية "إضافة فريق عمل" (add_staff) —
  // زي ما طلب الحساب: المساعد يقدر يضيف مساعدين تانيين لو المدرس منحه الصلاحية دي، مع حماية
  // ضد تصعيد الصلاحيات (assertNoPermissionEscalation تحت) عشان ميقدرش يمنح صلاحية مش معاه هو
  await requireAssistantPermission(payload, "add_staff");
  const { teacherId, username, name, permissions } = body;
  if (!teacherId || !username || !name) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const finalTeacherId = requireOwnClientId(payload, teacherId);
  await requireTeacherPlanPermission(finalTeacherId, "can_manage_assistants");
  await assertNoPermissionEscalation(payload, permissions);

  const { data: teacher, error: teacherError } = await supabase.from("teachers").select("client_id, permissions").eq("client_id", finalTeacherId).maybeSingle();
  if (teacherError || !teacher) {
    return new Response(JSON.stringify({ success: false, message: "❌ المدرس غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const teacherPerms = teacher.permissions || {};
  if (teacherPerms.can_manage_assistants === false) {
    return new Response(JSON.stringify({ success: false, message: "⛔ باقتك الحالية لا تسمح بإضافة مساعدين، تواصل مع الإدارة" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ عدد المساعدين بقى غير محدود (Aug 2026) — العمود max_assistants لسه موجود في الجدول لأسباب توافق تاريخية بس مش بيتقرأ أو يتكتب هنا خالص

  const { data: existing } = await supabase.from("assistants").select("id").eq("username", username).maybeSingle();
  if (existing) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ اسم المستخدم "${username}" مأخوذ بالفعل` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let tempPassword = "";
  for (let i = 0; i < 8; i++) tempPassword += chars.charAt(Math.floor(Math.random() * chars.length));

  // ✅ (هجرة Supabase Auth) بنسجّل الصف الأول عشان ناخد الـid (المعرّف الحقيقي المستخدم في كل
  // مكان تاني زي assistants.id)، وبعدين ننشئ حساب Supabase Auth بـsub = نفس الـid ده، وأخيراً
  // نحدّث الصف بالـauth_user_id الراجع
  const { data, error } = await supabase.from("assistants").insert({
    teacher_id: finalTeacherId, username, name, must_change_password: true, is_active: true,
    permissions: permissions || {
      view_students: true, add_students: false, edit_students: false, delete_students: false,
      record_grades: false, record_payments: false, view_reports: false,
      manage_attendance: false, manage_groups: false, reset_parent_password: false,
      manage_books: false, send_messages: false, manage_conversations: false, manage_exams: false,
      view_financial: false, view_activity_log: false, view_staff: false,
      add_staff: false, edit_staff: false, delete_staff: false,
    }
  }).select();

  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const newAssistantId = data[0]?.id;
  try {
    const authUserId = await provisionAuthUser({
      email: syntheticEmailFor("assistant", username),
      password: tempPassword,
      appMetadata: { role: "assistant", teacherId: finalTeacherId, username, sub: String(newAssistantId), name },
    });
    await supabase.from("assistants").update({ auth_user_id: authUserId }).eq("id", newAssistantId);
    data[0].auth_user_id = authUserId;
  } catch (provisionError) {
    // ✅ تراجع: لو فشل إنشاء حساب الدخول، نمسح الصف اللي اتسجّل عشان ميفضلش مساعد من غير حساب دخول خالص
    await supabase.from("assistants").delete().eq("id", newAssistantId);
    const msg = provisionError instanceof Error ? provisionError.message : "⚠️ فشل إنشاء حساب الدخول";
    return new Response(JSON.stringify({ success: false, message: msg }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ Batch 21: لو منفّذ الإجراء مساعد (add_staff)، نسجّله كمنفّذ فعلي (assistant_id = هو نفسه،
  // performer_role "assistant") بدل ما يتسجّل زي ما لو المدرس نفسه هو اللي عمله — عشان سجل
  // النشاطات يكون دقيق (assistant_id هنا معناها "المساعد المنفّذ"، زي باقي دوال النظام مثل
  // manage-payment، مش "المساعد المضاف" اللي كانت الكود القديم بيسجّله غلط)
  const isAssistantActor = payload.role === "assistant";
  await supabase.from("activity_logs").insert({
    teacher_id: finalTeacherId, assistant_id: isAssistantActor ? payload.sub : null, action_type: "add_assistant",
    entity_type: "assistant", entity_id: data[0]?.id?.toString() || null,
    details: { username, name, permissions: permissions || {} },
    performer_id: isAssistantActor ? payload.sub : finalTeacherId,
    performer_role: isAssistantActor ? "assistant" : "teacher",
    performer_name: payload.name || (isAssistantActor ? "مساعد" : "مدرس"),
  });

  return new Response(JSON.stringify({ success: true, message: `✅ تم إضافة المساعد "${name}" بنجاح`, data: { ...data[0], tempPassword } }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  // ✅ Batch 21: مربوط بصلاحية "تعديل فريق عمل" (edit_staff) بدل الرفض القاطع، مع حماية تصعيد
  // الصلاحيات تحت
  await requireAssistantPermission(payload, "edit_staff");
  const tokenClientId = ownerClientId(payload);
  await requireTeacherPlanPermission(tokenClientId, "can_manage_assistants");
  const { assistantId, name, isActive, permissions } = body;
  await assertNoPermissionEscalation(payload, permissions);

  if (!assistantId || !name) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: oldData, error: fetchError } = await supabase.from("assistants").select("name, is_active, permissions, teacher_id, username").eq("id", assistantId).maybeSingle();
  if (fetchError || !oldData) {
    return new Response(JSON.stringify({ success: false, message: "❌ المساعد غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldData.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بتعديل هذا المساعد" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  // ✅ Batch 23 (بند 1): مساعد معاه صلاحية تعديل فريق العمل ميقدرش يعدّل حسابه هو نفسه بيها —
  // ده بيمنعه يفعّل/يعطّل حسابه أو يغيّر صلاحياته هو بنفسه (assertNoPermissionEscalation بتمنع
  // منح صلاحية أعلى مما هو حاصل عليها، لكن مكانش فيه حماية ضد تعديل صلاحياته الحالية بأي شكل تاني)
  if (payload.role === "assistant" && String(payload.sub) === String(assistantId)) {
    return new Response(JSON.stringify({ success: false, message: "⛔ لا يمكنك تعديل حسابك أنت بنفسك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const updateData = { name, is_active: isActive !== undefined ? isActive : true, permissions: permissions || oldData.permissions };
  const { error } = await supabase.from("assistants").update(updateData).eq("id", assistantId);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const changes: any = {};
  if (oldData.name !== name) changes.name = { old: oldData.name, new: name };
  if (oldData.is_active !== isActive) changes.is_active = { old: oldData.is_active, new: isActive };
  if (JSON.stringify(oldData.permissions) !== JSON.stringify(permissions)) changes.permissions = { old: oldData.permissions, new: permissions };

  // ✅ Batch 21: تسجيل المنفّذ الفعلي (مساعد أو مدرس) بدل ما يتسجّل زي ما لو المدرس دايماً هو المنفّذ
  const isAssistantActor2 = payload.role === "assistant";
  await supabase.from("activity_logs").insert({
    teacher_id: oldData.teacher_id, assistant_id: isAssistantActor2 ? payload.sub : null, action_type: "update_assistant",
    entity_type: "assistant", entity_id: assistantId.toString(),
    details: { username: oldData.username || "غير معروف", changes },
    performer_id: isAssistantActor2 ? payload.sub : oldData.teacher_id,
    performer_role: isAssistantActor2 ? "assistant" : "teacher",
    performer_name: payload.name || (isAssistantActor2 ? "مساعد" : "مدرس"),
  });

  return new Response(JSON.stringify({ success: true, message: "✅ تم تحديث بيانات المساعد" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  // ✅ Batch 21: مربوط بصلاحية "حذف فريق عمل" (delete_staff) بدل الرفض القاطع
  await requireAssistantPermission(payload, "delete_staff");
  const tokenClientId = ownerClientId(payload);
  await requireTeacherPlanPermission(tokenClientId, "can_manage_assistants");
  const { assistantId } = body;

  if (!assistantId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ assistantId مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: assistant, error: fetchError } = await supabase.from("assistants").select("username, name, teacher_id, auth_user_id").eq("id", assistantId).maybeSingle();
  if (fetchError || !assistant) {
    return new Response(JSON.stringify({ success: false, message: "❌ المساعد غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (assistant.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بحذف هذا المساعد" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  // ✅ Batch 23 (بند 1): مساعد معاه صلاحية حذف فريق العمل ميقدرش يحذف حسابه هو نفسه بيها
  if (payload.role === "assistant" && String(payload.sub) === String(assistantId)) {
    return new Response(JSON.stringify({ success: false, message: "⛔ لا يمكنك حذف حسابك أنت بنفسك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error } = await supabase.from("assistants").delete().eq("id", assistantId);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  await deleteAuthUser(assistant.auth_user_id);

  // ✅ Batch 21: تسجيل المنفّذ الفعلي (مساعد أو مدرس) بدل ما يتسجّل زي ما لو المدرس دايماً هو المنفّذ
  const isAssistantActor3 = payload.role === "assistant";
  await supabase.from("activity_logs").insert({
    teacher_id: assistant.teacher_id, assistant_id: isAssistantActor3 ? payload.sub : null, action_type: "delete_assistant",
    entity_type: "assistant", entity_id: assistantId.toString(),
    details: { username: assistant.username, name: assistant.name },
    performer_id: isAssistantActor3 ? payload.sub : assistant.teacher_id,
    performer_role: isAssistantActor3 ? "assistant" : "teacher",
    performer_name: payload.name || (isAssistantActor3 ? "مساعد" : "مدرس"),
  });

  return new Response(JSON.stringify({ success: true, message: "✅ تم حذف المساعد" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

/**
 * ✅ (طلب) لون واجهة خاص بالمساعد نفسه، مستقل عن لون المدرس (الشعار يفضل شعار المدرس زي ما هو).
 * كل مساعد بيقدر يغيّر لونه هو بس — مفيش داعي لصلاحية خاصة، ولا تأثير على أي مساعد تاني.
 */
async function handleUpdateOwnColor(supabase: any, payload: TokenPayload, body: any) {
  if (payload.role !== "assistant") {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه الميزة للمساعد فقط" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { brandColor } = body;
  // ✅ تمرير قيمة فاضية بيرجّع المساعد للون الافتراضي (بدون تخصيص)
  let finalColor: string | null = null;
  if (brandColor) {
    if (!/^#[0-9A-Fa-f]{6}$/.test(brandColor)) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ صيغة اللون غير صحيحة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    finalColor = brandColor;
  }

  const { error } = await supabase.from("assistants").update({ brand_color: finalColor }).eq("id", payload.sub);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  return new Response(JSON.stringify({ success: true, message: "✅ تم تحديث لون الواجهة بنجاح", brandColor: finalColor }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطريقة غير مسموحة" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  try {
    const payload = await verifyToken(req);
    const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
    const supabase = createClient(supabaseUrl, supabaseKey);

    let body: any;
    try { body = await req.json(); }
    catch (_e) {
      return new Response(JSON.stringify({ success: false, message: "الطلب يجب أن يحتوي على JSON صالح" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const action = body.action;
    if (action === "add") return await handleAdd(supabase, payload, body);
    if (action === "update") return await handleUpdate(supabase, payload, body);
    if (action === "delete") return await handleDelete(supabase, payload, body);
    if (action === "updateOwnColor") return await handleUpdateOwnColor(supabase, payload, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
