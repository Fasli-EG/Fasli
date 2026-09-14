// supabase/functions/admin-manage-teacher/index.ts
// ✅ دالة موحّدة تجمع admin-add-teacher + admin-update-teacher + admin-delete-teacher بـ "action" parameter
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, TokenPayload, AuthError, verifyToken, requireAdmin, authErrorResponse } from "../_shared/auth.ts";
import { provisionAuthUser, deleteAuthUser, syntheticEmailFor } from "../_shared/authProvision.ts";

// ============================================
// ⭐ العملية 1: إضافة مدرس (منطق admin-add-teacher الأصلي كامل)
// ============================================
async function handleAdd(supabase: any, body: any) {
  const { clientId, name, expiryDate, maxStudents, permissions, isCenter } = body;
  if (!clientId || !name) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (clientId === "master_admin") {
    return new Response(JSON.stringify({ success: false, message: "⛔ لا يمكن إضافة حساب المشرف الرئيسي" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  // ✅ (هجرة Supabase Auth) الكود بيتحط كباسورد افتراضي للمدرس، وSupabase Auth بيرفض أي باسورد
  // أقل من 6 حروف — لازم نتحقق هنا بدل ما يوصل الرفض في شكل خطأ 500 غامض وقت الإنشاء
  if (clientId.length < 6) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الكود لازم يكون 6 حروف/أرقام على الأقل (بيُستخدم كباسورد مبدئي للمدرس)" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: existing } = await supabase.from("teachers").select("client_id").eq("client_id", clientId).maybeSingle();
  if (existing) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ هذا الكود موجود بالفعل" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const finalExpiryDate = expiryDate || null;
  const deviceSecretBytes = crypto.getRandomValues(new Uint8Array(16));
  const deviceSecret = Array.from(deviceSecretBytes).map((b) => b.toString(16).padStart(2, "0")).join("");

  // ✅ (هجرة Supabase Auth) الباسورد الافتراضي لسه نفس الكود نفسه زي ما كان دايماً —
  // بس دلوقتي بيتخزّن كحساب Supabase Auth حقيقي بدل هاش يدوي، وmust_change_password بيفرض تغييره فوراً
  const authUserId = await provisionAuthUser({
    email: syntheticEmailFor("teacher", clientId),
    password: clientId,
    appMetadata: { role: "teacher", clientId, sub: clientId, name, isAdmin: false },
  });

  const { data, error } = await supabase.from("teachers").insert({
    client_id: clientId, name, auth_user_id: authUserId, must_change_password: true, is_active: true,
    expiry_date: finalExpiryDate, max_students: maxStudents || 0,
    // ✅ عدد المساعدين غير محدود من Aug 2026 — max_assistants لم يعد يُكتب هنا
    student_count: 0, device_secret: deviceSecret,
    // ✅ Aug 2026 (تعديل جوهري): بدل ما يكون السنتر حساب منفصل بجدول centers خاص،
    // بقى مجرد مدرس عادي عليه العلامة دي — بتفتحله إدارة "أسماء مدرسين" (تاجات بدون تسجيل دخول)
    is_center: isCenter === true,
    // ✅ Aug 2026 (تصحيح): بعد مراجعة الطلب — مفيش نظام صلاحيات جزئي للمدرس خالص من دلوقتي.
    // كل مدرس بيتضاف بكل الصلاحيات مفعّلة تلقائياً في النظام، من غير ما الماستر يحتاج يحدد حاجة.
    // (كروت الصلاحيات اتشالت من الواجهة، وأي permissions مبعوتة من الفورم بتتجاهل هنا عمداً)
    permissions: {
      can_manage_students: true, can_manage_groups: true, can_manage_grades: true, can_manage_payments: true,
      can_manage_books: true, can_send_messages: true, can_view_reports: true, can_view_financial: true,
      can_use_backup: true, can_manage_assistants: true, can_use_rfid: true,
      // ✅ Aug 2026 (تصحيح): can_create_exams كان ناقص من هنا من الأساس — أي مدرس جديد كان
      // بيتضاف من غيرها فعلياً، فأي أكشن في manage-exam (إنشاء/تعديل/نشر/حذف اختبار إلكتروني)
      // كان بيرجع 403 دايماً بغض النظر عن نية "كل الصلاحيات مفعّلة تلقائياً" المذكورة فوق
      can_create_exams: true,
    }
  }).select();

  if (error) {
    // ✅ تراجع: لو فشل إدخال صف المدرس بعد ما اتعمل له حساب Supabase Auth، لازم نمسح الحساب اليتيم ده
    await deleteAuthUser(authUserId);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  return new Response(JSON.stringify({
    success: true,
    message: `✅ تم إضافة المدرس ${name} بنجاح${finalExpiryDate ? ` (صلاحية حتى ${finalExpiryDate})` : " (صلاحية غير محدودة)"}`,
    data
  }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 2: تعديل مدرس (منطق admin-update-teacher الأصلي كامل)
// ============================================
async function handleUpdate(supabase: any, body: any) {
  const { clientId, name, isActive: isActiveParam, expiryDate, maxStudents, permissions, notes, isCenter } = body;
  if (!clientId || !name) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (clientId === "master_admin") {
    return new Response(JSON.stringify({ success: false, message: "⛔ لا يمكن تعديل حساب المشرف الرئيسي" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  let calculatedIsActive = isActiveParam;
  if (expiryDate) {
    const today = new Date().toISOString().split("T")[0];
    calculatedIsActive = expiryDate >= today;
  }

  const { data: oldTeacher } = await supabase.from("teachers").select("name, is_active, expiry_date, max_students, permissions").eq("client_id", clientId).maybeSingle();

  const updateData: any = {
    name, max_students: maxStudents || 0,
    permissions, notes: notes || null, is_active: calculatedIsActive, expiry_date: expiryDate || null,
    is_center: isCenter === true,
  };

  const { error } = await supabase.from("teachers").update(updateData).eq("client_id", clientId);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: updatedTeacher } = await supabase.from("teachers").select("*").eq("client_id", clientId).maybeSingle();

  const changes: any = {};
  if (oldTeacher) {
    if (oldTeacher.name !== name) changes.name = { old: oldTeacher.name, new: name };
    if (oldTeacher.is_active !== calculatedIsActive) changes.is_active = { old: oldTeacher.is_active, new: calculatedIsActive };
    if (oldTeacher.expiry_date !== (expiryDate || null)) changes.expiry_date = { old: oldTeacher.expiry_date, new: expiryDate || null };
    if (oldTeacher.max_students !== (maxStudents || 0)) changes.max_students = { old: oldTeacher.max_students, new: maxStudents || 0 };
    if (JSON.stringify(oldTeacher.permissions) !== JSON.stringify(permissions)) changes.permissions = { old: oldTeacher.permissions, new: permissions };
  }

  let statusMessage = "✅ تم تحديث بيانات المدرس بنجاح";
  if (expiryDate) {
    const today = new Date().toISOString().split("T")[0];
    if (expiryDate < today) {
      statusMessage += " (⚠️ الترخيص منتهي الصلاحية)";
    } else {
      const daysRemaining = Math.ceil((new Date(expiryDate).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      statusMessage += ` (📅 متبقي ${daysRemaining} يوم)`;
    }
  } else {
    statusMessage += " (♾️ صلاحية غير محدودة)";
  }

  return new Response(JSON.stringify({ success: true, message: statusMessage, data: updatedTeacher || null }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 3: حذف مدرس (منطق admin-delete-teacher الأصلي كامل — بنفس ترتيب الحذف بالظبط)
// ============================================
async function handleDelete(supabase: any, body: any) {
  const { clientId } = body;
  if (!clientId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ clientId مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (clientId === "master_admin") {
    return new Response(JSON.stringify({ success: false, message: "⛔ لا يمكن حذف حساب المشرف الرئيسي" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: teacher } = await supabase.from("teachers").select("client_id, auth_user_id").eq("client_id", clientId).maybeSingle();
  if (!teacher) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ المدرس غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  await supabase.from("grades").delete().eq("teacher_id", clientId);
  await supabase.from("payments").delete().eq("teacher_id", clientId);
  await supabase.from("book_payments").delete().eq("teacher_id", clientId);
  await supabase.from("attendance").delete().eq("teacher_id", clientId);

  // ✅ لازم يتمسحوا هنا صراحةً قبل ما نوصل لحذف teachers تحت — card_action_mode فيه
  // active_session_id بيشاور على attendance_sessions من غير ON DELETE CASCADE على العمود ده،
  // فلو فضل موجود وقت ما الـcascade بتاع teachers يحاول يمسح attendance_sessions هيفشل بخطأ FK
  await supabase.from("card_action_mode").delete().eq("teacher_id", clientId);
  await supabase.from("attendance_sessions").delete().eq("teacher_id", clientId);
  await supabase.from("rfid_scans").delete().eq("client_id", clientId);

  await supabase.from("system_cards").delete().eq("teacher_id", clientId);
  await supabase.from("pending_card_registrations").delete().eq("teacher_id", clientId);

  const { data: students } = await supabase.from("students").select("uid, parent_phone, auth_user_id").eq("teacher_id", clientId);
  await supabase.from("students").delete().eq("teacher_id", clientId);
  for (const s of students || []) await deleteAuthUser(s.auth_user_id);

  const parentPhones = [...new Set((students || []).map((s: any) => s.parent_phone).filter(Boolean))];
  for (const phone of parentPhones) {
    const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("parent_phone", phone);
    if (!count || count === 0) {
      const { data: parent } = await supabase.from("parents").select("auth_user_id").eq("phone", phone).maybeSingle();
      await supabase.from("parents").delete().eq("phone", phone);
      await deleteAuthUser(parent?.auth_user_id);
    }
  }

  const { data: assistants } = await supabase.from("assistants").select("auth_user_id").eq("teacher_id", clientId);
  await supabase.from("assistants").delete().eq("teacher_id", clientId);
  for (const a of assistants || []) await deleteAuthUser(a.auth_user_id);

  await supabase.from("groups").delete().eq("teacher_id", clientId);
  await supabase.from("books").delete().eq("teacher_id", clientId);
  await supabase.from("payment_titles").delete().eq("teacher_id", clientId);
  await supabase.from("exam_titles").delete().eq("teacher_id", clientId);

  await supabase.from("notifications").delete().eq("teacher_id", clientId);
  await supabase.from("push_tokens").delete().eq("recipient_type", "teacher").eq("recipient_id", clientId);
  await supabase.from("activity_logs").delete().eq("teacher_id", clientId);
  // ✅ conversation_messages مفيهاش أي foreign key خالص (عمود teacher_id نص عادي) — لازم
  // تُمسح هنا صراحةً، مفيش cascade على مستوى القاعدة يعملها لوحده
  await supabase.from("conversation_messages").delete().eq("teacher_id", clientId);

  const { error } = await supabase.from("teachers").delete().eq("client_id", clientId);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  await deleteAuthUser(teacher.auth_user_id);

  return new Response(JSON.stringify({ success: true, message: "✅ تم حذف المدرس وجميع بياناته المرتبطة بنجاح" }),
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
    requireAdmin(payload);

    const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
    if (!supabaseKey) throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
    const supabase = createClient(supabaseUrl, supabaseKey);

    let body: any;
    try { body = await req.json(); }
    catch (_e) {
      return new Response(JSON.stringify({ success: false, message: "الطلب يجب أن يحتوي على JSON صالح" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const action = body.action;
    if (action === "add") return await handleAdd(supabase, body);
    if (action === "update") return await handleUpdate(supabase, body);
    if (action === "delete") return await handleDelete(supabase, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة — لازم تكون add أو update أو delete" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
