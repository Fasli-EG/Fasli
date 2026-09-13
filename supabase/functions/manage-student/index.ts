// supabase/functions/manage-student/index.ts
// ============================================
// ✅ دالة موحّدة تجمع add-student + update-student + delete-student في دالة واحدة
// بـ "action" parameter (add | update | delete) — بديل عن 3 دوال منفصلة لتقليل العدد الكلي
// كل منطق الدوال الثلاث الأصلية اتحافظ عليه بالكامل بدون أي تغيير في السلوك
// ============================================
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// ✅ (هجرة Supabase Auth، تصحيح 1.4) الملف ده كان بيعمل تحقق JWT مكرر بمنطقه الخاص بدل ما
// يستورد من _shared/auth.ts زي كل الفانكشنز التانية — بقى موحّد دلوقتي زي الباقي
import { corsHeaders, TokenPayload, AuthError, verifyToken, authErrorResponse, requireTeacherPlanPermission, requireAssistantPermission } from "../_shared/auth.ts";
import { provisionAuthUser, deleteAuthUser, updateAuthUserContact } from "../_shared/authProvision.ts";

// ✅ (طلب) لو المجموعة وصلت للحد الأقصى لعدد الطلاب (max_students)، لازم نرفض أي عملية إضافة
// جديدة ليها. العدد الحالي = الطلاب اللي المجموعة دي مجموعتهم الأساسية (students.group_name)
// + الطلاب المربوطين بيها كمجموعة إضافية (student_group_links) — نفس منطق العدّ المستخدم في
// manage-group's handleListDetailed بالظبط. مجموعة من غير max_students محدد (null/0) = بلا حد
// أقصى، مفيش رفض.
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

async function handleAdd(req: Request, supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId;
  const tokenRole = payload.role;
  const tokenUserId = payload.sub;
  const tokenName = payload.name;

  const { clientId: requestedClientId, groupName, uid, name, phone, parentPhone, assistantName } = body;

  if (!requestedClientId || !groupName || !uid || !name || !parentPhone) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة: clientId, groupName, uid, name, parentPhone" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (tokenRole === "teacher") {
    if (requestedClientId !== tokenClientId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ غير مصرح لك بإضافة طلاب لمدرس آخر" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  } else if (tokenRole === "assistant") {
    const { data: assistant, error: assistantError } = await supabase
      .from("assistants").select("permissions, teacher_id").eq("id", tokenUserId).maybeSingle();
    if (assistantError || !assistant) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ المساعد غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const permissions = assistant.permissions || {};
    if (!permissions.add_students) {
      return new Response(JSON.stringify({ success: false, message: "⛔ ليس لديك صلاحية إضافة طلاب" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (assistant.teacher_id !== requestedClientId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ لا يمكنك إضافة طلاب لهذا المدرس" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  } else if (tokenRole === "parent") {
    return new Response(JSON.stringify({ success: false, message: "⛔ ولي الأمر لا يمكنه إضافة طلاب" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const clientId = tokenRole === "teacher" ? tokenClientId : requestedClientId;
  if (tokenRole !== "parent") await requireTeacherPlanPermission(clientId, "can_manage_students");

  const { data: teacher, error: teacherError } = await supabase
    .from("teachers").select("client_id, name, max_students, student_count").eq("client_id", clientId).single();

  if (teacherError || !teacher) {
    return new Response(JSON.stringify({ success: false, message: "المدرس غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (teacher.max_students > 0 && teacher.student_count >= teacher.max_students) {
    return new Response(JSON.stringify({ success: false, message: `تم الوصول إلى الحد الأقصى للطلاب (${teacher.max_students})` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const capacity = await checkGroupCapacity(supabase, clientId, groupName);
  if (!capacity.ok) {
    return new Response(JSON.stringify({ success: false, message: capacity.message }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: existingStudent } = await supabase.from("students").select("uid").eq("uid", uid).maybeSingle();
  if (existingStudent) {
    return new Response(JSON.stringify({ success: false, message: "UID موجود مسبقاً" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: existingParent } = await supabase.from("parents").select("phone").eq("phone", parentPhone).maybeSingle();
  let tempPassword = "";
  let newParentAuthUserId: string | null = null;

  if (!existingParent) {
    tempPassword = parentPhone;
    const parentName = `ولي أمر ${name}`;
    // ✅ (هجرة Supabase Auth) رقم التليفون الحقيقي بيتسجّل كحقل phone الأصلي في Supabase Auth
    // مع الرقم نفسه كباسورد افتراضي (نفس السلوك القديم بالظبط) — من غير أي SMS
    newParentAuthUserId = await provisionAuthUser({
      phone: parentPhone,
      password: tempPassword,
      appMetadata: { role: "parent", phone: parentPhone, sub: parentPhone, name: parentName },
    });
    const { error: insertParentError } = await supabase
      .from("parents").insert({ phone: parentPhone, name: parentName, auth_user_id: newParentAuthUserId, must_change_password: true, is_active: true });
    if (insertParentError) {
      await deleteAuthUser(newParentAuthUserId);
      return new Response(JSON.stringify({ success: false, message: `فشل إنشاء ولي الأمر: ${insertParentError.message}` }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  const { data: student, error: insertError } = await supabase
    .from("students").insert({ uid, name, phone: phone || null, parent_phone: parentPhone, group_name: groupName, teacher_id: clientId }).select().single();
  if (insertError) {
    // ✅ تراجع: لو فشل إدخال الطالب بعد ما اتعمل حساب ولي أمر جديد له، نمسح الحساب اليتيم ده
    if (newParentAuthUserId) {
      await deleteAuthUser(newParentAuthUserId);
      await supabase.from("parents").delete().eq("phone", parentPhone);
    }
    throw new Error(`فشل إضافة الطالب: ${insertError.message}`);
  }

  const { data: matchingCard } = await supabase
    .from("system_cards").select("id").eq("card_uid", uid).eq("teacher_id", clientId).eq("status", "assigned").eq("is_active", true).is("student_uid", null).maybeSingle();
  if (matchingCard) {
    await supabase.from("system_cards").update({ student_uid: uid, linked_at: new Date().toISOString() }).eq("id", matchingCard.id);
  }

  const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", clientId).is("archived_at", null);
  await supabase.from("teachers").update({ student_count: count }).eq("client_id", clientId);

  const performerId = tokenRole === "assistant" ? tokenUserId : clientId;
  const performerRole = tokenRole === "assistant" ? "assistant" : "teacher";
  const performerName = tokenRole === "assistant" ? (assistantName || tokenName || "مساعد") : (teacher.name || "مدرس");

  await supabase.from("activity_logs").insert({
    client_id: clientId, teacher_id: clientId, assistant_id: tokenRole === "assistant" ? Number(tokenUserId) : null,
    action_type: "add_student", entity_type: "student", entity_id: String(student.id),
    details: { student_id: student.id, student_uid: uid, student_name: name, group_name: groupName, parent_phone: parentPhone, phone: phone || null, temp_password_set: !!tempPassword, performer_name: performerName },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
    ip_address: req.headers.get("x-forwarded-for") || req.headers.get("cf-connecting-ip") || null,
  });

  return new Response(JSON.stringify({ success: true, message: "تم إضافة الطالب بنجاح", data: student, tempPassword, parentExists: !!existingParent }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_students");
  await requireAssistantPermission(payload, "edit_students");

  const { studentId, name, phone, parentPhone, assistantId, assistantName } = body;
  if (!studentId) {
    return new Response(JSON.stringify({ success: false, message: "معرف الطالب مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: oldStudent, error: fetchError } = await supabase.from("students").select("*").eq("id", studentId).maybeSingle();
  if (fetchError || !oldStudent) {
    return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldStudent.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const updates: any = {};
  const changes: any = {};
  if (name !== undefined && name !== oldStudent.name) { updates.name = name; changes.name = { old: oldStudent.name, new: name }; }
  if (phone !== undefined && phone !== oldStudent.phone) { updates.phone = phone || null; changes.phone = { old: oldStudent.phone || "غير محدد", new: phone || "غير محدد" }; }
  const parentPhoneChanged = parentPhone !== undefined && parentPhone !== oldStudent.parent_phone;
  if (parentPhoneChanged) { updates.parent_phone = parentPhone; changes.parent_phone = { old: oldStudent.parent_phone, new: parentPhone }; }

  if (Object.keys(updates).length === 0) {
    return new Response(JSON.stringify({ success: true, message: "لا توجد تغييرات" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  let oldPhone: string | null = null;
  let oldPhoneStillUsedBySiblings = false;
  let reusedOldParentAuthUserId: string | null = null;

  if (parentPhoneChanged) {
    oldPhone = oldStudent.parent_phone;
    if (oldPhone) {
      const { data: siblingsOnOldPhone } = await supabase.from("students").select("id").eq("parent_phone", oldPhone).neq("id", studentId);
      oldPhoneStillUsedBySiblings = (siblingsOnOldPhone || []).length > 0;
    }
    const { data: existingNewParent } = await supabase.from("parents").select("phone").eq("phone", parentPhone).maybeSingle();
    if (!existingNewParent) {
      let sourceMustChange = true;
      let sourceName = `ولي أمر ${oldStudent.name}`;
      let reuseAuthUserId: string | null = null;
      if (oldPhone) {
        const { data: oldParent } = await supabase.from("parents").select("auth_user_id, must_change_password, name").eq("phone", oldPhone).maybeSingle();
        if (oldParent) {
          sourceMustChange = oldParent.must_change_password;
          sourceName = oldParent.name || sourceName;
          // ✅ (هجرة Supabase Auth) لو الرقم القديم مش مستخدَم من إخوة تانيين، فده نفس ولي الأمر
          // وبس غيّر رقمه — نعيد استخدام نفس حساب Supabase Auth بعد تحديث رقمه بدل إنشاء حساب مكرر
          if (oldParent.auth_user_id && !oldPhoneStillUsedBySiblings) reuseAuthUserId = oldParent.auth_user_id;
        }
      }

      let newParentAuthUserId: string;
      if (reuseAuthUserId) {
        await updateAuthUserContact(reuseAuthUserId, {
          phone: parentPhone,
          appMetadata: { role: "parent", phone: parentPhone, sub: parentPhone, name: sourceName },
        });
        newParentAuthUserId = reuseAuthUserId;
        reusedOldParentAuthUserId = reuseAuthUserId;
      } else {
        newParentAuthUserId = await provisionAuthUser({
          phone: parentPhone,
          password: parentPhone,
          appMetadata: { role: "parent", phone: parentPhone, sub: parentPhone, name: sourceName },
        });
      }

      const { error: insertParentError } = await supabase
        .from("parents").insert({ phone: parentPhone, name: sourceName, auth_user_id: newParentAuthUserId, is_active: true, must_change_password: sourceMustChange });
      if (insertParentError) {
        console.error("❌ فشل إنشاء/تجهيز حساب ولي الأمر الجديد:", insertParentError);
        if (!reuseAuthUserId) await deleteAuthUser(newParentAuthUserId);
        return new Response(JSON.stringify({ success: false, message: `فشل تحديث رقم ولي الأمر: ${insertParentError.message}` }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }
  }

  const { data: updatedStudent, error: updateError } = await supabase.from("students").update(updates).eq("id", studentId).select().single();
  if (updateError) {
    console.error("❌ خطأ في تحديث الطالب:", updateError);
    return new Response(JSON.stringify({ success: false, message: `فشل تحديث الطالب: ${updateError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (parentPhoneChanged && oldPhone && oldPhone !== parentPhone && !oldPhoneStillUsedBySiblings) {
    // ✅ لو حسابه اتنقل (renamed) للرقم الجديد بالفعل فوق، محدش يتمسح — غير كده نمسح حساب
    // Supabase Auth اليتيم بتاع الرقم القديم مع صف ولي الأمر نفسه
    const { data: oldParentRow } = await supabase.from("parents").select("auth_user_id").eq("phone", oldPhone).maybeSingle();
    await supabase.from("parents").delete().eq("phone", oldPhone);
    if (oldParentRow?.auth_user_id && oldParentRow.auth_user_id !== reusedOldParentAuthUserId) {
      await deleteAuthUser(oldParentRow.auth_user_id);
    }
  }

  let teacherName = "مدرس";
  if (oldStudent.teacher_id) {
    const { data: teacher, error: teacherError } = await supabase.from("teachers").select("name").eq("client_id", oldStudent.teacher_id).maybeSingle();
    if (!teacherError && teacher) teacherName = teacher.name || "مدرس";
  }

  const performerId = assistantId || oldStudent.teacher_id || "unknown";
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = assistantId ? (assistantName || "مساعد") : teacherName;
  let assistantIdNum = null;
  if (assistantId) assistantIdNum = typeof assistantId === "string" ? parseInt(assistantId) : assistantId;

  await supabase.from("activity_logs").insert({
    client_id: oldStudent.teacher_id, teacher_id: oldStudent.teacher_id, assistant_id: assistantIdNum,
    action_type: "edit_student", entity_type: "student", entity_id: String(studentId),
    details: { student_uid: oldStudent.uid, student_name: oldStudent.name, group_name: oldStudent.group_name, changes },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  return new Response(JSON.stringify({ success: true, message: "تم تحديث بيانات الطالب بنجاح", data: updatedStudent, changes }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  const userRole = payload.role;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_students");
  await requireAssistantPermission(payload, "delete_students");

  const { studentId, assistantId } = body;
  if (!studentId) {
    return new Response(JSON.stringify({ success: false, message: "معرف الطالب مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: student, error: getError } = await supabase.from("students").select("name, uid, teacher_id, parent_phone, auth_user_id").eq("id", studentId).single();
  if (getError || !student) {
    return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (student.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (userRole === "assistant") {
    const { data: assistant, error: assError } = await supabase.from("assistants").select("teacher_id").eq("id", parseInt(assistantId || "0")).maybeSingle();
    if (assError || !assistant || assistant.teacher_id !== tokenClientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بحذف هذا الطالب" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  const { error: deleteError } = await supabase.from("students").delete().eq("id", studentId);
  if (deleteError) throw new Error(`فشل حذف الطالب: ${deleteError.message}`);
  await deleteAuthUser(student.auth_user_id);

  // ✅ إعادة عدّ فعلية بدل زيادة/نقصان تراكمي — بتفضل صحيحة حتى لو الطالب كان مؤرشف بالفعل
  // (يعني مستبعد من العدّاد أصلاً) وقت الحذف النهائي
  const { count: afterDeleteCount } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", student.teacher_id).is("archived_at", null);
  await supabase.from("teachers").update({ student_count: afterDeleteCount }).eq("client_id", student.teacher_id);

  if (student.parent_phone) {
    const { data: remainingSiblings } = await supabase.from("students").select("id").eq("parent_phone", student.parent_phone).limit(1);
    if (!remainingSiblings || remainingSiblings.length === 0) {
      const { data: parentRow } = await supabase.from("parents").select("auth_user_id").eq("phone", student.parent_phone).maybeSingle();
      await supabase.from("parents").delete().eq("phone", student.parent_phone);
      await deleteAuthUser(parentRow?.auth_user_id);
    }
  }

  await supabase.from("system_cards").update({ student_uid: null, linked_at: null }).eq("student_uid", student.uid);

  await supabase.from("activity_logs").insert({
    client_id: student.teacher_id, teacher_id: student.teacher_id, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "delete_student", entity_type: "student", entity_id: String(studentId),
    details: { student_id: studentId, student_name: student.name, student_uid: student.uid },
    performer_id: assistantId || student.teacher_id, performer_role: assistantId ? "assistant" : "teacher",
    performer_name: payload.name || (assistantId ? "مساعد" : "مدرس"),
  });

  return new Response(JSON.stringify({ success: true, message: "تم حذف الطالب بنجاح" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ✅ أرشفة بدل حذف نهائي — بيانات الطالب (درجات/حضور/مدفوعات) بتفضل محفوظة بالكامل،
// الطالب بس بيتشال من القوائم النشطة وعداد الطلاب (وبيتحرر كارته لإعادة الاستخدام)، وممكن استرجاعه في أي وقت.
async function handleArchive(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_students");
  await requireAssistantPermission(payload, "delete_students");

  const { studentId } = body;
  if (!studentId) {
    return new Response(JSON.stringify({ success: false, message: "معرف الطالب مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: student, error: getError } = await supabase.from("students").select("name, uid, teacher_id, archived_at").eq("id", studentId).single();
  if (getError || !student) {
    return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (student.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (student.archived_at) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب ده مؤرشف بالفعل" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  await supabase.from("students").update({ archived_at: new Date().toISOString() }).eq("id", studentId);
  await supabase.from("system_cards").update({ student_uid: null, linked_at: null }).eq("student_uid", student.uid);

  const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", student.teacher_id).is("archived_at", null);
  await supabase.from("teachers").update({ student_count: count }).eq("client_id", student.teacher_id);

  await supabase.from("activity_logs").insert({
    client_id: student.teacher_id, teacher_id: student.teacher_id,
    action_type: "archive_student", entity_type: "student", entity_id: String(studentId),
    details: { student_name: student.name, student_uid: student.uid },
    performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
  });

  return new Response(JSON.stringify({ success: true, message: "✅ تم أرشفة الطالب — بياناته محفوظة وتقدر تسترجعه في أي وقت" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleUnarchive(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_students");
  await requireAssistantPermission(payload, "delete_students");

  const { studentId } = body;
  if (!studentId) {
    return new Response(JSON.stringify({ success: false, message: "معرف الطالب مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: student, error: getError } = await supabase.from("students").select("name, teacher_id, archived_at").eq("id", studentId).single();
  if (getError || !student) {
    return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (student.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (!student.archived_at) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب ده مش مؤرشف أصلاً" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  await supabase.from("students").update({ archived_at: null }).eq("id", studentId);

  const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", student.teacher_id).is("archived_at", null);
  await supabase.from("teachers").update({ student_count: count }).eq("client_id", student.teacher_id);

  await supabase.from("activity_logs").insert({
    client_id: student.teacher_id, teacher_id: student.teacher_id,
    action_type: "unarchive_student", entity_type: "student", entity_id: String(studentId),
    details: { student_name: student.name },
    performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
  });

  return new Response(JSON.stringify({ success: true, message: "✅ تم استرجاع الطالب" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const payload = await verifyToken(req);
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    let body: any;
    try {
      body = await req.json();
    } catch (_e) {
      return new Response(JSON.stringify({ success: false, message: "الطلب يجب أن يحتوي على JSON صالح" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const action = body.action;
    if (action === "add") return await handleAdd(req, supabase, payload, body);
    if (action === "update") return await handleUpdate(supabase, payload, body);
    if (action === "delete") return await handleDelete(supabase, payload, body);
    if (action === "archive") return await handleArchive(supabase, payload, body);
    if (action === "unarchive") return await handleUnarchive(supabase, payload, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة — لازم تكون add أو update أو delete أو archive أو unarchive" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في manage-student:", error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return new Response(JSON.stringify({ success: false, message }),
      { status: message.includes("التوكن") ? 401 : 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
