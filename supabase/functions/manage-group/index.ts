// supabase/functions/manage-group/index.ts
// ✅ دالة موحّدة تجمع create-group + rename-group + delete-group بـ "action" parameter
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, TokenPayload, AuthError, verifyToken, requireTeacherPlanPermission, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

// ✅ (طلب) لو المجموعة وصلت للحد الأقصى لعدد الطلاب (max_students)، لازم نرفض أي عملية إضافة
// أو ربط جديدة ليها. العدد الحالي = الطلاب اللي المجموعة دي مجموعتهم الأساسية (students.group_name)
// + الطلاب المربوطين بيها كمجموعة إضافية (student_group_links) — نفس منطق العدّ المستخدم في
// handleListDetailed بالظبط عشان الرقم المعروض على الكارت يطابق رقم الرفض هنا. مجموعة من غير
// max_students محدد (null/0) = بلا حد أقصى، مفيش رفض.
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

async function handleCreate(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");

  const { clientId, groupName, maxStudents, instructorNameId, levelId } = body;
  if (!clientId || !groupName) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة: clientId, groupName" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (tokenClientId !== clientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: existingGroup, error: checkError } = await supabase.from("groups").select("id").eq("teacher_id", clientId).eq("name", groupName).maybeSingle();
  if (checkError) {
    return new Response(JSON.stringify({ success: false, message: `فشل التحقق من المجموعة: ${checkError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (existingGroup) {
    return new Response(JSON.stringify({ success: false, message: `المجموعة "${groupName}" موجودة مسبقاً` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const normalizedMax = (maxStudents === "" || maxStudents === null || maxStudents === undefined) ? null : Number(maxStudents);
  // ✅ Aug 2026 (Phase I): كل مجموعة ممكن تتبع اسم مدرس معيّن (تاج بدون حساب) — بيستخدم بعدين
  // في تحديد سياق جلسة القارئ ووقت رصد الحضور/الدرجات/المدفوعات تلقائياً
  const normalizedInstructorId = (instructorNameId === "" || instructorNameId === null || instructorNameId === undefined) ? null : Number(instructorNameId);
  if (normalizedInstructorId !== null) {
    const { data: instructorRow } = await supabase.from("instructor_names").select("id").eq("id", normalizedInstructorId).eq("teacher_id", clientId).maybeSingle();
    if (!instructorRow) {
      return new Response(JSON.stringify({ success: false, message: "❌ اسم المدرس غير موجود أو غير تابع لحسابك" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }
  // ✅ (المرحلة الدراسية) كل مجموعة ممكن تتبع مرحلة دراسية — متاحة لكل المدرسين مش بس السنتر،
  // بتستخدم بعدين وقت التسجيل العام عشان ولي الأمر يختار مرحلة بدل ما يختار مجموعة مباشرة
  const normalizedLevelId = (levelId === "" || levelId === null || levelId === undefined) ? null : Number(levelId);
  if (normalizedLevelId !== null) {
    const { data: levelRow } = await supabase.from("education_levels").select("id").eq("id", normalizedLevelId).eq("teacher_id", clientId).maybeSingle();
    if (!levelRow) {
      return new Response(JSON.stringify({ success: false, message: "❌ المرحلة الدراسية غير موجودة أو غير تابعة لحسابك" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }
  const { data: newGroup, error: insertError } = await supabase.from("groups").insert({ teacher_id: clientId, name: groupName, max_students: normalizedMax, instructor_name_id: normalizedInstructorId, level_id: normalizedLevelId }).select().single();
  if (insertError) {
    return new Response(JSON.stringify({ success: false, message: `فشل إنشاء المجموعة: ${insertError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  await supabase.from("activity_logs").insert({
    client_id: clientId, teacher_id: clientId, action_type: "create_group", entity_type: "group", entity_id: String(newGroup.id),
    details: { group_name: groupName }, performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
  });

  return new Response(JSON.stringify({ success: true, message: `تم إنشاء المجموعة "${groupName}" بنجاح`, data: newGroup }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleRename(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");

  const { clientId, oldName, newName } = body;
  if (!clientId || !oldName || !newName) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة: clientId, oldName, newName" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (tokenClientId !== clientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldName === newName) {
    return new Response(JSON.stringify({ success: true, message: "لا توجد تغييرات في اسم المجموعة" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: group, error: groupError } = await supabase.from("groups").select("id").eq("teacher_id", clientId).eq("name", oldName).maybeSingle();
  if (groupError) console.error("❌ خطأ في البحث عن المجموعة في groups:", groupError);

  const { data: students, error: studentsError } = await supabase.from("students").select("id").eq("teacher_id", clientId).eq("group_name", oldName);
  if (studentsError) console.error("❌ خطأ في جلب الطلاب:", studentsError);

  if (!group && (!students || students.length === 0)) {
    return new Response(JSON.stringify({ success: false, message: `المجموعة "${oldName}" غير موجودة` }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  let groupUpdated = false;
  let studentsAffected = 0;

  if (group) {
    const { error: updateGroupError } = await supabase.from("groups").update({ name: newName }).eq("id", group.id);
    if (updateGroupError) console.error("❌ فشل تحديث groups:", updateGroupError);
    else groupUpdated = true;
  }

  if (students && students.length > 0) {
    const { error: updateStudentsError } = await supabase.from("students").update({ group_name: newName }).eq("teacher_id", clientId).eq("group_name", oldName);
    if (updateStudentsError) console.error("❌ فشل تحديث students:", updateStudentsError);
    else studentsAffected = students.length;
  }

  await supabase.from("activity_logs").insert({
    client_id: tokenClientId, teacher_id: tokenClientId, action_type: "rename_group", entity_type: "group",
    details: { old_name: oldName, new_name: newName }, performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
  });

  return new Response(JSON.stringify({ success: true, message: `تم تغيير اسم المجموعة من "${oldName}" إلى "${newName}"`, data: { oldName, newName, studentsAffected, groupUpdated } }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");

  const { clientId, groupName } = body;
  if (!clientId || !groupName) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة: clientId, groupName" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (tokenClientId !== clientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: students, error: fetchStudentsError } = await supabase.from("students").select("name, uid, parent_phone").eq("teacher_id", clientId).eq("group_name", groupName);
  if (fetchStudentsError) {
    return new Response(JSON.stringify({ success: false, message: `فشل جلب الطلاب: ${fetchStudentsError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (students && students.length > 0) {
    const { error: deleteStudentsError } = await supabase.from("students").delete().eq("teacher_id", clientId).eq("group_name", groupName);
    if (deleteStudentsError) {
      return new Response(JSON.stringify({ success: false, message: `فشل حذف الطلاب: ${deleteStudentsError.message}` }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const studentUids = students.map((s: any) => s.uid);
    if (studentUids.length > 0) {
      await supabase.from("system_cards").update({ student_uid: null, linked_at: null }).in("student_uid", studentUids);
    }

    const parentPhones = [...new Set(students.map((s: any) => s.parent_phone).filter(Boolean))];
    for (const phone of parentPhones) {
      const { count: remainingCount } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("parent_phone", phone);
      if (!remainingCount || remainingCount === 0) await supabase.from("parents").delete().eq("phone", phone);
    }
  }

  const { error: deleteGroupError } = await supabase.from("groups").delete().eq("teacher_id", clientId).eq("name", groupName);
  if (deleteGroupError) console.error("❌ فشل حذف المجموعة من groups:", deleteGroupError);

  const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", clientId);
  await supabase.from("teachers").update({ student_count: count }).eq("client_id", clientId);

  await supabase.from("activity_logs").insert({
    client_id: clientId, teacher_id: clientId, action_type: "delete_group", entity_type: "group",
    details: { group_name: groupName, students_deleted: students?.length || 0 },
    performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
  });

  return new Response(JSON.stringify({ success: true, message: `تم حذف المجموعة "${groupName}" و ${students?.length || 0} طالب`, data: { groupName, studentsDeleted: students?.length || 0 } }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleSetCapacity(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");

  const { clientId, groupName, maxStudents } = body;
  if (!clientId || !groupName) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة: clientId, groupName" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (tokenClientId !== clientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const normalizedMax = (maxStudents === "" || maxStudents === null || maxStudents === undefined) ? null : Number(maxStudents);

  // ✅ بعض المجموعات القديمة اتعملت بس من خلال group_name على الطلاب، من غير صف في جدول groups —
  // لو مفيش صف، بننشئه دلوقتي عشان نقدر نحفظ الحد الأقصى
  const { data: existingGroup } = await supabase.from("groups").select("id").eq("teacher_id", clientId).eq("name", groupName).maybeSingle();

  if (existingGroup) {
    const { error: updateError } = await supabase.from("groups").update({ max_students: normalizedMax }).eq("id", existingGroup.id);
    if (updateError) {
      return new Response(JSON.stringify({ success: false, message: `فشل تحديث الحد الأقصى: ${updateError.message}` }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  } else {
    const { error: insertError } = await supabase.from("groups").insert({ teacher_id: clientId, name: groupName, max_students: normalizedMax });
    if (insertError) {
      return new Response(JSON.stringify({ success: false, message: `فشل حفظ الحد الأقصى: ${insertError.message}` }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  return new Response(JSON.stringify({ success: true, message: normalizedMax ? `تم تحديد الحد الأقصى بـ ${normalizedMax} طالب` : "تم إلغاء الحد الأقصى" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleListDetailed(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  const { clientId } = body;
  if (clientId && clientId !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: groupRows, error: groupsError } = await supabase.from("groups").select("id, name, max_students, instructor_name_id, level_id").eq("teacher_id", tokenClientId);
  if (groupsError) {
    return new Response(JSON.stringify({ success: false, message: `فشل جلب المجموعات: ${groupsError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: students, error: studentsError } = await supabase.from("students").select("group_name").eq("teacher_id", tokenClientId).not("group_name", "is", null);
  if (studentsError) {
    return new Response(JSON.stringify({ success: false, message: `فشل جلب الطلاب: ${studentsError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ (طلب) الطالب المربوط بمجموعة إضافية (تعدد المواد/المدرسين، student_group_links) لازم يتحسب
  // في عدد طلاب المجموعة دي كمان — قبل كده كان العدد بيتحسب من group_name الأساسي بس، فالطالب
  // المربوط ما كانش "بيظهر" في المجموعة اللي اتربط بيها من ناحية العدد المعروض على الكارت
  const { data: groupLinks, error: groupLinksError } = await supabase
    .from("student_group_links").select("group_name").eq("teacher_id", tokenClientId);
  if (groupLinksError) {
    return new Response(JSON.stringify({ success: false, message: `فشل جلب روابط المجموعات: ${groupLinksError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ Aug 2026 (Phase I): اسم المدرس التابعة له كل مجموعة (لو محدد) — بنجيب أسماء المدرسين
  // بتاعة السنتر مرة واحدة ونربطهم يدوياً بدل embed، عشان يفضل نفس أسلوب الكود في باقي المشروع
  const instructorIds = [...new Set((groupRows || []).map((g: any) => g.instructor_name_id).filter((id: any) => id !== null && id !== undefined))];
  let instructorById: Record<number, string> = {};
  if (instructorIds.length > 0) {
    const { data: instructors } = await supabase.from("instructor_names").select("id, name").in("id", instructorIds);
    (instructors || []).forEach((i: any) => { instructorById[i.id] = i.name; });
  }

  // ✅ (المرحلة الدراسية) نفس أسلوب instructorById بالظبط — بنجيب أسماء المراحل مرة واحدة
  // ونربطها يدوياً بدل embed، عشان يفضل نفس أسلوب الكود في باقي المشروع
  const levelIds = [...new Set((groupRows || []).map((g: any) => g.level_id).filter((id: any) => id !== null && id !== undefined))];
  let levelById: Record<number, string> = {};
  if (levelIds.length > 0) {
    const { data: levels } = await supabase.from("education_levels").select("id, name").in("id", levelIds);
    (levels || []).forEach((l: any) => { levelById[l.id] = l.name; });
  }

  const countByGroup: Record<string, number> = {};
  (students || []).forEach((s: any) => { countByGroup[s.group_name] = (countByGroup[s.group_name] || 0) + 1; });
  (groupLinks || []).forEach((l: any) => { countByGroup[l.group_name] = (countByGroup[l.group_name] || 0) + 1; });

  const groupByName: Record<string, any> = {};
  (groupRows || []).forEach((g: any) => { groupByName[g.name] = g; });

  const allNames = [...new Set([...Object.keys(countByGroup), ...Object.keys(groupByName)])].sort();
  const data = allNames.map((name) => {
    const g = groupByName[name];
    return {
      id: g?.id ?? null,
      name,
      studentCount: countByGroup[name] || 0,
      maxStudents: g?.max_students ?? null,
      instructorNameId: g?.instructor_name_id ?? null,
      instructorName: g?.instructor_name_id ? (instructorById[g.instructor_name_id] || null) : null,
      levelId: g?.level_id ?? null,
      levelName: g?.level_id ? (levelById[g.level_id] || null) : null,
    };
  });

  return new Response(JSON.stringify({ success: true, data }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ Aug 2026 (Phase I): ربط مجموعة باسم مدرس (تاج) — كل عملية في سياق المجموعة دي بتاخده تلقائياً
// ============================================
async function handleAssignInstructor(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");

  const { groupName, instructorNameId } = body;
  if (!groupName) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ اسم المجموعة مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const normalizedId = (instructorNameId === "" || instructorNameId === null || instructorNameId === undefined) ? null : Number(instructorNameId);
  if (normalizedId !== null) {
    const { data: instructorRow } = await supabase.from("instructor_names").select("id").eq("id", normalizedId).eq("teacher_id", tokenClientId).maybeSingle();
    if (!instructorRow) {
      return new Response(JSON.stringify({ success: false, message: "❌ اسم المدرس غير موجود أو غير تابع لحسابك" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  const { data: existing } = await supabase.from("groups").select("id").eq("teacher_id", tokenClientId).eq("name", groupName).maybeSingle();
  if (!existing) {
    // ✅ زي setCapacity بالظبط — بعض المجموعات القديمة اتعملت بس من خلال group_name على الطلاب
    const { error: createError } = await supabase.from("groups").insert({ teacher_id: tokenClientId, name: groupName, instructor_name_id: normalizedId });
    if (createError) {
      return new Response(JSON.stringify({ success: false, message: createError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  } else {
    const { error: updateError } = await supabase.from("groups").update({ instructor_name_id: normalizedId }).eq("id", existing.id);
    if (updateError) {
      return new Response(JSON.stringify({ success: false, message: updateError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  return new Response(JSON.stringify({ success: true, message: normalizedId ? `✅ تم ربط المجموعة "${groupName}" بالمدرس المحدد` : `✅ تم إلغاء ربط المجموعة "${groupName}" بأي مدرس` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ (المرحلة الدراسية) ربط مجموعة بمرحلة دراسية — نفس شكل handleAssignInstructor بالظبط،
// بس متاحة لكل المدرسين مش بس السنتر
// ============================================
async function handleAssignLevel(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");

  const { groupName, levelId } = body;
  if (!groupName) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ اسم المجموعة مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const normalizedId = (levelId === "" || levelId === null || levelId === undefined) ? null : Number(levelId);
  if (normalizedId !== null) {
    const { data: levelRow } = await supabase.from("education_levels").select("id").eq("id", normalizedId).eq("teacher_id", tokenClientId).maybeSingle();
    if (!levelRow) {
      return new Response(JSON.stringify({ success: false, message: "❌ المرحلة الدراسية غير موجودة أو غير تابعة لحسابك" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  const { data: existing } = await supabase.from("groups").select("id").eq("teacher_id", tokenClientId).eq("name", groupName).maybeSingle();
  if (!existing) {
    // ✅ زي setCapacity/assignInstructor بالظبط — بعض المجموعات القديمة اتعملت بس من خلال group_name على الطلاب
    const { error: createError } = await supabase.from("groups").insert({ teacher_id: tokenClientId, name: groupName, level_id: normalizedId });
    if (createError) {
      return new Response(JSON.stringify({ success: false, message: createError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  } else {
    const { error: updateError } = await supabase.from("groups").update({ level_id: normalizedId }).eq("id", existing.id);
    if (updateError) {
      return new Response(JSON.stringify({ success: false, message: updateError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  return new Response(JSON.stringify({ success: true, message: normalizedId ? `✅ تم ربط المجموعة "${groupName}" بالمرحلة الدراسية المحددة` : `✅ تم إلغاء ربط المجموعة "${groupName}" بأي مرحلة دراسية` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ Aug 2026 (Phase I): طالب واحد ممكن يتابع أكتر من مجموعة (تعدد المواد/المدرسين)
// المجموعة الأساسية تفضل students.group_name — دي روابط إضافية بس
// ============================================
async function handleLinkStudentToGroup(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");

  const { studentUid, groupName } = body;
  if (!studentUid || !groupName) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid و groupName مطلوبين" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: student } = await supabase.from("students").select("uid, group_name").eq("uid", studentUid).eq("teacher_id", tokenClientId).maybeSingle();
  if (!student) {
    return new Response(JSON.stringify({ success: false, message: "❌ الطالب غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (student.group_name === groupName) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب أصلاً في المجموعة دي كمجموعة أساسية" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const capacity = await checkGroupCapacity(supabase, tokenClientId, groupName);
  if (!capacity.ok) {
    return new Response(JSON.stringify({ success: false, message: capacity.message }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error } = await supabase.from("student_group_links").insert({ student_uid: studentUid, teacher_id: tokenClientId, group_name: groupName });
  if (error) {
    if (error.code === "23505") {
      return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب مربوط بالمجموعة دي بالفعل" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  return new Response(JSON.stringify({ success: true, message: `✅ تم ربط الطالب بمجموعة "${groupName}" إضافية` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleUnlinkStudentFromGroup(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");

  const { linkId } = body;
  if (!linkId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ linkId مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: link } = await supabase.from("student_group_links").select("teacher_id").eq("id", linkId).maybeSingle();
  if (!link || link.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بحذف الربط ده" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error } = await supabase.from("student_group_links").delete().eq("id", linkId);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  return new Response(JSON.stringify({ success: true, message: "✅ تم إلغاء الربط" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleListStudentGroupLinks(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  const { studentUid, groupName } = body;

  let query = supabase.from("student_group_links").select("*").eq("teacher_id", tokenClientId);
  if (studentUid) query = query.eq("student_uid", studentUid);
  if (groupName) query = query.eq("group_name", groupName);

  const { data, error } = await query.order("created_at", { ascending: true });
  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  return new Response(JSON.stringify({ success: true, data: data || [] }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    let body: any;
    try { body = await req.json(); }
    catch (_e) {
      return new Response(JSON.stringify({ success: false, message: "الطلب يجب أن يحتوي على JSON صالح" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const action = body.action;
    if (action === "create") return await handleCreate(supabase, payload, body);
    if (action === "rename") return await handleRename(supabase, payload, body);
    if (action === "delete") return await handleDelete(supabase, payload, body);
    if (action === "setCapacity") return await handleSetCapacity(supabase, payload, body);
    if (action === "listDetailed") return await handleListDetailed(supabase, payload, body);
    if (action === "assignInstructor") return await handleAssignInstructor(supabase, payload, body);
    if (action === "assignLevel") return await handleAssignLevel(supabase, payload, body);
    if (action === "linkStudentToGroup") return await handleLinkStudentToGroup(supabase, payload, body);
    if (action === "unlinkStudentFromGroup") return await handleUnlinkStudentFromGroup(supabase, payload, body);
    if (action === "listStudentGroupLinks") return await handleListStudentGroupLinks(supabase, payload, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة — لازم تكون create أو rename أو delete أو setCapacity أو listDetailed أو assignInstructor أو assignLevel أو linkStudentToGroup أو unlinkStudentFromGroup أو listStudentGroupLinks" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في manage-group:", error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
