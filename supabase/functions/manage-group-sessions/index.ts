import { corsHeaders, verifyToken } from "../_shared/auth.ts";
// supabase/functions/manage-group-sessions/index.ts
// ✅ Aug 2026 (Phase I follow-up 10): إدارة "الحصص اليومية" الجديدة — بديل نظام
// الحصص الأسبوعي المتكرر القديم (group_sessions) اللي اتلغى بالكامل.
// كل حصة بتتنشئ فعلياً لحظة بدء تسجيل الحضور (قارئ كروت أو يدوي)، وبتتسجّل
// بتاريخ إنشائها، ومتاحة للاختيار في تسجيل الحضور بس في نفس يوم إنشائها.
// action: create | listToday | updateThreshold | history | rosterForSession | delete
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/** تاريخ النهاردة بتوقيت القاهرة كـ YYYY-MM-DD (نفس المعيار المستخدم في باقي المشروع لمقارنة أعمدة date) */
function cairoToday(): string {
  const cairoNow = new Date(new Date().toLocaleString("en-US", { timeZone: "Africa/Cairo" }));
  return cairoNow.toISOString().split("T")[0];
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const body = await req.json();
    const action = body.action;
    const today = cairoToday();

    // ✅ إنشاء حصة جديدة (بتاريخ النهاردة تلقائياً) — بتحصل لحظة بدء تسجيل الحضور
    if (action === "create") {
      const { groupName, sessionLabel, absenceThresholdMinutes, instructorNameId, durationMinutes } = body;
      if (!groupName || !sessionLabel) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ اسم المجموعة واسم الحصة مطلوبان" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      let instructorName: string | null = null;
      let validInstructorId: number | null = null;
      if (instructorNameId) {
        const { data: instructorRow } = await supabase
          .from("instructor_names").select("id, name").eq("id", instructorNameId).eq("teacher_id", tokenClientId).maybeSingle();
        if (instructorRow) { instructorName = instructorRow.name; validInstructorId = instructorRow.id; }
      }
      const threshold = Number(absenceThresholdMinutes) > 0 ? Number(absenceThresholdMinutes) : 30;
      // ✅ Batch 23 (بند 10): مدة الحصة — اختيارية. لو محددة، بتستخدم في الفرونت إند لتحديد هل
      // الحصة "شغالة دلوقتي" بدل الاعتماد على عتبة احتساب الغياب بس (اللي أصلاً غرضها تاني —
      // تحديد آخر وقت يُحسب فيه غياب الطالب اللي معملش حضور، مش وقت انتهاء الحصة نفسها)
      const duration = Number(durationMinutes) > 0 ? Number(durationMinutes) : null;

      const { data, error } = await supabase.from("attendance_sessions").insert({
        teacher_id: tokenClientId, group_name: groupName, session_label: sessionLabel,
        instructor_name_id: validInstructorId, instructor_name: instructorName,
        absence_threshold_minutes: threshold, duration_minutes: duration, session_date: today,
        created_by_role: payload.role, created_by_id: payload.sub, created_by_name: payload.name || null,
      }).select().single();
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم إنشاء الحصة", data }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ الحصص اللي اتنشأت النهاردة — دي اللي بتظهر في قوائم الاختيار عند تفعيل القارئ أو
    // الحضور اليدوي (زي ما طلب المستخدم بالظبط). لو groupName محدد بيفلتر عليها بس، وإلا
    // بيرجّع كل حصص النهاردة (لعرضها في ودجت "حصص اليوم" في لوحة التحكم)
    if (action === "listToday") {
      const { groupName } = body;
      let query = supabase.from("attendance_sessions").select("*")
        .eq("teacher_id", tokenClientId).eq("session_date", today).order("created_at", { ascending: false });
      if (groupName) query = query.eq("group_name", groupName);
      const { data, error } = await query;
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, data: data || [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ تعديل عتبة احتساب الغياب لحصة موجودة بالفعل من نفس اليوم فقط
    if (action === "updateThreshold") {
      const { sessionId, absenceThresholdMinutes } = body;
      if (!sessionId || !(Number(absenceThresholdMinutes) > 0)) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ بيانات غير مكتملة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: existing } = await supabase.from("attendance_sessions").select("teacher_id, session_date").eq("id", sessionId).maybeSingle();
      if (!existing || existing.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بتعديل هذه الحصة" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (existing.session_date !== today) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ لا يمكن تعديل حصة من يوم سابق" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { error } = await supabase.from("attendance_sessions")
        .update({ absence_threshold_minutes: Number(absenceThresholdMinutes) }).eq("id", sessionId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم تحديث مدة احتساب الغياب" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ سجل كل حصص مجموعة معيّنة عبر كل الأيام (لعرضها/طباعتها من صفحة المجموعات)
    if (action === "history") {
      const { groupName } = body;
      if (!groupName) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ اسم المجموعة مطلوب" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data, error } = await supabase.from("attendance_sessions").select("*")
        .eq("teacher_id", tokenClientId).eq("group_name", groupName)
        .order("session_date", { ascending: false }).order("created_at", { ascending: false });
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, data: data || [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ سجل حضور/غياب حصة معيّنة (لكل طلاب المجموعة) — لعرضه أو طباعته
    if (action === "rosterForSession") {
      const { sessionId } = body;
      if (!sessionId) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ sessionId مطلوب" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: session } = await supabase.from("attendance_sessions").select("*").eq("id", sessionId).maybeSingle();
      if (!session || session.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بعرض هذه الحصة" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      // ✅ (طلب) دفعة 44: كان بيجيب بس الطلاب اللي المجموعة دي أساسية عندهم — الطلاب المربوطين
      // بيها كمجموعة ثانوية (تعدد مواد/مدرسين عن طريق student_group_links) مكانوش بيظهروا
      // في سجل الحصة خالص، فلو غالبية أو كل طلاب الحصة مربوطين بيها كثانوية، السجل كان بيطلع
      // فاضي تماماً رغم وجود حضور/غياب مسجل فعلاً على الحصة دي
      const { data: primaryStudents } = await supabase
        .from("students").select("uid, name").eq("teacher_id", tokenClientId).eq("group_name", session.group_name);
      const { data: secondaryLinks } = await supabase
        .from("student_group_links").select("student_uid").eq("group_name", session.group_name);
      const secondaryUids = (secondaryLinks || []).map((l: any) => l.student_uid);
      let secondaryStudents: any[] = [];
      if (secondaryUids.length > 0) {
        const { data } = await supabase
          .from("students").select("uid, name").eq("teacher_id", tokenClientId).in("uid", secondaryUids);
        secondaryStudents = data || [];
      }

      const { data: attendanceRows } = await supabase
        .from("attendance").select("student_uid, student_name, time, status, is_absent, is_manual").eq("session_id", sessionId);

      const studentMap: Record<string, { uid: string; name: string }> = {};
      [...(primaryStudents || []), ...secondaryStudents].forEach((s: any) => { studentMap[s.uid] = s; });
      // ✅ شبكة أمان إضافية: أي طالب ليه صف حضور/غياب فعلي مسجّل على الحصة دي بالذات، لازم
      // يظهر في السجل حتى لو مش موجود في أي من الاستعلامين فوق لأي سبب (تغيير مجموعة بعد
      // الحصة، بيانات قديمة، إلخ) — بنستخدم اسمه المحفوظ وقت التسجيل (student_name) كبديل
      (attendanceRows || []).forEach((a: any) => {
        if (!studentMap[a.student_uid]) {
          studentMap[a.student_uid] = { uid: a.student_uid, name: a.student_name || a.student_uid };
        }
      });

      const attendanceByUid: Record<string, any> = {};
      (attendanceRows || []).forEach((a: any) => { attendanceByUid[a.student_uid] = a; });

      const roster = Object.values(studentMap).map((s: any) => {
        const att = attendanceByUid[s.uid];
        return {
          uid: s.uid, name: s.name,
          present: !!att && !att.is_absent,
          time: att?.time || null,
          isManual: att?.is_manual || false,
        };
      });

      return new Response(JSON.stringify({ success: true, session, data: roster }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ حذف حصة — بس لو من نفس اليوم ومفيهاش حضور مسجّل عليها (حماية من فقدان بيانات)
    if (action === "delete") {
      const { sessionId } = body;
      if (!sessionId) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ sessionId مطلوب" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: existing } = await supabase.from("attendance_sessions").select("teacher_id, session_date").eq("id", sessionId).maybeSingle();
      if (!existing || existing.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بحذف هذه الحصة" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (existing.session_date !== today) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ لا يمكن حذف حصة من يوم سابق" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { count } = await supabase.from("attendance").select("id", { count: "exact", head: true }).eq("session_id", sessionId);
      if (count && count > 0) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ لا يمكن حذف حصة تم تسجيل حضور فيها بالفعل" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { error } = await supabase.from("attendance_sessions").delete().eq("id", sessionId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم حذف الحصة" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
