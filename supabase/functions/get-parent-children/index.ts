// supabase/functions/get-parent-children/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, requireParentPhone, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة"); // ✅ رفض واضح بدل السقوط الصامت لصلاحيات anon
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطريقة غير مسموحة" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  try {
    const payload = await verifyToken(req);
    const { parentPhone } = await req.json();

    if (!parentPhone) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ رقم الهاتف مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // ✅ لازم توكن ولي أمر بنفس رقم الهاتف المطلوب
    requireParentPhone(payload, parentPhone);

    const { data: students, error: studentError } = await supabase
      .from("students").select("uid, name, group_name, teacher_id").eq("parent_phone", parentPhone);

    if (studentError) {
      return new Response(JSON.stringify({ success: false, message: studentError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (!students || students.length === 0) {
      return new Response(JSON.stringify({ success: true, data: [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const today = new Date().toISOString().split("T")[0];
    const result: any[] = [];

    const groupsMap = new Map<string, any[]>();
    students.forEach((s: any) => {
      const group = s.group_name || "بدون مجموعة";
      if (!groupsMap.has(group)) groupsMap.set(group, []);
      groupsMap.get(group)!.push(s);
    });

    const workingDaysCache = new Map<string, Set<string>>();
    const presentDatesByStudent = new Map<string, Set<string>>();

    for (const [groupName, groupStudents] of groupsMap) {
      const uids = groupStudents.map((s: any) => s.uid);
      const { data: attendanceData, error: attError } = await supabase
        .from("attendance").select("date, student_uid").in("student_uid", uids).eq("status", "present").not("date", "is", null);

      if (attError) { console.error(`خطأ في جلب أيام العمل للمجموعة ${groupName}:`, attError); continue; }

      const workingDaysSet = new Set<string>();
      attendanceData?.forEach((record: any) => {
        if (!record.date) return;
        workingDaysSet.add(record.date);
        if (!presentDatesByStudent.has(record.student_uid)) presentDatesByStudent.set(record.student_uid, new Set());
        presentDatesByStudent.get(record.student_uid)!.add(record.date);
      });
      workingDaysCache.set(groupName, workingDaysSet);
    }

    // ✅ دفعة واحدة بدل استعلام منفصل لكل طالب: المدرسين، درجات كل الطلاب، وحضور اليوم لكل الطلاب
    const allUids = students.map((s: any) => s.uid);
    const uniqueTeacherIds = [...new Set(students.map((s: any) => s.teacher_id).filter(Boolean))];

    const [{ data: teachers }, { data: allGrades }, { data: todayAttendance }, { data: allPayments }, { data: allExamAttempts }] = await Promise.all([
      uniqueTeacherIds.length > 0
        ? supabase.from("teachers").select("client_id, name, contact_whatsapp, contact_phone, conversations_enabled, whatsapp_visible, phone_visible").in("client_id", uniqueTeacherIds)
        : Promise.resolve({ data: [] as any[] }),
      supabase.from("grades").select("student_uid, score, max_score").in("student_uid", allUids),
      supabase.from("attendance").select("student_uid, status").in("student_uid", allUids).eq("date", today),
      // ✅ Batch 22 (بند 2): إجمالي المدفوعات كان غايب تماماً من كارت الطالب عند ولي الأمر
      supabase.from("payments").select("student_uid, amount, total_amount").in("student_uid", allUids),
      // ✅ Batch 23 (بند 2): "عدد الامتحانات" في الكارت كان فعليًا بيعدّ صفوف جدول grades بس
      // (يشمل الاختبار الإلكتروني لو counts_toward_grade فقط) — مش كل الاختبارات الإلكترونية اللي
      // الطالب فعلاً دخلها. exam_attempts (mode='official') هو السجل الحقيقي لكل محاولة اختبار
      // إلكتروني رسمية بغض النظر عن احتسابها في الدرجة من عدمه
      supabase.from("exam_attempts").select("student_uid").in("student_uid", allUids).eq("mode", "official"),
    ]);

    const teacherMap = new Map<string, any>((teachers || []).map((t: any) => [t.client_id, t]));
    const gradesByStudent = new Map<string, any[]>();
    (allGrades || []).forEach((g: any) => {
      if (!gradesByStudent.has(g.student_uid)) gradesByStudent.set(g.student_uid, []);
      gradesByStudent.get(g.student_uid)!.push(g);
    });
    // ✅ Batch 24 (بند 1): طالب ممكن يحضر أكتر من حصة في نفس اليوم دلوقتي — لو معاه أكتر من صف
    // حضور النهاردة (حاضر لحصة وغايب عن حصة تانية مثلاً)، بيتعرض "حاضر" لولي الأمر طالما حضر
    // ولو حصة واحدة، بدل ما يعتمد على آخر صف وصل بترتيب عشوائي
    const todayAttendanceMap = new Map<string, string>();
    (todayAttendance || []).forEach((a: any) => {
      const prev = todayAttendanceMap.get(a.student_uid);
      if (prev !== "present") todayAttendanceMap.set(a.student_uid, a.status);
    });
    const paymentsByStudent = new Map<string, any[]>();
    (allPayments || []).forEach((p: any) => {
      if (!paymentsByStudent.has(p.student_uid)) paymentsByStudent.set(p.student_uid, []);
      paymentsByStudent.get(p.student_uid)!.push(p);
    });
    const examAttemptsCountByStudent = new Map<string, number>();
    (allExamAttempts || []).forEach((e: any) => {
      examAttemptsCountByStudent.set(e.student_uid, (examAttemptsCountByStudent.get(e.student_uid) || 0) + 1);
    });

    for (const student of students as any[]) {
      const group = student.group_name || "بدون مجموعة";
      const workingDaysSet = workingDaysCache.get(group) || new Set<string>();
      const totalWorkingDays = workingDaysSet.size;

      const teacher = teacherMap.get(student.teacher_id);
      const grades = gradesByStudent.get(student.uid) || [];

      let gradesCount = grades.length;
      let avgGrade = 0;
      if (grades.length > 0) {
        let totalScore = 0, totalMax = 0;
        grades.forEach((g: any) => { totalScore += Number(g.score); totalMax += Number(g.max_score) || 100; });
        avgGrade = totalMax > 0 ? (totalScore / totalMax) * 100 : 0;
      }

      const presentDays = presentDatesByStudent.get(student.uid)?.size || 0;
      const absentDays = totalWorkingDays - presentDays;
      const attendancePercent = totalWorkingDays > 0 ? Math.round((presentDays / totalWorkingDays) * 100) : 0;

      // ✅ Batch 22 (بند 2): إجمالي المدفوع + إجمالي المطلوب لكل طالب
      const payments = paymentsByStudent.get(student.uid) || [];
      let totalPaid = 0, totalDue = 0;
      payments.forEach((p: any) => { totalPaid += Number(p.amount) || 0; totalDue += Number(p.total_amount) || 0; });

      result.push({
        uid: student.uid, name: student.name, group_name: group,
        teacher_name: teacher?.name || "غير محدد",
        // ✅ (طلب) المدرس يقدر يخفي رقم الواتساب عن أولياء الأمور — منفصل تماماً عن محادثات داخل التطبيق
        teacher_whatsapp: (teacher?.whatsapp_visible !== false) ? (teacher?.contact_whatsapp || null) : null,
        // ✅ (طلب) نفس منطق إخفاء الواتساب بالظبط — كان رقم الهاتف بيتعرض دايماً من غير أي تحكم،
        // ودلوقتي بقى المدرس يقدر يخفيه عن أولياء الأمور برضه (phone_visible)
        teacher_phone: (teacher?.phone_visible !== false) ? (teacher?.contact_phone || null) : null,
        conversations_enabled: teacher?.conversations_enabled !== false,
        today_attendance: todayAttendanceMap.get(student.uid) || "absent",
        grades_count: gradesCount, avg_grade: Math.round(avgGrade),
        attendance_percent: attendancePercent, present_days: presentDays,
        total_working_days: totalWorkingDays, absent_days: absentDays,
        total_paid: totalPaid, total_due: totalDue,
        // ✅ Batch 23 (بند 2): عدد الاختبارات الإلكترونية الرسمية الفعلية اللي الطالب دخلها
        exams_count: examAttemptsCountByStudent.get(student.uid) || 0
      });
    }

    return new Response(JSON.stringify({ success: true, data: result }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ عام:", error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
