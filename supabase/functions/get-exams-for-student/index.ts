// supabase/functions/get-exams-for-student/index.ts
// ✅ بترجع للطالب كل الاختبارات المنشورة للمجموعة بتاعته، مع حالة كل واحد (لسه، جاري، خلص)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, verifyToken } from "../_shared/auth.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    // ✅ (طلب) الاختبارات الإلكترونية كانت متاحة للطالب بس — ولي الأمر كان مش شايفها خالص.
    // بنسمح كمان لولي الأمر يشوفها لابنه، بنفس منطق التحقق المستخدم في get-student-full-profile
    let studentUid: string;
    if (payload.role === "student") {
      studentUid = payload.sub;
    } else if (payload.role === "parent") {
      let body: any = {};
      try { body = await req.json(); } catch (_e) { /* body فاضي */ }
      const { studentUid: reqStudentUid, parentPhone } = body;
      if (!reqStudentUid || !parentPhone) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (payload.phone !== parentPhone) {
        return new Response(JSON.stringify({ success: false, message: "غير مصرح لك بمشاهدة هذا الطالب" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: ownerCheck } = await supabase.from("students").select("parent_phone").eq("uid", reqStudentUid).maybeSingle();
      if (!ownerCheck || ownerCheck.parent_phone !== parentPhone) {
        return new Response(JSON.stringify({ success: false, message: "غير مصرح لك بمشاهدة هذا الطالب" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      studentUid = reqStudentUid;
    } else {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: student } = await supabase.from("students").select("group_name, teacher_id").eq("uid", studentUid).maybeSingle();
    if (!student) {
      return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ (طلب) الطالب ممكن يكون مربوط بأكتر من مجموعة (تعدد المواد/المدرسين) — الاختبارات
    // الإلكترونية لازم تشمل كل المجموعات اللي هو فيها، مش بس مجموعته الأساسية
    const { data: groupLinks } = await supabase
      .from("student_group_links").select("group_name").eq("student_uid", studentUid);
    const allGroups = Array.from(new Set([
      student.group_name,
      ...((groupLinks || []).map((l: any) => l.group_name)),
    ].filter(Boolean)));

    const { data: exams } = await supabase
      .from("online_exams").select("*, exam_questions(count)")
      .eq("teacher_id", student.teacher_id).in("group_name", allGroups).eq("is_published", true)
      .order("created_at", { ascending: false });

    // ✅ لو الاختبار محدد لطلاب معيّنين، الطالب ده لازم يكون من ضمنهم عشان يشوفه
    const examIds = (exams || []).map((e: any) => e.id);
    const { data: allTargets } = examIds.length > 0
      ? await supabase.from("exam_target_students").select("exam_id, student_uid").in("exam_id", examIds)
      : { data: [] };
    const targetsByExam: Record<number, Set<string>> = {};
    (allTargets || []).forEach((t: any) => {
      if (!targetsByExam[t.exam_id]) targetsByExam[t.exam_id] = new Set();
      targetsByExam[t.exam_id].add(t.student_uid);
    });
    const visibleExams = (exams || []).filter((e: any) => {
      const targets = targetsByExam[e.id];
      return !targets || targets.size === 0 || targets.has(studentUid);
    });

    // ✅ محاولات التدريب متعتبرش هنا خالص — الحالة/الدرجة المعروضة للطالب في القائمة
    // لازم تفضل بس مرآة للمحاولة الرسمية، حتى لو عنده محاولات تدريب كتير بعدها
    const { data: attempts } = await supabase
      .from("exam_attempts").select("*").eq("student_uid", studentUid).eq("mode", "official");

    const attemptsByExam: Record<number, any> = {};
    (attempts || []).forEach((a: any) => { attemptsByExam[a.exam_id] = a; });

    const result = visibleExams.map((e: any) => {
      const attempt = attemptsByExam[e.id];
      return {
        id: e.id, title: e.title, durationMinutes: e.duration_minutes,
        groupName: e.group_name,
        questionCount: e.exam_questions?.[0]?.count || 0,
        status: attempt ? attempt.status : "not_started",
        score: attempt?.score ?? null,
        totalPossible: attempt?.total_possible ?? null,
        // ✅ (طلب) التدريب الحر متاح بس على الاختبارات اللي مابتتحسبش في الدرجات — الاختبار
        // الرسمي (بيتحسب في الدرجة) مالوش خيار "دخول كتدريب حر" خالص، عشان الطالب مايقدرش
        // يشوف أسئلة الاختبار الرسمي كتدريب قبل ما يدخله فعلاً بشكل رسمي
        canPractice: e.counts_toward_grade !== true,
        // ✅ (طلب) الواجهة محتاجة تعرف هل الاختبار ده بيتحسب في الدرجات ولا تدريب حر بس،
        // عشان تعرض للطالب "دخول للاختبار" أو "دخول كتدريب حر" بدل ما تعرض دايماً نفس الزرار
        countsTowardGrade: e.counts_toward_grade === true,
      };
    });

    return new Response(JSON.stringify({ success: true, data: result }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
