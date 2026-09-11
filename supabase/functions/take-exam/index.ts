// supabase/functions/take-exam/index.ts
// ✅ دالة موحّدة لأداء الاختبار (جانب الطالب) — action: start | submit
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, verifyToken } from "../_shared/auth.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    if (payload.role !== "student") {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const studentUid = payload.sub;
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const body = await req.json();
    const action = body.action;

    // ✅ التأكد إن الطالب ده أصلاً من ضمن مجموعة الاختبار، قبل أي حاجة تانية
    async function verifyEligibility(examId: number) {
      const { data: exam } = await supabase.from("online_exams").select("*").eq("id", examId).maybeSingle();
      if (!exam || !exam.is_published) throw new Error("⚠️ الاختبار غير متاح");
      // ✅ (طلب) وقت غلق الاختبار — لو المدرس حدده وفات، الاختبار يبقى مقفول تماماً (رسمي أو
      // تدريب)، مايفتحش لأي محاولة جديدة حتى لو الطالب لسه ماخدش الاختبار خالص
      if (exam.closes_at && new Date(exam.closes_at).getTime() <= Date.now()) throw new Error("⚠️ اتقفل الاختبار ده، مش متاح تدخليه دلوقتي");
      const { data: student } = await supabase.from("students").select("group_name, name").eq("uid", studentUid).maybeSingle();
      if (!student) throw new Error("⛔ الاختبار ده مش لمجموعتك");
      // ✅ (طلب) الطالب ممكن يكون مربوط بأكتر من مجموعة (تعدد المواد/المدرسين) — لازم نتأكد من
      // مجموعته الأساسية + كل المجموعات المربوطة، مش بس مجموعته الأساسية (نفس الباتش اللي صلح
      // نفس المشكلة في get-exams-for-student و get-student-full-profile)
      const { data: groupLinks } = await supabase
        .from("student_group_links").select("group_name").eq("student_uid", studentUid);
      const allGroups = new Set([student.group_name, ...((groupLinks || []).map((l: any) => l.group_name))].filter(Boolean));
      if (!allGroups.has(exam.group_name)) throw new Error("⛔ الاختبار ده مش لمجموعتك");

      // ✅ لو المدرس حدد طلاب معيّنين للاختبار ده، لازم الطالب يكون من ضمنهم
      const { data: targets } = await supabase.from("exam_target_students").select("student_uid").eq("exam_id", examId);
      if (targets && targets.length > 0) {
        const isTargeted = targets.some((t: any) => t.student_uid === studentUid);
        if (!isTargeted) throw new Error("⛔ الاختبار ده مش موجّه ليك");
      }

      return { exam, studentName: student.name };
    }

    if (action === "start") {
      const { examId } = body;
      const mode = body.mode === "practice" ? "practice" : "official";
      const { exam } = await verifyEligibility(examId);

      // ✅ وضع التدريب: مفيش قفل على عدد المحاولات ولا وقت — كل ضغطة "ابدأ" بتفتح محاولة تدريب جديدة
      // منفصلة تماماً عن المحاولة الرسمية (ماتظهرش في تقارير المدرس ولا بتمنع محاولة رسمية)
      if (mode === "practice") {
        // ✅ (طلب) الاختبار اللي بيتحسب في الدرجات مالوش وضع تدريب حر خالص — منعاً لإن الطالب
        // يشوف أسئلة الاختبار الرسمي كتدريب الأول (حتى لو من غير الإجابة الصحيحة، لسه مش
        // المفروض يشوف نص الأسئلة نفسها قبل المحاولة الرسمية). الواجهة أصلاً بقت مابتعرضش
        // زرار "تدريب حر" للاختبارات دي، وده تأكيد من السيرفر إن محدش يعدّي الفحص بمناداة
        // الدالة مباشرة برابط مصنوع يدوياً
        if (exam.counts_toward_grade === true) {
          return new Response(JSON.stringify({ success: false, message: "⚠️ الاختبار ده رسمي ومحتسب في درجاتك، مفيش وضع تدريب حر ليه" }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        const { data: attempt, error } = await supabase.from("exam_attempts").insert({
          exam_id: examId, student_uid: studentUid, status: "in_progress", mode: "practice",
        }).select().single();
        if (error) throw new Error(error.message);
        const { data: questions } = await supabase.from("exam_questions").select("id, question_text, question_type, options, points").eq("exam_id", examId).order("order_index");
        return new Response(JSON.stringify({
          success: true, attemptId: attempt.id, startedAt: attempt.started_at, mode: "practice",
          durationMinutes: null, title: exam.title, questions: questions || [],
        }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ لو عنده محاولة رسمية سابقة (مكتملة أو منتهي وقتها)، مايقدرش يبدأ تاني
      const { data: existing } = await supabase.from("exam_attempts").select("*").eq("exam_id", examId).eq("student_uid", studentUid).eq("mode", "official").maybeSingle();
      if (existing) {
        if (existing.status !== "in_progress") {
          return new Response(JSON.stringify({ success: false, message: "⚠️ خلّصت الاختبار ده قبل كده" }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        // ✅ محاولة شغّالة بالفعل — نتأكد لو وقتها لسه ماخلصش (مدة الاختبار أو وقت الغلق العام،
        // أيهما أقرب)، ونرجّعها بدل ما نعمل واحدة جديدة
        const elapsedMs = Date.now() - new Date(existing.started_at).getTime();
        const closedByDuration = elapsedMs > exam.duration_minutes * 60 * 1000;
        const closedByDeadline = exam.closes_at && Date.now() > new Date(exam.closes_at).getTime();
        if (closedByDuration || closedByDeadline) {
          return new Response(JSON.stringify({ success: false, message: "⚠️ انتهى وقت الاختبار ده بالفعل، هيتقفل تلقائياً" }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        const { data: questions } = await supabase.from("exam_questions").select("id, question_text, question_type, options, points").eq("exam_id", examId).order("order_index");
        return new Response(JSON.stringify({
          success: true, attemptId: existing.id, startedAt: existing.started_at, mode: "official",
          durationMinutes: exam.duration_minutes, closesAt: exam.closes_at, title: exam.title, questions: questions || [],
        }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: attempt, error } = await supabase.from("exam_attempts").insert({
        exam_id: examId, student_uid: studentUid, status: "in_progress", mode: "official",
      }).select().single();
      if (error) throw new Error(error.message);

      // ✅ الأسئلة بترجع من غير الإجابة الصحيحة خالص، عشان الطالب مايشوفهاش في كود الصفحة
      const { data: questions } = await supabase.from("exam_questions").select("id, question_text, question_type, options, points").eq("exam_id", examId).order("order_index");

      return new Response(JSON.stringify({
        success: true, attemptId: attempt.id, startedAt: attempt.started_at, mode: "official",
        durationMinutes: exam.duration_minutes, closesAt: exam.closes_at, title: exam.title, questions: questions || [],
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "submit") {
      const { attemptId, answers } = body; // answers: [{ questionId, selectedAnswer }]
      const { data: attempt } = await supabase.from("exam_attempts").select("*").eq("id", attemptId).maybeSingle();
      if (!attempt || attempt.student_uid !== studentUid) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (attempt.status !== "in_progress") {
        return new Response(JSON.stringify({ success: false, message: "⚠️ الاختبار ده اتقفل بالفعل" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: exam } = await supabase.from("online_exams").select("duration_minutes, teacher_id, group_name, title, counts_toward_grade, closes_at").eq("id", attempt.exam_id).maybeSingle();
      const elapsedMs = Date.now() - new Date(attempt.started_at).getTime();
      // ✅ وضع التدريب بلا وقت أبداً — التوقيت بيتفعّل بس للمحاولة الرسمية. وقت الغلق العام
      // للاختبار (لو موجود) بيتحسب برضه كسبب لانتهاء الوقت، مش بس مدة المحاولة الفردية
      const isTimedOut = attempt.mode !== "practice" && exam && (
        elapsedMs > exam.duration_minutes * 60 * 1000 ||
        (exam.closes_at != null && Date.now() > new Date(exam.closes_at).getTime())
      );

      const { data: questions } = await supabase.from("exam_questions").select("*").eq("exam_id", attempt.exam_id);
      const questionsById: Record<number, any> = {};
      (questions || []).forEach((q: any) => { questionsById[q.id] = q; });

      let totalScore = 0;
      let totalPossible = 0;
      const answerRows = [];

      for (const q of questions || []) {
        totalPossible += Number(q.points);
        const submitted = (answers || []).find((a: any) => a.questionId === q.id);
        const selectedAnswer = submitted?.selectedAnswer ?? null;
        // ✅ لو الوقت خلص، أي سؤال متأخر ماكانش الطالب سلّمه بيتحسب غلط تلقائياً (مش بيتجاهل)
        const isCorrect = !isTimedOut && selectedAnswer !== null && String(selectedAnswer).trim() === String(q.correct_answer).trim();
        const pointsEarned = isCorrect ? Number(q.points) : 0;
        totalScore += pointsEarned;
        answerRows.push({ attempt_id: attemptId, question_id: q.id, selected_answer: selectedAnswer, is_correct: isCorrect, points_earned: pointsEarned });
      }

      if (answerRows.length > 0) await supabase.from("exam_answers").insert(answerRows);

      await supabase.from("exam_attempts").update({
        status: isTimedOut ? "timed_out" : "completed",
        finished_at: new Date().toISOString(),
        score: totalScore, total_possible: totalPossible,
      }).eq("id", attemptId);

      // ✅ (طلب) لو المدرس حدد إن الاختبار ده "بيتحسب في الدرجات" (مش تدريب حر بس)، درجة المحاولة
      // الرسمية بتتسجّل تلقائياً في نفس جدول grades — عشان تدخل في متوسط الطالب ومخطط نمو مستواه
      // زي أي درجة تانية بيرصدها المدرس يدوي. التدريب الحر (mode: practice) مابيتحسبش أبداً.
      if (attempt.mode === "official" && exam?.counts_toward_grade && totalPossible > 0) {
        const { data: studentRow } = await supabase.from("students").select("name").eq("uid", studentUid).maybeSingle();
        await supabase.from("grades").insert({
          student_uid: studentUid, student_name: studentRow?.name || "طالب", teacher_id: exam.teacher_id,
          group_name: exam.group_name, exam_name: exam.title, score: totalScore, max_score: totalPossible,
        });
      }

      return new Response(JSON.stringify({
        success: true,
        message: attempt.mode === "practice"
          ? "✅ خلّصت محاولة التدريب — مش هتتحسب في تقرير المدرس"
          : (isTimedOut ? "⏰ انتهى وقت الاختبار، اتصحّح تلقائياً" : "✅ تم تسليم الاختبار وتصحيحه"),
        score: totalScore, totalPossible, isTimedOut, mode: attempt.mode,
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: message.includes("⛔") ? 403 : 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
