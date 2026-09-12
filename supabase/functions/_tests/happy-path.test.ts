// supabase/functions/_tests/happy-path.test.ts
// ============================================
// اختبار تكاملي حقيقي: بينشئ مدرس اختبار كامل على staging، وبيمشي بيه في دورة حياة
// حقيقية (مجموعة → طالب → حضور → درجة → دفعة → اختبار إلكتروني بصورة → تقرير مالي/إنذار
// مبكر → مساعد)، ثم يمسح كل حاجة في النهاية (حذف المدرس بيكسح كل الباقي بالـcascade).
//
// ده أقوى من ملفات منفصلة لكل فانكشن لوحده، لأنه بيتأكد إن الفانكشنز شغالة مع بعضها
// صح (مثلاً: مجموعة اتعملت فعلاً بيقدر طالب ينضم لها، درجة بترتبط بمجموعة حقيقية، إلخ)
// — نفس فلسفة اختبار الـQA الحي اللي اتعمل يدوياً على الإنتاج، بس آلي وقابل للتكرار.
// ============================================
import { assertEquals, assert } from "https://deno.land/std@0.208.0/assert/mod.ts";
import { adminToken, teacherToken, studentToken, callFn } from "./_helpers.ts";

const TEST_TEACHER_ID = `qa_test_teacher_${Date.now()}`;
const TEST_GROUP = "QA Test Group";
const TEST_STUDENT_UID = `qa_test_student_${Date.now()}`;

Deno.test("دورة حياة كاملة لمدرس: مجموعة → طالب → حضور → درجة → دفعة → اختبار → تقارير", async (t) => {
  const admin = await adminToken();
  let teacherTok = "";

  try {
    await t.step("admin-manage-teacher: إنشاء مدرس اختبار جديد", async () => {
      const { status, json } = await callFn("admin-manage-teacher", admin, {
        action: "add", clientId: TEST_TEACHER_ID, name: "مدرس اختبار QA",
        permissions: { can_create_exams: true },
      });
      assertEquals(status, 200);
      assert(json.success, json.message);
      teacherTok = await teacherToken(TEST_TEACHER_ID);
    });

    await t.step("manage-group: إنشاء مجموعة", async () => {
      const { status, json } = await callFn("manage-group", teacherTok, {
        action: "create", clientId: TEST_TEACHER_ID, groupName: TEST_GROUP,
      });
      assertEquals(status, 200);
      assert(json.success, json.message);
    });

    await t.step("manage-student: إضافة طالب للمجموعة", async () => {
      const { status, json } = await callFn("manage-student", teacherTok, {
        action: "add", clientId: TEST_TEACHER_ID, groupName: TEST_GROUP,
        uid: TEST_STUDENT_UID, name: "طالب اختبار QA", parentPhone: "01000000000",
      });
      assertEquals(status, 200);
      assert(json.success, json.message);
    });

    await t.step("get-students: الطالب يظهر في قائمة مدرسه", async () => {
      const { status, json } = await callFn("get-students", teacherTok, { clientId: TEST_TEACHER_ID });
      assertEquals(status, 200);
      assert(json.success, json.message);
      assert(json.data.some((s: any) => s.uid === TEST_STUDENT_UID), "الطالب المُنشأ مش موجود في القائمة");
    });

    await t.step("record-attendance: تسجيل حضور يدوي للطالب", async () => {
      const { status, json } = await callFn("record-attendance", teacherTok, {
        clientId: TEST_TEACHER_ID, uid: TEST_STUDENT_UID, manual: true,
        newSessionLabel: "حصة اختبار QA", groupName: TEST_GROUP,
      });
      assertEquals(status, 200);
      assert(json.success, json.message);
    });

    await t.step("manage-grade: تسجيل درجة", async () => {
      const { status, json } = await callFn("manage-grade", teacherTok, {
        action: "add", clientId: TEST_TEACHER_ID, studentUid: TEST_STUDENT_UID,
        groupName: TEST_GROUP, examName: "اختبار QA", maxScore: 10, score: 8,
      });
      assertEquals(status, 200);
      assert(json.success, json.message);
    });

    await t.step("get-grades: الدرجة اتسجلت صح", async () => {
      const { status, json } = await callFn("get-grades", teacherTok, { clientId: TEST_TEACHER_ID });
      assertEquals(status, 200);
      assert(json.success, json.message);
      assert(json.data.some((g: any) => g.student_uid === TEST_STUDENT_UID && Number(g.score) === 8));
    });

    await t.step("manage-payment: تسجيل دفعة", async () => {
      const { status, json } = await callFn("manage-payment", teacherTok, {
        action: "add", clientId: TEST_TEACHER_ID, studentUid: TEST_STUDENT_UID,
        groupName: TEST_GROUP, title: "اشتراك شهري", totalAmount: 200, amount: 200,
      });
      assertEquals(status, 200);
      assert(json.success, json.message);
    });

    await t.step("get-payments + get-payment-titles: الدفعة والبند اتسجلوا", async () => {
      const payments = await callFn("get-payments", teacherTok, { clientId: TEST_TEACHER_ID });
      assert(payments.json.success);
      assert(payments.json.data.some((p: any) => p.student_uid === TEST_STUDENT_UID));

      const titles = await callFn("get-payment-titles", teacherTok, { clientId: TEST_TEACHER_ID });
      assert(titles.json.success);
      assert(titles.json.data.some((t: any) => t.title === "اشتراك شهري"));
    });

    let examId: number | undefined;
    await t.step("manage-exam: إنشاء اختبار وسؤال بصورة بس (من غير نص)", async () => {
      const created = await callFn("manage-exam", teacherTok, {
        action: "create", title: "اختبار QA", groupName: TEST_GROUP, durationMinutes: 20,
      });
      assert(created.json.success, created.json.message);
      examId = created.json.data.id;

      // ✅ بكسل PNG شفاف 1×1 — كفاية لاختبار مسار الرفع من غير ما نضخّم حجم الاختبار
      const tinyPng = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
      const added = await callFn("manage-exam", teacherTok, {
        action: "addQuestion", examId, questionText: "", questionImageBase64: tinyPng,
        questionType: "true_false", correctAnswer: "true", points: 10,
      });
      assert(added.json.success, added.json.message);
      assert(added.json.data.question_image_url, "السؤال المنشأ من غير رابط صورة");
    });

    await t.step("manage-exam publish + take-exam: طالب يأدي الاختبار ويتصحح تلقائياً", async () => {
      const published = await callFn("manage-exam", teacherTok, { action: "publish", examId });
      assert(published.json.success, published.json.message);

      const studentTok = await studentToken(TEST_STUDENT_UID);
      const started = await callFn("take-exam", studentTok, { action: "start", examId });
      assert(started.json.success, started.json.message);
      assert(started.json.questions[0].question_image_url, "الطالب مايشوفش رابط صورة السؤال");

      const submitted = await callFn("take-exam", studentTok, {
        action: "submit", attemptId: started.json.attemptId,
        answers: [{ questionId: started.json.questions[0].id, selectedAnswer: "true" }],
      });
      assert(submitted.json.success, submitted.json.message);
      assertEquals(submitted.json.score, 10);
    });

    await t.step("get-exam-report: تقرير الاختبار بيشوف محاولة الطالب", async () => {
      const { json } = await callFn("get-exam-report", teacherTok, { examId });
      assert(json.success, json.message);
      const row = json.data.report.find((r: any) => r.studentUid === TEST_STUDENT_UID);
      assert(row, "الطالب مش موجود في تقرير الاختبار");
      assertEquals(row.score, 10);
    });

    await t.step("get-dashboard / get-financial-summary / get-at-risk-students: بترد بنجاح", async () => {
      const dash = await callFn("get-dashboard", teacherTok, { clientId: TEST_TEACHER_ID });
      assert(dash.json.success, dash.json.message);

      const fin = await callFn("get-financial-summary", teacherTok, { clientId: TEST_TEACHER_ID });
      assert(fin.json.success, fin.json.message);

      const risk = await callFn("get-at-risk-students", teacherTok, { clientId: TEST_TEACHER_ID });
      assert(risk.json.success, risk.json.message);
    });

    let assistantUsername = "";
    await t.step("manage-assistant: إضافة مساعد وحذفه", async () => {
      assistantUsername = `qa_assistant_${Date.now()}`;
      const added = await callFn("manage-assistant", teacherTok, {
        action: "add", teacherId: TEST_TEACHER_ID, username: assistantUsername, name: "مساعد اختبار QA",
      });
      assert(added.json.success, added.json.message);

      const list = await callFn("get-assistants", teacherTok, { clientId: TEST_TEACHER_ID });
      assert(list.json.success);
      const created = list.json.data.find((a: any) => a.username === assistantUsername);
      assert(created, "المساعد المُنشأ مش موجود في القائمة");

      const deleted = await callFn("manage-assistant", teacherTok, { action: "delete", assistantId: created.id, teacherId: TEST_TEACHER_ID });
      assert(deleted.json.success, deleted.json.message);
    });
  } finally {
    // ✅ التنظيف: حذف مدرس الاختبار بيكسح كل الباقي تلقائياً (مجموعة/طالب/حضور/درجة/دفعة/اختبار)
    // بفضل on delete cascade على كل الجداول دي في baseline_schema.sql
    await callFn("admin-manage-teacher", admin, { action: "delete", clientId: TEST_TEACHER_ID });
  }
});
