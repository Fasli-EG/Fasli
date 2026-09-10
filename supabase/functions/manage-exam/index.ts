// supabase/functions/manage-exam/index.ts
// ✅ إدارة الاختبارات الإلكترونية (جانب المدرس) — action: create | addQuestion | updateQuestion | deleteQuestion | publish | delete | list | listWithStats | setTargets | getOne
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
};

interface TokenPayload { sub: string; clientId?: string; teacherId?: string; role: string; name: string; }

async function verifyToken(req: Request): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) throw new Error("⚠️ التوكن مطلوب");
  const token = authHeader.substring(7);
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) throw new Error("⚠️ JWT_SECRET غير مضبوط");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return (await verify(token, key, "HS256")) as unknown as TokenPayload;
}

// ✅ تتأكد إن المدرس أصلاً مسموحله يستخدم ميزة الاختبارات الإلكترونية (صلاحية زي باقي الصلاحيات)
async function requireExamPermission(supabase: any, teacherId: string) {
  const { data: teacher } = await supabase.from("teachers").select("permissions").eq("client_id", teacherId).maybeSingle();
  const perms = teacher?.permissions || {};
  if (perms.can_create_exams !== true) {
    throw new Error("⛔ ميزة الاختبارات الإلكترونية غير متاحة في باقتك الحالية، تواصلي مع الإدارة لتفعيلها");
  }
}

// ✅ تتأكد إن المساعد (لو التوكن بتاع مساعد) عنده صلاحية "manage_exams" الممنوحة له من المدرس —
// نفس نمط requireAssistantPermission في باقي الدوال (manage-grade / manage-book)، لكن هنا بتستخدم
// عميل supabase المتاح أصلاً في نطاق الطلب بدل عمل عميل ترخيص منفصل
async function requireAssistantPermission(supabase: any, payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const { data: assistant } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) {
    throw new Error("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس");
  }
}

// ============================================
// (من _shared/push.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// إرسال إشعارات Push حقيقية عبر Firebase Cloud Messaging (HTTP v1 API)
// ============================================
interface ServiceAccount { client_email: string; private_key: string; project_id: string; }
let cachedAccessToken: { token: string; expiresAt: number } | null = null;

function base64url(input: ArrayBuffer | string): string {
  let bytes: Uint8Array;
  if (typeof input === "string") bytes = new TextEncoder().encode(input);
  else bytes = new Uint8Array(input);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function getAccessToken(sa: ServiceAccount): Promise<string> {
  if (cachedAccessToken && cachedAccessToken.expiresAt > Date.now() + 60_000) return cachedAccessToken.token;
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claims = { iss: sa.client_email, scope: "https://www.googleapis.com/auth/firebase.messaging", aud: "https://oauth2.googleapis.com/token", exp: now + 3600, iat: now };
  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const pemBody = sa.private_key.replace(/-----BEGIN PRIVATE KEY-----/, "").replace(/-----END PRIVATE KEY-----/, "").replace(/\s/g, "");
  const binaryKey = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey("pkcs8", binaryKey.buffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, new TextEncoder().encode(unsigned));
  const jwt = `${unsigned}.${base64url(signature)}`;
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwt }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) throw new Error("فشل مصادقة Firebase");
  cachedAccessToken = { token: tokenData.access_token, expiresAt: Date.now() + tokenData.expires_in * 1000 };
  return tokenData.access_token;
}

async function sendPushToRecipient(supabase: any, recipientType: "parent" | "assistant" | "teacher" | "student", recipientId: string, title: string, body: string): Promise<void> {
  try {
    const saJson = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
    if (!saJson) return;
    const { data: tokens } = await supabase.from("push_tokens").select("id, token").eq("recipient_type", recipientType).eq("recipient_id", recipientId);
    if (!tokens || tokens.length === 0) return;
    const sa: ServiceAccount = JSON.parse(saJson);
    const accessToken = await getAccessToken(sa);
    for (const row of tokens) {
      const res = await fetch(`https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`, {
        method: "POST", headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ message: { token: row.token, notification: { title, body }, android: { priority: "high", notification: { sound: "default", channel_id: "fasli_notifications" } } } }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        if (errData?.error?.status === "NOT_FOUND" || errData?.error?.status === "INVALID_ARGUMENT") {
          await supabase.from("push_tokens").delete().eq("id", row.id);
        } else { console.error("⚠️ فشل إرسال Push notification:", errData); }
      }
    }
  } catch (error) { console.error("⚠️ خطأ غير متوقع في إرسال Push notification:", error); }
}

// ✅ دالة مشتركة بين النشر اليدوي (فوري) والنشر المجدول (تلقائي) — بتحترم الطلاب المستهدفين
// لو محددين، وإلا بتبعت لكل طلاب المجموعة (السلوك الافتراضي القديم)
async function publishExamAndNotify(supabase: any, exam: any, teacherId: string): Promise<number> {
  await supabase.from("online_exams").update({ is_published: true }).eq("id", exam.id);

  const { data: teacher } = await supabase.from("teachers").select("name").eq("client_id", teacherId).maybeSingle();

  const { data: targets } = await supabase.from("exam_target_students").select("student_uid").eq("exam_id", exam.id);
  const targetUids = (targets || []).map((t: any) => t.student_uid);

  let studentsQuery = supabase.from("students").select("uid, parent_phone").eq("teacher_id", teacherId).eq("group_name", exam.group_name);
  if (targetUids.length > 0) studentsQuery = studentsQuery.in("uid", targetUids);
  const { data: students } = await studentsQuery;

  const teacherLabel = teacher?.name ? ` — مدرس ${teacher.name}` : "";
  const parentRows = (students || []).filter((s: any) => s.parent_phone).map((s: any) => ({
    teacher_id: teacherId, parent_phone: s.parent_phone, student_uid: s.uid, type: "exam", audience: "parent",
    title: "اختبار جديد", message: `اختبار "${exam.title}" جاهز الآن لـ ${exam.group_name} — مدته ${exam.duration_minutes} دقيقة${teacherLabel}`,
    details: { exam_title: exam.title, exam_id: exam.id, group_name: exam.group_name },
  }));
  // ✅ (طلب) إشعار مستقل للطالب نفسه (صيغة مخاطب مباشر تحثّه على الدخول للاختبار)، معزول
  // تماماً عن إشعار ولي الأمر (الاطّلاعي فقط) — لكل طلاب المجموعة (أو المستهدفين) بغض النظر
  // عن وجود رقم ولي أمر من عدمه
  const studentRows = (students || []).map((s: any) => ({
    teacher_id: teacherId, student_uid: s.uid, type: "exam", audience: "student",
    title: "اختبار جديد", message: `عندك اختبار جديد "${exam.title}" — مدته ${exam.duration_minutes} دقيقة، ادخل واختبر نفسك دلوقتي${teacherLabel}`,
    details: { exam_title: exam.title, exam_id: exam.id, group_name: exam.group_name },
  }));
  const notifRows = [...parentRows, ...studentRows];
  if (notifRows.length > 0) await supabase.from("notifications").insert(notifRows);
  // ✅ (طلب) نشر الاختبار مكانش بيبعت أي Push حقيقي خالص — بس إشعار جوه التطبيق فوق
  parentRows.forEach((r: any) => { sendPushToRecipient(supabase, "parent", r.parent_phone, r.title, r.message); });
  studentRows.forEach((r: any) => { sendPushToRecipient(supabase, "student", r.student_uid, r.title, r.message); });
  return parentRows.length;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const body = await req.json();
    const action = body.action;

    // ✅ كل العمليات هنا (عدا list/getOne) محتاجة صلاحية إنشاء اختبارات
    // ✅ (مراجعة أمان) setClosesAt/closeNow/reopen كانت ناقصة من القائمة دي — كان أي مساعد
    // (حتى من غير صلاحية manage_exams) يقدر يقفل اختبار الطلاب وهما بيمتحنوا فيه لسه، أو
    // يعيد فتح اختبار مقفول ويمدد وقته، لمجرد إن التوكن بتاعه صالح
    if (["create", "addQuestion", "updateQuestion", "deleteQuestion", "publish", "delete", "setTargets", "setClosesAt", "closeNow", "reopen"].includes(action)) {
      await requireExamPermission(supabase, tokenClientId!);
      await requireAssistantPermission(supabase, payload, "manage_exams");
    }

    if (action === "create") {
      const { title, groupName, durationMinutes, scheduledAt, countsTowardGrade, closesAt } = body;
      if (!title || !groupName || !durationMinutes) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (scheduledAt && new Date(scheduledAt).getTime() < Date.now()) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ وقت الجدولة لازم يكون في المستقبل" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      // ✅ (طلب) وقت غلق الاختبار — لو المدرس حدده، لازم يكون بعد وقت النشر/الجدولة عشان
      // يكون فيه فترة حقيقية متاحة للطلاب يدخلوا فيها الاختبار
      if (closesAt) {
        const closesAtMs = new Date(closesAt).getTime();
        const startReferenceMs = scheduledAt ? new Date(scheduledAt).getTime() : Date.now();
        if (closesAtMs <= startReferenceMs) {
          return new Response(JSON.stringify({ success: false, message: "⚠️ وقت غلق الاختبار لازم يكون بعد وقت بدايته" }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }
      // ✅ (طلب) المدرس بيحدد وقت الإنشاء لو الاختبار ده هيتحسب فعلياً في درجات الطالب ومستواه
      // (زي أي درجة يدوية)، أو إنه مجرد تدريب حر للطلاب — القيمة الافتراضية false (تدريب فقط)
      // عشان ميحصلش تغيير سلوك مفاجئ في اختبارات موجودة بالفعل
      const { data, error } = await supabase.from("online_exams").insert({
        teacher_id: tokenClientId, title, group_name: groupName, duration_minutes: Number(durationMinutes),
        scheduled_at: scheduledAt || null, counts_toward_grade: countsTowardGrade === true,
        closes_at: closesAt || null,
      }).select().single();
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم إنشاء الاختبار، دلوقتي ضيفي الأسئلة", data }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "addQuestion") {
      const { examId, questionText, questionType, options, correctAnswer, points } = body;
      if (!examId || !questionText || !questionType || correctAnswer === undefined || !points) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (!["mcq", "true_false"].includes(questionType)) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ نوع السؤال غير صحيح" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (questionType === "mcq" && (!Array.isArray(options) || options.length < 2)) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ الأسئلة الاختيارية محتاجة اختيارين على الأقل" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: exam } = await supabase.from("online_exams").select("teacher_id, is_published").eq("id", examId).maybeSingle();
      if (!exam || exam.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بتعديل هذا الاختبار" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      // ✅ Aug 2026: مينفعش تتعدّل أسئلة اختبار اتنشر بالفعل — الطلاب ممكن يكونوا شايفينه أو امتحنوه بالفعل
      if (exam.is_published) {
        return new Response(JSON.stringify({ success: false, message: "⛔ الاختبار ده منشور بالفعل، مينفعش تضيفي أسئلة جديدة بعد النشر" }),
          { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { count } = await supabase.from("exam_questions").select("id", { count: "exact", head: true }).eq("exam_id", examId);

      const { data, error } = await supabase.from("exam_questions").insert({
        exam_id: examId, question_text: questionText, question_type: questionType,
        options: questionType === "mcq" ? options : null,
        correct_answer: String(correctAnswer), points: Number(points), order_index: count || 0,
      }).select().single();
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم إضافة السؤال", data }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ Aug 2026: تعديل سؤال موجود (نص/نوع/اختيارات/إجابة صحيحة/درجة) — نفس قيد النشر بتاع
    // addQuestion/deleteQuestion، مينفعش تتعدّل أسئلة اختبار منشور بالفعل
    if (action === "updateQuestion") {
      const { questionId, questionText, questionType, options, correctAnswer, points } = body;
      if (!questionId || !questionText || !questionType || correctAnswer === undefined || !points) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (!["mcq", "true_false"].includes(questionType)) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ نوع السؤال غير صحيح" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (questionType === "mcq" && (!Array.isArray(options) || options.length < 2)) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ الأسئلة الاختيارية محتاجة اختيارين على الأقل" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: q } = await supabase.from("exam_questions").select("exam_id, online_exams(teacher_id, is_published)").eq("id", questionId).maybeSingle();
      if (!q || (q as any).online_exams?.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if ((q as any).online_exams?.is_published) {
        return new Response(JSON.stringify({ success: false, message: "⛔ الاختبار ده منشور بالفعل، مينفعش تعدّلي أسئلته بعد النشر" }),
          { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data, error } = await supabase.from("exam_questions").update({
        question_text: questionText, question_type: questionType,
        options: questionType === "mcq" ? options : null,
        correct_answer: String(correctAnswer), points: Number(points),
      }).eq("id", questionId).select().single();
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم تعديل السؤال", data }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "deleteQuestion") {
      const { questionId } = body;
      const { data: q } = await supabase.from("exam_questions").select("exam_id, online_exams(teacher_id, is_published)").eq("id", questionId).maybeSingle();
      if (!q || (q as any).online_exams?.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      // ✅ Aug 2026: نفس القيد — مينفعش تتحذف أسئلة اختبار منشور بالفعل
      if ((q as any).online_exams?.is_published) {
        return new Response(JSON.stringify({ success: false, message: "⛔ الاختبار ده منشور بالفعل، مينفعش تحذفي أسئلته بعد النشر" }),
          { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { error } = await supabase.from("exam_questions").delete().eq("id", questionId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم حذف السؤال" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "setTargets") {
      const { examId, studentUids } = body; // studentUids: array — فاضية معناها "كل المجموعة"
      const { data: exam } = await supabase.from("online_exams").select("teacher_id, group_name").eq("id", examId).maybeSingle();
      if (!exam || exam.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ نتأكد إن كل الطلاب المحددين فعلاً تابعين لنفس مجموعة الاختبار، قبل ما نسجّلهم كأهداف
      if (Array.isArray(studentUids) && studentUids.length > 0) {
        const { data: validStudents } = await supabase
          .from("students").select("uid").eq("teacher_id", tokenClientId).eq("group_name", exam.group_name).in("uid", studentUids);
        const validUids = new Set((validStudents || []).map((s: any) => s.uid));
        const invalidCount = studentUids.filter((u: string) => !validUids.has(u)).length;
        if (invalidCount > 0) {
          return new Response(JSON.stringify({ success: false, message: "⚠️ فيه طلاب محددين مش تابعين لمجموعة الاختبار" }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }

      await supabase.from("exam_target_students").delete().eq("exam_id", examId);
      if (Array.isArray(studentUids) && studentUids.length > 0) {
        await supabase.from("exam_target_students").insert(studentUids.map((uid: string) => ({ exam_id: examId, student_uid: uid })));
      }

      const message = Array.isArray(studentUids) && studentUids.length > 0
        ? `✅ الاختبار دلوقتي هيتبعت لـ ${studentUids.length} طالب بس`
        : "✅ الاختبار دلوقتي هيتبعت لكل طلاب المجموعة";
      return new Response(JSON.stringify({ success: true, message }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "publish") {
      const { examId } = body;
      const { data: exam } = await supabase.from("online_exams").select("*").eq("id", examId).maybeSingle();
      if (!exam || exam.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { count: qCount } = await supabase.from("exam_questions").select("id", { count: "exact", head: true }).eq("exam_id", examId);
      if (!qCount || qCount === 0) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تضيفي سؤال واحد على الأقل قبل النشر" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ (طلب) لو وقت غلق الاختبار محدد وفات بالفعل، منسمحش بالنشر أصلاً — مفيش فايدة
      // إن اختبار يتنشر وهو مقفول من الأساس
      if (exam.closes_at && new Date(exam.closes_at).getTime() <= Date.now()) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ وقت غلق الاختبار ده فات بالفعل — عدّلي وقت الغلق الأول" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ Aug 2026: مينفعش تعيدي نشر اختبار اتنشر بالفعل وفيه طلاب امتحنوه — ده هيبعت إشعار مكرر
      // لأولياء الأمور من غير أي فايدة حقيقية، وأخطر من كده ممكن يوهم إن فيه اختبار جديد وسط
      // نتايج طلاب موجودة بالفعل
      if (exam.is_published) {
        const { count: attemptsCount } = await supabase.from("exam_attempts").select("id", { count: "exact", head: true })
          .eq("exam_id", examId).eq("mode", "official");
        if (attemptsCount && attemptsCount > 0) {
          return new Response(JSON.stringify({ success: false, message: "⛔ الاختبار ده منشور بالفعل وفيه طلاب امتحنوه — مينفعش تعيدي نشره تاني" }),
            { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }

      // ✅ لو محدد وقت جدولة في المستقبل، منشرش دلوقتي — نستنى check-scheduled-exams تنشره في وقته
      if (exam.scheduled_at && new Date(exam.scheduled_at).getTime() > Date.now()) {
        return new Response(JSON.stringify({
          success: true,
          message: `✅ الاختبار مجدول للنشر تلقائياً في ${new Date(exam.scheduled_at).toLocaleString("ar-EG", { timeZone: "Africa/Cairo" })}`,
        }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const notifiedCount = await publishExamAndNotify(supabase, exam, tokenClientId!);
      return new Response(JSON.stringify({ success: true, message: `✅ تم نشر الاختبار وإرسال إشعار لـ ${notifiedCount} ولي أمر` }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ (طلب) تعديل وقت غلق الاختبار — منفصل عن باقي التعديلات لأنه مسموح حتى بعد النشر
    // (عكس تعديل الأسئلة)، فالمدرس يقدر يمدد أو يقصّر فترة الاختبار في أي وقت
    if (action === "setClosesAt") {
      const { examId, closesAt } = body;
      const { data: exam } = await supabase.from("online_exams").select("teacher_id, scheduled_at").eq("id", examId).maybeSingle();
      if (!exam || exam.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (closesAt) {
        const closesAtMs = new Date(closesAt).getTime();
        const startReferenceMs = exam.scheduled_at ? new Date(exam.scheduled_at).getTime() : Date.now();
        if (closesAtMs <= startReferenceMs) {
          return new Response(JSON.stringify({ success: false, message: "⚠️ وقت غلق الاختبار لازم يكون بعد وقت بدايته" }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }
      const { error } = await supabase.from("online_exams").update({ closes_at: closesAt || null }).eq("id", examId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: closesAt ? "✅ تم تحديد وقت غلق الاختبار" : "✅ تم إلغاء وقت الغلق" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ (طلب) قفل فوري للاختبار في أي وقت — نفس عمود closes_at، بس بنحسب "دلوقتي" على السيرفر
    // نفسه (مش من ساعة جهاز المتصفح) عشان يقفل فوراً بدقة من غير أي فرق توقيت. الطلاب اللي
    // لسه ماخدوش الاختبار (أو محاولتهم شغّالة) مش هيقدروا يبدأوا/يكملوا بعد كده — take-exam
    // بيتأكد من closes_at في كل من verifyEligibility وsubmit
    if (action === "closeNow") {
      const { examId } = body;
      const { data: exam } = await supabase.from("online_exams").select("teacher_id").eq("id", examId).maybeSingle();
      if (!exam || exam.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const closedAt = new Date().toISOString();
      const { error } = await supabase.from("online_exams").update({ closes_at: closedAt }).eq("id", examId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم قفل الاختبار فوراً — محدش هيقدر يبدأ أو يكمّل بعد كده", closesAt: closedAt }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ (طلب) إعادة فتح اختبار مقفول لمدة يحددها المدرس بالدقايق — بيمدّد closes_at لوقت
    // جديد في المستقبل، فأي طالب لسه ماخدش الاختبار (أو محاولته لسه في حدود مدتها الشخصية)
    // يقدر يدخل تاني خلال المدة الجديدة دي
    if (action === "reopen") {
      const { examId, minutes } = body;
      const minutesNum = Number(minutes);
      if (!minutesNum || minutesNum <= 0 || minutesNum > 10080) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ حددي مدة إعادة الفتح بالدقايق (من 1 لحد أسبوع كامل)" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: exam } = await supabase.from("online_exams").select("teacher_id").eq("id", examId).maybeSingle();
      if (!exam || exam.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const newClosesAt = new Date(Date.now() + minutesNum * 60 * 1000).toISOString();
      const { error } = await supabase.from("online_exams").update({ closes_at: newClosesAt }).eq("id", examId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({
        success: true,
        message: `✅ اتفتح الاختبار تاني لحد ${new Date(newClosesAt).toLocaleString("ar-EG", { timeZone: "Africa/Cairo" })}`,
        closesAt: newClosesAt,
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "delete") {
      const { examId } = body;
      const { data: exam } = await supabase.from("online_exams").select("teacher_id").eq("id", examId).maybeSingle();
      if (!exam || exam.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { error } = await supabase.from("online_exams").delete().eq("id", examId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم حذف الاختبار" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "list") {
      const { data, error } = await supabase.from("online_exams").select("*, exam_questions(count)").eq("teacher_id", tokenClientId).order("created_at", { ascending: false });
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, data: data || [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ Aug 2026: ملخص كل الاختبارات الإلكترونية لتبويب "الاختبارات الإلكترونية" في grades.html —
    // بيرجع صف واحد لكل اختبار (بدل تفاصيل كل طالب زي get-exam-report) عشان يتعرض في جدول تلخيصي؛
    // تفاصيل كل طالب لسه بتتجاب من get-exam-report نفسها لما المدرس يضغط على صف معيّن (مفيش تكرار منطق)
    if (action === "listWithStats") {
      const { data: exams, error } = await supabase.from("online_exams").select("*").eq("teacher_id", tokenClientId).order("created_at", { ascending: false });
      if (error) throw new Error(error.message);
      const examIds = (exams || []).map((e: any) => e.id);

      const { data: attempts } = examIds.length > 0
        ? await supabase.from("exam_attempts").select("exam_id, score, status").in("exam_id", examIds).eq("mode", "official")
        : { data: [] as any[] };

      const groupNames = [...new Set((exams || []).map((e: any) => e.group_name))];
      const { data: allStudents } = groupNames.length > 0
        ? await supabase.from("students").select("uid, group_name").eq("teacher_id", tokenClientId).in("group_name", groupNames)
        : { data: [] as any[] };
      const studentCountByGroup: Record<string, number> = {};
      (allStudents || []).forEach((s: any) => { studentCountByGroup[s.group_name] = (studentCountByGroup[s.group_name] || 0) + 1; });

      const attemptsByExam: Record<number, any[]> = {};
      (attempts || []).forEach((a: any) => { (attemptsByExam[a.exam_id] ||= []).push(a); });

      const data = (exams || []).map((e: any) => {
        const examAttempts = attemptsByExam[e.id] || [];
        const scored = examAttempts.filter((a: any) => a.score !== null);
        return {
          id: e.id, title: e.title, groupName: e.group_name, durationMinutes: e.duration_minutes,
          isPublished: e.is_published, scheduledAt: e.scheduled_at, closesAt: e.closes_at, createdAt: e.created_at,
          countsTowardGrade: e.counts_toward_grade === true,
          totalStudents: studentCountByGroup[e.group_name] || 0,
          took: examAttempts.length,
          timedOut: examAttempts.filter((a: any) => a.status === "timed_out").length,
          avgScore: scored.length > 0 ? Math.round((scored.reduce((sum: number, a: any) => sum + (a.score || 0), 0) / scored.length) * 10) / 10 : 0,
        };
      });
      return new Response(JSON.stringify({ success: true, data }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "getOne") {
      const { examId } = body;
      const { data: exam } = await supabase.from("online_exams").select("*").eq("id", examId).maybeSingle();
      if (!exam || exam.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: questions } = await supabase.from("exam_questions").select("*").eq("exam_id", examId).order("order_index");
      const { data: targets } = await supabase.from("exam_target_students").select("student_uid").eq("exam_id", examId);
      const { data: groupStudents } = await supabase.from("students").select("uid, name").eq("teacher_id", tokenClientId).eq("group_name", exam.group_name);
      return new Response(JSON.stringify({
        success: true,
        data: { ...exam, questions: questions || [], targetStudentUids: (targets || []).map((t: any) => t.student_uid), groupStudents: groupStudents || [] },
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
