// supabase/functions/check-scheduled-exams/index.ts
// ✅ بتتنادى دورياً (كل ما حد فاتح لوحة التحكم أو صفحة الطالب) — بتنشر أي اختبار وصل وقت جدولته ولسه مانشرش
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verifyToken } from "../_shared/auth.ts";

// ✅ (هجرة Supabase Auth) الدالة دي كانت لسه بتتحقق بمنطقها الخاص (توكن مخصص قديم بـJWT_SECRET)
// بدل ما تستورد من _shared/auth.ts زي باقي الفانكشنز — نفس نوع الاستثناء اللي كان في
// manage-student.ts قبل ما نصلحه. دلوقتي بتستخدم verifyToken الموحّد؛ أي مستخدم مسجّل دخول
// (مدرس أو طالب، أيًا كان) يكفي — أو x-cron-secret لو هتتحول لـ pg_cron حقيقي لاحقًا.
async function verifyAnyToken(req: Request): Promise<boolean> {
  try {
    await verifyToken(req, { skipLicenseCheck: true });
    return true;
  } catch (_e) {
    return false;
  }
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
};

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

// ✅ نفس منطق النشر والإشعار المستخدم في manage-exam، بس مستقل هنا عشان الدالة دي ماتحتاجش توكن مدرس محدد
async function publishExamAndNotify(supabase: any, exam: any): Promise<number> {
  await supabase.from("online_exams").update({ is_published: true }).eq("id", exam.id);

  const { data: teacher } = await supabase.from("teachers").select("name").eq("client_id", exam.teacher_id).maybeSingle();
  const { data: targets } = await supabase.from("exam_target_students").select("student_uid").eq("exam_id", exam.id);
  const targetUids = (targets || []).map((t: any) => t.student_uid);

  let studentsQuery = supabase.from("students").select("uid, parent_phone").eq("teacher_id", exam.teacher_id).eq("group_name", exam.group_name);
  if (targetUids.length > 0) studentsQuery = studentsQuery.in("uid", targetUids);
  const { data: students } = await studentsQuery;

  const teacherLabel = teacher?.name ? ` — مدرس ${teacher.name}` : "";
  const parentRows = (students || []).filter((s: any) => s.parent_phone).map((s: any) => ({
    teacher_id: exam.teacher_id, parent_phone: s.parent_phone, student_uid: s.uid, type: "exam", audience: "parent",
    title: "اختبار جديد", message: `اختبار "${exam.title}" جاهز الآن لـ ${exam.group_name} — مدته ${exam.duration_minutes} دقيقة${teacherLabel}`,
    details: { exam_title: exam.title, exam_id: exam.id, group_name: exam.group_name },
  }));
  const studentRows = (students || []).map((s: any) => ({
    teacher_id: exam.teacher_id, student_uid: s.uid, type: "exam", audience: "student",
    title: "اختبار جديد", message: `عندك اختبار جديد "${exam.title}" — مدته ${exam.duration_minutes} دقيقة، ادخل واختبر نفسك دلوقتي${teacherLabel}`,
    details: { exam_title: exam.title, exam_id: exam.id, group_name: exam.group_name },
  }));
  const notifRows = [...parentRows, ...studentRows];
  if (notifRows.length > 0) await supabase.from("notifications").insert(notifRows);
  parentRows.forEach((r: any) => { sendPushToRecipient(supabase, "parent", r.parent_phone, r.title, r.message); });
  studentRows.forEach((r: any) => { sendPushToRecipient(supabase, "student", r.student_uid, r.title, r.message); });
  return parentRows.length;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const cronSecretEnv = Deno.env.get("CRON_SECRET");
    const providedCronSecret = req.headers.get("x-cron-secret");
    const isSystemRun = !!cronSecretEnv && providedCronSecret === cronSecretEnv;
    if (!isSystemRun && !(await verifyAnyToken(req))) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ التوكن مطلوب" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const { data: dueExams } = await supabase
      .from("online_exams").select("*")
      .eq("is_published", false)
      .not("scheduled_at", "is", null)
      .lte("scheduled_at", new Date().toISOString());

    // ✅ (أداء) كان بيعمل استعلام عدّ أسئلة منفصل لكل اختبار مستحق على حدة — بقى استعلام واحد
    // لكل الاختبارات مع بعض، والعدّ بيتحسب في الكود بدل ما يتكرر لكل اختبار
    const examIds = (dueExams || []).map((e: any) => e.id);
    const questionCountByExam = new Map<number, number>();
    if (examIds.length > 0) {
      const { data: allQuestions } = await supabase.from("exam_questions").select("exam_id").in("exam_id", examIds);
      (allQuestions || []).forEach((q: any) => questionCountByExam.set(q.exam_id, (questionCountByExam.get(q.exam_id) || 0) + 1));
    }

    let publishedCount = 0;
    for (const exam of dueExams || []) {
      const qCount = questionCountByExam.get(exam.id) || 0;
      if (qCount === 0) continue; // اختبار فاضي من الأسئلة، منشرهوش لحد ما يتضاف له أسئلة
      await publishExamAndNotify(supabase, exam);
      publishedCount++;
    }

    return new Response(JSON.stringify({ success: true, publishedCount }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
