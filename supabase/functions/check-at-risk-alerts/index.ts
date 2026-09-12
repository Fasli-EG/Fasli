// supabase/functions/check-at-risk-alerts/index.ts
// ✅ نسخة استباقية من get-at-risk-students: بدل ما تفضل التقرير مستني المدرس يفتح الصفحة
// عشان يشوفه، الدالة دي بتتشغل يومياً (pg_cron) لكل المدرسين مرة واحدة، وبتبعت Push notification
// حقيقي لأي مدرس عنده طالب "جديد" دخل في دايرة الخطر (مش اتقالت له عنه قبل كده في آخر 7 أيام،
// عشان مايتكررش نفس التنبيه كل يوم لنفس الطالب من غير أي جديد).
//
// بيقبل نفس نمط x-cron-secret + systemRun اللي في check-session-absences بالظبط، وبرضه
// بيشتغل بتوكن مستخدم عادي (مدرس واحد بس) لتجربة يدوية من لوحة التحكم أو من الاختبارات.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders as baseCorsHeaders, verifyToken, AuthError, authErrorResponse } from "../_shared/auth.ts";

const corsHeaders = { ...baseCorsHeaders, "Access-Control-Allow-Headers": baseCorsHeaders["Access-Control-Allow-Headers"] + ", x-cron-secret" };

// ============================================
// (من _shared/push.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
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

async function sendPushToRecipient(supabase: any, recipientType: string, recipientId: string, title: string, body: string): Promise<void> {
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
        }
      }
    }
  } catch (error) {
    console.error("⚠️ خطأ غير متوقع في إرسال Push notification:", error);
  }
}

// ✅ نفس منطق تحليل الخطر بالظبط اللي في get-at-risk-students — مدموج هنا مباشرة (Dashboard
// مايدعمش استيراد فانكشن من فانكشن تانية)، عشان الرقم/الأسباب يفضلوا متطابقين بين الصفحة والتنبيه
async function computeAtRiskStudents(supabase: any, teacherId: string) {
  const { data: students } = await supabase.from("students").select("uid, name, group_name, parent_phone").eq("teacher_id", teacherId);
  if (!students || students.length === 0) return [];

  const uids = students.map((s: any) => s.uid);
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();

  const [{ data: recentAttendance }, { data: olderAttendance }, { data: recentPayments }] = await Promise.all([
    supabase.from("attendance").select("student_uid, status, created_at").in("student_uid", uids).gte("created_at", thirtyDaysAgo),
    supabase.from("attendance").select("student_uid, status, created_at").in("student_uid", uids).gte("created_at", sixtyDaysAgo).lt("created_at", thirtyDaysAgo),
    supabase.from("payments").select("student_uid, amount, total_amount, created_at").in("student_uid", uids).order("created_at", { ascending: false }),
  ]);

  const results: any[] = [];
  for (const student of students) {
    const reasons: string[] = [];
    let riskScore = 0;
    const recentRecords = (recentAttendance || []).filter((a: any) => a.student_uid === student.uid);
    const olderRecords = (olderAttendance || []).filter((a: any) => a.student_uid === student.uid);
    const recentPresentRate = recentRecords.length > 0 ? recentRecords.filter((a: any) => a.status === "present").length / recentRecords.length : null;
    const olderPresentRate = olderRecords.length > 0 ? olderRecords.filter((a: any) => a.status === "present").length / olderRecords.length : null;

    if (recentPresentRate !== null && olderPresentRate !== null && (olderPresentRate - recentPresentRate) > 0.25) {
      riskScore += 2;
      reasons.push(`نسبة الحضور نزلت من ${Math.round(olderPresentRate * 100)}% لـ ${Math.round(recentPresentRate * 100)}%`);
    } else if (recentPresentRate !== null && recentPresentRate < 0.5 && recentRecords.length >= 3) {
      riskScore += 1;
      reasons.push(`نسبة الحضور في آخر شهر ${Math.round(recentPresentRate * 100)}% بس`);
    }
    if (recentRecords.length === 0 && olderRecords.length > 0) {
      riskScore += 2;
      reasons.push("مفيش أي حضور مسجّل في آخر شهر");
    }
    const studentPayments = (recentPayments || []).filter((p: any) => p.student_uid === student.uid);
    if (studentPayments.length > 0) {
      const lastPayment = studentPayments[0];
      const isPartial = Number(lastPayment.amount) < Number(lastPayment.total_amount);
      const daysSinceLastPayment = (Date.now() - new Date(lastPayment.created_at).getTime()) / (1000 * 60 * 60 * 24);
      if (isPartial) { riskScore += 1; reasons.push("آخر دفعة كانت جزئية ومحصّلتش بالكامل"); }
      if (daysSinceLastPayment > 45) { riskScore += 1; reasons.push(`آخر سداد كان من ${Math.round(daysSinceLastPayment)} يوم`); }
    }
    if (riskScore >= 2) {
      results.push({ studentUid: student.uid, studentName: student.name, groupName: student.group_name, riskScore, reasons });
    }
  }
  return results;
}

const ALERT_TYPE = "at_risk_alert";
const RENOTIFY_AFTER_DAYS = 7;

async function alertTeacherForAtRiskStudents(supabase: any, teacherId: string): Promise<number> {
  const atRiskStudents = await computeAtRiskStudents(supabase, teacherId);
  if (atRiskStudents.length === 0) return 0;

  const cutoff = new Date(Date.now() - RENOTIFY_AFTER_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const { data: recentAlerts } = await supabase
    .from("notifications").select("student_uid").eq("teacher_id", teacherId).eq("type", ALERT_TYPE).gte("created_at", cutoff);
  const alreadyAlertedUids = new Set((recentAlerts || []).map((n: any) => n.student_uid));

  const newlyAtRisk = atRiskStudents.filter((s: any) => !alreadyAlertedUids.has(s.studentUid));
  if (newlyAtRisk.length === 0) return 0;

  const notifRows = newlyAtRisk.map((s: any) => ({
    teacher_id: teacherId, student_uid: s.studentUid, student_name: s.studentName, audience: "teacher",
    type: ALERT_TYPE, title: "⚠️ طالب معرّض للخطر", message: `${s.studentName} (${s.groupName || "بدون مجموعة"}) — ${s.reasons[0] || "نمط حضور/سداد غير منتظم"}`,
    details: { riskScore: s.riskScore, reasons: s.reasons },
  }));
  await supabase.from("notifications").insert(notifRows);

  const pushBody = newlyAtRisk.length === 1
    ? `${newlyAtRisk[0].studentName} بقى معرّض للخطر — ${newlyAtRisk[0].reasons[0]}`
    : `${newlyAtRisk.length} طلاب جداد دخلوا دايرة الخطر — افتح تقرير الإنذار المبكر للتفاصيل`;
  await sendPushToRecipient(supabase, "teacher", teacherId, "⚠️ إنذار مبكر", pushBody);

  return newlyAtRisk.length;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    let body: any = {};
    try { body = await req.json(); } catch (_e) { body = {}; }

    const cronSecretEnv = Deno.env.get("AT_RISK_CRON_SECRET");
    const providedCronSecret = req.headers.get("x-cron-secret");
    const isSystemRun = body?.systemRun === true && !!cronSecretEnv && providedCronSecret === cronSecretEnv;

    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    let teacherIds: string[] = [];
    if (isSystemRun) {
      const { data: teacherRows } = await supabase.from("teachers").select("client_id").eq("is_active", true);
      teacherIds = (teacherRows || []).map((t: any) => t.client_id);
    } else {
      const payload = await verifyToken(req);
      if (payload.role !== "teacher" && payload.role !== "assistant") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      teacherIds = [payload.clientId || payload.teacherId].filter(Boolean) as string[];
    }

    let totalAlerted = 0;
    for (const teacherId of teacherIds) {
      totalAlerted += await alertTeacherForAtRiskStudents(supabase, teacherId);
    }

    return new Response(JSON.stringify({ success: true, teachersChecked: teacherIds.length, studentsAlerted: totalAlerted }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ:", error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
