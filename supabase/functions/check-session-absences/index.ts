import { verifyToken } from "../_shared/auth.ts";
// supabase/functions/check-session-absences/index.ts
// ✅ بتتنادى دورياً (كل ما حد فاتح لوحة التحكم، أو عبر جدولة) — بتفحص كل حصص "النهاردة"
// (attendance_sessions اللي session_date = تاريخ اليوم) اللي فات عليها مدة احتساب الغياب
// الخاصة بيها (absence_threshold_minutes لكل حصة على حدة)، ولسه محدش سجّل حضور فيها،
// وتسجّلهم غايبين + تبعت إشعار. (Aug 2026 — Phase I follow-up 10: استبدال النظام القديم
// القائم على جدول أسبوعي متكرر group_sessions + عتبة عامة على مستوى المدرس)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  // ✅ (طلب) x-cron-secret مضافة عشان استدعاء الجدولة الدورية (pg_cron) اللي بيغطي كل
  // المدرسين مرة واحدة، بدل الاعتماد بس على فتح لوحة تحكم مدرس بعينه
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info, x-cron-secret",
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

// ✅ (طلب) منطق فحص واحتساب غياب مدرس واحد — اتفصل في دالة مستقلة عشان نقدر نستخدمه
// مرة واحدة (نداء توكن عادي من لوحة التحكم) أو في حلقة على كل المدرسين (نداء الجدولة
// الدورية اللي بتغطي كل الحسابات مرة واحدة، من غير ما حد يكون فاتح أي صفحة أصلاً)
async function processTeacherAbsences(
  supabase: any, teacherId: string, todayDateStr: string, nowMs: number
): Promise<{ absentMarked: number; notifRows: any[] }> {
  const { data: sessions } = await supabase
    .from("attendance_sessions").select("*").eq("teacher_id", teacherId).eq("session_date", todayDateStr);

  if (!sessions || sessions.length === 0) return { absentMarked: 0, notifRows: [] };

  let absentMarked = 0;
  const notifRows: any[] = [];

  for (const session of sessions) {
    const thresholdMinutes = session.absence_threshold_minutes ?? 30;
    const sessionStart = new Date(session.created_at);
    const elapsedMinutes = (nowMs - sessionStart.getTime()) / 60000;

    // ✅ الحصة دي وقتها فات بالمدة المحددة ليها هي بالذات؟ لو لأ، نتخطاها (لسه بدري نحكم على غياب حد)
    if (elapsedMinutes < thresholdMinutes) continue;

    // ✅ (طلب) دفعة 44: كان بيجيب بس الطلاب اللي المجموعة دي أساسية عندهم — الطلاب المربوطين
    // بيها كمجموعة ثانوية (تعدد مواد/مدرسين عن طريق student_group_links) مكانوش بيتحسبلهم
    // غياب خالص لو غابوا عن الحصة دي، بعكس تسجيل الحضور نفسه (record-attendance) اللي بيقبل
    // الاتنين. بنجمع الاتنين هنا كمان عشان الاحتساب يبقى متطابق مع اللي بيتسجل فعلاً
    const { data: primaryStudents } = await supabase
      .from("students").select("uid, name, parent_phone").eq("teacher_id", teacherId).eq("group_name", session.group_name);
    const { data: secondaryLinks } = await supabase
      .from("student_group_links").select("student_uid").eq("group_name", session.group_name);
    const secondaryUids = (secondaryLinks || []).map((l: any) => l.student_uid);
    let secondaryStudents: any[] = [];
    if (secondaryUids.length > 0) {
      const { data } = await supabase
        .from("students").select("uid, name, parent_phone").eq("teacher_id", teacherId).in("uid", secondaryUids);
      secondaryStudents = data || [];
    }
    const groupStudentsMap: Record<string, any> = {};
    [...(primaryStudents || []), ...secondaryStudents].forEach((s: any) => { groupStudentsMap[s.uid] = s; });
    const groupStudents = Object.values(groupStudentsMap);

    if (!groupStudents || groupStudents.length === 0) continue;

    // ✅ (مراجعة أداء) الاستعلامين "حاضر" و"سبق تسجيله غايب" كانا منفصلين وبيقروا نفس
    // الصفوف تقريباً — دمجناهم في استعلام واحد بس، وفرّقنا بينهم بعدين في الكود بـ is_absent
    const { data: existingAttendance } = await supabase
      .from("attendance").select("student_uid, is_absent")
      .in("student_uid", groupStudents.map((s: any) => s.uid))
      .eq("session_id", session.id);

    const presentUids = new Set((existingAttendance || []).filter((a: any) => !a.is_absent).map((a: any) => a.student_uid));
    // ✅ هل سبق اتسجّل غياب لنفس الحصة دي؟ (منع تكرار الإشعار لو الدالة اتنادت أكتر من مرة)
    const alreadyMarkedUids = new Set((existingAttendance || []).filter((a: any) => a.is_absent).map((a: any) => a.student_uid));

    // ✅ (مراجعة أداء) كان في INSERT منفصل جوه الحلقة لكل طالب غايب (لغاية 30+ نداء لقاعدة
    // البيانات لمجموعة واحدة كبيرة) — دلوقتي بنجمع كل صفوف الحصة دي ونعملها INSERT واحد مجمّع
    const absentRowsForSession: any[] = [];
    for (const student of groupStudents) {
      if (presentUids.has(student.uid) || alreadyMarkedUids.has(student.uid)) continue;

      // ✅ Batch 27: status مكنش بيتحط خالص هنا، فكان بياخد القيمة الافتراضية 'present' رغم
      // إن is_absent:true — تناقض بيكسر أي منطق بيعتمد على status بدل is_absent (زي حساب
      // نسبة الحضور في check-at-risk-alerts، اللي كان بيعتبر الغياب التلقائي ده "حضور" فعلي)
      absentRowsForSession.push({
        student_uid: student.uid, student_name: student.name, teacher_id: teacherId, group_name: session.group_name,
        session_id: session.id, session_label: session.session_label,
        date: todayDateStr, status: "absent", is_absent: true, created_at: new Date().toISOString(),
      });
      absentMarked++;

      if (student.parent_phone) {
        notifRows.push({
          teacher_id: teacherId, parent_phone: student.parent_phone, student_uid: student.uid,
          type: "absence", title: "تسجيل غياب", audience: "parent",
          message: `${student.name} محضرش ${session.session_label || "حصة"} النهاردة`,
          details: { student_name: student.name, group_name: session.group_name, session_label: session.session_label },
        });
      }
      // ✅ (طلب) نفس منطق عزل إشعارات الطالب عن ولي الأمر المطبّق على باقي الدوال — إشعار
      // مستقل للطالب نفسه بصيغة مخاطب مباشر، بغض النظر عن وجود رقم ولي الأمر من عدمه
      notifRows.push({
        teacher_id: teacherId, student_uid: student.uid,
        type: "absence", title: "تسجيل غياب", audience: "student",
        message: `اتسجّلت غايب في ${session.session_label || "حصة"} النهاردة`,
        details: { group_name: session.group_name, session_label: session.session_label },
      });
    }

    if (absentRowsForSession.length > 0) {
      await supabase.from("attendance").insert(absentRowsForSession);
    }
  }

  return { absentMarked, notifRows };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    // ✅ (طلب) بنقرا الـ body الأول (قبل أي تحقق) عشان نحدد نوع الاستدعاء: نداء نظامي من
    // جدولة السيرفر الدورية (pg_cron، بيغطي كل المدرسين مرة واحدة) أو نداء عادي بتوكن مستخدم
    // (مدرس واحد بس — زي ما كان شغّال قبل كده من لوحة التحكم)
    let body: any = {};
    try { body = await req.json(); } catch (_e) { body = {}; }

    const cronSecretEnv = Deno.env.get("CRON_SECRET");
    const providedCronSecret = req.headers.get("x-cron-secret");
    const isSystemRun = body?.systemRun === true && !!cronSecretEnv && providedCronSecret === cronSecretEnv;

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    // ✅ وقت النهاردة بتوقيت القاهرة (مش UTC)، عشان نطابق اليوم والوقت صح
    const now = new Date();
    const cairoNow = new Date(now.toLocaleString("en-US", { timeZone: "Africa/Cairo" }));
    const todayDateStr = cairoNow.toISOString().split("T")[0];
    const nowMs = now.getTime();

    let teacherIds: string[] = [];
    if (isSystemRun) {
      // ✅ (طلب) الفحص لازم يشتغل في الخلفية لوحده حتى لو كل الصفحات مقفولة — بنجيب كل
      // المدرسين اللي عندهم حصص النهاردة (بغض النظر عن مين فاتح إيه)، ونفحص غيابهم كلهم
      // في نفس النداء الدوري ده
      const { data: teacherRows } = await supabase
        .from("attendance_sessions").select("teacher_id").eq("session_date", todayDateStr);
      teacherIds = Array.from(new Set((teacherRows || []).map((r: any) => r.teacher_id).filter(Boolean)));
    } else {
      const payload = await verifyToken(req);
      const tokenClientId = payload.clientId || payload.teacherId;
      if (!tokenClientId) throw new Error("⚠️ توكن غير صالح");
      teacherIds = [tokenClientId];
    }

    if (teacherIds.length === 0) {
      return new Response(JSON.stringify({ success: true, message: "مفيش حصص اتنشأت النهاردة", absentCount: 0 }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    let totalAbsentMarked = 0;
    const allNotifRows: any[] = [];

    for (const teacherId of teacherIds) {
      const { absentMarked, notifRows } = await processTeacherAbsences(supabase, teacherId, todayDateStr, nowMs);
      totalAbsentMarked += absentMarked;
      allNotifRows.push(...notifRows);
    }

    if (allNotifRows.length > 0) {
      await supabase.from("notifications").insert(allNotifRows);
      // ✅ (طلب) تسجيل الغياب مكانش بيبعت Push حقيقي خالص لولي الأمر أو الطالب — بس إشعار جوه التطبيق فوق
      allNotifRows.forEach((r: any) => {
        if (r.audience === "parent" && r.parent_phone) sendPushToRecipient(supabase, "parent", r.parent_phone, r.title, r.message);
        else if (r.audience === "student" && r.student_uid) sendPushToRecipient(supabase, "student", r.student_uid, r.title, r.message);
      });
    }

    return new Response(JSON.stringify({
      success: true, message: `✅ اتسجّل غياب ${totalAbsentMarked} طالب`,
      absentCount: totalAbsentMarked, teachersProcessed: teacherIds.length,
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
