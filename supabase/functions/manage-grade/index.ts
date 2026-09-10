// supabase/functions/manage-grade/index.ts
// ✅ دالة موحّدة تجمع add-grade + update-grade + delete-grade بـ "action" parameter
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
  "Access-Control-Max-Age": "86400",
};

export interface TokenPayload {
  sub: string; clientId?: string; teacherId?: string; username?: string; phone?: string;
  role: "teacher" | "assistant" | "parent"; name: string; exp: number;
}

export class AuthError extends Error {
  status: number; code?: string;
  constructor(message: string, status = 401, code?: string) { super(message); this.status = status; this.code = code; }
}

async function getKey() {
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) throw new Error("⚠️ JWT_SECRET غير مضبوط في متغيرات البيئة");
  return await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
}

async function licenseCheckClient() {
  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2.38.4");
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

async function checkLicenseActive(teacherClientId: string): Promise<{ active: boolean; reason?: string }> {
  if (teacherClientId === "master_admin") return { active: true };
  const supabase = await licenseCheckClient();
  const { data: teacher, error } = await supabase.from("teachers").select("is_active, expiry_date").eq("client_id", teacherClientId).maybeSingle();
  if (error || !teacher) return { active: false, reason: "الحساب غير موجود" };
  if (teacher.is_active === false) return { active: false, reason: "الحساب معطّل" };
  if (teacher.expiry_date) {
    const todayCLA = new Date().toISOString().split("T")[0];
    if (teacher.expiry_date < todayCLA) return { active: false, reason: "انتهت صلاحية الترخيص" };
  }
  return { active: true };
}

export async function verifyToken(req: Request): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) throw new AuthError("⚠️ التوكن مطلوب", 401);
  const token = authHeader.substring(7);
  const key = await getKey();
  let payload: TokenPayload;
  try { payload = (await verify(token, key, "HS256")) as unknown as TokenPayload; }
  catch (_e) { throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401); }
  if (payload.role === "teacher" || payload.role === "assistant") {
    const ownerId = payload.clientId || payload.teacherId;
    if (ownerId) {
      const license = await checkLicenseActive(ownerId);
      if (!license.active) throw new AuthError(`⛔ ${license.reason || "انتهت صلاحية الترخيص"} — يرجى التواصل مع الإدارة`, 402, "LICENSE_EXPIRED");
    }
  }
  return payload;
}

export function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

export async function requireTeacherPlanPermission(clientId: string, permKey: string): Promise<void> {
  if (clientId === "master_admin") return;
  const supabase = await licenseCheckClient();
  const { data: teacher } = await supabase.from("teachers").select("permissions").eq("client_id", clientId).maybeSingle();
  const perms = teacher?.permissions || {};
  if (perms[permKey] === false) throw new AuthError("⛔ هذه الميزة غير متاحة في باقتك الحالية، تواصل مع الإدارة لتفعيلها", 403, "PLAN_RESTRICTED");
}

export async function requireAssistantPermission(payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const supabase = await licenseCheckClient();
  const { data: assistant } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) throw new AuthError("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس", 403);
}

// ============================================
// Push Notifications (Firebase FCM)
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

// ============================================
// ⭐ العملية 1: رصد درجة (منطق add-grade الأصلي كامل)
// ============================================
async function handleAdd(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_grades");
  await requireAssistantPermission(payload, "record_grades");

  const { clientId, studentUid, studentUids, examName, maxScore, score, assistantId, assistantName, groupName } = body;
  const uidsList: string[] = Array.isArray(studentUids) && studentUids.length > 0 ? studentUids : (studentUid ? [studentUid] : []);

  if (!clientId || uidsList.length === 0 || !examName || maxScore === undefined || score === undefined) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  // ✅ (طلب) لازم نعرف تحت أي مجموعة بيتسجّل الامتحان ده — عشان امتحانات كل مجموعة تفضل منفصلة
  // عن التانية، وميحصلش تداخل لطالب مربوط بأكتر من مجموعة (تعدد المواد/المدرسين)
  if (!groupName) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ المجموعة مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (isNaN(Number(score)) || Number(score) < 0 || isNaN(Number(maxScore)) || Number(maxScore) <= 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ أدخل درجة ودرجة نهائية صحيحتين" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (Number(score) > Number(maxScore)) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ الدرجة (${score}) مايصحش تكون أكبر من الدرجة النهائية (${maxScore})` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (tokenClientId !== clientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ (طلب) اسم الامتحان بقى مرتبط بمجموعة معيّنة — نفس الاسم ("امتحان 1" مثلاً) ممكن يتكرر
  // في أكتر من مجموعة كامتحانين مختلفين تماماً (مواد مختلفة)، من غير ما يتلخبطوا مع بعض
  const { error: examTitleError } = await supabase.from("exam_titles").upsert(
    { teacher_id: clientId, title: examName, default_max_score: Number(maxScore), group_name: groupName },
    { onConflict: "teacher_id,title,group_name", ignoreDuplicates: false }
  );
  if (examTitleError) console.error("⚠️ فشل تسجيل اسم الامتحان في القائمة:", examTitleError.message);

  const { data: notifyTeacherInfo } = await supabase.from("teachers").select("name").eq("client_id", clientId).maybeSingle();
  const teacherLabel = notifyTeacherInfo?.name ? ` — مدرس ${notifyTeacherInfo.name}` : "";
  const performerId = assistantId || clientId;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = assistantId ? (assistantName || "مساعد") : (notifyTeacherInfo?.name || "مدرس");
  const percent = Number(maxScore) > 0 ? Math.round((Number(score) / Number(maxScore)) * 100) : 0;

  const results: any[] = [];
  const loggedStudents: any[] = [];
  const skipped: string[] = [];

  // ✅ الطلاب المشتركين (student_teacher_links) بيقدر المدرس يرصد لهم درجات كمان، مش بس طلابه الأساسيين
  const { data: myLinks } = await supabase.from("student_teacher_links").select("student_uid").eq("teacher_id", clientId);
  const linkedUidsForMe = new Set((myLinks || []).map((l: any) => l.student_uid));

  // ✅ (طلب) فحص "اتسجّلت له درجة بالفعل" لازم يتقيّد بنفس المجموعة (groupName) كمان، مش بس اسم
  // الامتحان — وإلا طالب مربوط بمجموعتين وليه امتحان بنفس الاسم في الاتنين (مواد مختلفة) هيتمنع
  // من رصد الدرجة التانية بالغلط لمجرد إن الاسم اتكرر
  const [{ data: candidateStudents }, { data: existingGrades }] = await Promise.all([
    supabase.from("students").select("uid, name, group_name, teacher_id, parent_phone").in("uid", uidsList),
    supabase.from("grades").select("student_uid").in("student_uid", uidsList).eq("teacher_id", clientId).eq("exam_name", examName).eq("group_name", groupName),
  ]);
  const foundStudents = (candidateStudents || []).filter((s: any) => s.teacher_id === clientId || linkedUidsForMe.has(s.uid));

  const studentsByUid = new Map((foundStudents || []).map((s: any) => [s.uid, s]));
  const alreadyGradedUids = new Set((existingGrades || []).map((g: any) => g.student_uid));
  for (const uid of uidsList) {
    if (!studentsByUid.has(uid)) { skipped.push(`${uid} (طالب غير موجود)`); continue; }
    if (alreadyGradedUids.has(uid)) skipped.push(`${studentsByUid.get(uid).name} (اتسجّلت له درجة في "${examName}" بالفعل)`);
  }
  const validStudents = uidsList.map((uid) => studentsByUid.get(uid)).filter((s) => s && !alreadyGradedUids.has(s.uid)) as any[];

  if (validStudents.length > 0) {
    // ✅ (طلب) group_name بيتسجّل بالمجموعة اللي المدرس بيرصد الدرجة تحتها فعلياً (groupName)، مش
    // بمجموعة الطالب الأساسية (student.group_name) — عشان طالب مربوط بمجموعة إضافية (تعدد
    // المواد/المدرسين) لما يتاخد امتحان تحت المجموعة التانية، الدرجة تتسجّل صح تحتها هي، مش تحت
    // مجموعته الأساسية بالغلط (وده كان بيسبب ظهور امتحانات مجموعة تحت مجموعة تانية غلط)
    const { data: insertedGrades, error: insertError } = await supabase.from("grades").insert(validStudents.map((student) => ({
      student_uid: student.uid, student_name: student.name, teacher_id: clientId, group_name: groupName,
      exam_name: examName, score: Number(score), max_score: Number(maxScore),
    }))).select();

    if (insertError) {
      console.error("❌ خطأ في إدراج الدرجات:", insertError);
    } else if (insertedGrades) {
      results.push(...insertedGrades);
      loggedStudents.push(...validStudents.map((s) => ({ name: s.name, uid: s.uid, group_name: groupName })));
      // ✅ (طلب) الإشعارات لازم تتفصل بين الطالب وولي الأمر — صف مستقل لكل جمهور بنص مخصص له
      // (بدل صف واحد مشترك كان بيظهر لكل الاتنين بنفس النص العام)، معلّم بعمود audience عشان
      // get-notifications تقدر تفلتر كل جمهور على صفوفه بس
      const notifRows = [
        ...validStudents.filter((s) => s.parent_phone).map((s) => ({
          teacher_id: clientId, parent_phone: s.parent_phone, student_uid: s.uid, type: "grade", title: "رصد درجة", audience: "parent",
          message: `${s.name} حصل على ${score}/${maxScore} في "${examName}" (${percent}%)${teacherLabel}`,
          details: { student_name: s.name, exam_name: examName, score: Number(score), max_score: Number(maxScore), percent },
        })),
        ...validStudents.map((s) => ({
          teacher_id: clientId, student_uid: s.uid, type: "grade", title: "رصد درجة", audience: "student",
          message: `حصلت على ${score}/${maxScore} في "${examName}" (${percent}%)${teacherLabel}`,
          details: { exam_name: examName, score: Number(score), max_score: Number(maxScore), percent },
        })),
      ];
      if (notifRows.length > 0) {
        await supabase.from("notifications").insert(notifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعارات الدرجات:", error.message); });
        validStudents.filter((s) => s.parent_phone).forEach((s) => {
          sendPushToRecipient(supabase, "parent", s.parent_phone, "رصد درجة", `${s.name} حصل على ${score}/${maxScore} في "${examName}" (${percent}%)${teacherLabel}`);
        });
        validStudents.forEach((s) => {
          sendPushToRecipient(supabase, "student", s.uid, "رصد درجة", `حصلت على ${score}/${maxScore} في "${examName}" (${percent}%)${teacherLabel}`);
        });
      }
    }
  }

  if (results.length === 0) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ مفيش أي درجة اتسجّلت: ${skipped.join("، ")}`, skipped }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const isBulk = loggedStudents.length > 1;
  await supabase.from("activity_logs").insert({
    client_id: clientId, teacher_id: clientId, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: isBulk ? "bulk_add_grade" : "add_grade", entity_type: "grade", entity_id: String(results[0].id),
    details: isBulk
      ? { exam_name: examName, score: Number(score), max_score: Number(maxScore), count: loggedStudents.length, students: loggedStudents }
      : { student_name: loggedStudents[0].name, student_uid: loggedStudents[0].uid, exam_name: examName, score: Number(score), max_score: Number(maxScore), group_name: loggedStudents[0].group_name },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  let message = uidsList.length === 1 ? "تم رصد الدرجة بنجاح" : `تم رصد الدرجة لـ ${results.length} طالب بنجاح`;
  if (skipped.length > 0) message += ` (اتخطّى: ${skipped.join("، ")})`;

  return new Response(JSON.stringify({ success: true, message, data: results.length === 1 ? results[0] : results }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 2: تعديل درجة (منطق update-grade الأصلي كامل)
// ============================================
async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_grades");
  await requireAssistantPermission(payload, "record_grades");

  const { gradeId, score, assistantId, assistantName } = body;
  if (!gradeId || score === undefined) {
    return new Response(JSON.stringify({ success: false, message: "معرف الدرجة والدرجة الجديدة مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: oldGrade, error: fetchError } = await supabase.from("grades").select("*, students(name, uid, teacher_id, group_name, parent_phone)").eq("id", gradeId).single();
  if (fetchError || !oldGrade) {
    return new Response(JSON.stringify({ success: false, message: "الدرجة غير موجودة" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldGrade.students?.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه الدرجة ليست تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const oldScore = oldGrade.score;
  const newScore = Number(score);
  if (isNaN(newScore) || newScore < 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ أدخل درجة صحيحة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (newScore > oldGrade.max_score) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ الدرجة (${newScore}) مايصحش تكون أكبر من الدرجة النهائية (${oldGrade.max_score})` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldScore === newScore) {
    return new Response(JSON.stringify({ success: true, message: "لا توجد تغييرات في الدرجة" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: updatedGrade, error: updateError } = await supabase.from("grades").update({ score: newScore }).eq("id", gradeId).select().single();
  if (updateError) throw new Error(updateError.message);

  const teacherId = oldGrade.students?.teacher_id;
  const performerId = assistantId || teacherId;
  const performerRole = assistantId ? "assistant" : "teacher";
  let performerName = assistantId ? (assistantName || "مساعد") : "مدرس";
  if (!assistantId) {
    const { data: performerTeacherInfo } = await supabase.from("teachers").select("name").eq("client_id", teacherId).maybeSingle();
    performerName = performerTeacherInfo?.name || "مدرس";
  }

  await supabase.from("activity_logs").insert({
    client_id: teacherId, teacher_id: teacherId, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "edit_grade", entity_type: "grade", entity_id: String(gradeId),
    details: { student_name: oldGrade.students?.name, student_uid: oldGrade.students?.uid, exam_name: oldGrade.exam_name, old_score: oldScore, new_score: newScore, max_score: oldGrade.max_score, changes: { score: { old: oldScore, new: newScore } } },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  {
    const percent = oldGrade.max_score > 0 ? Math.round((newScore / oldGrade.max_score) * 100) : 0;
    const editNotifRows = [
      ...(oldGrade.students?.parent_phone ? [{
        teacher_id: teacherId, parent_phone: oldGrade.students.parent_phone, student_uid: oldGrade.students.uid, type: "grade", title: "تعديل درجة", audience: "parent",
        message: `تم تعديل درجة ${oldGrade.students.name} في "${oldGrade.exam_name}" من ${oldScore} إلى ${newScore}/${oldGrade.max_score} (${percent}%)`,
        details: { student_name: oldGrade.students.name, exam_name: oldGrade.exam_name, old_score: oldScore, new_score: newScore, max_score: oldGrade.max_score, percent },
      }] : []),
      {
        teacher_id: teacherId, student_uid: oldGrade.students?.uid, type: "grade", title: "تعديل درجة", audience: "student",
        message: `تم تعديل درجتك في "${oldGrade.exam_name}" من ${oldScore} إلى ${newScore}/${oldGrade.max_score} (${percent}%)`,
        details: { exam_name: oldGrade.exam_name, old_score: oldScore, new_score: newScore, max_score: oldGrade.max_score, percent },
      },
    ];
    await supabase.from("notifications").insert(editNotifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعار تعديل الدرجة:", error.message); });
    if (oldGrade.students?.parent_phone) {
      sendPushToRecipient(supabase, "parent", oldGrade.students.parent_phone, "تعديل درجة", `تم تعديل درجة ${oldGrade.students.name} في "${oldGrade.exam_name}" من ${oldScore} إلى ${newScore}/${oldGrade.max_score} (${percent}%)`);
    }
    if (oldGrade.students?.uid) {
      sendPushToRecipient(supabase, "student", oldGrade.students.uid, "تعديل درجة", `تم تعديل درجتك في "${oldGrade.exam_name}" من ${oldScore} إلى ${newScore}/${oldGrade.max_score} (${percent}%)`);
    }
  }

  return new Response(JSON.stringify({ success: true, message: "تم تحديث الدرجة بنجاح", data: updatedGrade }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 3: حذف درجة (منطق delete-grade الأصلي كامل)
// ============================================
async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_grades");
  await requireAssistantPermission(payload, "record_grades");

  const { gradeId, assistantId, assistantName } = body;
  if (!gradeId) {
    return new Response(JSON.stringify({ success: false, message: "معرف الدرجة مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: grade, error: fetchError } = await supabase.from("grades").select("*, students(name, uid, teacher_id, group_name, parent_phone)").eq("id", parseInt(gradeId)).single();
  if (fetchError || !grade) {
    return new Response(JSON.stringify({ success: false, message: "الدرجة غير موجودة" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (grade.students?.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه الدرجة ليست تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error: deleteError } = await supabase.from("grades").delete().eq("id", parseInt(gradeId));
  if (deleteError) throw new Error(deleteError.message);

  const teacherId = grade.students?.teacher_id;
  const performerId = assistantId || teacherId;
  const performerRole = assistantId ? "assistant" : "teacher";
  let performerName = assistantId ? (assistantName || "مساعد") : "مدرس";
  if (!assistantId) {
    const { data: performerTeacherInfo } = await supabase.from("teachers").select("name").eq("client_id", teacherId).maybeSingle();
    performerName = performerTeacherInfo?.name || "مدرس";
  }

  await supabase.from("activity_logs").insert({
    client_id: teacherId, teacher_id: teacherId, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "delete_grade", entity_type: "grade", entity_id: String(gradeId),
    details: { student_name: grade.students?.name, student_uid: grade.students?.uid, exam_name: grade.exam_name, score: grade.score, max_score: grade.max_score, group_name: grade.students?.group_name },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  // ✅ (تعديل) حذف الدرجة مكانش بيبعت أي إشعار لولي الأمر/الطالب — بيتحذف بصمت من غير ما
  // حد يعرف، بعكس التعديل اللي بيبعت إشعار. أضفنا نفس منطق إشعار التعديل هنا
  if (grade.students?.uid) {
    const deleteNotifRows = [
      ...(grade.students?.parent_phone ? [{
        teacher_id: teacherId, parent_phone: grade.students.parent_phone, student_uid: grade.students.uid, type: "grade", title: "حذف درجة", audience: "parent",
        message: `تم حذف درجة ${grade.students.name} في "${grade.exam_name}" (${grade.score}/${grade.max_score})`,
        details: { student_name: grade.students.name, exam_name: grade.exam_name, score: grade.score, max_score: grade.max_score },
      }] : []),
      {
        teacher_id: teacherId, student_uid: grade.students.uid, type: "grade", title: "حذف درجة", audience: "student",
        message: `تم حذف درجتك في "${grade.exam_name}" (${grade.score}/${grade.max_score})`,
        details: { exam_name: grade.exam_name, score: grade.score, max_score: grade.max_score },
      },
    ];
    await supabase.from("notifications").insert(deleteNotifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعار حذف الدرجة:", error.message); });
    // ✅ (طلب) حذف الدرجة مكانش بيبعت Push حقيقي خالص لولي الأمر أو الطالب
    if (grade.students?.parent_phone) {
      sendPushToRecipient(supabase, "parent", grade.students.parent_phone, "حذف درجة", `تم حذف درجة ${grade.students.name} في "${grade.exam_name}" (${grade.score}/${grade.max_score})`);
    }
    sendPushToRecipient(supabase, "student", grade.students.uid, "حذف درجة", `تم حذف درجتك في "${grade.exam_name}" (${grade.score}/${grade.max_score})`);
  }

  return new Response(JSON.stringify({ success: true, message: "تم حذف الدرجة بنجاح", data: { gradeId: parseInt(gradeId), student_name: grade.students?.name, exam_name: grade.exam_name } }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ Aug 2026: حذف "اسم امتحان" بالكامل من قائمة exam_titles — بيُرفض لو فيه درجات
// مسجّلة تحته فعلاً (المستخدم لازم يمسح الدرجات دي الأول)، عشان منمسحش بيانات طلاب
// بالغلط من غير قصد صريح
// ============================================
async function handleDeleteTitle(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_grades");
  await requireAssistantPermission(payload, "record_grades");

  const { title, groupName } = body;
  const cleanTitle = (title || "").trim();
  if (!cleanTitle) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ اسم الامتحان مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ (طلب) الحذف والفحص لازم يتقيّدوا بالمجموعة كمان — وإلا حذف "امتحان 1" من مجموعة هيتمنع
  // بالغلط بسبب درجات "امتحان 1" في مجموعة تانية خالص (اسم متشابه بس امتحان مختلف)
  let gradesCountQuery = supabase.from("grades").select("id", { count: "exact", head: true })
    .eq("teacher_id", tokenClientId).eq("exam_name", cleanTitle);
  let deleteQuery = supabase.from("exam_titles").delete().eq("teacher_id", tokenClientId).eq("title", cleanTitle);
  if (groupName) {
    gradesCountQuery = gradesCountQuery.eq("group_name", groupName);
    deleteQuery = deleteQuery.eq("group_name", groupName);
  }

  const { count: gradesCount } = await gradesCountQuery;
  if (gradesCount && gradesCount > 0) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ فيه ${gradesCount} درجة مسجّلة تحت "${cleanTitle}" — لازم تمسحيها الأول من "الدرجات المسجلة" قبل ما تقدري تمسحي اسم الامتحان نفسه` }),
      { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error: deleteError } = await deleteQuery;
  if (deleteError) throw new Error(deleteError.message);

  return new Response(JSON.stringify({ success: true, message: `✅ تم حذف "${cleanTitle}" من قائمة أسماء الامتحانات` }),
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
    if (action === "add") return await handleAdd(supabase, payload, body);
    if (action === "update") return await handleUpdate(supabase, payload, body);
    if (action === "delete") return await handleDelete(supabase, payload, body);
    if (action === "deleteTitle") return await handleDeleteTitle(supabase, payload, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة — لازم تكون add أو update أو delete أو deleteTitle" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في manage-grade:", error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
