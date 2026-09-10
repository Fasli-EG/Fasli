// supabase/functions/manage-payment/index.ts
// ✅ دالة موحّدة تجمع add-payment + update-payment + delete-payment بـ "action" parameter
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
// ⭐ العملية 1: تسجيل دفعة (منطق add-payment الأصلي كامل)
// ============================================
async function handleAdd(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_payments");
  await requireAssistantPermission(payload, "record_payments");

  const { clientId, studentUid, studentUids, title, totalAmount, amount, assistantId, assistantName, defaultAmount, groupName } = body;
  const uidsList: string[] = Array.isArray(studentUids) && studentUids.length > 0 ? studentUids : (studentUid ? [studentUid] : []);

  if (!clientId || uidsList.length === 0 || !title || totalAmount === undefined || amount === undefined) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (tokenClientId !== clientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (Number(amount) > Number(totalAmount)) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ المبلغ (${amount} ج.م) يتجاوز المبلغ الكامل (${totalAmount} ج.م)` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error: titleError } = await supabase.from("payment_titles").upsert(
    { teacher_id: clientId, title, default_amount: defaultAmount !== undefined ? Number(defaultAmount) : Number(totalAmount) },
    { onConflict: "teacher_id,title", ignoreDuplicates: false }
  );
  if (titleError) console.error("⚠️ فشل تسجيل بند السداد في القائمة:", titleError.message);

  const { data: notifyTeacherInfo } = await supabase.from("teachers").select("name").eq("client_id", clientId).maybeSingle();
  const teacherLabel = notifyTeacherInfo?.name ? ` — مدرس ${notifyTeacherInfo.name}` : "";
  const performerId = assistantId || clientId;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = assistantId ? (assistantName || "مساعد") : (notifyTeacherInfo?.name || "مدرس");

  const results: any[] = [];
  const loggedStudents: any[] = [];
  const skipped: string[] = [];

  // ✅ الطلاب المشتركين (student_teacher_links) بيقدر المدرس يسجّل لهم مدفوعات كمان، مش بس طلابه الأساسيين
  const { data: myLinks } = await supabase.from("student_teacher_links").select("student_uid").eq("teacher_id", clientId);
  const linkedUidsForMe = new Set((myLinks || []).map((l: any) => l.student_uid));

  const [{ data: candidateStudents }, { data: existingPayments }, { data: groupLinks }] = await Promise.all([
    supabase.from("students").select("uid, name, group_name, teacher_id, parent_phone").in("uid", uidsList),
    supabase.from("payments").select("student_uid").in("student_uid", uidsList).eq("teacher_id", clientId).eq("title", title),
    // ✅ Batch 22 (بند 3): لازم نعرف كل المجموعات اللي كل طالب مربوط بيها (مش بس مجموعته الأساسية)
    // عشان نتأكد إن المجموعة المختارة فعلياً في فورم التسجيل (groupName) صحيحة لكل طالب قبل ما نستخدمها
    supabase.from("student_group_links").select("student_uid, group_name").in("student_uid", uidsList),
  ]);
  const foundStudents = (candidateStudents || []).filter((s: any) => s.teacher_id === clientId || linkedUidsForMe.has(s.uid));

  const studentsByUid = new Map((foundStudents || []).map((s: any) => [s.uid, s]));
  const alreadyPaidUids = new Set((existingPayments || []).map((p: any) => p.student_uid));
  const linkedGroupsByUid = new Map<string, Set<string>>();
  (groupLinks || []).forEach((l: any) => {
    if (!linkedGroupsByUid.has(l.student_uid)) linkedGroupsByUid.set(l.student_uid, new Set());
    linkedGroupsByUid.get(l.student_uid)!.add(l.group_name);
  });

  const validStudents: any[] = [];
  for (const uid of uidsList) {
    const student = studentsByUid.get(uid);
    if (!student) { skipped.push(`${uid} (طالب غير موجود)`); continue; }
    if (alreadyPaidUids.has(uid)) { skipped.push(`${student.name} (مسدّد بالفعل)`); continue; }
    validStudents.push(student);
  }

  // ✅ Batch 22 (بند 3): كانت المدفوعة بتتسجّل دايماً على مجموعة الطالب الأساسية (students.group_name)
  // بغض النظر عن أي مجموعة اختارها المدرس فعلياً في الفورم (paymentGroup) — بما إن ده كان بيتجاهل
  // تماماً في الباك إند. دلوقتي لو groupName اتبعت من الفرونت إند ومطابقة فعلاً لمجموعة الطالب
  // الأساسية أو لمجموعة مربوط بيها (student_group_links)، بنستخدمها؛ غير كده بنرجع لمجموعته الأساسية
  // زي ما كان (توافق مع أي استدعاء قديم من غير groupName)
  function resolveGroupName(student: any): string {
    if (groupName && (student.group_name === groupName || linkedGroupsByUid.get(student.uid)?.has(groupName))) {
      return groupName;
    }
    return student.group_name;
  }

  if (validStudents.length > 0) {
    const { data: insertedPayments, error: insertError } = await supabase.from("payments").insert(validStudents.map((student) => ({
      student_uid: student.uid, student_name: student.name, group_name: resolveGroupName(student),
      teacher_id: clientId, title: title, total_amount: Number(totalAmount), amount: Number(amount),
    }))).select();

    if (insertError) {
      console.error("❌ فشل إضافة الدفعات:", insertError);
    } else if (insertedPayments) {
      const isFullPaid = Number(amount) >= Number(totalAmount);
      const statusText = isFullPaid ? "مدفوع بالكامل" : (Number(amount) > 0 ? "دفعة جزئية" : "غير مدفوع");
      results.push(...insertedPayments);
      loggedStudents.push(...validStudents.map((s) => ({ name: s.name, uid: s.uid, group_name: s.group_name, status: statusText })));

      const notifRows = [
        ...validStudents.filter((s) => s.parent_phone).map((s) => ({
          teacher_id: clientId, parent_phone: s.parent_phone, student_uid: s.uid, type: "payment", title: "تسجيل دفعة", audience: "parent",
          message: `تم تسجيل دفعة "${title}" بمبلغ ${amount} ج.م لـ ${s.name} (${statusText})${teacherLabel}`,
          details: { student_name: s.name, title, amount: Number(amount), total_amount: Number(totalAmount), status: statusText },
        })),
        // ✅ (طلب) إشعار مستقل للطالب نفسه، معزول عن نص ولي الأمر
        ...validStudents.map((s) => ({
          teacher_id: clientId, student_uid: s.uid, type: "payment", title: "تسجيل دفعة", audience: "student",
          message: `اتسجّلت دفعة "${title}" بمبلغ ${amount} ج.م على اشتراكك (${statusText})${teacherLabel}`,
          details: { title, amount: Number(amount), total_amount: Number(totalAmount), status: statusText },
        })),
      ];
      if (notifRows.length > 0) {
        await supabase.from("notifications").insert(notifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعارات الدفعات:", error.message); });
        validStudents.filter((s) => s.parent_phone).forEach((s) => {
          sendPushToRecipient(supabase, "parent", s.parent_phone, "تسجيل دفعة", `تم تسجيل دفعة "${title}" بمبلغ ${amount} ج.م لـ ${s.name} (${statusText})${teacherLabel}`);
        });
        // ✅ (طلب) نفس Push دلوقتي بيوصل الطالب نفسه كمان، مش بس ولي الأمر
        validStudents.forEach((s) => {
          sendPushToRecipient(supabase, "student", s.uid, "تسجيل دفعة", `اتسجّلت دفعة "${title}" بمبلغ ${amount} ج.م على اشتراكك (${statusText})${teacherLabel}`);
        });
      }
    }
  }

  if (results.length === 0) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ مفيش أي دفعة اتسجّلت: ${skipped.join("، ")}`, skipped }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const isBulk = loggedStudents.length > 1;
  await supabase.from("activity_logs").insert({
    client_id: clientId, teacher_id: clientId, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: isBulk ? "bulk_add_payment" : "add_payment", entity_type: "payment", entity_id: String(results[0].id),
    details: isBulk
      ? { title, total_amount: Number(totalAmount), amount: Number(amount), count: loggedStudents.length, students: loggedStudents }
      : { student_name: loggedStudents[0].name, student_uid: loggedStudents[0].uid, title, total_amount: Number(totalAmount), amount: Number(amount), group_name: loggedStudents[0].group_name, status: loggedStudents[0].status },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  let message = uidsList.length === 1 ? "تم تسجيل الدفعة بنجاح" : `تم تسجيل الدفعة لـ ${results.length} طالب بنجاح`;
  if (skipped.length > 0) message += ` (اتخطّى: ${skipped.join("، ")})`;

  return new Response(JSON.stringify({ success: true, message, data: results.length === 1 ? results[0] : results }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 2: تعديل دفعة (منطق update-payment الأصلي كامل)
// ============================================
async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_payments");
  await requireAssistantPermission(payload, "record_payments");

  const { paymentId, amount, assistantId, assistantName } = body;
  if (!paymentId || amount === undefined) {
    return new Response(JSON.stringify({ success: false, message: "معرف الدفعة والمبلغ الجديد مطلوبان" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: oldPayment, error: fetchError } = await supabase
    .from("payments").select("amount, total_amount, title, student_uid, student_name, group_name, teacher_id").eq("id", paymentId).single();
  if (fetchError || !oldPayment) {
    return new Response(JSON.stringify({ success: false, message: "الدفعة غير موجودة" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldPayment.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه الدفعة ليست تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const oldAmount = oldPayment.amount;
  const newAmount = Number(amount);
  if (isNaN(newAmount) || newAmount < 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ أدخل مبلغاً صحيحاً" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (newAmount > oldPayment.total_amount) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ المبلغ المدفوع (${newAmount}) مايصحش يكون أكبر من قيمة الاشتراك (${oldPayment.total_amount})` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldAmount === newAmount) {
    return new Response(JSON.stringify({ success: true, message: "لا توجد تغييرات في المبلغ" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: updatedPayment, error: updateError } = await supabase.from("payments").update({ amount: newAmount }).eq("id", paymentId).select().single();
  if (updateError) {
    console.error("❌ فشل تحديث الدفعة:", updateError);
    return new Response(JSON.stringify({ success: false, message: `فشل تحديث الدفعة: ${updateError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  let teacherName = "مدرس";
  if (oldPayment.teacher_id) {
    const { data: teacher, error: teacherError } = await supabase.from("teachers").select("name").eq("client_id", oldPayment.teacher_id).maybeSingle();
    if (!teacherError && teacher) teacherName = teacher.name || "مدرس";
  }

  const performerId = assistantId || oldPayment.teacher_id;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = assistantId ? (assistantName || "مساعد") : teacherName;
  const wasFullPaid = oldAmount >= oldPayment.total_amount;
  const isFullPaid = newAmount >= oldPayment.total_amount;

  await supabase.from("activity_logs").insert({
    client_id: oldPayment.teacher_id, teacher_id: oldPayment.teacher_id, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "edit_payment", entity_type: "payment", entity_id: String(paymentId),
    details: {
      student_name: oldPayment.student_name, student_uid: oldPayment.student_uid, title: oldPayment.title, total_amount: oldPayment.total_amount,
      old_amount: oldAmount, new_amount: newAmount, group_name: oldPayment.group_name,
      changes: { amount: { old: oldAmount, new: newAmount }, status: { old: wasFullPaid ? "مدفوع بالكامل" : (oldAmount > 0 ? "دفعة جزئية" : "غير مدفوع"), new: isFullPaid ? "مدفوع بالكامل" : (newAmount > 0 ? "دفعة جزئية" : "غير مدفوع") } },
    },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  const { data: studentForNotif } = await supabase.from("students").select("parent_phone").eq("uid", oldPayment.student_uid).maybeSingle();
  {
    const statusText = isFullPaid ? "مدفوع بالكامل" : (newAmount > 0 ? "دفعة جزئية" : "غير مدفوع");
    const editNotifRows = [
      ...(studentForNotif?.parent_phone ? [{
        teacher_id: oldPayment.teacher_id, parent_phone: studentForNotif.parent_phone, student_uid: oldPayment.student_uid, type: "payment", title: "تعديل دفعة", audience: "parent",
        message: `تم تعديل دفعة "${oldPayment.title}" لـ ${oldPayment.student_name} من ${oldAmount} ج.م إلى ${newAmount} ج.م (${statusText})`,
        details: { student_name: oldPayment.student_name, title: oldPayment.title, old_amount: oldAmount, new_amount: newAmount, total_amount: oldPayment.total_amount, status: statusText },
      }] : []),
      {
        teacher_id: oldPayment.teacher_id, student_uid: oldPayment.student_uid, type: "payment", title: "تعديل دفعة", audience: "student",
        message: `تم تعديل دفعتك "${oldPayment.title}" من ${oldAmount} ج.م إلى ${newAmount} ج.م (${statusText})`,
        details: { title: oldPayment.title, old_amount: oldAmount, new_amount: newAmount, total_amount: oldPayment.total_amount, status: statusText },
      },
    ];
    await supabase.from("notifications").insert(editNotifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعار تعديل الدفعة:", error.message); });
    if (studentForNotif?.parent_phone) {
      sendPushToRecipient(supabase, "parent", studentForNotif.parent_phone, "تعديل دفعة", `تم تعديل دفعة "${oldPayment.title}" لـ ${oldPayment.student_name} من ${oldAmount} ج.م إلى ${newAmount} ج.م (${statusText})`);
    }
    // ✅ (طلب) الطالب مكانش بيوصله Push حقيقي أبداً على أي تعديل دفعة، بس إشعار جوه التطبيق
    sendPushToRecipient(supabase, "student", oldPayment.student_uid, "تعديل دفعة", `تم تعديل دفعتك "${oldPayment.title}" من ${oldAmount} ج.م إلى ${newAmount} ج.م (${statusText})`);
  }

  return new Response(JSON.stringify({ success: true, message: "تم تحديث الدفعة بنجاح", data: updatedPayment, changes: { amount: { old: oldAmount, new: newAmount } } }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 3: حذف دفعة (منطق delete-payment الأصلي كامل)
// ============================================
async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_payments");
  await requireAssistantPermission(payload, "record_payments");

  const { paymentId, assistantId, assistantName } = body;
  if (!paymentId) {
    return new Response(JSON.stringify({ success: false, message: "معرف الدفعة مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: payment, error: fetchError } = await supabase.from("payments").select("*, students(name, uid, teacher_id, group_name, parent_phone)").eq("id", paymentId).single();
  if (fetchError || !payment) {
    return new Response(JSON.stringify({ success: false, message: "الدفعة غير موجودة" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (payment.students?.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه الدفعة ليست تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error: deleteError } = await supabase.from("payments").delete().eq("id", paymentId);
  if (deleteError) {
    console.error("❌ فشل حذف الدفعة:", deleteError);
    return new Response(JSON.stringify({ success: false, message: `فشل حذف الدفعة: ${deleteError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  let teacherName = "مدرس";
  if (payment.students?.teacher_id) {
    const { data: teacher, error: teacherError } = await supabase.from("teachers").select("name").eq("client_id", payment.students.teacher_id).maybeSingle();
    if (!teacherError && teacher) teacherName = teacher.name || "مدرس";
  }

  const performerId = assistantId || payment.students?.teacher_id;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = assistantId ? (assistantName || "مساعد") : teacherName;

  await supabase.from("activity_logs").insert({
    client_id: payment.students?.teacher_id, teacher_id: payment.students?.teacher_id, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "delete_payment", entity_type: "payment", entity_id: String(paymentId),
    details: {
      student_name: payment.students?.name, student_uid: payment.students?.uid, title: payment.title, total_amount: payment.total_amount,
      amount: payment.amount, group_name: payment.students?.group_name,
      status: payment.amount >= payment.total_amount ? "مدفوع بالكامل" : (payment.amount > 0 ? "دفعة جزئية" : "غير مدفوع"),
    },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  // ✅ (تعديل) حذف الدفعة مكانش بيبعت أي إشعار لولي الأمر/الطالب — أضفنا نفس منطق إشعار التعديل هنا
  if (payment.students?.uid) {
    const statusText = payment.amount >= payment.total_amount ? "مدفوع بالكامل" : (payment.amount > 0 ? "دفعة جزئية" : "غير مدفوع");
    const deleteNotifRows = [
      ...(payment.students?.parent_phone ? [{
        teacher_id: payment.students.teacher_id, parent_phone: payment.students.parent_phone, student_uid: payment.students.uid, type: "payment", title: "حذف دفعة", audience: "parent",
        message: `تم حذف دفعة "${payment.title}" لـ ${payment.students.name} (${payment.amount} ج.م، ${statusText})`,
        details: { student_name: payment.students.name, title: payment.title, amount: payment.amount, total_amount: payment.total_amount, status: statusText },
      }] : []),
      {
        teacher_id: payment.students.teacher_id, student_uid: payment.students.uid, type: "payment", title: "حذف دفعة", audience: "student",
        message: `تم حذف دفعتك "${payment.title}" (${payment.amount} ج.م، ${statusText})`,
        details: { title: payment.title, amount: payment.amount, total_amount: payment.total_amount, status: statusText },
      },
    ];
    await supabase.from("notifications").insert(deleteNotifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعار حذف الدفعة:", error.message); });
    // ✅ (طلب) حذف الدفعة مكانش بيبعت Push حقيقي خالص لولي الأمر أو الطالب — بس إشعار جوه التطبيق
    if (payment.students?.parent_phone) {
      sendPushToRecipient(supabase, "parent", payment.students.parent_phone, "حذف دفعة", `تم حذف دفعة "${payment.title}" لـ ${payment.students.name} (${payment.amount} ج.م، ${statusText})`);
    }
    sendPushToRecipient(supabase, "student", payment.students.uid, "حذف دفعة", `تم حذف دفعتك "${payment.title}" (${payment.amount} ج.م، ${statusText})`);
  }

  return new Response(JSON.stringify({ success: true, message: "تم حذف الدفعة بنجاح", data: { paymentId } }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ✅ (طلب) حذف بند سداد (payment_titles) نفسه — مش عملية سداد فعلية. نفس نمط
// manage-grade's handleDeleteTitle بالظبط: يرفض الحذف (409) لو فيه مدفوعات فعلية مسجّلة
// تحت البند ده أولاً، لازم تتشال من "المدفوعات المسجلة" الأول.
async function handleDeleteTitle(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_payments");
  await requireAssistantPermission(payload, "record_payments");

  const { title } = body;
  const cleanTitle = (title || "").trim();
  if (!cleanTitle) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ اسم البند مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { count: paymentsCount } = await supabase.from("payments").select("id", { count: "exact", head: true })
    .eq("teacher_id", tokenClientId).eq("title", cleanTitle);
  if (paymentsCount && paymentsCount > 0) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ فيه ${paymentsCount} عملية سداد مسجّلة تحت "${cleanTitle}" — لازم تُحذف أولاً من "المدفوعات المسجلة" قبل حذف البند نفسه` }),
      { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error: deleteError } = await supabase.from("payment_titles").delete().eq("teacher_id", tokenClientId).eq("title", cleanTitle);
  if (deleteError) throw new Error(deleteError.message);

  return new Response(JSON.stringify({ success: true, message: `✅ تم حذف بند "${cleanTitle}"` }),
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
    console.error("❌ خطأ في manage-payment:", error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
