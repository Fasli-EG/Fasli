// supabase/functions/manage-book-payment/index.ts
// ✅ دالة موحّدة تجمع pay-book + update-book-payment + delete-book-payment بـ "action" parameter
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
  "Access-Control-Max-Age": "86400",
};

export interface TokenPayload {
  sub: string; clientId?: string; teacherId?: string; role: "teacher" | "assistant" | "parent"; name: string; exp: number;
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
        if (errData?.error?.status === "NOT_FOUND" || errData?.error?.status === "INVALID_ARGUMENT") await supabase.from("push_tokens").delete().eq("id", row.id);
        else console.error("⚠️ فشل إرسال Push notification:", errData);
      }
    }
  } catch (error) { console.error("⚠️ خطأ غير متوقع في إرسال Push notification:", error); }
}

// ============================================
// ⭐ العملية 1: سداد مذكرة (منطق pay-book الأصلي كامل)
// ============================================
async function handlePay(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_books");
  await requireAssistantPermission(payload, "manage_books");

  const { teacherId, bookId, studentUid, studentUids, amount, assistantId, assistantName } = body;
  const uidsList: string[] = Array.isArray(studentUids) && studentUids.length > 0 ? studentUids : (studentUid ? [studentUid] : []);

  if (!teacherId || !bookId || uidsList.length === 0 || amount === undefined) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (tokenClientId !== teacherId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: book, error: bookError } = await supabase.from("books").select("name, price").eq("id", bookId).eq("teacher_id", teacherId).single();
  if (bookError || !book) {
    return new Response(JSON.stringify({ success: false, message: "المذكرة غير موجودة" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const newAmount = Number(amount);
  if (newAmount > book.price) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ المبلغ (${newAmount} ج.م) يتجاوز سعر المذكرة (${book.price} ج.م)` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: notifyTeacherInfo } = await supabase.from("teachers").select("name").eq("client_id", teacherId).maybeSingle();
  const teacherLabel = notifyTeacherInfo?.name ? ` — مدرس ${notifyTeacherInfo.name}` : "";
  const performerId = assistantId || teacherId;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = assistantId ? (assistantName || "مساعد") : (notifyTeacherInfo?.name || "مدرس");

  const results: any[] = [];
  const loggedStudents: any[] = [];
  const skipped: string[] = [];

  const [{ data: foundStudents }, { data: existingPayments }] = await Promise.all([
    supabase.from("students").select("uid, name, group_name, parent_phone").in("uid", uidsList).eq("teacher_id", teacherId),
    supabase.from("book_payments").select("student_uid").in("student_uid", uidsList).eq("book_id", bookId).eq("teacher_id", teacherId),
  ]);

  const studentsByUid = new Map((foundStudents || []).map((s: any) => [s.uid, s]));
  const alreadyPaidUids = new Set((existingPayments || []).map((p: any) => p.student_uid));

  const validStudents: any[] = [];
  for (const uid of uidsList) {
    const student = studentsByUid.get(uid);
    if (!student) { skipped.push(`${uid} (طالب غير موجود)`); continue; }
    if (alreadyPaidUids.has(uid)) { skipped.push(`${student.name} (مسدّد بالفعل)`); continue; }
    validStudents.push(student);
  }

  if (validStudents.length > 0) {
    const { data: insertedPayments, error: insertError } = await supabase.from("book_payments").insert(validStudents.map((student) => ({
      book_id: bookId, student_uid: student.uid, student_name: student.name, group_name: student.group_name, teacher_id: teacherId, amount: newAmount,
    }))).select();

    if (insertError) {
      console.error("❌ فشل إدراج الدفعات:", insertError);
    } else if (insertedPayments) {
      const remaining = Math.max(0, (book.price || 0) - newAmount);
      results.push(...insertedPayments);
      loggedStudents.push(...validStudents.map((s) => ({ name: s.name, uid: s.uid, group_name: s.group_name, amount: newAmount })));

      const notifRows = [
        ...validStudents.filter((s) => s.parent_phone).map((s) => ({
          teacher_id: teacherId, parent_phone: s.parent_phone, student_uid: s.uid, type: "book_payment", title: "سداد مذكرة", audience: "parent",
          message: `تم سداد ${newAmount} ج.م من مذكرة "${book.name}" لـ ${s.name}` + (remaining > 0 ? ` (متبقي ${remaining} ج.م)` : " (مدفوعة بالكامل)") + teacherLabel,
          details: { student_name: s.name, book_name: book.name, amount_paid_now: newAmount, total_paid: newAmount, remaining },
        })),
        ...validStudents.map((s) => ({
          teacher_id: teacherId, student_uid: s.uid, type: "book_payment", title: "سداد مذكرة", audience: "student",
          message: `اتسجّل سداد ${newAmount} ج.م من مذكرة "${book.name}"` + (remaining > 0 ? ` (متبقي ${remaining} ج.م)` : " (مدفوعة بالكامل)") + teacherLabel,
          details: { book_name: book.name, amount_paid_now: newAmount, total_paid: newAmount, remaining },
        })),
      ];
      if (notifRows.length > 0) {
        await supabase.from("notifications").insert(notifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعارات سداد المذكرة:", error.message); });
        validStudents.filter((s) => s.parent_phone).forEach((s) => {
          sendPushToRecipient(supabase, "parent", s.parent_phone, "سداد مذكرة", `تم سداد ${newAmount} ج.م من مذكرة "${book.name}" لـ ${s.name}` + (remaining > 0 ? ` (متبقي ${remaining} ج.م)` : " (مدفوعة بالكامل)") + teacherLabel);
        });
        validStudents.forEach((s) => {
          sendPushToRecipient(supabase, "student", s.uid, "سداد مذكرة", `اتسجّل سداد ${newAmount} ج.م من مذكرة "${book.name}"` + (remaining > 0 ? ` (متبقي ${remaining} ج.م)` : " (مدفوعة بالكامل)") + teacherLabel);
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
    client_id: teacherId, teacher_id: teacherId, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: isBulk ? "bulk_pay_book" : "pay_book", entity_type: "book_payment", entity_id: String(results[0].id),
    details: isBulk
      ? { book_name: book.name, book_price: book.price, count: loggedStudents.length, students: loggedStudents }
      : { student_name: loggedStudents[0].name, student_uid: loggedStudents[0].uid, book_name: book.name, book_price: book.price, old_amount: 0, new_amount: loggedStudents[0].amount, group_name: loggedStudents[0].group_name, is_update: false },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  let message = uidsList.length === 1 ? "تم تسجيل الدفعة بنجاح" : `تم تسجيل الدفعة لـ ${results.length} طالب بنجاح`;
  if (skipped.length > 0) message += ` (اتخطّى: ${skipped.join("، ")})`;

  return new Response(JSON.stringify({ success: true, message, data: results.length === 1 ? results[0] : results }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 2: تعديل سداد مذكرة (منطق update-book-payment الأصلي كامل)
// ============================================
async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_books");
  await requireAssistantPermission(payload, "manage_books");

  const { paymentId, amount, assistantId, assistantName } = body;
  if (!paymentId || amount === undefined) {
    return new Response(JSON.stringify({ success: false, message: "معرف الدفعة والمبلغ الجديد مطلوبان" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: oldPayment, error: fetchError } = await supabase.from("book_payments").select("*, books(price)").eq("id", paymentId).single();
  if (fetchError || !oldPayment) {
    return new Response(JSON.stringify({ success: false, message: "الدفعة غير موجودة" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldPayment.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه الدفعة ليست تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const newAmount = Number(amount);
  const bookPrice = oldPayment.books?.price ?? 0;
  if (isNaN(newAmount) || newAmount < 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ أدخل مبلغاً صحيحاً" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (bookPrice > 0 && newAmount > bookPrice) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ المبلغ المدفوع (${newAmount}) مايصحش يكون أكبر من سعر المذكرة (${bookPrice})` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: updatedPayment, error: updateError } = await supabase.from("book_payments").update({ amount: newAmount }).eq("id", paymentId).select().single();
  if (updateError) {
    return new Response(JSON.stringify({ success: false, message: `فشل تحديث الدفعة: ${updateError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const teacherId = oldPayment.teacher_id;
  const performerId = assistantId || teacherId;
  const performerRole = assistantId ? "assistant" : "teacher";
  let performerName = assistantId ? (assistantName || "مساعد") : "مدرس";
  if (!assistantId) {
    const { data: performerTeacherInfo } = await supabase.from("teachers").select("name").eq("client_id", teacherId).maybeSingle();
    performerName = performerTeacherInfo?.name || "مدرس";
  }

  await supabase.from("activity_logs").insert({
    client_id: teacherId, teacher_id: teacherId, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "edit_book_payment", entity_type: "book_payment", entity_id: String(paymentId),
    details: { student_name: oldPayment.student_name, student_uid: oldPayment.student_uid, book_id: oldPayment.book_id, old_amount: oldPayment.amount, new_amount: newAmount, changes: { amount: { old: oldPayment.amount, new: newAmount } } },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  const [{ data: studentForNotif }, { data: bookForNotif }] = await Promise.all([
    supabase.from("students").select("parent_phone").eq("uid", oldPayment.student_uid).maybeSingle(),
    supabase.from("books").select("name").eq("id", oldPayment.book_id).maybeSingle(),
  ]);

  {
    const editNotifRows = [
      ...(studentForNotif?.parent_phone ? [{
        teacher_id: teacherId, parent_phone: studentForNotif.parent_phone, student_uid: oldPayment.student_uid, type: "book_payment", title: "تعديل سداد مذكرة", audience: "parent",
        message: `تم تعديل سداد مذكرة "${bookForNotif?.name || ""}" لـ ${oldPayment.student_name} من ${oldPayment.amount} ج.م إلى ${newAmount} ج.م`,
        details: { student_name: oldPayment.student_name, book_name: bookForNotif?.name, old_amount: oldPayment.amount, new_amount: newAmount },
      }] : []),
      {
        teacher_id: teacherId, student_uid: oldPayment.student_uid, type: "book_payment", title: "تعديل سداد مذكرة", audience: "student",
        message: `تم تعديل سداد مذكرة "${bookForNotif?.name || ""}" من ${oldPayment.amount} ج.م إلى ${newAmount} ج.م`,
        details: { book_name: bookForNotif?.name, old_amount: oldPayment.amount, new_amount: newAmount },
      },
    ];
    await supabase.from("notifications").insert(editNotifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعار تعديل سداد المذكرة:", error.message); });
    if (studentForNotif?.parent_phone) {
      sendPushToRecipient(supabase, "parent", studentForNotif.parent_phone, "تعديل سداد مذكرة", `تم تعديل سداد مذكرة "${bookForNotif?.name || ""}" لـ ${oldPayment.student_name} من ${oldPayment.amount} ج.م إلى ${newAmount} ج.م`);
    }
    sendPushToRecipient(supabase, "student", oldPayment.student_uid, "تعديل سداد مذكرة", `تم تعديل سداد مذكرة "${bookForNotif?.name || ""}" من ${oldPayment.amount} ج.م إلى ${newAmount} ج.م`);
  }

  return new Response(JSON.stringify({ success: true, message: "تم تحديث الدفعة بنجاح", data: updatedPayment }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 3: حذف سداد مذكرة (منطق delete-book-payment الأصلي كامل)
// ============================================
async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_books");
  await requireAssistantPermission(payload, "manage_books");

  const { paymentId, assistantId, assistantName } = body;
  if (!paymentId) {
    return new Response(JSON.stringify({ success: false, message: "معرف الدفعة مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: payment, error: fetchError } = await supabase.from("book_payments")
    .select("id, student_uid, student_name, group_name, teacher_id, amount, paid_at, books (id, name, price)").eq("id", paymentId).single();
  if (fetchError || !payment) {
    return new Response(JSON.stringify({ success: false, message: "الدفعة غير موجودة" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (payment.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه الدفعة ليست تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error: deleteError } = await supabase.from("book_payments").delete().eq("id", paymentId);
  if (deleteError) {
    return new Response(JSON.stringify({ success: false, message: `فشل حذف الدفعة: ${deleteError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const teacherId = payment.teacher_id;
  const performerId = assistantId || teacherId;
  const performerRole = assistantId ? "assistant" : "teacher";
  let performerName = assistantId ? (assistantName || "مساعد") : "مدرس";
  if (!assistantId) {
    const { data: teacherInfo } = await supabase.from("teachers").select("name").eq("client_id", teacherId).maybeSingle();
    performerName = teacherInfo?.name || "مدرس";
  }

  await supabase.from("activity_logs").insert({
    client_id: teacherId, teacher_id: teacherId, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "delete_book_payment", entity_type: "book_payment", entity_id: String(paymentId),
    details: { student_name: payment.student_name, student_uid: payment.student_uid, book_name: payment.books?.name || "غير معروف", book_price: payment.books?.price || 0, amount: payment.amount, group_name: payment.group_name, paid_at: payment.paid_at },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  // ✅ (تعديل) حذف سداد المذكرة مكانش بيبعت أي إشعار لولي الأمر/الطالب — أضفنا نفس منطق إشعار التعديل هنا
  if (payment.student_uid) {
    const { data: studentForNotif } = await supabase.from("students").select("parent_phone").eq("uid", payment.student_uid).maybeSingle();
    const bookName = payment.books?.name || "";
    const deleteNotifRows = [
      ...(studentForNotif?.parent_phone ? [{
        teacher_id: teacherId, parent_phone: studentForNotif.parent_phone, student_uid: payment.student_uid, type: "book_payment", title: "حذف سداد مذكرة", audience: "parent",
        message: `تم حذف سداد مذكرة "${bookName}" لـ ${payment.student_name} (${payment.amount} ج.م)`,
        details: { student_name: payment.student_name, book_name: bookName, amount: payment.amount },
      }] : []),
      {
        teacher_id: teacherId, student_uid: payment.student_uid, type: "book_payment", title: "حذف سداد مذكرة", audience: "student",
        message: `تم حذف سداد مذكرة "${bookName}" (${payment.amount} ج.م)`,
        details: { book_name: bookName, amount: payment.amount },
      },
    ];
    await supabase.from("notifications").insert(deleteNotifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعار حذف سداد المذكرة:", error.message); });
    // ✅ (طلب) حذف سداد المذكرة مكانش بيبعت Push حقيقي خالص لولي الأمر أو الطالب
    if (studentForNotif?.parent_phone) {
      sendPushToRecipient(supabase, "parent", studentForNotif.parent_phone, "حذف سداد مذكرة", `تم حذف سداد مذكرة "${bookName}" لـ ${payment.student_name} (${payment.amount} ج.م)`);
    }
    sendPushToRecipient(supabase, "student", payment.student_uid, "حذف سداد مذكرة", `تم حذف سداد مذكرة "${bookName}" (${payment.amount} ج.م)`);
  }

  return new Response(JSON.stringify({ success: true, message: "تم حذف سداد المذكرة بنجاح", data: { paymentId, student_name: payment.student_name, book_name: payment.books?.name, amount: payment.amount } }),
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
    if (action === "pay") return await handlePay(supabase, payload, body);
    if (action === "update") return await handleUpdate(supabase, payload, body);
    if (action === "delete") return await handleDelete(supabase, payload, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة — لازم تكون pay أو update أو delete" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في manage-book-payment:", error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
