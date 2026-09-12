// supabase/functions/manage-payment-receipt/index.ts
// ✅ (طلب) الحل المجاني لتأكيد الدفع: ولي الأمر يرفع صورة إيصال تحويل يدوي (InstaPay/محفظة)،
// والمدرس/المساعد يراجعها من "المدفوعات" ويأكّدها أو يرفضها. دالة موحّدة بنفس نمط manage-payment:
// submit (ولي أمر) / list, approve, reject (مدرس/مساعد).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, TokenPayload, AuthError, verifyToken, requireTeacherPlanPermission, requireAssistantPermission, requireParentPhone, authErrorResponse } from "../_shared/auth.ts";
import { recordPayments } from "../_shared/payments.ts";

const BUCKET = "payment-receipts";
// ✅ صور موبايل حقيقية (تصوير إيصال) — أكبر شوية من حد صور أسئلة الامتحانات (4 ميجا)
const MAX_RECEIPT_SIZE_BYTES = 5 * 1024 * 1024;
const ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png"];

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

function jsonResponse(body: any, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ ولي الأمر: رفع إيصال جديد
// ============================================
async function handleSubmit(supabase: any, payload: TokenPayload, body: any) {
  const parentPhone = requireParentPhone(payload);
  const { studentUid, title, groupName, fileBase64, fileName } = body;

  if (!studentUid || !title || !fileBase64 || !fileName) {
    return jsonResponse({ success: false, message: "⚠️ جميع الحقول مطلوبة" }, 400);
  }

  // ✅ لازم نتأكد إن الطالب ده فعلاً ابن ولي الأمر صاحب التوكن — من غير الفحص ده أي حد
  // يقدر يرفع إيصال باسم طالب مش بتاعه
  const { data: student } = await supabase.from("students").select("uid, teacher_id, parent_phone, name, group_name").eq("uid", studentUid).maybeSingle();
  if (!student || student.parent_phone !== parentPhone) {
    return jsonResponse({ success: false, message: "⛔ غير مصرح لك بهذا الطالب" }, 403);
  }

  // ✅ (طلب) المدرس لازم يكون فعّل الميزة دي بنفسه من إعدادات الحساب — معطّلة افتراضيًا
  const { data: teacher } = await supabase.from("teachers").select("electronic_payment_enabled").eq("client_id", student.teacher_id).maybeSingle();
  if (!teacher || teacher.electronic_payment_enabled !== true) {
    return jsonResponse({ success: false, message: "⛔ المدرس لسه ما فعّلش استقبال إيصالات الدفع الإلكتروني" }, 403);
  }

  // ✅ منع تكرار: لو فيه إيصال معلّق بالفعل لنفس البند، نرجّعه بدل ما نسمح بإيصال تاني فوقه
  const { data: existingPending } = await supabase.from("payment_receipts")
    .select("*").eq("student_uid", studentUid).eq("title", title).eq("status", "pending").maybeSingle();
  if (existingPending) {
    return jsonResponse({ success: true, message: "⏳ فيه إيصال بانتظار المراجعة بالفعل لنفس البند", data: existingPending });
  }

  // ✅ (طلب) الإيصال لازم يغطي المبلغ المتبقي بالكامل — مفيش دفعات جزئية عن طريق الإيصال.
  // بنحسب المبلغ الكامل والمتبقي من عندنا (مش من كلام ولي الأمر) عشان محدش يقدر يلاعب في الرقم:
  // لو فيه دفعة مسجّلة بالفعل لنفس البند نستخدم سعرها المسجّل، وإلا نرجع لسعر البند الافتراضي
  const { data: existingPayment } = await supabase.from("payments")
    .select("amount, total_amount").eq("student_uid", studentUid).eq("teacher_id", student.teacher_id).eq("title", title).maybeSingle();

  let totalAmount: number;
  let remaining: number;
  if (existingPayment) {
    totalAmount = Number(existingPayment.total_amount);
    remaining = totalAmount - Number(existingPayment.amount);
  } else {
    const { data: titleRow } = await supabase.from("payment_titles").select("default_amount").eq("teacher_id", student.teacher_id).eq("title", title).maybeSingle();
    if (!titleRow) return jsonResponse({ success: false, message: "⚠️ بند السداد ده مش موجود" }, 400);
    totalAmount = Number(titleRow.default_amount);
    remaining = totalAmount;
  }
  if (remaining <= 0) {
    return jsonResponse({ success: false, message: "⚠️ البند ده متسدد بالكامل بالفعل" }, 400);
  }
  const claimedAmount = remaining;

  const ext = ("." + (fileName.split(".").pop() || "")).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return jsonResponse({ success: false, message: "⚠️ لازم تكون الصورة بصيغة JPG أو PNG" }, 400);
  }

  const base64Data = fileBase64.includes(",") ? fileBase64.split(",")[1] : fileBase64;
  const binaryData = Uint8Array.from(atob(base64Data), (c) => c.charCodeAt(0));
  if (binaryData.length > MAX_RECEIPT_SIZE_BYTES) {
    return jsonResponse({ success: false, message: "⚠️ حجم الصورة أكبر من الحد المسموح (5 ميجا)" }, 400);
  }

  const storagePath = `${student.teacher_id}/${studentUid}-${Date.now()}${ext}`;
  const { error: uploadError } = await supabase.storage.from(BUCKET).upload(storagePath, binaryData, {
    contentType: ext === ".png" ? "image/png" : "image/jpeg", upsert: true,
  });
  if (uploadError) {
    if (String(uploadError.message || "").toLowerCase().includes("bucket not found")) {
      return jsonResponse({ success: false, message: `⚠️ مساحة تخزين إيصالات الدفع (${BUCKET}) لسه مش متعملة على السيرفر — لازم تتعمل يدوياً من Supabase Storage أولاً` }, 500);
    }
    throw new Error(uploadError.message);
  }

  const { data: inserted, error: insertError } = await supabase.from("payment_receipts").insert({
    teacher_id: student.teacher_id, student_uid: studentUid, group_name: groupName || student.group_name,
    title, total_amount: Number(totalAmount), claimed_amount: Number(claimedAmount), receipt_path: storagePath,
  }).select().single();
  if (insertError) throw new Error(insertError.message);

  return jsonResponse({ success: true, message: "✅ تم رفع الإيصال، هيتراجع من المدرس قريب", data: inserted });
}

// ============================================
// ⭐ مدرس/مساعد: قائمة الإيصالات
// ============================================
async function handleList(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_payments");
  await requireAssistantPermission(payload, "record_payments");

  const { clientId, status } = body;
  if (tokenClientId !== clientId) return jsonResponse({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }, 403);

  let query = supabase.from("payment_receipts").select("*, students(name)").eq("teacher_id", clientId).order("submitted_at", { ascending: false });
  if (status) query = query.eq("status", status);
  else query = query.eq("status", "pending");

  const { data: receipts, error } = await query;
  if (error) throw new Error(error.message);

  const withUrls = await Promise.all((receipts || []).map(async (r: any) => {
    const { data: signed } = await supabase.storage.from(BUCKET).createSignedUrl(r.receipt_path, 600);
    return { ...r, student_name: r.students?.name, students: undefined, receiptUrl: signed?.signedUrl || null };
  }));

  return jsonResponse({ success: true, data: withUrls });
}

// ============================================
// ⭐ ولي الأمر: إيصالاته هو بس على طالب بعينه (عشان يعرف حالة إيصال سابق — معلّق/مرفوض)
// ============================================
async function handleListMine(supabase: any, payload: TokenPayload, body: any) {
  const parentPhone = requireParentPhone(payload);
  const { studentUid } = body;
  if (!studentUid) return jsonResponse({ success: false, message: "⚠️ معرف الطالب مطلوب" }, 400);

  const { data: student } = await supabase.from("students").select("uid, parent_phone").eq("uid", studentUid).maybeSingle();
  if (!student || student.parent_phone !== parentPhone) {
    return jsonResponse({ success: false, message: "⛔ غير مصرح لك بهذا الطالب" }, 403);
  }

  const { data: receipts, error } = await supabase.from("payment_receipts")
    .select("id, title, status, claimed_amount, rejection_reason, submitted_at")
    .eq("student_uid", studentUid).order("submitted_at", { ascending: false });
  if (error) throw new Error(error.message);

  return jsonResponse({ success: true, data: receipts || [] });
}

// ============================================
// ⭐ مدرس/مساعد: تأكيد إيصال (بيسجّل الدفعة فعليًا بنفس منطق manage-payment)
// ============================================
async function handleApprove(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_payments");
  await requireAssistantPermission(payload, "record_payments");

  const { clientId, receiptId, assistantId, assistantName } = body;
  if (tokenClientId !== clientId) return jsonResponse({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }, 403);
  if (!receiptId) return jsonResponse({ success: false, message: "⚠️ معرف الإيصال مطلوب" }, 400);

  const { data: receipt, error: fetchError } = await supabase.from("payment_receipts").select("*").eq("id", receiptId).maybeSingle();
  if (fetchError || !receipt) return jsonResponse({ success: false, message: "الإيصال غير موجود" }, 404);
  if (receipt.teacher_id !== tokenClientId) return jsonResponse({ success: false, message: "⛔ هذا الإيصال ليس تابعاً لك" }, 403);
  if (receipt.status !== "pending") return jsonResponse({ success: false, message: "⚠️ الإيصال ده اتراجع بالفعل" }, 409);

  const result = await recordPayments(
    supabase,
    { clientId, uidsList: [receipt.student_uid], title: receipt.title, totalAmount: Number(receipt.total_amount), amount: Number(receipt.claimed_amount), assistantId, assistantName, groupName: receipt.group_name },
    sendPushToRecipient
  );

  if (!result.success) {
    // ✅ مش بنعلّم الإيصال كـ approved لو فشل التسجيل الفعلي (مثلاً اتسجّلت دفعة تانية يدوي
    // لنفس البند لحد ما ولي الأمر كان مستني المراجعة) — المدرس يقدر يرفضه بسبب واضح بدل كده
    return jsonResponse({ success: false, message: result.message });
  }

  await supabase.from("payment_receipts").update({
    status: "approved", reviewed_by: assistantId || clientId, reviewed_at: new Date().toISOString(),
  }).eq("id", receiptId);

  return jsonResponse({ success: true, message: "✅ تم تأكيد الإيصال وتسجيل الدفعة", data: result.data });
}

// ============================================
// ⭐ مدرس/مساعد: رفض إيصال
// ============================================
async function handleReject(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_payments");
  await requireAssistantPermission(payload, "record_payments");

  const { clientId, receiptId, reason, assistantId, assistantName } = body;
  if (tokenClientId !== clientId) return jsonResponse({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }, 403);
  if (!receiptId || !reason || !String(reason).trim()) {
    return jsonResponse({ success: false, message: "⚠️ سبب الرفض مطلوب" }, 400);
  }

  const { data: receipt, error: fetchError } = await supabase.from("payment_receipts").select("*").eq("id", receiptId).maybeSingle();
  if (fetchError || !receipt) return jsonResponse({ success: false, message: "الإيصال غير موجود" }, 404);
  if (receipt.teacher_id !== tokenClientId) return jsonResponse({ success: false, message: "⛔ هذا الإيصال ليس تابعاً لك" }, 403);
  if (receipt.status !== "pending") return jsonResponse({ success: false, message: "⚠️ الإيصال ده اتراجع بالفعل" }, 409);

  const cleanReason = String(reason).trim();
  await supabase.from("payment_receipts").update({
    status: "rejected", rejection_reason: cleanReason, reviewed_by: assistantId || clientId, reviewed_at: new Date().toISOString(),
  }).eq("id", receiptId);

  const { data: student } = await supabase.from("students").select("uid, name, parent_phone").eq("uid", receipt.student_uid).maybeSingle();
  if (student) {
    const message = `تم رفض إيصال دفعة "${receipt.title}" — السبب: ${cleanReason}. يمكنك رفع إيصال جديد.`;
    const notifRows = [
      ...(student.parent_phone ? [{
        teacher_id: clientId, parent_phone: student.parent_phone, student_uid: student.uid, type: "payment", title: "رفض إيصال دفع", audience: "parent",
        message, details: { title: receipt.title, reason: cleanReason },
      }] : []),
      { teacher_id: clientId, student_uid: student.uid, type: "payment", title: "رفض إيصال دفع", audience: "student", message, details: { title: receipt.title, reason: cleanReason } },
    ];
    await supabase.from("notifications").insert(notifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعار رفض الإيصال:", error.message); });
    if (student.parent_phone) sendPushToRecipient(supabase, "parent", student.parent_phone, "رفض إيصال دفع", message);
    sendPushToRecipient(supabase, "student", student.uid, "رفض إيصال دفع", message);
  }

  return jsonResponse({ success: true, message: "تم رفض الإيصال" });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    let body: any;
    try { body = await req.json(); }
    catch (_e) { return jsonResponse({ success: false, message: "الطلب يجب أن يحتوي على JSON صالح" }, 400); }

    const action = body.action;
    if (action === "submit") return await handleSubmit(supabase, payload, body);
    if (action === "list") return await handleList(supabase, payload, body);
    if (action === "listMine") return await handleListMine(supabase, payload, body);
    if (action === "approve") return await handleApprove(supabase, payload, body);
    if (action === "reject") return await handleReject(supabase, payload, body);

    return jsonResponse({ success: false, message: "⚠️ action غير معروفة — لازم تكون submit أو list أو listMine أو approve أو reject" }, 400);
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في manage-payment-receipt:", error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return jsonResponse({ success: false, message }, 500);
  }
});
