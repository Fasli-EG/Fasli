// supabase/functions/manage-payment/index.ts
// ✅ دالة موحّدة تجمع add-payment + update-payment + delete-payment بـ "action" parameter
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, TokenPayload, AuthError, verifyToken, requireTeacherPlanPermission, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";
import { recordPayments, updatePaymentAmount } from "../_shared/payments.ts";

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

  // ✅ منطق الإدراج الفعلي في payments + upsert payment_titles + الإشعارات اتنقل لـ
  // _shared/payments.ts عشان يتشارك مع manage-payment-receipt (تأكيد إيصال مرفوع من ولي
  // الأمر) — نفس السلوك بالظبط في الحالتين، من غير أي تكرار كود.
  const result = await recordPayments(
    supabase,
    { clientId, uidsList, title, totalAmount: Number(totalAmount), amount: Number(amount), assistantId, assistantName, defaultAmount, groupName },
    sendPushToRecipient
  );

  return new Response(JSON.stringify(result),
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

  const result = await updatePaymentAmount(
    supabase,
    { paymentId, tokenClientId, newAmount: Number(amount), assistantId, assistantName },
    sendPushToRecipient
  );

  return new Response(JSON.stringify(result), { status: result.status || 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
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
