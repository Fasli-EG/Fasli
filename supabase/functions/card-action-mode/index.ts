// supabase/functions/card-action-mode/index.ts
// ✅ دالة موحّدة تجمع get-card-action-mode + set-card-action-mode — action: get | set
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
  "Access-Control-Max-Age": "86400",
};

interface TokenPayload { sub: string; clientId?: string; teacherId?: string; role: string; name: string; }

class AuthError extends Error {
  status: number; code?: string;
  constructor(message: string, status = 401, code?: string) { super(message); this.status = status; this.code = code; }
}

async function verifyToken(req: Request): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) throw new AuthError("⚠️ التوكن مطلوب", 401);
  const token = authHeader.substring(7);
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) throw new Error("⚠️ JWT_SECRET غير مضبوط");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  try { return (await verify(token, key, "HS256")) as unknown as TokenPayload; }
  catch (_e) { throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401); }
}

/**
 * ✅ (طلب) جهاز القارئ (ESP32) نفسه محتاج يعرف أي الأوضاع شغّالة دلوقتي (حضور/دفع اشتراك/سداد
 * مذكرة) عشان يضيء اللمبة المناسبة على جسمه — بسر الجهاز الخاص بكل مدرس بدل توكن مستخدم،
 * بنفس فكرة verifyDeviceSecret المستخدمة في record-attendance، لكن هنا للقراءة فقط
 * (الجهاز ممنوع يعدّل الوضع، بس يقرأه).
 */
async function verifyDeviceSecret(supabase: any, clientId: string, deviceSecret: string): Promise<void> {
  if (!clientId || !deviceSecret) throw new AuthError("⚠️ بيانات الجهاز ناقصة (clientId أو deviceSecret)", 401);
  const { data: teacher, error } = await supabase
    .from("teachers").select("device_secret, is_active, expiry_date").eq("client_id", clientId).maybeSingle();
  if (error || !teacher || !teacher.device_secret) throw new AuthError("⛔ جهاز غير معروف", 401);
  if (teacher.device_secret !== deviceSecret) throw new AuthError("⛔ سر الجهاز غير صحيح", 401);
  if (teacher.is_active === false) throw new AuthError("⛔ حساب المدرس معطّل", 402, "LICENSE_EXPIRED");
  if (teacher.expiry_date) {
    const today = new Date().toISOString().split("T")[0];
    if (teacher.expiry_date < today) throw new AuthError("⛔ انتهت صلاحية الترخيص", 402, "LICENSE_EXPIRED");
  }
}

async function requireAssistantPermission(payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");
  const { data: assistant } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) throw new AuthError("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس", 403);
}

async function requireTeacherPlanPermission(clientId: string, permKey: string): Promise<void> {
  if (clientId === "master_admin") return;
  const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");
  const { data: teacher } = await supabase.from("teachers").select("permissions").eq("client_id", clientId).maybeSingle();
  const perms = teacher?.permissions || {};
  if (perms[permKey] === false) throw new AuthError("⛔ هذه الميزة غير متاحة في باقتك الحالية، تواصل مع الإدارة لتفعيلها", 403, "PLAN_RESTRICTED");
}

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 1: قراءة الوضع الحالي (مع الرجوع التلقائي لحضور بس بعد انتهاء المدة)
// ============================================
async function handleGet(supabase: any, tokenClientId: string) {
  // ✅ (طلب متابعة) لو فيه طلب تسجيل/ربط كارت معلّق (تسجيل طالب جديد، أو ربط كارت بطالب
  // موجود بالفعل — عن طريق teacher-start-new-student-scan أو manage-card-registration)،
  // القارئ لازم يشتغل عشان يقدر يمسك الكارت، حتى لو مفيش أي وضع (حضور/دفع/مذكرة) مفعّل
  // أصلاً دلوقتي. بنتأكد إن الطلب "طازة" (آخر 5 دقايق من requested_at) عشان طلب اتنسي أو
  // الصفحة اتقفلت من غير إلغاء رسمي (manage-card-registration action=cancel) ميفضلش
  // القارئ شغّال للأبد بلا داعي
  const { data: pendingReg } = await supabase
    .from("pending_card_registrations")
    .select("requested_at")
    .eq("teacher_id", tokenClientId)
    .is("registered_card_uid", null)
    .maybeSingle();
  if (pendingReg?.requested_at) {
    const pendingAgeMs = Date.now() - new Date(pendingReg.requested_at).getTime();
    if (pendingAgeMs <= 5 * 60 * 1000) {
      return new Response(JSON.stringify({ success: true, readerEnabled: true, modes: [], isEnabled: false, pendingRegistration: true }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  const { data: mode } = await supabase.from("card_action_mode").select("*").eq("teacher_id", tokenClientId).maybeSingle();

  // ✅ (طلب متابعة) لو مفيش أي وضع محدد (حضور/دفع/مذكرة) دلوقتي — القارئ يفضل شغّال قراية
  // برضو (مش مقفول) عشان يسهّل استخدامه فى تسجيل/ربط كروت الطلاب الجدد بسرعة من غير ما
  // المدرس يضطر يفعّل وضع الحضور الأول بس عشان يفتح الهوائي. الجهاز نفسه (FasliT.ino) بيقرأ
  // القيمة دي بس عشان يقرر يفتح الهوائي فيزيائياً ولا لأ — modes فاضية يعني مفيش أي معالجة
  // (حضور/دفع/مذكرة) هتحصل للكارت اللي هيتقرا، هيتسجل بس فى rfid_scans من غير تأثير فعلي
  // (بالظبط زي حالة "طلب تسجيل معلّق" فوق). القفل الفعلي الوحيد المتبقي هو وضع الإعداد
  // (Access Point) نفسه، وده بيتحكم فيه الجهاز مباشرة بغض النظر عن القيمة دي
  if (!mode || !mode.is_enabled) {
    return new Response(JSON.stringify({ success: true, readerEnabled: true, modes: [], isEnabled: false, pendingRegistration: false }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const onlyAttendance = mode.attendance_enabled && !mode.payment_enabled && !mode.book_payment_enabled;
  if (onlyAttendance) {
    return new Response(JSON.stringify({ success: true, readerEnabled: true, modes: ["attendance"], isEnabled: true, pendingRegistration: false }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const durationMs = (mode.duration_minutes || 30) * 60 * 1000;
  const idleMs = Date.now() - new Date(mode.set_at || mode.updated_at).getTime();
  if (idleMs > durationMs) {
    await supabase.from("card_action_mode").update({
      attendance_enabled: true, payment_enabled: false, book_payment_enabled: false,
      updated_at: new Date().toISOString(),
    }).eq("teacher_id", tokenClientId);
    return new Response(JSON.stringify({ success: true, readerEnabled: true, modes: ["attendance"], autoReverted: true, isEnabled: true, pendingRegistration: false }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const activeModes = [];
  if (mode.attendance_enabled) activeModes.push("attendance");
  if (mode.payment_enabled) activeModes.push("payment");
  if (mode.book_payment_enabled) activeModes.push("book_payment");

  return new Response(JSON.stringify({
    success: true, readerEnabled: true, modes: activeModes, isEnabled: true, pendingRegistration: false,
    paymentTitle: mode.payment_title, paymentAmount: mode.payment_amount,
    bookId: mode.book_id, bookAmount: mode.book_amount, setBy: mode.set_by,
    remainingSeconds: Math.max(0, Math.round((durationMs - idleMs) / 1000)),
    // ✅ Aug 2026 (Phase I): سياق الجلسة الحالية (مدرس/مجموعة/حصة) — بيبقى معبّى بس لحسابات السنتر
    activeInstructorNameId: mode.active_instructor_name_id || null,
    activeGroupName: mode.active_group_name || null,
    activeSessionId: mode.active_session_id || null,
    activeSessionLabel: mode.active_session_label || null,
  }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 2: تحديد الوضع (تفعيل/تعطيل القارئ، أو تحديد الأوضاع النشطة)
// ============================================
async function handleSet(supabase: any, payload: TokenPayload, tokenClientId: string, body: any) {
  const {
    modes, paymentTitle, paymentAmount, bookId, bookAmount, isEnabled, durationMinutes,
    // ✅ Aug 2026 (Phase I follow-up 10): سياق الجلسة الحالية — مجموعة+حصة مطلوبة إجباري
    // لكل الحسابات (سنتر وعادي)، والمدرس (instructorNameId) مطلوب لحسابات السنتر بس
    instructorNameId, groupName, sessionId, newSessionLabel, newSessionThresholdMinutes,
    // ✅ (طلب دفعة 45، متابعة) مدة الحصة نفسها (طول الحصة الفعلي) — نفس المبدأ اللي
    // موجود أصلاً في مسار التسجيل اليدوي (record-attendance)، هنا كانت ناقصة في مسار
    // تفعيل القارئ لحصة جديدة
    newSessionDurationMinutes,
  } = body;

  if (isEnabled === false) {
    const { error: disableError } = await supabase.from("card_action_mode").upsert({
      teacher_id: tokenClientId, is_enabled: false, updated_at: new Date().toISOString(),
      active_instructor_name_id: null, active_group_name: null, active_session_id: null, active_session_label: null,
    }, { onConflict: "teacher_id" });
    if (disableError) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, message: "⏸ تم إيقاف القارئ" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const attendanceEnabled = Array.isArray(modes) ? modes.includes("attendance") : true;
  const paymentEnabled = Array.isArray(modes) && modes.includes("payment");
  const bookPaymentEnabled = Array.isArray(modes) && modes.includes("book_payment");

  if (!attendanceEnabled && !paymentEnabled && !bookPaymentEnabled) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ اختر وضع واحد على الأقل" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (paymentEnabled && (!paymentTitle || paymentAmount === undefined)) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ اختر بند السداد والمبلغ" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (bookPaymentEnabled && (!bookId || bookAmount === undefined)) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ اختر المذكرة والمبلغ" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ Aug 2026 (Phase I follow-up 10): تحديد المجموعة والحصة بقى مطلوب إجباري قبل
  // تفعيل القارئ لكل الحسابات (سنتر وعادي) — المدرس (instructorNameId) لسه مطلوب
  // لحسابات السنتر بس، لأن الحساب العادي هو نفسه المدرس الوحيد
  const { data: teacherRow } = await supabase.from("teachers").select("is_center").eq("client_id", tokenClientId).maybeSingle();
  const isCenter = teacherRow?.is_center === true;

  let activeInstructorNameId: number | null = null;
  let activeGroupName: string | null = null;
  let activeSessionId: number | null = null;
  let activeSessionLabel: string | null = null;

  if (!groupName) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تحدد المجموعة قبل تفعيل القارئ" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  let resolvedInstructorId: number | null = null;
  let resolvedInstructorName: string | null = null;

  if (isCenter) {
    if (!instructorNameId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تحدد المدرس والمجموعة قبل تفعيل القارئ" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { data: instructorRow } = await supabase.from("instructor_names").select("id, name")
      .eq("id", instructorNameId).eq("teacher_id", tokenClientId).maybeSingle();
    if (!instructorRow) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ المدرس المحدد غير موجود" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { data: groupRow } = await supabase.from("groups").select("name, instructor_name_id")
      .eq("name", groupName).eq("teacher_id", tokenClientId).maybeSingle();
    if (!groupRow || groupRow.instructor_name_id !== instructorRow.id) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ المجموعة المحددة غير مربوطة بهذا المدرس" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    resolvedInstructorId = instructorRow.id;
    resolvedInstructorName = instructorRow.name;
  }

  // ✅ اليوم بتوقيت القاهرة — الحصة تبقى متاحة للاختيار (أو التعديل) بس لو اتنشأت النهاردة
  const cairoNow = new Date(new Date().toLocaleString("en-US", { timeZone: "Africa/Cairo" }));
  const today = cairoNow.toISOString().split("T")[0];

  if (sessionId) {
    const { data: sessionRow } = await supabase.from("attendance_sessions").select("id, session_label, group_name, session_date")
      .eq("id", sessionId).eq("teacher_id", tokenClientId).maybeSingle();
    if (!sessionRow || sessionRow.group_name !== groupName || sessionRow.session_date !== today) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ الحصة المحددة غير متاحة اليوم لهذه المجموعة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    activeSessionId = sessionRow.id;
    activeSessionLabel = sessionRow.session_label || null;
  } else if (newSessionLabel) {
    const threshold = Number(newSessionThresholdMinutes) > 0 ? Number(newSessionThresholdMinutes) : 30;
    // ✅ نفس منطق record-attendance بالظبط: مدة الحصة اختيارية، مفيش قيمة افتراضية مفروضة
    const sessionDuration = Number(newSessionDurationMinutes) > 0 ? Number(newSessionDurationMinutes) : null;
    const { data: newSession, error: newSessionError } = await supabase.from("attendance_sessions").insert({
      teacher_id: tokenClientId, group_name: groupName, session_label: newSessionLabel,
      instructor_name_id: resolvedInstructorId, instructor_name: resolvedInstructorName,
      absence_threshold_minutes: threshold, duration_minutes: sessionDuration, session_date: today,
      created_by_role: payload.role, created_by_id: payload.sub, created_by_name: payload.name || null,
    }).select("id, session_label").single();
    if (newSessionError || !newSession) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ تعذر إنشاء الحصة الجديدة" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    activeSessionId = newSession.id;
    activeSessionLabel = newSession.session_label || null;
  } else {
    return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تحدد حصة موجودة من النهاردة أو تنشئ حصة جديدة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  activeInstructorNameId = resolvedInstructorId;
  activeGroupName = groupName;

  const finalDuration = durationMinutes && Number(durationMinutes) > 0 ? Number(durationMinutes) : 30;
  const setByName = payload.name || (payload.role === "assistant" ? "مساعد" : "مدرس");

  const { error } = await supabase.from("card_action_mode").upsert({
    teacher_id: tokenClientId, is_enabled: true,
    attendance_enabled: attendanceEnabled, payment_enabled: paymentEnabled, book_payment_enabled: bookPaymentEnabled,
    payment_title: paymentEnabled ? paymentTitle : null, payment_amount: paymentEnabled ? Number(paymentAmount) : null,
    book_id: bookPaymentEnabled ? bookId : null, book_amount: bookPaymentEnabled ? Number(bookAmount) : null,
    duration_minutes: finalDuration, set_by: setByName, set_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    active_instructor_name_id: activeInstructorNameId, active_group_name: activeGroupName,
    active_session_id: activeSessionId, active_session_label: activeSessionLabel,
  }, { onConflict: "teacher_id" });

  if (error) {
    console.error("❌ فشل تحديد وضع الكارت:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const activeLabels = [];
  if (attendanceEnabled) activeLabels.push("تسجيل الحضور");
  if (paymentEnabled) activeLabels.push("دفع اشتراك");
  if (bookPaymentEnabled) activeLabels.push("سداد مذكرة");

  return new Response(JSON.stringify({ success: true, message: `✅ الكارت دلوقتي شغّال على: ${activeLabels.join(" + ")} لمدة ${finalDuration} دقيقة، وبعدها هيرجع لوضع الحضور بس تلقائياً` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    const body = await req.json();
    const action = body.action;

    // ✅ (طلب) مسار جهاز القارئ نفسه — بسر الجهاز بدل توكن مستخدم، قراءة بس (action=get)،
    // عشان يعرف يضيء لمبة الوضع الصحيحة على جسمه (حضور/دفع اشتراك/سداد مذكرة)
    if (body.secret && body.clientId) {
      await verifyDeviceSecret(supabase, body.clientId, body.secret);
      if (action !== "get") {
        return new Response(JSON.stringify({ success: false, message: "⛔ الجهاز مسموح له بقراءة الوضع بس" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return await handleGet(supabase, body.clientId);
    }

    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;
    if ((payload.role !== "teacher" && payload.role !== "assistant") || !tokenClientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ متاح للمدرس أو المساعد بس" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "get") {
      await requireAssistantPermission(payload, "manage_card_mode");
      return await handleGet(supabase, tokenClientId);
    }
    if (action === "set") {
      await requireTeacherPlanPermission(tokenClientId, "can_use_rfid");
      await requireAssistantPermission(payload, "manage_card_mode");
      return await handleSet(supabase, payload, tokenClientId, body);
    }

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
