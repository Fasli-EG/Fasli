// supabase/functions/record-attendance/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, TokenPayload, AuthError, verifyToken, ownerClientId, requireOwnClientId, requireAdmin, requireParentPhone, requireTeacherPlanPermission, requireAssistantPermission, verifyDeviceSecret, authErrorResponse } from "../_shared/auth.ts";

// ============================================
// (من _shared/push.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// ============================================
// إرسال إشعارات Push حقيقية عبر Firebase Cloud Messaging (HTTP v1 API)
// محتاج متغير بيئة اسمه FIREBASE_SERVICE_ACCOUNT فيه محتوى ملف الـ Service Account JSON كامل كنص

interface ServiceAccount {
  client_email: string;
  private_key: string;
  project_id: string;
}

let cachedAccessToken: { token: string; expiresAt: number } | null = null;

function base64url(input: ArrayBuffer | string): string {
  let bytes: Uint8Array;
  if (typeof input === "string") {
    bytes = new TextEncoder().encode(input);
  } else {
    bytes = new Uint8Array(input);
  }
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function getAccessToken(sa: ServiceAccount): Promise<string> {
  if (cachedAccessToken && cachedAccessToken.expiresAt > Date.now() + 60_000) {
    return cachedAccessToken.token;
  }

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };

  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;

  // ✅ نجهّز المفتاح الخاص للتوقيع (PEM -> CryptoKey)
  const pemBody = sa.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  const binaryKey = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryKey.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, new TextEncoder().encode(unsigned));
  const jwt = `${unsigned}.${base64url(signature)}`;

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    console.error("❌ فشل الحصول على access token من Firebase:", tokenData);
    throw new Error("فشل مصادقة Firebase");
  }

  cachedAccessToken = { token: tokenData.access_token, expiresAt: Date.now() + tokenData.expires_in * 1000 };
  return tokenData.access_token;
}

/**
 * يبعت إشعار Push حقيقي لكل الأجهزة المسجّلة لمستخدم معيّن (ولي أمر أو مساعد أو مدرس).
 * أي فشل هنا بيتسجّل في السيرفر بس، ومايوقفش العملية الأساسية (زي تسجيل حضور أو دفعة).
 */
export async function sendPushToRecipient(
  supabase: any,
  recipientType: "parent" | "assistant" | "teacher" | "student",
  recipientId: string,
  title: string,
  body: string
): Promise<void> {
  try {
    const saJson = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
    if (!saJson) return; // Firebase لسه مش متفعّل، نتجاهل بهدوء

    const { data: tokens } = await supabase
      .from("push_tokens")
      .select("id, token")
      .eq("recipient_type", recipientType)
      .eq("recipient_id", recipientId);

    if (!tokens || tokens.length === 0) return;

    const sa: ServiceAccount = JSON.parse(saJson);
    const accessToken = await getAccessToken(sa);

    for (const row of tokens) {
      const res = await fetch(
        `https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            message: {
              token: row.token,
              notification: { title, body },
              android: { priority: "high", notification: { sound: "default", channel_id: "fasli_notifications" } },
            },
          }),
        }
      );

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        // ✅ لو التوكن بقى غير صالح (اتفصل التطبيق أو اتمسح)، نمسحه من القائمة عشان منحاولش نبعتله تاني
        if (errData?.error?.status === "NOT_FOUND" || errData?.error?.status === "INVALID_ARGUMENT") {
          await supabase.from("push_tokens").delete().eq("id", row.id);
        } else {
          console.error("⚠️ فشل إرسال Push notification:", errData);
        }
      }
    }
  } catch (error) {
    console.error("⚠️ خطأ غير متوقع في إرسال Push notification:", error);
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    // ✅ Aug 2026 (Phase I follow-up 10 fix): طلب فاضي/غير صالح (مثلاً من جهاز قارئ اتقطعت شبكته
    // نص الطلب) كان بيرمي استثناء من req.json() بيوصل لمنصة Supabase كخطأ عام بيترجم أحياناً
    // كحالة 402 غلط — ده كان بيخلّي واجهة المستخدم تفتكرها انتهاء ترخيص وتحوّله لصفحة القفل غلط.
    // بنمسك الخطأ ده بنفسنا هنا ونرجّع 400 واضح، عشان أي فشل في تحليل الطلب يبقى مستحيل يتفسّر
    // غلط كأنه انتهاء ترخيص عند الواجهة (اللي بتفحص status === 402 بس)
    let body: any;
    try {
      body = await req.json();
    } catch (_e) {
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ طلب غير صالح (بيانات فاضية أو تالفة)" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
    const {
      clientId, uid, secret, manual, notes, assistantId, instructorNameId, groupName, sessionId,
      // ✅ (طلب) لما يكون فيه "إنشاء حصة جديدة" مع الحضور اليدوي، بقينا ننشئها ونستخدمها في
      // نفس الطلب ده مباشرة (بدل طلبين منفصلين: طلب إنشاء ثم طلب تسجيل) — كان ده بيسبب فشل
      // صامت في تسجيل أول طالب لما التحقق اللاحق من الحصة (في طلب منفصل) مايتحققش، فيتسجل
      // الحضور من غير ما يترتبط بالحصة خالص (session_id فاضي) من غير أي رسالة خطأ واضحة
      newSessionLabel, newSessionThresholdMinutes, newSessionDurationMinutes,
    } = body || {};

    if (!clientId || !uid) {
      return new Response(
        JSON.stringify({ success: false, message: "clientId و uid مطلوبان" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ✅ رسائل عمليات إضافية (دفع/سداد مذكرة) اللي حصلت مع الحضور في نفس المسحة، لو الوضع مفعّل
    const extraActionMessages: string[] = [];

    // ✅ Aug 2026 (Phase I): سياق الجلسة الحالية اللي القارئ شغّال عليه (لحسابات السنتر) —
    // بيتحدد من card_action_mode.active_* ويبقى هو المرجع بدل التخمين، ويتفحص إن الطالب فعلاً
    // تابع للمجموعة دي (أساسية أو مربوطة) قبل ما يتسجّل حضوره تحتها
    let centerActiveContext: {
      instructorNameId: number | null; instructorName: string | null; groupName: string;
      sessionId: number | null; sessionLabel: string | null;
      // ✅ (طلب) محتاجين وقت إنشاء الحصة ومهلة أخذ الغياب بتاعتها هنا عشان نقدر نرفض أي
      // تسجيل حضور (قارئ أو يدوي) بعد ما المهلة دي تخلص — نفس الحساب المستخدم في
      // check-session-absences بالظبط
      sessionCreatedAt: string | null; sessionThresholdMinutes: number | null;
    } | null = null;

    // ✅ مصدر الطلب: إما جهاز قارئ كروت (بسر خاص بالمدرس) أو مستخدم مسجل دخول عادي (توكن)
    if (secret) {
      await verifyDeviceSecret(clientId, secret);
      await requireTeacherPlanPermission(clientId, "can_use_rfid");

      // ✅ لو المدرس/المساعد فاتح وضع "قراءة كارت" في قسم إضافة طالب أو ربط كارت دلوقتي،
      // أي كارت يتمرّغ في الوقت ده لازم يتجاهل تسجيل الحضور خالص — هو بيتفحص بس، مش بيحضر فعلياً
      const { data: activeSession } = await supabase
        .from("pending_card_registrations").select("id, requested_at").eq("teacher_id", clientId).maybeSingle();

      // ✅ بنحسب الفرق بالثواني، عشان نضمن الحماية تفضل شغّالة حتى لو الواجهة نضّفت الصف بسرعة
      // (فرق التوقيت بين الطلبين اللي بيبعتهم البورد ممكن ياخد كذا ثانية بسبب زمن استجابة الشبكة)
      const isRecentSession = activeSession?.requested_at
        ? (Date.now() - new Date(activeSession.requested_at).getTime()) < 20000
        : false;

      if (activeSession && isRecentSession) {
        return new Response(JSON.stringify({ success: true, ignored: true, message: "تم تجاهل التسجيل — وضع فحص/تسجيل كارت شغّال حالياً" }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ لو الكارت ده معطّل رسمياً من الأدمن، نرفض تسجيل الحضور بيه فوراً
      // (البورد بيبعت لدالة submit-rfid-scan ودالة تسجيل الحضور دي كل مرة بشكل مستقل، فلازم نفس التحقق هنا كمان)
      const { data: knownCard } = await supabase
        .from("system_cards").select("id, is_active, teacher_id, center_id").eq("card_uid", uid).maybeSingle();

      // ✅ الكارت ممكن يكون مربوط مباشرة بالمدرس، أو مربوط بالسنتر اللي المدرس تابع له
      // (لو المدرس تابع لسنتر، الكروت المخصصة للسنتر كله متاحة لكل مدرسيه)
      let cardBelongsToTeacher = knownCard?.teacher_id === clientId;
      if (!cardBelongsToTeacher && knownCard?.center_id) {
        const { data: teacherRow } = await supabase.from("teachers").select("center_id").eq("client_id", clientId).maybeSingle();
        cardBelongsToTeacher = !!teacherRow?.center_id && teacherRow.center_id === knownCard.center_id;
      }

      if (knownCard && cardBelongsToTeacher && !knownCard.is_active) {
        return new Response(JSON.stringify({ success: false, message: "⛔ الكارت ده معطّل حالياً" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: cardSettings } = await supabase.from("system_settings").select("require_registered_cards").eq("id", 1).maybeSingle();
      if (cardSettings?.require_registered_cards) {
        const isRegisteredAndActive = knownCard && cardBelongsToTeacher && knownCard.is_active;
        if (!isRegisteredAndActive) {
          return new Response(JSON.stringify({ success: false, message: "⛔ الكارت ده مش مسجّل رسمياً أو مش مفعّل في النظام" }),
            { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }

      // ✅ وضع الكارت: دلوقتي بيدعم أكتر من عملية في نفس الوقت (حضور + دفع اشتراك + سداد مذكرة مع بعض)
      // بدل ما يكون وضع واحد بس شغال — كل عملية مفعّلة بتتنفّذ لوحدها، وبعدين نكمّل لتسجيل الحضور العادي
      const { data: cardMode } = await supabase.from("card_action_mode").select("*").eq("teacher_id", clientId).maybeSingle();

      // ✅ القارئ متعطّل تماماً بمعرفة المدرس نفسه — مايسجّلش أي حاجة خالص، حتى الحضور العادي
      if (!cardMode || !cardMode.is_enabled) {
        return new Response(JSON.stringify({ success: false, message: "⏸ جهاز القارئ متوقف حالياً، فعّله من لوحة التحكم الأول" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ Aug 2026 (Phase I follow-up 10): سياق الجلسة (مجموعة + حصة يومية) بقى مطلوب
      // لكل الحسابات — المدرس (instructor) بيتحدد كمان لو الحساب سنتر بس
      if (cardMode.active_group_name) {
        let activeInstructorName: string | null = null;
        if (cardMode.active_instructor_name_id) {
          const { data: activeInstructorRow } = await supabase
            .from("instructor_names").select("id, name").eq("id", cardMode.active_instructor_name_id).maybeSingle();
          activeInstructorName = activeInstructorRow?.name || null;
        }
        // ✅ (طلب) لازم نجيب وقت إنشاء الحصة ومهلتها عشان نقدر نرفض أي كارت يتمسح بعد
        // ما المهلة تخلص — قبل كده القارئ كان بيفضل يسجل حضور "حاضر" بغض النظر عن الوقت
        // طول ما هو مفعّل، حتى لو فات على بداية الحصة ساعات
        let sessionCreatedAt: string | null = null;
        let sessionThresholdMinutes: number | null = null;
        if (cardMode.active_session_id) {
          const { data: activeSessionRow } = await supabase
            .from("attendance_sessions").select("created_at, absence_threshold_minutes")
            .eq("id", cardMode.active_session_id).maybeSingle();
          if (activeSessionRow) {
            sessionCreatedAt = activeSessionRow.created_at;
            sessionThresholdMinutes = activeSessionRow.absence_threshold_minutes;
          }
        }
        centerActiveContext = {
          instructorNameId: cardMode.active_instructor_name_id || null,
          instructorName: activeInstructorName,
          groupName: cardMode.active_group_name,
          sessionId: cardMode.active_session_id || null,
          sessionLabel: cardMode.active_session_label || null,
          sessionCreatedAt, sessionThresholdMinutes,
        };
      }

      // ✅ المدة بقت قابلة للتخصيص من المدرس، بدل ما تكون 5 دقايق ثابتة دايماً
      const durationMs = (cardMode.duration_minutes || 30) * 60 * 1000;
      const extraModesActive = (cardMode.payment_enabled || cardMode.book_payment_enabled) &&
        (Date.now() - new Date(cardMode.set_at || cardMode.updated_at).getTime()) < durationMs;

      if (extraModesActive) {
        const { data: modeStudent } = await supabase
          .from("students").select("uid, name, group_name, parent_phone").eq("uid", uid).eq("teacher_id", clientId).maybeSingle();

        if (!modeStudent) {
          return new Response(JSON.stringify({ success: false, message: "⚠️ الكارت ده مش مربوط بأي طالب عندك" }),
            { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // ✅ نمدّد المهلة مع كل كارت ناجح، عشان يقدر يكمّل يمرّغ كروت تانية من غير ما الوضع يرجع لحضور فجأة
        await supabase.from("card_action_mode").update({ updated_at: new Date().toISOString() }).eq("teacher_id", clientId);

        if (cardMode.payment_enabled) {
          const { data: existingPayment } = await supabase
            .from("payments").select("id").eq("student_uid", uid).eq("teacher_id", clientId).eq("title", cardMode.payment_title).maybeSingle();
          if (existingPayment) {
            extraActionMessages.push(`⚠️ ${modeStudent.name} مسدّد بند "${cardMode.payment_title}" بالفعل`);
          } else {
            const { data: titleRow } = await supabase
              .from("payment_titles").select("default_amount").eq("teacher_id", clientId).eq("title", cardMode.payment_title).maybeSingle();
            const realTotalAmount = titleRow?.default_amount ?? Number(cardMode.payment_amount);

            if (Number(cardMode.payment_amount) > realTotalAmount) {
              extraActionMessages.push(`⚠️ مبلغ بند "${cardMode.payment_title}" أكبر من سعره الأصلي — اتلغى`);
            } else {
              await supabase.from("payments").insert({
                student_uid: uid, student_name: modeStudent.name, group_name: modeStudent.group_name, teacher_id: clientId,
                title: cardMode.payment_title, total_amount: Number(realTotalAmount), amount: Number(cardMode.payment_amount),
              });
              const isPartial = Number(cardMode.payment_amount) < Number(realTotalAmount);
              extraActionMessages.push(`💰 اتسجّل دفع "${cardMode.payment_title}"${isPartial ? " (دفعة جزئية)" : ""}`);
            }
          }
        }

        if (cardMode.book_payment_enabled) {
          const { data: bookRow } = await supabase.from("books").select("name, price").eq("id", cardMode.book_id).maybeSingle();
          const { data: existingBookPayment } = await supabase
            .from("book_payments").select("id").eq("student_uid", uid).eq("teacher_id", clientId).eq("book_id", cardMode.book_id).maybeSingle();
          if (existingBookPayment) {
            extraActionMessages.push(`⚠️ ${modeStudent.name} مسدّد المذكرة دي بالفعل`);
          } else if (bookRow && Number(cardMode.book_amount) > bookRow.price) {
            extraActionMessages.push(`⚠️ مبلغ المذكرة أكبر من سعرها الأصلي — اتلغى`);
          } else {
            await supabase.from("book_payments").insert({
              book_id: cardMode.book_id, student_uid: uid, student_name: modeStudent.name, group_name: modeStudent.group_name,
              teacher_id: clientId, amount: Number(cardMode.book_amount),
            });
            const isPartialBook = bookRow && Number(cardMode.book_amount) < bookRow.price;
            extraActionMessages.push(`📖 اتسجّل سداد "${bookRow?.name || "المذكرة"}"${isPartialBook ? " (دفعة جزئية)" : ""}`);
          }
        }

        // ✅ لو الحضور مش مفعّل ضمن الأوضاع الحالية، نكتفي بالعمليات الإضافية دي بس ونوقف هنا
        if (cardMode.attendance_enabled === false) {
          return new Response(JSON.stringify({ success: true, cardAction: "combo", message: extraActionMessages.join(" — ") }),
            { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        // ✅ غير كده، نكمّل تسجيل الحضور العادي تحت، ونرفق رسائل العمليات الإضافية في الرد النهائي
      }
    } else {
      const payload = await verifyToken(req);
      const tokenClientId = payload.clientId || payload.teacherId;
      if (tokenClientId !== clientId) {
        return new Response(
          JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      await requireAssistantPermission(payload, "manage_attendance");

      // ✅ Aug 2026 (Phase I follow-up 10): الحضور اليدوي — لكل الحسابات — بيبعت المجموعة
      // والحصة اليومية اللي اتختاروا صراحةً من الواجهة (مدرس[سنتر فقط] → مجموعاته → حصصه
      // اليومية)، فبنستخدمهم كسياق أكيد بدل تخمين أقرب حصة — نفس فكرة سياق قارئ الكروت
      // (centerActiveContext) بس مصدره هنا اختيار يدوي مش card_action_mode
      if (manual === true && groupName) {
        let resolvedInstructorId: number | null = null;
        let resolvedInstructorName: string | null = null;
        if (instructorNameId) {
          const { data: instructorRow } = await supabase
            .from("instructor_names").select("id, name, teacher_id").eq("id", instructorNameId).maybeSingle();
          if (instructorRow && instructorRow.teacher_id === clientId) {
            resolvedInstructorId = instructorRow.id;
            resolvedInstructorName = instructorRow.name;
          }
        }
        let sessionLabel: string | null = null;
        let validSessionId: number | null = null;
        let sessionCreatedAt: string | null = null;
        let sessionThresholdMinutes: number | null = null;
        const cairoNowForSession = new Date(new Date().toLocaleString("en-US", { timeZone: "Africa/Cairo" }));
        const todayDateStr = cairoNowForSession.toISOString().split("T")[0];

        if (sessionId) {
          const { data: sessionRow } = await supabase
            .from("attendance_sessions")
            .select("id, session_label, group_name, teacher_id, session_date, created_at, absence_threshold_minutes")
            .eq("id", sessionId).maybeSingle();
          if (sessionRow && sessionRow.teacher_id === clientId && sessionRow.group_name === groupName && sessionRow.session_date === todayDateStr) {
            validSessionId = sessionRow.id;
            sessionLabel = sessionRow.session_label;
            sessionCreatedAt = sessionRow.created_at;
            sessionThresholdMinutes = sessionRow.absence_threshold_minutes;
          }
        } else if (newSessionLabel) {
          // ✅ (طلب) إنشاء الحصة الجديدة واستخدامها فوراً في نفس هذا الطلب — بدل ما تتنشئ في
          // طلب منفصل (manage-group-sessions) وبعدين نرجع نتأكد منها هنا في طلب تاني، وهو
          // اللي كان بيسبب فشل صامت في تسجيل أول طالب. نفس أسلوب تفعيل القارئ (card-action-mode)
          // بالظبط — إنشاء + استخدام فوري، من غير أي فجوة بين طلبين
          const threshold = Number(newSessionThresholdMinutes) > 0 ? Number(newSessionThresholdMinutes) : 30;
          const duration = Number(newSessionDurationMinutes) > 0 ? Number(newSessionDurationMinutes) : null;
          const { data: createdSession, error: createSessionError } = await supabase
            .from("attendance_sessions").insert({
              teacher_id: clientId, group_name: groupName, session_label: newSessionLabel,
              instructor_name_id: resolvedInstructorId, instructor_name: resolvedInstructorName,
              absence_threshold_minutes: threshold, duration_minutes: duration, session_date: todayDateStr,
              created_by_role: payload.role, created_by_id: payload.sub, created_by_name: payload.name || null,
            })
            .select("id, session_label, created_at, absence_threshold_minutes")
            .single();
          if (createSessionError || !createdSession) {
            return new Response(JSON.stringify({ success: false, message: "⚠️ تعذر إنشاء الحصة الجديدة" }),
              { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          validSessionId = createdSession.id;
          sessionLabel = createdSession.session_label;
          sessionCreatedAt = createdSession.created_at;
          sessionThresholdMinutes = createdSession.absence_threshold_minutes;
        }

        centerActiveContext = {
          instructorNameId: resolvedInstructorId,
          instructorName: resolvedInstructorName,
          groupName: groupName,
          sessionId: validSessionId,
          sessionLabel: sessionLabel,
          sessionCreatedAt, sessionThresholdMinutes,
        };
      }
    }
    await requireTeacherPlanPermission(clientId, "can_manage_students");

    const { data: student, error: studentError } = await supabase
      .from("students")
      .select("name, group_name, parent_phone")
      .eq("uid", uid)
      .eq("teacher_id", clientId)
      .single();

    if (studentError) {
      return new Response(
        JSON.stringify({ success: false, message: "UNREGISTERED" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ✅ Aug 2026 (Phase I): لو فيه سياق جلسة سنتر شغّال، لازم الطالب يكون تابع للمجموعة المحددة
    // فعلاً (أساسية أو مربوطة عن طريق student_group_links)، وإلا الكارت يترفض من غير تسجيل
    let attendanceGroupName = student.group_name;
    if (centerActiveContext) {
      const belongsToActiveGroup = student.group_name === centerActiveContext.groupName ||
        (await supabase.from("student_group_links").select("id")
          .eq("student_uid", uid).eq("group_name", centerActiveContext.groupName).maybeSingle()).data;
      if (!belongsToActiveGroup) {
        return new Response(
          JSON.stringify({ success: false, message: `⛔ ${student.name} مش مسجّل في مجموعة "${centerActiveContext.groupName}" الحالية` }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      attendanceGroupName = centerActiveContext.groupName;
    }

    // ✅ (طلب) لازم نرفض تسجيل الحضور — قارئ كروت أو يدوي، مفيش فرق — بعد ما مهلة أخذ
    // الغياب بتاعة الحصة تخلص، بنفس الحساب المستخدم في احتساب الغياب التلقائي بالظبط
    // (elapsed = الوقت من إنشاء الحصة). قبل كده كان ممكن يتسجل حضور "حاضر" في أي وقت
    // طول ما القارئ مفعّل أو شاشة الحضور اليدوي مفتوحة، حتى لو فات على بداية الحصة ساعات
    if (centerActiveContext?.sessionCreatedAt && centerActiveContext?.sessionThresholdMinutes != null) {
      const elapsedMinutes = (Date.now() - new Date(centerActiveContext.sessionCreatedAt).getTime()) / 60000;
      if (elapsedMinutes >= centerActiveContext.sessionThresholdMinutes) {
        return new Response(
          JSON.stringify({ success: false, message: "⛔ انتهت مهلة تسجيل الحضور لهذه الحصة", code: "SESSION_THRESHOLD_PASSED" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
    }

    const today = new Date().toISOString().split("T")[0];

    // ✅ Batch 24 (بند 1): الفحص القديم كان بيمنع أي تسجيل حضور تاني لنفس الطالب في نفس اليوم
    // بغض النظر عن الحصة — يعني طالب حضر حصة الصبح وجه حصة تانية بعد الضهر في نفس اليوم كان
    // بيترفض بـ"DUPLICATE_IGNORE" وكأنه بيحاول يسجّل حضور مكرر لنفس الحصة. دلوقتي الفحص بقى
    // لكل (طالب + حصة) لو فيه سياق حصة فعلي (session_id) — كل حصة بتاخد صف حضور منفصل، فالطالب
    // يقدر يحضر أكتر من حصة عادي في نفس اليوم. لو مفيش session_id خالص (حالة نادرة/قديمة قبل
    // ما الحصص بقت إجبارية)، بيرجع لنفس السلوك القديم (فحص على مستوى اليوم كله) عشان مايتكررش
    // صف حضور من غير حصة محددة.
    const matchedSessionId: number | null = centerActiveContext?.sessionId ?? null;
    let existingQuery = supabase.from("attendance").select("id").eq("student_uid", uid).eq("date", today);
    existingQuery = matchedSessionId
      ? existingQuery.eq("session_id", matchedSessionId)
      : existingQuery.is("session_id", null);
    const { data: existing, error: existError } = await existingQuery.maybeSingle();

    if (existError) throw new Error(`فشل التحقق من الحضور: ${existError.message}`);

    if (existing) {
      return new Response(
        JSON.stringify({ success: false, message: "DUPLICATE_IGNORE" }),
        { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const now = new Date();
    const timeStr = now.toLocaleTimeString("ar-EG", {
      timeZone: "Africa/Cairo",
      hour: "2-digit",
      minute: "2-digit",
    });

    // ✅ Aug 2026 (Phase I follow-up 10): الحصة بقت لازم تتحدد صراحةً (سياق القارئ أو الحضور
    // اليدوي) — اتلغى تخمين "أقرب حصة" القديم القائم على جدول أسبوعي متكرر خالص
    // (matchedSessionId اتحسبت فوق قبل فحص التكرار — batch 24 بند 1)
    const matchedSessionLabel: string | null = centerActiveContext?.sessionLabel ?? null;

    // ✅ Aug 2026 (تعديل جوهري): لو الحساب المسجّل سنتر (is_center) وحدد اسم مدرس معيّن وقت تسجيل
    // الحضور، بنتحقق إن الاسم ده فعلاً تابع له وبنحفظ نص اسمه (snapshot) مع الحضور — عشان تقدر
    // تطلع تقارير منفصلة لكل اسم حتى لو الاسم اتغيّر أو اتحذف بعد كده
    // ✅ Aug 2026 (Phase I): لو فيه سياق جلسة سنتر شغّال، هو اللي بيحدد المدرس مش بارامتر الطلب
    let instructorNameSnapshot: string | null = centerActiveContext?.instructorName ?? null;
    let finalInstructorNameId: number | null = centerActiveContext?.instructorNameId ?? null;
    if (!centerActiveContext && instructorNameId) {
      const { data: instructorRow } = await supabase
        .from("instructor_names").select("id, name, teacher_id").eq("id", instructorNameId).maybeSingle();
      if (instructorRow && instructorRow.teacher_id === clientId) {
        finalInstructorNameId = instructorRow.id;
        instructorNameSnapshot = instructorRow.name;
      }
    }

    const { data: attendance, error: attError } = await supabase.from("attendance")
      .insert({
        student_uid: uid,
        student_name: student.name,
        group_name: attendanceGroupName,
        teacher_id: clientId,
        date: today,
        time: timeStr,
        status: "present",
        is_manual: manual === true,
        notes: notes || null,
        session_id: matchedSessionId,
        session_label: matchedSessionLabel,
        instructor_name_id: finalInstructorNameId,
        instructor_name: instructorNameSnapshot,
      })
      .select()
      .single();

    if (attError) throw new Error(`فشل تسجيل الحضور: ${attError.message}`);

    // ✅ نجيب اسم المدرس عشان يبقى واضح لولي الأمر مين اللي بعت الإشعار (مهم لو عنده أكتر من ابن عند مدرسين مختلفين)
    // ✅ (مراجعة أداء) الاستعلام ده كان بيتكرر تاني بالظبط تحت (في تحديد performerName) — دلوقتي
    // بنجيبه مرة واحدة بس ونعيد استخدام نفس النتيجة في الحالتين
    const { data: notifyTeacherInfo } = await supabase.from("teachers").select("name").eq("client_id", clientId).maybeSingle();
    const teacherLabel = notifyTeacherInfo?.name ? ` — مدرس ${notifyTeacherInfo.name}` : "";
    const sessionPart = matchedSessionLabel ? ` (${matchedSessionLabel})` : "";
    // ✅ (طلب) إشعار مستقل لكل جمهور (audience) — الطالب بيتكلّم معاه بصيغة المخاطب، وولي الأمر
    // بيتكلّم معاه عن ابنه بالاسم، بدل صف واحد مشترك كان بيظهر لهم الاتنين بنفس النص
    const attendanceMsgParent = `تم تسجيل حضور ${student.name}${sessionPart} اليوم الساعة ${timeStr}${teacherLabel}`;
    const attendanceMsgStudent = `اتسجّل حضورك${sessionPart} اليوم الساعة ${timeStr}${teacherLabel}`;
    const attNotifRows = [
      ...(student.parent_phone ? [{
        teacher_id: clientId, parent_phone: student.parent_phone, student_uid: uid, type: "attendance", title: "تسجيل حضور", audience: "parent",
        message: attendanceMsgParent, details: { student_name: student.name, time: timeStr, date: today, session_label: matchedSessionLabel },
      }] : []),
      {
        teacher_id: clientId, student_uid: uid, type: "attendance", title: "تسجيل حضور", audience: "student",
        message: attendanceMsgStudent, details: { time: timeStr, date: today, session_label: matchedSessionLabel },
      },
    ];
    await supabase.from("notifications").insert(attNotifRows).then(({ error }) => { if (error) console.error("⚠️ فشل إرسال إشعار الحضور:", error.message); });
    // ✅ (طلب) قبل كده كان بيتبعت Push لولي الأمر بس — الطالب معاه صف إشعار "student" جوه
    // التطبيق برضه (فوق) لكن مايوصلوش Push حقيقي على جهازه. دلوقتي بيوصله هو كمان
    if (student.parent_phone) sendPushToRecipient(supabase, "parent", student.parent_phone, "تسجيل حضور", attendanceMsgParent);
    sendPushToRecipient(supabase, "student", uid, "تسجيل حضور", attendanceMsgStudent);

    let performerName = "مدرس";
    if (assistantId) {
      const { data: assistantInfo } = await supabase.from("assistants").select("name").eq("id", assistantId).maybeSingle();
      performerName = assistantInfo?.name || "مساعد";
    } else {
      performerName = notifyTeacherInfo?.name || "مدرس";
    }

    // ✅ Batch 27: كان الإدراج ده ناقص teacher_id وentity_type — الاتنين NOT NULL في الجدول،
    // فالإدراج كان بيفشل بصمت (من غير أي error handling هنا على عكس باقي إدراجات الملف)، ومعنى
    // كده إن تسجيل الحضور — أهم عملية يومية في النظام — مالوش أي أثر في سجل النشاطات خالص
    const { error: activityLogError } = await supabase.from("activity_logs").insert({
      client_id: clientId,
      teacher_id: clientId,
      action_type: "record_attendance",
      entity_type: "attendance",
      entity_id: uid,
      details: {
        student_name: student.name,
        student_uid: uid,
        is_manual: manual === true,
        notes: notes || null,
      },
      performer_id: assistantId || clientId,
      performer_role: assistantId ? "assistant" : "teacher",
      performer_name: performerName,
    });
    if (activityLogError) console.error("⚠️ فشل تسجيل نشاط تسجيل الحضور:", activityLogError.message);

    const finalMessage = extraActionMessages.length > 0
      ? `✅ تم تسجيل الحضور بنجاح — ${extraActionMessages.join(" — ")}`
      : "تم تسجيل الحضور بنجاح";

    return new Response(
      JSON.stringify({ success: true, message: finalMessage, data: attendance, extraActions: extraActionMessages }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ:", error);
    return new Response(
      JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});