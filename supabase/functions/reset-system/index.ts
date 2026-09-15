// supabase/functions/reset-system/index.ts
// أخطر دالة في النظام: تمسح كل بيانات المدرس (طلاب، مجموعات، مدفوعات، درجات، مذكرات، كروت، إشعارات، سجل نشاطات)
// وتُبقي على حساب المدرس نفسه وحسابات المساعدين بتوعه فقط
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, AuthError, verifyToken, requireOwnClientId, authErrorResponse } from "../_shared/auth.ts";
import { signInAuthUser, syntheticEmailFor } from "../_shared/authProvision.ts";

// ============================================
// (من _shared/rateLimit.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// ============================================
// ============================================
// حماية عامة من الاستخدام المتكرر/التخمين (rate limiting)
// يعتمد على جدول login_attempts (key, attempts, locked_until, last_attempt)
// نفس الجدول يُستخدم لأي مفتاح (login أو change-password...) بادئة مختلفة فقط
// ============================================
// اسم مستعار فريد عمداً لتفادي أي تعارض مع "createClient" في الملفات اللي بتدمج هذا الموديول
import { createClient as _createRateLimitClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

export interface RateLimitOptions {
  maxAttempts?: number;   // الحد الأقصى للمحاولات قبل الحظر (افتراضي 5)
  lockMinutes?: number;   // مدة الحظر بالدقائق (افتراضي 15)
}

function adminClient() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return _createRateLimitClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

/** يتحقق هل المفتاح محظور حالياً. يرجّع رسالة عربية جاهزة لو محظور. */
export async function checkRateLimit(
  key: string,
  opts: RateLimitOptions = {}
): Promise<{ blocked: boolean; message?: string }> {
  const supabase = adminClient();
  const { data } = await supabase
    .from("login_attempts")
    .select("attempts, locked_until")
    .eq("username", key)
    .maybeSingle();

  if (data?.locked_until && new Date(data.locked_until) > new Date()) {
    const minutes = Math.ceil((new Date(data.locked_until).getTime() - Date.now()) / 60000);
    return { blocked: true, message: `⛔ تم حظر المحاولات مؤقتاً، حاول بعد ${minutes} دقيقة` };
  }
  return { blocked: false };
}

/** يسجّل محاولة فاشلة، ويحظر المفتاح تلقائياً لو تخطى الحد الأقصى */
export async function registerFailedAttempt(key: string, opts: RateLimitOptions = {}) {
  const maxAttempts = opts.maxAttempts ?? 5;
  const lockMinutes = opts.lockMinutes ?? 15;

  const supabase = adminClient();
  const { data } = await supabase
    .from("login_attempts")
    .select("attempts")
    .eq("username", key)
    .maybeSingle();

  const attempts = (data?.attempts || 0) + 1;
  const lockedUntil = attempts >= maxAttempts ? new Date(Date.now() + lockMinutes * 60 * 1000).toISOString() : null;

  await supabase.from("login_attempts").upsert({
    username: key,
    attempts,
    locked_until: lockedUntil,
    last_attempt: new Date().toISOString(),
  });
}

/** يصفّر عداد المحاولات عند النجاح */
export async function clearAttempts(key: string) {
  const supabase = adminClient();
  await supabase.from("login_attempts").delete().eq("username", key);
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    // ✅ أخطر دالة في النظام (حذف كل بيانات المدرس نهائياً) — لازم توكن + تأكيد صريح
    const payload = await verifyToken(req);
    if (payload.role === "assistant") {
      return new Response(JSON.stringify({ success: false, message: "⛔ العملية دي للمدرس نفسه بس، مش متاحة للمساعد خالص" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { clientId, password, options } = await req.json();

    // ✅ يحدد أي فئات بيانات تتحذف. لو "options" مش موجودة خالص (كود فرونت قديم مخزّن كاش)
    // نحذف كل حاجة زي الوضع القديم (توافق خلفي). لو موجودة، نحترمها بالظبط فئة فئة.
    const opts: Record<string, boolean> = options && typeof options === "object" ? options : {};
    const hasOptions = options && typeof options === "object";
    const want = (key: string) => (hasOptions ? opts[key] === true : true);

    if (!clientId) {
      return new Response(JSON.stringify({ success: false, message: "clientId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (!password) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ يجب إدخال كلمة المرور لتأكيد هذه العملية" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const finalClientId = requireOwnClientId(payload, clientId);

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    // ✅ حماية من محاولات تخمين الباسورد على هذه الدالة تحديداً
    const rateLimitKey = `reset-system:${finalClientId}`;
    const rateLimit = await checkRateLimit(rateLimitKey);
    if (rateLimit.blocked) {
      return new Response(JSON.stringify({ success: false, message: rateLimit.message }),
        { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ Batch 25: التحقق الفعلي من كلمة مرور المدرس نفسه — كان بيتحقق من عمود password_hash المحلي
    // القديم، اللي بقى ممكن يكون null (حساب مربوط بجوجل مثلاً) أو قيمة قديمة متحدّتش بعد هجرة
    // Supabase Auth، فيفشل الحذف بصمت لكل حساب متعمل بيه تسجيل دخول حديث. لازم نتحقق من Supabase
    // Auth نفسه، بنفس الطريقة اللي /login بتتحقق بيها فعليًا
    const { error: signInError } = await signInAuthUser({
      email: syntheticEmailFor("teacher", finalClientId),
      password,
    });
    if (signInError) {
      await registerFailedAttempt(rateLimitKey);
      return new Response(JSON.stringify({ success: false, message: "⛔ كلمة المرور غير صحيحة" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    await clearAttempts(rateLimitKey);

    const { data: students, error: studentsError } = await supabase
      .from("students").select("uid").eq("teacher_id", finalClientId);

    if (studentsError) throw new Error(`فشل جلب الطلاب: ${studentsError.message}`);
    const uids = (students || []).map((s: any) => s.uid);

    // ✅ بيانات الطلاب الأكاديمية (الحضور، المدفوعات، الدرجات، سداد المذكرات) — كل فئة حسب اختيار المستخدم
    if (want("attendance")) {
      await supabase.from("attendance").delete().eq("teacher_id", finalClientId);
      // ✅ جلسات الحضور (attendance_sessions) تابعة لنفس فئة "سجلات الحضور"
      await supabase.from("attendance_sessions").delete().eq("teacher_id", finalClientId);
    }
    if (uids.length > 0) {
      if (want("payments")) await supabase.from("payments").delete().in("student_uid", uids);
      if (want("grades")) await supabase.from("grades").delete().in("student_uid", uids);
      if (want("bookPayments")) await supabase.from("book_payments").delete().in("student_uid", uids);
    }

    // ✅ كروت RFID: بما إنها ملك المدرس فعلياً (باعها الماستر له)، تفضل عنده لكن تتفصل عن الطلاب المحذوفين
    // (بيحصل بس لو هيتحذف الطلاب أنفسهم، عشان الكروت متتفصلش من طلاب لسه موجودين)
    if (want("students")) {
      await supabase.from("system_cards")
        .update({ student_uid: null, linked_at: null })
        .eq("teacher_id", finalClientId);
      await supabase.from("pending_card_registrations").delete().eq("teacher_id", finalClientId);

      // ✅ الطلاب أنفسهم
      await supabase.from("students").delete().eq("teacher_id", finalClientId).select("parent_phone").then(async ({ data: deletedStudents }) => {
        const parentPhones = [...new Set((deletedStudents || []).map((s: any) => s.parent_phone).filter(Boolean))];
        for (const phone of parentPhones) {
          const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("parent_phone", phone);
          if (!count || count === 0) {
            await supabase.from("parents").delete().eq("phone", phone);
          }
        }
      });

      await supabase.from("teachers").update({ student_count: 0 }).eq("client_id", finalClientId);
    }

    // ✅ المجموعات (وأسماء المدرسين التابعين للسنتر، بيانات تنظيمية مرتبطة بنفس فئة "المجموعات")
    if (want("groups")) {
      await supabase.from("groups").delete().eq("teacher_id", finalClientId);
      await supabase.from("instructor_names").delete().eq("teacher_id", finalClientId);
    }

    // ✅ المذكرات نفسها + ملفات الـ PDF المرفوعة لها في التخزين (Storage)
    if (want("books")) {
      await supabase.from("books").delete().eq("teacher_id", finalClientId);
      try {
        const { data: storageFiles } = await supabase.storage.from("book-files").list(finalClientId);
        if (storageFiles && storageFiles.length > 0) {
          const paths = storageFiles.map((f: any) => `${finalClientId}/${f.name}`);
          await supabase.storage.from("book-files").remove(paths);
        }
      } catch (storageErr) {
        // ✅ فشل حذف ملفات التخزين مش لازم يوقف باقي عملية إعادة التهيئة
        console.error("⚠️ تعذر حذف ملفات المذكرات من التخزين:", storageErr);
      }
    }

    // ✅ بنود السداد الثابتة
    if (want("paymentTitles")) {
      await supabase.from("payment_titles").delete().eq("teacher_id", finalClientId);
    }

    // ✅ المصروفات (كانت موجودة في التصدير/الاستعادة بس متاحة أبداً كخيار حذف هنا)
    if (want("expenses")) {
      await supabase.from("expenses").delete().eq("teacher_id", finalClientId);
    }

    // ✅ إيصالات الدفع الإلكتروني المرفوعة + الصور بتاعتها في التخزين (Storage)
    if (want("paymentReceipts")) {
      await supabase.from("payment_receipts").delete().eq("teacher_id", finalClientId);
      try {
        const { data: storageFiles } = await supabase.storage.from("payment-receipts").list(finalClientId);
        if (storageFiles && storageFiles.length > 0) {
          const paths = storageFiles.map((f: any) => `${finalClientId}/${f.name}`);
          await supabase.storage.from("payment-receipts").remove(paths);
        }
      } catch (storageErr) {
        console.error("⚠️ تعذر حذف ملفات إيصالات الدفع من التخزين:", storageErr);
      }
    }

    // ✅ أسماء الامتحانات المحفوظة (بنود ثابتة تُستخدم في إدخال الدرجات، غير مرتبطة بالامتحانات الإلكترونية)
    if (want("examTitles")) {
      await supabase.from("exam_titles").delete().eq("teacher_id", finalClientId);
    }

    // ✅ الامتحانات الإلكترونية: أسئلتها، الطلاب المستهدفين بيها، محاولات الطلاب وإجاباتهم
    if (want("onlineExams")) {
      const { data: onlineExams } = await supabase.from("online_exams").select("id").eq("teacher_id", finalClientId);
      const examIds = (onlineExams || []).map((e: any) => e.id);
      if (examIds.length > 0) {
        const { data: attempts } = await supabase.from("exam_attempts").select("id").in("exam_id", examIds);
        const attemptIds = (attempts || []).map((a: any) => a.id);
        if (attemptIds.length > 0) {
          await supabase.from("exam_answers").delete().in("attempt_id", attemptIds);
        }
        await supabase.from("exam_attempts").delete().in("exam_id", examIds);
        await supabase.from("exam_target_students").delete().in("exam_id", examIds);
        await supabase.from("exam_questions").delete().in("exam_id", examIds);
      }
      await supabase.from("online_exams").delete().eq("teacher_id", finalClientId);
    }

    // ✅ الإشعارات
    if (want("notifications")) {
      await supabase.from("notifications").delete().eq("teacher_id", finalClientId);
    }

    // ✅ طلبات التسجيل المعلّقة (كانت موجودة كخيار في الواجهة بس متجاهلة هنا فعليًا)
    if (want("registrationRequests")) {
      await supabase.from("registration_requests").delete().eq("teacher_id", finalClientId);
    }

    // ✅ المحادثات مع أولياء الأمور (كانت موجودة كخيار في الواجهة بس متجاهلة هنا فعليًا)
    if (want("conversations")) {
      await supabase.from("conversation_messages").delete().eq("teacher_id", finalClientId);
    }

    // ✅ مسح كل سجل النشاطات القديم الخاص بالمدرس (كما طُلب)
    if (want("activityLogs")) {
      await supabase.from("activity_logs").delete().eq("teacher_id", finalClientId);
    }

    // ✅ تسجيل واحد فقط يوثّق حدوث عملية إعادة التهيئة نفسها (دليل بعد الحذف)
    await supabase.from("activity_logs").insert({
      client_id: finalClientId, teacher_id: finalClientId, action_type: "reset_system",
      entity_type: "teacher", entity_id: finalClientId,
      details: { deleted_students: uids.length, deleted_at: new Date().toISOString(), options: hasOptions ? opts : "all (legacy)" },
      performer_id: finalClientId, performer_role: payload.role, performer_name: payload.name,
    });

    return new Response(JSON.stringify({ success: true, message: "✅ تم حذف البيانات اللي حددتها بنجاح (عدا حسابك وحسابات المساعدين)" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في reset-system:", error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
