// supabase/functions/submit-rfid-scan/index.ts
// يستقبل قراية الكارت من جهاز ESP32 مباشرة (بدل الكتابة المباشرة في جدول rfid_scans بالـ anon key)
// التوثيق هنا بسر خاص بكل مدرس (device_secret) مش بتوكن عادي، لأن الجهاز مالوش تسجيل دخول
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, requireTeacherPlanPermission, verifyDeviceSecret } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const { clientId, uid, deviceSecret } = await req.json();

    if (!clientId || !uid || !deviceSecret) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ clientId و uid و deviceSecret مطلوبين" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ التحقق من إن الجهاز ده فعلاً بتاع المدرس صاحب clientId ده
    await verifyDeviceSecret(clientId, deviceSecret);
    await requireTeacherPlanPermission(clientId, "can_use_rfid");

    // ✅ أولاً: هل فيه طلب تسجيل كارت جديد معلّق لنفس المدرس ده؟ لو أيوه، الكارت ده يتسجّل كارت رسمي للطالب المطلوب
    // بدل ما يتسجّل كحضور عادي
    const NEW_STUDENT_SENTINEL = "__NEW_STUDENT__";
    const { data: pending } = await supabase
      .from("pending_card_registrations")
      .select("*")
      .eq("teacher_id", clientId)
      .is("registered_card_uid", null)
      .maybeSingle();

    if (pending) {
      const { data: card } = await supabase
        .from("system_cards").select("id, status, teacher_id, is_active, student_uid").eq("card_uid", uid).maybeSingle();

      let errorMsg: string | null = null;
      if (!card) {
        errorMsg = "⚠️ الكارت ده مش مسجّل في مخزون النظام خالص";
      } else if (card.status !== "assigned" || card.teacher_id !== clientId) {
        errorMsg = "⛔ الكارت ده مش متخصص لحسابك — كلّمي إدارة النظام";
      } else if (!card.is_active) {
        errorMsg = "⛔ الكارت ده متخصص لحسابك بس لسه مش مفعّل — كلّمي إدارة النظام";
      } else if (card.student_uid && card.student_uid !== pending.student_uid) {
        // ✅ لو الكارت مرتبط بطالب تاني بالفعل (وده مش نفس الطالب اللي بنحاول نربطه دلوقتي) — نجيب اسمه عشان الرسالة تبقى واضحة
        const { data: linkedStudent } = await supabase.from("students").select("name").eq("uid", card.student_uid).maybeSingle();
        errorMsg = `⚠️ الكارت ده متسجّل بالفعل للطالب: ${linkedStudent?.name || "غير معروف"}`;
      }

      if (errorMsg) {
        await supabase.from("pending_card_registrations").update({ error_message: errorMsg }).eq("teacher_id", clientId);
        return new Response(JSON.stringify({ success: false, message: errorMsg }),
          { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      if (pending.student_uid === NEW_STUDENT_SENTINEL) {
        // ✅ ده كارت لطالب لسه ما اتسجّلش أصلاً — نخزّن رقم الكارت بس ونسيب باقي التسجيل للفورم
        // (الربط الفعلي بـ system_cards هيحصل وقت إضافة الطالب نفسه في add-student)
        await supabase.from("pending_card_registrations").update({ registered_card_uid: uid, error_message: null }).eq("teacher_id", clientId);
        return new Response(JSON.stringify({ success: true, message: "✅ تم قراءة الكارت", registered: true }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ ربط كارت بطالب موجود بالفعل.
      // ✅ (طلب) كان ده بيتم عن طريق دالة قاعدة بيانات (`link_card_to_student` RPC) مش متتبّعة في
      // أي migration محلي عندنا (اتعملت مباشرة على السيرفر من غير ما تتسجّل في الكود) — يعني
      // سلوكها الفعلي مش موثّق ومش قابل للمراجعة، وكان فيه احتمال حقيقي إنها بتـ"سيب" أي كارت
      // تاني مربوط بنفس الطالب (اسم الدالة والتعليق القديم "تبديل الكارت" بيرجّحوا كده)، وده كان
      // هيمنع الطالب من إنه يتربط بأكتر من كارت في نفس الوقت. استبدلناها بتحديث مباشر وواضح على
      // صف الكارت المطلوب بس — من غير أي مسّ لأي كارت تاني، فالطالب يقدر يكون ليه أكتر من كارت
      // شغال في نفس الوقت من غير ما ربط كارت جديد يفصل كارت قديم كان شغال بالفعل
      const studentUidToLink = pending.student_uid;
      const newCardUid = uid;

      const { error: swapError, count: linkedCount } = await supabase
        .from("system_cards")
        .update({ student_uid: studentUidToLink, linked_at: new Date().toISOString() }, { count: "exact" })
        .eq("id", card.id)
        .eq("teacher_id", clientId);

      if (swapError || !linkedCount) {
        console.error("❌ فشل ربط الكارت:", swapError);
        const errMsg = "⚠️ حدث خطأ أثناء ربط الكارت، حاول مرة أخرى";
        await supabase.from("pending_card_registrations").update({ error_message: errMsg }).eq("teacher_id", clientId);
        return new Response(JSON.stringify({ success: false, message: errMsg }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ سجل تدقيق: نوثّق عملية ربط الكارت في سجل النشاطات
      const { data: teacherInfo } = await supabase.from("teachers").select("name").eq("client_id", clientId).maybeSingle();

      await supabase.from("activity_logs").insert({
        client_id: clientId,
        teacher_id: clientId,
        action_type: "link_rfid_card",
        entity_type: "system_card",
        entity_id: String(card.id),
        details: { student_name: pending.student_name, student_uid: studentUidToLink, card_uid: newCardUid },
        performer_id: clientId,
        performer_role: "teacher",
        performer_name: teacherInfo?.name || "مدرس",
      });

      await supabase.from("pending_card_registrations").update({ registered_card_uid: uid, error_message: null }).eq("teacher_id", clientId);

      return new Response(JSON.stringify({ success: true, message: "✅ تم ربط الكارت بالطالب بنجاح", registered: true }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ لو الكارت ده مسجّل في النظام (سواء الخاصية العامة مفعّلة ولا لأ) ومعطّل، نرفضه دايماً —
    // التعطيل لازم يشتغل فوري بغض النظر عن إعداد "التحقق الإجباري"، عشان لو المدرس عطّل كارت لطالب يفضل معطّل فعلاً
    const { data: knownCard } = await supabase
      .from("system_cards").select("id, is_active, teacher_id").eq("card_uid", uid).maybeSingle();

    if (knownCard && knownCard.teacher_id === clientId && !knownCard.is_active) {
      return new Response(JSON.stringify({ success: false, message: "⛔ الكارت ده معطّل حالياً" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ لو مفيش طلب تسجيل معلّق: نتحقق هل النظام مضبوط يرفض أي كارت مش مسجّل رسمياً ومفعّل
    const { data: settings } = await supabase.from("system_settings").select("require_registered_cards").eq("id", 1).maybeSingle();

    if (settings?.require_registered_cards) {
      const isRegisteredAndActive = knownCard && knownCard.teacher_id === clientId && knownCard.is_active;
      if (!isRegisteredAndActive) {
        return new Response(JSON.stringify({ success: false, message: "⛔ الكارت ده مش مسجّل رسمياً أو مش مفعّل في النظام" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }

    const { error } = await supabase.from("rfid_scans").insert({
      uid,
      client_id: clientId, // موثّق فعلياً دلوقتي، مش نص عادي أي حد يقدر يبعته
    });

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: error.status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
