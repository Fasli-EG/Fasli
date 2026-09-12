// supabase/functions/update-teacher-contact/index.ts
// يسمح للمدرس بتحديث بيانات التواصل الخاصة بيه (تظهر لمساعديه وأولياء أمور طلابه عند المشاكل)
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, ownerClientId, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const payload = await verifyToken(req);
    const body = await req.json();
    const action = body.action;
    // ✅ (طلب) المساعد ملوش صلاحية يغيّر أي من بيانات تواصل/براندنج المدرس — إلا فعل واحد بس:
    // توليد رابط تسجيل جديد، ولو معاه صلاحية manage_registration الجديدة اللي المدرس يمنحها له
    // صراحة (نفس منطق باقي الصلاحيات — مفيش وصول تلقائي لحد ما المدرس يفعّلها)
    if (payload.role !== "teacher") {
      if (payload.role === "assistant" && action === "regenerateRegistrationToken") {
        await requireAssistantPermission(payload, "manage_registration");
      } else {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح إلا للمدرس نفسه" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }
    const tokenClientId = ownerClientId(payload);

    // ✅ رفع شعار فعلي (صورة) لتخزين Supabase Storage، بدل رابط نصي يدوي
    if (action === "uploadLogo") {
      const { imageBase64, fileExt } = body;
      if (!imageBase64 || !fileExt) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const cleanExt = String(fileExt).toLowerCase().replace(/^\./, "");
      const allowedExts: Record<string, string> = {
        png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp", svg: "image/svg+xml",
      };
      if (!allowedExts[cleanExt]) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ صيغة الصورة غير مدعومة (المسموح: png, jpg, jpeg, webp, svg)" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const base64Data = imageBase64.includes(",") ? imageBase64.split(",")[1] : imageBase64;
      const binaryData = Uint8Array.from(atob(base64Data), (c) => c.charCodeAt(0));
      const MAX_LOGO_SIZE_BYTES = 2 * 1024 * 1024;
      if (binaryData.length > MAX_LOGO_SIZE_BYTES) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ حجم الصورة أكبر من الحد المسموح (2 ميجا)" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ لو فيه شعار قديم مرفوع، نحاول نحذفه (best-effort — مش بيوقف العملية لو فشل)
      const { data: existingTeacher } = await supabase
        .from("teachers").select("brand_logo_url").eq("client_id", tokenClientId).maybeSingle();
      if (existingTeacher?.brand_logo_url) {
        try {
          const oldPath = existingTeacher.brand_logo_url.split("/teacher-logos/")[1];
          if (oldPath) await supabase.storage.from("teacher-logos").remove([oldPath]);
        } catch (_e) { /* تجاهل — حذف الشعار القديم اختياري */ }
      }

      const storagePath = `${tokenClientId}/logo-${Date.now()}.${cleanExt}`;
      const { error: uploadError } = await supabase.storage.from("teacher-logos").upload(storagePath, binaryData, {
        contentType: allowedExts[cleanExt], upsert: true,
      });
      if (uploadError) {
        // ✅ (طلب) لو الـ bucket نفسه مش موجود (لسه ما اتعملش يدوي في Supabase Storage)، بنوضح
        // ده صراحة بدل رسالة عامة زي "Bucket not found" — نفس نمط الحل المستخدم في manage-login-ad
        const rawMessage = (uploadError as any)?.message || "";
        const bucketMissing = /bucket/i.test(rawMessage) && /not found|does not exist/i.test(rawMessage);
        const friendlyMessage = bucketMissing
          ? "⚠️ مساحة تخزين شعارات المدرسين (teacher-logos) لسه مش متعملة على السيرفر — لازم تتعمل يدوياً من Supabase Storage كـ bucket عام (Public) الأول"
          : `⚠️ فشل رفع الشعار: ${rawMessage || "حاول مرة أخرى"}`;
        return new Response(JSON.stringify({ success: false, message: friendlyMessage }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: publicUrlData } = supabase.storage.from("teacher-logos").getPublicUrl(storagePath);

      const { error: updateError } = await supabase
        .from("teachers").update({ brand_logo_url: publicUrlData.publicUrl }).eq("client_id", tokenClientId);
      if (updateError) throw new Error(updateError.message);

      return new Response(JSON.stringify({ success: true, brand_logo_url: publicUrlData.publicUrl }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ Aug 2026: توليد رابط تسجيل جديد (registration_token عشوائي) — مفيد لو الرابط القديم
    // اتسرّب أو المدرس عايز يوقف اللي كان شغال بالرابط القديم من غير ما يعطّل حسابه كله.
    // بنحاول 3 مرات لو حصل تصادم نادر جداً (unique index على registration_token).
    if (action === "regenerateRegistrationToken") {
      let newToken = "";
      let saved = false;
      for (let attempt = 0; attempt < 3 && !saved; attempt++) {
        newToken = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
        const { error: tokenError } = await supabase
          .from("teachers").update({ registration_token: newToken }).eq("client_id", tokenClientId);
        if (!tokenError) { saved = true; break; }
        // ✅ لو الخطأ مش تصادم unique (23505)، مفيش داعي نكرر المحاولة
        if ((tokenError as any).code !== "23505") throw new Error(tokenError.message);
      }
      if (!saved) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ تعذّر توليد رابط جديد، حاول تاني" }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ success: true, message: "✅ تم توليد رابط تسجيل جديد", registrationToken: newToken }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { contactWhatsapp, contactPhone, absenceThresholdMinutes, brandLogoUrl, brandColor, conversationsEnabled, whatsappVisible, phoneVisible, electronicPaymentEnabled, paymentInstapay, paymentWallet, paymentBankDetails } = body;

    const updates: any = {};
    if (contactWhatsapp !== undefined) updates.contact_whatsapp = contactWhatsapp || null;
    if (contactPhone !== undefined) updates.contact_phone = contactPhone || null;
    if (absenceThresholdMinutes !== undefined) updates.absence_threshold_minutes = Number(absenceThresholdMinutes);
    if (brandLogoUrl !== undefined) updates.brand_logo_url = brandLogoUrl || null;
    if (brandColor !== undefined) updates.brand_color = brandColor || null;
    // ✅ (طلب) تفعيل/تعطيل محادثات أولياء الأمور — لما تتعطّل، تبويب "محادثات أولياء الأمور"
    // يختفي من messages.html عند المدرس، وتبويب "تواصل" يختفي من صفحة الطالب عند ولي الأمر
    if (conversationsEnabled !== undefined) updates.conversations_enabled = !!conversationsEnabled;
    // ✅ (طلب) إظهار/إخفاء رقم واتساب المدرس لأولياء الأمور — مستقل عن محادثات داخل التطبيق
    if (whatsappVisible !== undefined) updates.whatsapp_visible = !!whatsappVisible;
    // ✅ (طلب) إظهار/إخفاء رقم الهاتف للمدرس لأولياء الأمور — رقم مستقل تمامًا عن الواتساب
    if (phoneVisible !== undefined) updates.phone_visible = !!phoneVisible;
    // ✅ (طلب) رفع إيصال الدفع الإلكتروني (الحل المجاني) — اختياري بقرار المدرس، معطّل افتراضيًا
    if (electronicPaymentEnabled !== undefined) updates.electronic_payment_enabled = !!electronicPaymentEnabled;
    // ✅ (طلب) بيانات الدفع اللي بتظهر لولي الأمر قبل ما يرفع الإيصال — يعرف يحوّل على مين
    if (paymentInstapay !== undefined) updates.payment_instapay = paymentInstapay || null;
    if (paymentWallet !== undefined) updates.payment_wallet = paymentWallet || null;
    if (paymentBankDetails !== undefined) updates.payment_bank_details = paymentBankDetails || null;

    const { error } = await supabase
      .from("teachers")
      .update(updates)
      .eq("client_id", tokenClientId);

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ تم حفظ بيانات التواصل بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
