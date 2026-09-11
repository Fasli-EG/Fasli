// supabase/functions/update-system-settings/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, requireAdmin, authErrorResponse } from "../_shared/auth.ts";

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
    requireAdmin(payload);

    const body = await req.json();
    const {
      whatsappNumber, phoneNumber, facebookUrl, youtubeUrl, tiktokUrl, desktopDownloadUrl, mobileAppUrl,
      requireRegisteredCards, adminName, adminWhatsapp,
      portalBannerUrl, portalBannerLinkUrl, portalBannerShowStudent, portalBannerShowParent,
      portalBannerParentUrl, portalBannerParentLinkUrl,
      portalBannerStudentUrl, portalBannerStudentLinkUrl,
      portalBannerTeacherUrl, portalBannerTeacherLinkUrl, portalBannerShowTeacher,
      portalBannerAssistantUrl, portalBannerAssistantLinkUrl, portalBannerShowAssistant,
      loginCreditShow, loginCreditText,
      firebaseApiKey, firebaseAuthDomain, firebaseProjectId, firebaseStorageBucket,
      firebaseMessagingSenderId, firebaseAppId, firebaseVapidKey,
      showDownloadSection,
    } = body;

    // ✅ نبني كائن التحديث بس من الحقول اللي فعلاً اتبعتت، عشان مانمسحش إعدادات تانية بالغلط
    // لو حد استدعى الدالة دي بحقل واحد بس (زي تبديل خاصية الكروت من تاب تاني)
    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if ("whatsappNumber" in body) updates.whatsapp_number = whatsappNumber ?? null;
    if ("phoneNumber" in body) updates.phone_number = phoneNumber ?? null;
    if ("facebookUrl" in body) updates.facebook_url = facebookUrl ?? null;
    if ("youtubeUrl" in body) updates.youtube_url = youtubeUrl ?? null;
    if ("tiktokUrl" in body) updates.tiktok_url = tiktokUrl ?? null;
    if ("adminName" in body) updates.admin_name = adminName ?? null;
    if ("adminWhatsapp" in body) updates.admin_whatsapp = adminWhatsapp ?? null;
    if ("desktopDownloadUrl" in body) updates.desktop_download_url = desktopDownloadUrl ?? null;
    if ("mobileAppUrl" in body) updates.mobile_app_url = mobileAppUrl ?? null;
    if ("requireRegisteredCards" in body) updates.require_registered_cards = !!requireRegisteredCards;
    // ✅ Batch 24 (بند 8): اللافتة الإعلانية أعلى صفحة الطالب/ولي الأمر (حقول قديمة، لسه
    // متاحة للتوافق لكن الواجهة بقت بتستخدم الحقول المنفصلة بالأسفل لكل جمهور على حدة)
    if ("portalBannerUrl" in body) updates.portal_banner_url = portalBannerUrl ?? null;
    if ("portalBannerLinkUrl" in body) updates.portal_banner_link_url = portalBannerLinkUrl ?? null;
    if ("portalBannerShowStudent" in body) updates.portal_banner_show_student = !!portalBannerShowStudent;
    if ("portalBannerShowParent" in body) updates.portal_banner_show_parent = !!portalBannerShowParent;
    // ✅ Batch 28 (بند 1): لافتة إعلانية منفصلة بالكامل لكل جمهور (ولي أمر/طالب/مدرس/مساعد) —
    // كل واحدة عندها صورة ورابط وخيار إظهار مستقل، عشان الماستر يقدر يخصص إعلان مختلف لكل واحد
    if ("portalBannerParentUrl" in body) updates.portal_banner_parent_url = portalBannerParentUrl ?? null;
    if ("portalBannerParentLinkUrl" in body) updates.portal_banner_parent_link_url = portalBannerParentLinkUrl ?? null;
    if ("portalBannerStudentUrl" in body) updates.portal_banner_student_url = portalBannerStudentUrl ?? null;
    if ("portalBannerStudentLinkUrl" in body) updates.portal_banner_student_link_url = portalBannerStudentLinkUrl ?? null;
    if ("portalBannerTeacherUrl" in body) updates.portal_banner_teacher_url = portalBannerTeacherUrl ?? null;
    if ("portalBannerTeacherLinkUrl" in body) updates.portal_banner_teacher_link_url = portalBannerTeacherLinkUrl ?? null;
    if ("portalBannerShowTeacher" in body) updates.portal_banner_show_teacher = !!portalBannerShowTeacher;
    if ("portalBannerAssistantUrl" in body) updates.portal_banner_assistant_url = portalBannerAssistantUrl ?? null;
    if ("portalBannerAssistantLinkUrl" in body) updates.portal_banner_assistant_link_url = portalBannerAssistantLinkUrl ?? null;
    if ("portalBannerShowAssistant" in body) updates.portal_banner_show_assistant = !!portalBannerShowAssistant;
    // ✅ Batch 25 (بند 2): إظهار/إخفاء نص فوتر صفحة تسجيل الدخول، أو استبداله بنص مخصص كامل
    if ("loginCreditShow" in body) updates.login_credit_show = !!loginCreditShow;
    if ("loginCreditText" in body) updates.login_credit_text = loginCreditText ?? null;
    // ✅ Batch 32: إعدادات Firebase العامة (Web Config) — عشان تفعيل الإشعارات الحقيقية
    // (Push) لولي الأمر/الطالب/المدرس/المساعد. قيم عامة (public) بتصميم Firebase، مش أسرار
    if ("firebaseApiKey" in body) updates.firebase_api_key = firebaseApiKey ?? null;
    if ("firebaseAuthDomain" in body) updates.firebase_auth_domain = firebaseAuthDomain ?? null;
    if ("firebaseProjectId" in body) updates.firebase_project_id = firebaseProjectId ?? null;
    if ("firebaseStorageBucket" in body) updates.firebase_storage_bucket = firebaseStorageBucket ?? null;
    if ("firebaseMessagingSenderId" in body) updates.firebase_messaging_sender_id = firebaseMessagingSenderId ?? null;
    if ("firebaseAppId" in body) updates.firebase_app_id = firebaseAppId ?? null;
    if ("firebaseVapidKey" in body) updates.firebase_vapid_key = firebaseVapidKey ?? null;
    // ✅ Batch 33 (بند 2): تحكم الماستر في إظهار/إخفاء قسم روابط التحميل بالكامل في صفحة
    // تسجيل الدخول، مستقل عن كون الروابط نفسها متسجّلة أو لأ
    if ("showDownloadSection" in body) updates.show_download_section = !!showDownloadSection;

    const { error } = await supabase
      .from("system_settings")
      .update(updates)
      .eq("id", 1);

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ تم تحديث بيانات التواصل بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
