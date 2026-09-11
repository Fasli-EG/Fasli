// supabase/functions/get-system-settings/index.ts
// دالة عامة (بدون توكن) — تُستخدم في صفحة تسجيل الدخول وصفحة القفل لعرض وسائل التواصل
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SUPABASE_SERVICE_ROLE_KEY غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const { data, error } = await supabase
      .from("system_settings")
      .select("whatsapp_number, phone_number, facebook_url, youtube_url, tiktok_url, desktop_download_url, mobile_app_url, require_registered_cards, admin_name, admin_whatsapp, portal_banner_url, portal_banner_link_url, portal_banner_show_student, portal_banner_show_parent, portal_banner_parent_url, portal_banner_parent_link_url, portal_banner_student_url, portal_banner_student_link_url, portal_banner_teacher_url, portal_banner_teacher_link_url, portal_banner_show_teacher, portal_banner_assistant_url, portal_banner_assistant_link_url, portal_banner_show_assistant, login_credit_show, login_credit_text, firebase_api_key, firebase_auth_domain, firebase_project_id, firebase_storage_bucket, firebase_messaging_sender_id, firebase_app_id, firebase_vapid_key, show_download_section")
      .eq("id", 1)
      .maybeSingle();

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, data: data || {} }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
