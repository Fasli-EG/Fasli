// supabase/functions/mark-notification-read/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, TokenPayload, AuthError, verifyToken, ownerClientId, requireOwnClientId, requireAdmin, requireParentPhone, requireTeacherPlanPermission, requireAssistantPermission, verifyDeviceSecret, authErrorResponse } from "../_shared/auth.ts";

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

    let recipientColumn: "parent_phone" | "assistant_id" | "teacher_id" | "student_uid";
    let recipientValue: string;
    // ✅ عمود teacher_id مستخدم أصلاً كـ"المدرس المالك" في كل صفوف الإشعارات (حتى إشعارات أولياء الأمور/المساعدين)،
    // فلو المستلم مدرس لازم نقيّد كمان بـ type=center_teacher_message عشان منعلّمش كمقروء إشعارات مش بتاعته أصلاً
    let restrictToTeacherMessages = false;
    // ✅ (طلب) عزل الطالب عن ولي الأمر — عمود student_uid ممكن يكون موجود في صف موجّه لولي
    // الأمر برضه (نفس الطالب)، فلازم نقيّد بـ audience='student' بالظبط عشان الطالب ميعلّمش
    // كمقروء إشعار ولي أمره من غير ما يشوفه أصلاً
    let restrictToStudentAudience = false;
    // ✅ نفس الفكرة بالظبط من ناحية ولي الأمر (توافق مع الصفوف القديمة قبل إضافة audience)
    let restrictToParentAudience = false;

    if (payload.role === "parent") {
      recipientColumn = "parent_phone";
      recipientValue = requireParentPhone(payload);
      restrictToParentAudience = true;
    } else if (payload.role === "assistant") {
      recipientColumn = "assistant_id";
      recipientValue = payload.sub;
    } else if (payload.role === "teacher") {
      recipientColumn = "teacher_id";
      recipientValue = ownerClientId(payload);
      restrictToTeacherMessages = true;
    } else if (payload.role === "student") {
      // ✅ الطالب يعلّم إشعاراته الشخصية بس كمقروءة — نفس تقييد get-notifications (عمود student_uid = sub التوكن)
      recipientColumn = "student_uid";
      recipientValue = payload.sub;
      restrictToStudentAudience = true;
    } else {
      throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
    }

    const { notificationId, markAll } = await req.json();

    if (markAll) {
      let markAllQuery = supabase
        .from("notifications")
        .update({ is_read: true })
        .eq(recipientColumn, recipientValue)
        .eq("is_read", false);
      if (restrictToTeacherMessages) markAllQuery = markAllQuery.in("type", ["center_teacher_message", "parent_message"]);
      if (restrictToStudentAudience) markAllQuery = markAllQuery.eq("audience", "student");
      if (restrictToParentAudience) markAllQuery = markAllQuery.or("audience.eq.parent,audience.is.null");
      const { error } = await markAllQuery;

      if (error) {
        return new Response(JSON.stringify({ success: false, message: error.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ success: true }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (!notificationId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ notificationId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ التأكد إن الإشعار ده فعلاً بتاع نفس المستلم قبل ما نعلّمه كمقروء
    let singleQuery = supabase
      .from("notifications")
      .update({ is_read: true })
      .eq("id", notificationId)
      .eq(recipientColumn, recipientValue);
    if (restrictToTeacherMessages) singleQuery = singleQuery.in("type", ["center_teacher_message", "parent_message"]);
    if (restrictToStudentAudience) singleQuery = singleQuery.eq("audience", "student");
    if (restrictToParentAudience) singleQuery = singleQuery.or("audience.eq.parent,audience.is.null");
    const { error } = await singleQuery;

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
