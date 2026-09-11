// supabase/functions/get-latest-rfid-scan/index.ts
// يحل محل استعلام REST مباشر على جدول rfid_scans (كان محتاج anon key ويتخطى نظام التحقق المخصص)
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, ownerClientId, requireTeacherPlanPermission, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    // ✅ لازم توكن مدرس أو مساعد صالح (بدل الاعتماد على anon key مكشوف في الفرونت إند)
    const payload = await verifyToken(req);
    const tokenClientId = ownerClientId(payload); // يتأكد إن التوكن فيه clientId/teacherId صحيح
    await requireTeacherPlanPermission(tokenClientId, "can_use_rfid");

    const { data, error } = await supabase
      .from("rfid_scans")
      .select("*")
      .eq("client_id", tokenClientId) // ✅ الإصلاح: كل مدرس يشوف قراءات جهازه هو بس، مش أحدث قراءة في النظام كله
      .order("id", { ascending: false })
      .limit(1);

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // نفس شكل استجابة PostgREST القديم (مصفوفة) عشان الفرونت إند يفضل شغال بدون تعديل في منطق القراءة
    return new Response(JSON.stringify(data || []),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
