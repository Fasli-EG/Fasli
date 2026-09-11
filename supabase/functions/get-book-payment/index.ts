// supabase/functions/get-book-payment/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, AuthError, verifyToken, authErrorResponse } from "../_shared/auth.ts";

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    const { teacherId, bookId, studentUid } = await req.json();

    if (!teacherId || !bookId || !studentUid) {
      return new Response(
        JSON.stringify({ success: false, message: "teacherId, bookId, studentUid مطلوبة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (tokenClientId !== teacherId) {
      return new Response(
        JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { data, error } = await supabase
      .from("book_payments")
      .select("id, amount, paid_at")
      .eq("teacher_id", teacherId)
      .eq("book_id", bookId)
      .eq("student_uid", studentUid)
      .maybeSingle();

    if (error) {
      console.error("❌ فشل جلب الدفعة:", error);
      return new Response(
        JSON.stringify({ success: false, message: `فشل جلب الدفعة: ${error.message}` }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({ success: true, data: data || null }),
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

