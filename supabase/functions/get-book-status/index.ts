// supabase/functions/get-book-status/index.ts
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

    const { teacherId, bookId, groupName } = await req.json();

    if (!teacherId || !bookId || !groupName) {
      return new Response(
        JSON.stringify({ success: false, message: "جميع الحقول مطلوبة: teacherId, bookId, groupName" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (tokenClientId !== teacherId) {
      return new Response(
        JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { data: students, error: studentsError } = await supabase
      .from("students")
      .select("uid, name")
      .eq("teacher_id", teacherId)
      .eq("group_name", groupName);

    if (studentsError) {
      console.error("❌ فشل جلب الطلاب:", studentsError);
      return new Response(
        JSON.stringify({ success: false, message: `فشل جلب الطلاب: ${studentsError.message}` }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (students.length === 0) {
      return new Response(
        JSON.stringify({ success: true, data: [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const studentUids = students.map(s => s.uid);
    const { data: payments, error: paymentsError } = await supabase
      .from("book_payments")
      .select("id, student_uid, amount, paid_at")
      .eq("book_id", bookId)
      .eq("teacher_id", teacherId)
      .in("student_uid", studentUids);

    if (paymentsError) {
      console.error("❌ فشل جلب المدفوعات:", paymentsError);
      return new Response(
        JSON.stringify({ success: false, message: `فشل جلب المدفوعات: ${paymentsError.message}` }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { data: book, error: bookError } = await supabase
      .from("books")
      .select("name, price")
      .eq("id", bookId)
      .single();

    if (bookError) {
      console.error("❌ فشل جلب المذكرة:", bookError);
      return new Response(
        JSON.stringify({ success: false, message: `فشل جلب المذكرة: ${bookError.message}` }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const result = students.map(student => {
      const payment = payments?.find(p => p.student_uid === student.uid);
      const amount = payment?.amount || 0;
      const isFullyPaid = amount >= book.price;
      const isPartiallyPaid = amount > 0 && !isFullyPaid;

      let status = "غير مدفوع";
      if (isFullyPaid) status = "مدفوع";
      else if (isPartiallyPaid) status = "دفعة جزئية";

      return {
        student_name: student.name,
        student_uid: student.uid,
        book_name: book.name,
        amount: amount,
        price: book.price,
        paid_at: payment?.paid_at || null,
        payment_id: payment?.id || null,
        status: status,
        isFullyPaid: isFullyPaid,
        isPartiallyPaid: isPartiallyPaid,
      };
    });

    return new Response(
      JSON.stringify({ success: true, data: result }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(
      JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

