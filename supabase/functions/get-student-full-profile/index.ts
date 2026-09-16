// supabase/functions/get-student-full-profile/index.ts
// ✅ دالة موحّدة تجمع get-student-info + get-student-grades + get-student-payments +
// get-student-attendance + get-student-books في استجابة واحدة — بدل 5 طلبات شبكة منفصلة، طلب واحد بس
// (تحسين أداء حقيقي، مش بس توفير في عدد الدوال — الصلاحية بتتفحص مرة واحدة، والبيانات بتتجاب بالتوازي)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, TokenPayload, AuthError, verifyToken } from "../_shared/auth.ts";

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const { studentUid, parentPhone } = await req.json();
    if (!studentUid) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: student, error: studentError } = await supabase
      .from("students").select("*, teachers!inner(name, conversations_enabled, electronic_payment_enabled, payment_instapay, payment_wallet, payment_bank_details)").eq("uid", studentUid).maybeSingle();
    if (studentError || !student) {
      return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ فحص صلاحية موحّد لكل الأنواع الثلاثة — بيتفحص مرة واحدة بس بدل 5 مرات منفصلة
    if (payload.role === "parent") {
      if (!parentPhone) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (payload.phone !== parentPhone || student.parent_phone !== parentPhone) {
        return new Response(JSON.stringify({ success: false, message: "غير مصرح لك بمشاهدة هذا الطالب" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    } else if (payload.role === "student") {
      if (payload.sub !== studentUid) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بمشاهدة بيانات طالب تاني" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    } else if (payload.role === "teacher" || payload.role === "assistant") {
      const tokenClientId = payload.clientId || payload.teacherId;
      if (student.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    } else {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ كل بيانات الطالب بتتجاب بالتوازي في نفس الدالة — طلب شبكة واحد بس بدل 4 منفصلين
    const [gradesRes, paymentsRes, attendanceRes, bookPaymentsRes, groupLinksRes, paymentTitlesRes] = await Promise.all([
      supabase.from("grades").select("*").eq("student_uid", studentUid).order("created_at", { ascending: false }),
      supabase.from("payments").select("*").eq("student_uid", studentUid).order("created_at", { ascending: false }),
      supabase.from("attendance").select("*").eq("student_uid", studentUid).order("date", { ascending: false }),
      supabase.from("book_payments").select("id, amount, paid_at, group_name, book_id, books:book_id (id, name, price, file_url)").eq("student_uid", studentUid),
      supabase.from("student_group_links").select("group_name").eq("student_uid", studentUid),
      supabase.from("payment_titles").select("title, default_amount").eq("teacher_id", student.teacher_id),
    ]);

    // ✅ (طلب) بند سداد معمولش له ولا صف payments واحد للطالب ده كان مش بيظهر خالص في قايمته
    // (لا لولي الأمر ولا للمدرس) — رغم إن .missed كان أصلاً متعامل معاه في الواجهة، مكانش
    // بيتحط أبداً من أي فانكشن. بنضيف صف "افتراضي" (missed) لأي بند مالوش صف حقيقي، عشان
    // ولي الأمر يقدر يشوفه ويختاره ويدفعه من غير ما يستنى حد يسجّله له دفعة جزئية الأول
    const existingPaymentTitles = new Set((paymentsRes.data || []).map((p: any) => p.title));
    const missedPayments = (paymentTitlesRes.data || [])
      .filter((t: any) => !existingPaymentTitles.has(t.title))
      .map((t: any) => ({
        title: t.title, amount: 0, total_amount: t.default_amount || 0,
        student_uid: studentUid, teacher_id: student.teacher_id, group_name: student.group_name,
        missed: true,
      }));
    const paymentsWithMissed = [...(paymentsRes.data || []), ...missedPayments];

    // ✅ (طلب) لازم نرجّع كل المجموعات اللي الطالب فيها (الأساسية + المربوطة) عشان صفحة تفاصيل
    // الطالب تقدر تعرض فلتر مجموعات كامل، حتى لو مجموعة معينة لسه معملهاش أي درجات/حضور/مدفوعات
    const allGroups = Array.from(new Set([
      student.group_name,
      ...((groupLinksRes.data || []).map((l: any) => l.group_name)),
    ].filter(Boolean)));

    // ✅ (طلب) group_name بيتضاف هنا عشان صفحات تفاصيل الطالب (مدرس/طالب/ولي أمر) تقدر تفصل
    // بيانات المذكرات حسب المجموعة برضه، زي الدرجات والحضور والمدفوعات — لطالب مرتبط بأكتر من مجموعة
    const books = (bookPaymentsRes.data || []).map((item: any) => ({
      id: item.id, book_name: item.books?.name || "مذكرة غير معروفة", price: item.books?.price || 0,
      amount: item.amount || 0, paid_at: item.paid_at, file_url: item.books?.file_url || null,
      group_name: item.group_name || null,
      status: item.amount >= (item.books?.price || 0) ? "مدفوع بالكامل" : "دفعة جزئية",
    }));

    return new Response(JSON.stringify({
      success: true,
      data: {
        info: { id: student.id, uid: student.uid, name: student.name, phone: student.phone, group_name: student.group_name, groups: allGroups, teacher_name: student.teachers?.name || "غير محدد", conversations_enabled: student.teachers?.conversations_enabled !== false, electronic_payment_enabled: student.teachers?.electronic_payment_enabled === true, payment_instapay: student.teachers?.payment_instapay || null, payment_wallet: student.teachers?.payment_wallet || null, payment_bank_details: student.teachers?.payment_bank_details || null },
        grades: gradesRes.data || [],
        payments: paymentsWithMissed,
        attendance: attendanceRes.data || [],
        books,
      },
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في get-student-full-profile:", error);
    const message = error instanceof Error ? error.message : "خطأ غير معروف";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
