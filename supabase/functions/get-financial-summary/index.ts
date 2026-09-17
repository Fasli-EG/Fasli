// supabase/functions/get-financial-summary/index.ts
// إجمالي دخل المدرس (اشتراكات + مذكرات) لشهر معيّن، مع تفصيل لكل مجموعة
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, requireOwnClientId, requireTeacherPlanPermission, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

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
    const { clientId, month } = await req.json();

    if (!clientId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ clientId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const finalClientId = requireOwnClientId(payload, clientId);
    await requireAssistantPermission(payload, "view_financial");
    await requireTeacherPlanPermission(finalClientId, "can_view_financial");

    // الشهر بصيغة YYYY-MM. الافتراضي (لو مفيش month، أو month === "ALL") هو كل شهور السنة
    // بدون فلترة تاريخ — مفيش تحديد "شهر حالي" افتراضي بعد كده.
    let isAllMonths = !month || month === "ALL";
    let rangeStart = "";
    let rangeEnd = "";
    if (!isAllMonths) {
      const [y, m] = String(month).split("-").map(Number);
      // ✅ حماية إضافية: لو الشهر جاي بصيغة غير صالحة (مش YYYY-MM رقمي) من نسخة فرونت-إند قديمة/مخزّنة كاش،
      // نتعامل معاه كـ "كل الشهور" بدل ما نرمي RangeError من Date.UTC/toISOString
      if (!Number.isFinite(y) || !Number.isFinite(m) || m < 1 || m > 12) {
        isAllMonths = true;
      } else {
        rangeStart = new Date(Date.UTC(y, m - 1, 1)).toISOString();
        rangeEnd = new Date(Date.UTC(y, m, 1)).toISOString();
      }
    }

    let paymentsQuery = supabase
      .from("payments")
      .select("amount, group_name, title, created_at")
      .eq("teacher_id", finalClientId);
    if (!isAllMonths) {
      paymentsQuery = paymentsQuery.gte("created_at", rangeStart).lt("created_at", rangeEnd);
    }

    let bookPaymentsQuery = supabase
      .from("book_payments")
      .select("amount, group_name, book_id, paid_at, books(name)")
      .eq("teacher_id", finalClientId);
    if (!isAllMonths) {
      bookPaymentsQuery = bookPaymentsQuery.gte("paid_at", rangeStart).lt("paid_at", rangeEnd);
    }

    // ✅ نجيب مصروفات نفس الشهر (أو كل الشهور) عشان نحسب صافي الربح الحقيقي، مش الإيراد الخام بس
    let expensesQuery = supabase
      .from("expenses").select("amount, category")
      .eq("teacher_id", finalClientId);
    if (!isAllMonths) {
      expensesQuery = expensesQuery.gte("expense_date", rangeStart.split("T")[0]).lt("expense_date", rangeEnd.split("T")[0]);
    }

    // ✅ (أداء) الثلاث استعلامات دي كانت متسلسلة (await منفصل لكل واحدة) رغم إنها مستقلة
    // تمامًا عن بعضها — بقت متوازية
    const [
      { data: payments, error: paymentsError },
      { data: bookPayments, error: bookError },
      { data: expenses },
    ] = await Promise.all([paymentsQuery, bookPaymentsQuery, expensesQuery]);

    if (paymentsError) {
      return new Response(JSON.stringify({ success: false, message: paymentsError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (bookError) {
      return new Response(JSON.stringify({ success: false, message: bookError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const subsTotal = (payments || []).reduce((sum: number, p: any) => sum + (Number(p.amount) || 0), 0);
    const booksTotal = (bookPayments || []).reduce((sum: number, p: any) => sum + (Number(p.amount) || 0), 0);

    const expensesTotal = (expenses || []).reduce((sum: number, e: any) => sum + Number(e.amount), 0);
    const expensesByCategory: Record<string, number> = {};
    (expenses || []).forEach((e: any) => {
      expensesByCategory[e.category] = (expensesByCategory[e.category] || 0) + Number(e.amount);
    });

    const groupMap: Record<string, { subscriptions: number; books: number }> = {};
    (payments || []).forEach((p: any) => {
      const g = p.group_name || "بدون مجموعة";
      if (!groupMap[g]) groupMap[g] = { subscriptions: 0, books: 0 };
      groupMap[g].subscriptions += Number(p.amount) || 0;
    });
    (bookPayments || []).forEach((p: any) => {
      const g = p.group_name || "بدون مجموعة";
      if (!groupMap[g]) groupMap[g] = { subscriptions: 0, books: 0 };
      groupMap[g].books += Number(p.amount) || 0;
    });

    const byGroup = Object.entries(groupMap).map(([groupName, v]) => ({
      groupName,
      subscriptions: v.subscriptions,
      books: v.books,
      total: v.subscriptions + v.books,
    })).sort((a, b) => b.total - a.total);

    // ✅ تفصيل إضافي: الربح لكل (مجموعة + بند سداد) على حدة — عشان فلتر "أرباح بند معيّن" في صفحة الدخل الشهري
    const byGroupAndTitleMap: Record<string, { groupName: string; title: string; amount: number }> = {};
    (payments || []).forEach((p: any) => {
      const g = p.group_name || "بدون مجموعة";
      const t = p.title || "بدون بند";
      const key = g + "||" + t;
      if (!byGroupAndTitleMap[key]) byGroupAndTitleMap[key] = { groupName: g, title: t, amount: 0 };
      byGroupAndTitleMap[key].amount += Number(p.amount) || 0;
    });
    const byGroupAndTitle = Object.values(byGroupAndTitleMap).sort((a, b) => b.amount - a.amount);

    // ✅ تفصيل إضافي: الربح لكل (مجموعة + مذكرة) على حدة — عشان فلتر "أرباح مذكرة معيّنة"
    const byGroupAndBookMap: Record<string, { groupName: string; bookName: string; amount: number }> = {};
    (bookPayments || []).forEach((p: any) => {
      const g = p.group_name || "بدون مجموعة";
      const b = p.books?.name || "مذكرة محذوفة";
      const key = g + "||" + b;
      if (!byGroupAndBookMap[key]) byGroupAndBookMap[key] = { groupName: g, bookName: b, amount: 0 };
      byGroupAndBookMap[key].amount += Number(p.amount) || 0;
    });
    const byGroupAndBook = Object.values(byGroupAndBookMap).sort((a, b) => b.amount - a.amount);

    return new Response(JSON.stringify({
      success: true,
      data: {
        month: isAllMonths ? "ALL" : month,
        subscriptionsTotal: subsTotal,
        booksTotal: booksTotal,
        grandTotal: subsTotal + booksTotal,
        expensesTotal,
        expensesByCategory,
        netProfit: subsTotal + booksTotal - expensesTotal,
        byGroup,
        byGroupAndTitle,
        byGroupAndBook,
      }
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
