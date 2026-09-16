// supabase/functions/manage-expense/index.ts
// ✅ إدارة المصروفات — action: add | delete | list
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, verifyToken, authErrorResponse, requireAssistantPermission } from "../_shared/auth.ts";

const VALID_CATEGORIES = ["rent", "salaries", "utilities", "supplies", "marketing", "other"];

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    if (payload.role !== "teacher" && payload.role !== "assistant") {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // ✅ Batch 27: كانت الدالة دي مفتوحة لأي مساعد مسجّل دخول من غير أي فحص صلاحية خالص — لا
    // add ولا delete ولا حتى list. الواجهة (financial.html) بتقفل الصفحة كلها للمساعد إلا لو
    // معاه view_financial، فده نفس الصلاحية اللي المفروض تتحقق هنا (الميزة مالهاش تقسيم أدق
    // زي باقي الوحدات المالية — نفس الصلاحية بتغطي العرض والتسجيل والحذف)
    await requireAssistantPermission(payload, "view_financial");

    const tokenClientId = payload.clientId || payload.teacherId;
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const body = await req.json();
    const action = body.action;

    if (action === "add") {
      const { category, description, amount, expenseDate } = body;
      if (!category || !VALID_CATEGORIES.includes(category)) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ اختر نوع مصروف صحيح" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (amount === undefined || isNaN(Number(amount)) || Number(amount) <= 0) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ أدخلي مبلغاً صحيحاً" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data, error } = await supabase.from("expenses").insert({
        teacher_id: tokenClientId, category, description: description || null,
        amount: Number(amount), expense_date: expenseDate || new Date().toISOString().split("T")[0],
      }).select().single();
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم تسجيل المصروف", data }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "delete") {
      const { expenseId } = body;
      const { data: existing } = await supabase.from("expenses").select("teacher_id").eq("id", expenseId).maybeSingle();
      if (!existing || existing.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { error } = await supabase.from("expenses").delete().eq("id", expenseId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم حذف المصروف" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "list") {
      const { month } = body; // "YYYY-MM" — اختياري، لو فاضي أو "ALL" بيرجع كل المصروفات
      let query = supabase.from("expenses").select("*").eq("teacher_id", tokenClientId).order("expense_date", { ascending: false });
      if (month && month !== "ALL") {
        const [y, m] = month.split("-").map(Number);
        const rangeStart = `${month}-01`;
        const nextMonth = m === 12 ? `${y + 1}-01-01` : `${y}-${String(m + 1).padStart(2, "0")}-01`;
        query = query.gte("expense_date", rangeStart).lt("expense_date", nextMonth);
      }
      const { data, error } = await query;
      if (error) throw new Error(error.message);
      const total = (data || []).reduce((sum: number, e: any) => sum + Number(e.amount), 0);
      return new Response(JSON.stringify({ success: true, data: data || [], total }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    return authErrorResponse(error);
  }
});
