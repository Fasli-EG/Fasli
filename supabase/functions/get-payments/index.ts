// supabase/functions/get-payments/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, AuthError, verifyToken, authErrorResponse } from "../_shared/auth.ts";

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;
    if (!tokenClientId) {
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ التوكن لا يحتوي على clientId" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { clientId, groupName, title, page } = await req.json();
    if (clientId && clientId !== tokenClientId) {
      return new Response(
        JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    if (groupName) {
      // ✅ مجموعة محددة — نفس السلوك القديم بالظبط، من غير تغيير. النطاق ده دايمًا محدود
      // بعمر المجموعة نفسها (مش كل تاريخ المدرس)، فمش محتاج pagination من الأساس.
      let query = supabase.from("payments").select("*").eq("teacher_id", tokenClientId).eq("group_name", groupName);
      if (title) query = query.eq("title", title);
      const { data, error } = await query.order("created_at", { ascending: false }).limit(5000);
      if (error) throw new Error(error.message);
      return new Response(
        JSON.stringify({ success: true, data: data || [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ✅ (تنفيذ حذر) عرض "كل المجموعات" هو النطاق الوحيد اللي فعلاً بلا حدود (كل مدفوعات المدرس
    // من أول يوم). بدل pagination بالصف الخام (اللي كان هيكسر حساب "غير المسددين" — محتاج يشوف
    // كل سجلات المجموعة مع بعض عشان يقارن صح)، بنعمل pagination بوحدة "مجموعة كاملة" — كل صفحة
    // = مجموعة واحدة كاملة، بنفس البيانات اللي كانت هتترجع لو اخترتها إنتِ يدويًا بالظبط. كده
    // منطق المقارنة (يعتمد على get-students بنفس اسم المجموعة من الفرونت إند) يفضل صحيح 100%،
    // ومفيش أي تعديل مطلوب في get-students خالص.
    let groupsQuery = supabase.from("payments").select("group_name").eq("teacher_id", tokenClientId);
    if (title) groupsQuery = groupsQuery.eq("title", title);
    // ✅ سقف دفاعي هنا كمان — العمود ده خفيف (اسم مجموعة بس) فمش نفس خطورة select("*")،
    // بس بره أي حد خالص برضو مش آمن على المدى الطويل
    const { data: groupRows, error: groupsErr } = await groupsQuery.limit(20000);
    if (groupsErr) throw new Error(groupsErr.message);

    const allGroupNames = Array.from(
      new Set((groupRows || []).map((r: any) => r.group_name).filter(Boolean))
    ).sort((a: any, b: any) => String(a).localeCompare(String(b), "ar"));

    const totalGroups = allGroupNames.length;
    const pageNum = Math.max(1, Number(page) || 1);
    const currentGroupName = allGroupNames[pageNum - 1] || null;

    let data: any[] = [];
    if (currentGroupName) {
      let pageQuery = supabase.from("payments").select("*").eq("teacher_id", tokenClientId).eq("group_name", currentGroupName);
      if (title) pageQuery = pageQuery.eq("title", title);
      const { data: pageData, error: pageErr } = await pageQuery.order("created_at", { ascending: false }).limit(5000);
      if (pageErr) throw new Error(pageErr.message);
      data = pageData || [];
    }

    return new Response(
      JSON.stringify({
        success: true,
        data,
        pagination: { page: pageNum, totalPages: totalGroups, currentGroupName, hasMore: pageNum < totalGroups },
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في get-payments:", error);
    return new Response(
      JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

