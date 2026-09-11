// supabase/functions/get-activity-logs/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, requireOwnClientId, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة"); // ✅ رفض واضح بدل السقوط الصامت لصلاحيات anon
}
const supabase = createClient(supabaseUrl, supabaseKey); // ✅ تم إصلاح: كان العميل غير معرّف إطلاقاً في النسخة القديمة

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders, status: 200 });
  }

  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ success: false, message: "⚠️ الطريقة غير مسموحة" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    const payload = await verifyToken(req);
    const { clientId, action, dateFrom, dateTo } = await req.json();
    const finalClientId = requireOwnClientId(payload, clientId);
    await requireAssistantPermission(payload, "view_activity_log");

    let query = supabase
      .from("activity_logs")
      .select("*")
      .eq("teacher_id", finalClientId)
      // ✅ طبقة حماية إضافية: أي نشاط منسوب للماستر ميظهرش للمدرس خالص، حتى لو اتسجّل بالغلط من أي دالة تانية مستقبلاً
      // (or بدل neq عشان مانستبعدش بالغلط سجلات قديمة مفيهاش performer_role خالص)
      .or("performer_role.is.null,performer_role.neq.admin")
      .or("performer_id.is.null,performer_id.neq.master_admin")
      .order("created_at", { ascending: false })
      .limit(500);

    // ✅ Batch 20: لو اللي بيطلب مساعد، نقصر النتايج على نشاطه هو بس (مش كل نشاط المدرس/المساعدين
    // التانيين) — صلاحية "عرض سجل النشاطات" معناها يشوف شغله هو، مش يبقى عنده رؤية كاملة على الفريق
    if (payload.role === "assistant") {
      query = query.eq("assistant_id", payload.sub);
    }

    if (action) query = query.eq("action_type", action);
    if (dateFrom) query = query.gte("created_at", dateFrom);
    if (dateTo) query = query.lte("created_at", dateTo + "T23:59:59");

    const { data: logs, error: logsError } = await query;

    if (logsError) {
      return new Response(
        JSON.stringify({ success: false, message: logsError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!logs || logs.length === 0) {
      return new Response(
        JSON.stringify({ success: true, data: [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const teacherIds = new Set<string>();
    const assistantIds = new Set<string>();

    logs.forEach(log => {
      if (log.assistant_id) {
        assistantIds.add(log.assistant_id);
      } else {
        teacherIds.add(finalClientId);
      }
    });

    let teacherNames: Record<string, string> = {};
    if (teacherIds.size > 0) {
      const { data: teachers, error: teachersError } = await supabase
        .from("teachers")
        .select("client_id, name")
        .in("client_id", Array.from(teacherIds));

      if (!teachersError && teachers) {
        teachers.forEach(t => { teacherNames[t.client_id] = t.name; });
      }
    }

    let assistantNames: Record<string, string> = {};
    if (assistantIds.size > 0) {
      const { data: assistants, error: assistantsError } = await supabase
        .from("assistants")
        .select("id, name")
        .in("id", Array.from(assistantIds));

      if (!assistantsError && assistants) {
        assistants.forEach(a => { assistantNames[a.id] = a.name; });
      }
    }

    const processedData = logs.map(log => {
      // ✅ لو النشاط أصلاً متسجّل فيه اسم ودور المنفّذ الصحيح (كل الدوال الحديثة بتعمل كده)، نستخدمه زي ما هو
      // ونلجأ للبحث القديم بـ assistant_id بس لو كانت الأعمدة دي فاضية (نشاطات قديمة جداً من قبل ما نضيفها)
      if (log.performer_name && log.performer_role) {
        return log;
      }

      let performerName = "المدرس";
      let performerRole = "teacher";

      if (log.assistant_id && assistantNames[log.assistant_id]) {
        performerName = assistantNames[log.assistant_id];
        performerRole = "assistant";
      } else if (teacherNames[finalClientId]) {
        performerName = teacherNames[finalClientId];
        performerRole = "teacher";
      }

      return {
        ...log,
        performer_name: performerName,
        performer_role: performerRole
      };
    });

    return new Response(
      JSON.stringify({ success: true, data: processedData }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ عام:", error);
    return new Response(
      JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
