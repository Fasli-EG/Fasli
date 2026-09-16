// supabase/functions/get-students/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, AuthError, verifyToken, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const payload = await verifyToken(req);
    // ✅ Batch 27: كانت الدالة دي بترجع كل الطلاب لأي مساعد مسجّل دخول من غير ما تتحقق من
    // view_students خالص — لو المدرس مانع مساعد الصلاحية دي، كان لسه بيقدر يجيب القائمة كاملة
    await requireAssistantPermission(payload, "view_students");
    const tokenClientId = payload.clientId || payload.teacherId;
    if (!tokenClientId) {
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ التوكن لا يحتوي على clientId" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { clientId, groupName, includeArchived } = await req.json();
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

    let query = supabase.from("students").select("*").eq("teacher_id", tokenClientId);
    if (groupName) query = query.eq("group_name", groupName);
    // ✅ افتراضياً بنستبعد المؤرشفين من القائمة النشطة — includeArchived:true بيرجّع المؤرشفين بس (مش الاتنين مع بعض)
    query = includeArchived ? query.not("archived_at", "is", null) : query.is("archived_at", null);

    // ✅ (مراجعة أداء) الاستعلامين دول مالهمش أي علاقة ببعض (الطلاب الأساسيين، والروابط
    // المشتركة) — كانوا بينتظروا واحد بعد التاني من غير داعي، دلوقتي بيتنفذوا مع بعض بالتوازي
    const [{ data, error }, { data: links }] = await Promise.all([
      query.order("name"),
      supabase.from("student_teacher_links").select("student_uid, group_name").eq("teacher_id", tokenClientId),
    ]);
    if (error) throw new Error(error.message);

    // ✅ الطلاب المشتركين — طالب عند أكتر من مدرس (student_teacher_links)، بيظهروا هنا كمان
    // حتى لو مدرسهم الأساسي (teacher_id) شخص تاني، بشرط إن السنتر ربطهم بالمدرس صاحب التوكن
    let linkedData: any[] = [];
    if (links && links.length > 0) {
      const linkedUids = links.map((l: any) => l.student_uid);
      const groupOverride: Record<string, string | null> = {};
      links.forEach((l: any) => { groupOverride[l.student_uid] = l.group_name; });
      let linkedQuery = supabase.from("students").select("*").in("uid", linkedUids);
      linkedQuery = includeArchived ? linkedQuery.not("archived_at", "is", null) : linkedQuery.is("archived_at", null);
      const { data: linkedStudents } = await linkedQuery;
      linkedData = (linkedStudents || [])
        .map((s: any) => ({ ...s, isLinked: true, group_name: groupOverride[s.uid] || s.group_name }))
        .filter((s: any) => !groupName || s.group_name === groupName);
    }

    // ✅ Aug 2026 (Phase I): طالب ممكن يكون مربوط بمجموعة إضافية (تعدد مواد/مدرسين) عن طريق
    // student_group_links — بيظهر هنا كمان لو بنفلتر على المجموعة الإضافية دي بالذات
    let groupLinkedData: any[] = [];
    if (groupName) {
      const { data: groupLinks } = await supabase
        .from("student_group_links").select("student_uid").eq("teacher_id", tokenClientId).eq("group_name", groupName);
      if (groupLinks && groupLinks.length > 0) {
        const existingUids = new Set([...(data || []), ...linkedData].map((s: any) => s.uid));
        const groupLinkedUids = groupLinks.map((l: any) => l.student_uid).filter((u: string) => !existingUids.has(u));
        if (groupLinkedUids.length > 0) {
          let groupLinkedQuery = supabase.from("students").select("*").in("uid", groupLinkedUids);
          groupLinkedQuery = includeArchived ? groupLinkedQuery.not("archived_at", "is", null) : groupLinkedQuery.is("archived_at", null);
          const { data: groupLinkedStudents } = await groupLinkedQuery;
          groupLinkedData = (groupLinkedStudents || []).map((s: any) => ({ ...s, isGroupLinked: true, primaryGroupName: s.group_name, group_name: groupName }));
        }
      }
    }

    return new Response(
      JSON.stringify({ success: true, data: [...(data || []), ...linkedData, ...groupLinkedData] }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في get-students:", error);
    return new Response(
      JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

