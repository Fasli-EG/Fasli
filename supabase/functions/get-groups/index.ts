// supabase/functions/get-groups/index.ts
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

    const { clientId } = await req.json();
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

    const { data: students, error } = await supabase
      .from("students")
      .select("group_name")
      .eq("teacher_id", tokenClientId)
      .not("group_name", "is", null);

    if (error) throw new Error(error.message);

    // ✅ نجيب كمان أي مجموعة اتعملت من خلال create-group لكن لسه مفيهاش طلاب
    // (كانت مش بتظهر خالص قبل كده لأن القائمة كانت بتتجاب من الطلاب بس)
    const { data: groupRows, error: groupsError } = await supabase
      .from("groups")
      .select("name")
      .eq("teacher_id", tokenClientId);

    if (groupsError) {
      console.error("⚠️ تعذر جلب جدول groups، هنكمل بأسماء الطلاب بس:", groupsError.message);
    }

    const fromStudents = students.map(s => s.group_name);
    const fromGroupsTable = (groupRows || []).map(g => g.name);
    const groups = [...new Set([...fromStudents, ...fromGroupsTable])].sort();

    return new Response(
      JSON.stringify({ success: true, data: groups }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في get-groups:", error);
    return new Response(
      JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

