// supabase/functions/get-assistants/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, requireOwnClientId, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة"); // ✅ رفض واضح بدل السقوط الصامت لصلاحيات anon
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطريقة غير مسموحة" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  try {
    const payload = await verifyToken(req);
    const { teacherId } = await req.json();
    const finalTeacherId = requireOwnClientId(payload, teacherId);
    await requireAssistantPermission(payload, "view_staff");

    // ✅ Batch 20: لو الطالب لهذا الاستدعاء مساعد (بصلاحية "عرض فريق العمل")، نرجّع أعمدة آمنة بس —
    // مننزلش password_hash أو أي عمود حساس تاني، حتى لو المدرس نفسه بيجيب "*" زي ما كان دايماً
    const selectCols = payload.role === "assistant"
      ? "id, teacher_id, username, name, is_active, last_login, permissions, created_at"
      : "*";

    const { data, error } = await supabase
      .from("assistants").select(selectCols).eq("teacher_id", finalTeacherId).order("created_at", { ascending: false });

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, data: data || [] }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
