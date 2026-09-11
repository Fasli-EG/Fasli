// supabase/functions/manage-card-registration/index.ts
// ✅ دالة موحّدة تجمع teacher-start/cancel-card-registration + teacher-get-card-registration-status
// action: start | cancel | status — جانب المدرس/المساعد (لربط كارت بطالب)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, TokenPayload, AuthError, verifyToken } from "../_shared/auth.ts";

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleStart(supabase: any, tokenClientId: string, body: any) {
  const { studentUid } = body;
  if (!studentUid) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { data: student, error: studentError } = await supabase.from("students").select("name, teacher_id").eq("uid", studentUid).maybeSingle();
  if (studentError || !student) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب غير موجود في النظام (تحقق من UID)" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (student.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب ده مش تابع لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ نتحقق من الكروت المخصصة مباشرة للمدرس، أو المخصصة لسنتره لو كان تابع لسنتر
  const { data: teacherRow } = await supabase.from("teachers").select("center_id").eq("client_id", tokenClientId).maybeSingle();
  let cardsQuery = supabase.from("system_cards").select("id", { count: "exact", head: true }).eq("status", "assigned").eq("is_active", true);
  cardsQuery = teacherRow?.center_id
    ? cardsQuery.or(`teacher_id.eq.${tokenClientId},center_id.eq.${teacherRow.center_id}`)
    : cardsQuery.eq("teacher_id", tokenClientId);
  const { count: activeCount } = await cardsQuery;
  if (!activeCount || activeCount === 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ مفيش أي كروت مفعّلة ليك دلوقتي، تواصل مع الإدارة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error } = await supabase.from("pending_card_registrations").upsert(
    { teacher_id: tokenClientId, student_uid: studentUid, student_name: student.name, requested_at: new Date().toISOString(), registered_card_uid: null, error_message: null },
    { onConflict: "teacher_id" }
  );
  if (error) {
    console.error("❌ فشل بدء طلب ربط الكارت:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: `✅ في انتظار تمريغ الكارت لربطه بـ ${student.name}` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleCancel(supabase: any, tokenClientId: string) {
  await supabase.from("pending_card_registrations").delete().eq("teacher_id", tokenClientId);
  return new Response(JSON.stringify({ success: true, message: "✅ تم إلغاء طلب الربط" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleStatus(supabase: any, tokenClientId: string) {
  const { data: pending } = await supabase.from("pending_card_registrations").select("*").eq("teacher_id", tokenClientId).maybeSingle();
  if (!pending) {
    return new Response(JSON.stringify({ success: true, status: "none" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (pending.error_message) {
    return new Response(JSON.stringify({ success: true, status: "error", message: pending.error_message }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (pending.registered_card_uid) {
    return new Response(JSON.stringify({ success: true, status: "done", studentName: pending.student_name, cardUid: pending.registered_card_uid }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, status: "waiting", studentName: pending.student_name }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const tokenClientId = payload.clientId || payload.teacherId;
    if ((payload.role !== "teacher" && payload.role !== "assistant") || !tokenClientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ متاح للمدرس أو المساعد بس" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    const body = await req.json();
    const action = body.action;

    if (action === "start") return await handleStart(supabase, tokenClientId, body);
    if (action === "cancel") return await handleCancel(supabase, tokenClientId);
    if (action === "status") return await handleStatus(supabase, tokenClientId);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
