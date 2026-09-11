// supabase/functions/admin-manage-card-registration/index.ts
// ✅ دالة موحّدة تجمع start/cancel-card-registration + get-card-registration-status (جانب الأدمن)
// action: start | cancel | status
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
};

interface TokenPayload { sub: string; clientId?: string; role: string; name: string; }

class AuthError extends Error {
  status: number; code?: string;
  constructor(message: string, status = 401, code?: string) { super(message); this.status = status; this.code = code; }
}

async function verifyToken(req: Request): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) throw new AuthError("⚠️ التوكن مطلوب", 401);
  const token = authHeader.substring(7);
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) throw new Error("⚠️ JWT_SECRET غير مضبوط");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  try { return (await verify(token, key, "HS256")) as unknown as TokenPayload; }
  catch (_e) { throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401); }
}

function requireAdmin(payload: TokenPayload) {
  if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
    throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
  }
}

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleStart(supabase: any, body: any) {
  const { teacherId, studentUid } = body;
  if (!teacherId || !studentUid) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ teacherId و studentUid مطلوبين" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { data: student, error: studentError } = await supabase.from("students").select("name, teacher_id").eq("uid", studentUid).maybeSingle();
  if (studentError || !student) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (student.teacher_id !== teacherId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب ده مش تابع للمدرس المختار" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error } = await supabase.from("pending_card_registrations").upsert(
    { teacher_id: teacherId, student_uid: studentUid, student_name: student.name, requested_at: new Date().toISOString(), registered_card_uid: null },
    { onConflict: "teacher_id" }
  );
  if (error) {
    console.error("❌ فشل بدء طلب تسجيل الكارت:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: `✅ في انتظار تمريغ الكارت على بورد ${teacherId} لتسجيله لـ ${student.name}` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleCancel(supabase: any, body: any) {
  const { teacherId } = body;
  if (!teacherId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ teacherId مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  await supabase.from("pending_card_registrations").delete().eq("teacher_id", teacherId);
  return new Response(JSON.stringify({ success: true, message: "✅ تم إلغاء طلب التسجيل" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleStatus(supabase: any, body: any) {
  const { teacherId } = body;
  if (!teacherId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ teacherId مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { data: pending } = await supabase.from("pending_card_registrations").select("*").eq("teacher_id", teacherId).maybeSingle();
  if (!pending) {
    return new Response(JSON.stringify({ success: true, status: "none" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (pending.registered_card_uid) {
    await supabase.from("pending_card_registrations").delete().eq("teacher_id", teacherId);
    return new Response(JSON.stringify({ success: true, status: "done", cardUid: pending.registered_card_uid, studentName: pending.student_name }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, status: "waiting", studentName: pending.student_name }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    requireAdmin(payload);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    const body = await req.json();
    const action = body.action;

    if (action === "start") return await handleStart(supabase, body);
    if (action === "cancel") return await handleCancel(supabase, body);
    if (action === "status") return await handleStatus(supabase, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
