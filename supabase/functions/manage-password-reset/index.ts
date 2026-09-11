// supabase/functions/manage-password-reset/index.ts
// ✅ دالة موحّدة تجمع reset-assistant-password + reset-parent-password + admin-reset-teacher-password
// action: assistant | parent | teacher
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
};

interface TokenPayload { sub: string; clientId?: string; teacherId?: string; role: string; name: string; phone?: string; }

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

const ITERATIONS = 100_000;
function toHex(bytes: Uint8Array): string { return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(""); }
async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, keyMaterial, 256);
  return new Uint8Array(bits);
}
async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2(password, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${toHex(salt)}$${toHex(hashBytes)}`;
}

// ============================================
// ⭐ إعادة تعيين كلمة مرور مساعد (المدرس بس، مش المساعد نفسه)
// ============================================
async function handleAssistant(supabase: any, payload: TokenPayload, body: any) {
  if (payload.role !== "teacher") {
    return new Response(JSON.stringify({ success: false, message: "⛔ متاح للمدرس بس" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const tokenClientId = payload.clientId!;
  const { assistantId } = body;
  if (!assistantId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ assistantId مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { data: assistant, error: fetchError } = await supabase.from("assistants").select("username, name, teacher_id").eq("id", assistantId).maybeSingle();
  if (fetchError || !assistant) {
    return new Response(JSON.stringify({ success: false, message: "❌ المساعد غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (assistant.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذا الإجراء" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let tempPassword = "";
  for (let i = 0; i < 8; i++) tempPassword += chars.charAt(Math.floor(Math.random() * chars.length));
  const hashedPassword = await hashPassword(tempPassword);

  const { error } = await supabase.from("assistants").update({ password_hash: hashedPassword, must_change_password: true }).eq("id", assistantId);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  await supabase.from("activity_logs").insert({
    teacher_id: assistant.teacher_id, assistant_id: assistantId, action_type: "reset_password",
    entity_type: "assistant", entity_id: assistantId.toString(),
    details: { username: assistant.username, name: assistant.name },
    performer_id: assistant.teacher_id, performer_role: "teacher", performer_name: payload.name || "مدرس",
  });

  return new Response(JSON.stringify({ success: true, message: `✅ تم إعادة تعيين كلمة مرور المساعد "${assistant.name}"`, tempPassword }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ إعادة تعيين كلمة مرور ولي أمر (المدرس أو المساعد بصلاحية)
// ============================================
async function handleParent(supabase: any, payload: TokenPayload, body: any) {
  if (payload.role !== "teacher" && payload.role !== "assistant") {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const finalClientId = payload.clientId || payload.teacherId;
  const { studentUid } = body;

  if (payload.role === "assistant") {
    const { data: assistantRow } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
    if (!assistantRow?.permissions?.reset_parent_password) {
      return new Response(JSON.stringify({ success: false, message: "⛔ ليس لديك صلاحية لإعادة تعيين كلمة مرور ولي الأمر" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }
  if (!studentUid) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: student, error: studentError } = await supabase.from("students").select("name, parent_phone, teacher_id").eq("uid", studentUid).maybeSingle();
  if (studentError || !student) {
    return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (student.teacher_id !== finalClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (!student.parent_phone) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ لا يوجد رقم ولي أمر مسجّل لهذا الطالب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const newHash = await hashPassword(student.parent_phone);
  const { error: updateError } = await supabase.from("parents").update({ password_hash: newHash, must_change_password: true }).eq("phone", student.parent_phone);
  if (updateError) {
    return new Response(JSON.stringify({ success: false, message: updateError.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  await supabase.from("activity_logs").insert({
    client_id: finalClientId, teacher_id: finalClientId,
    action_type: "reset_parent_password", entity_type: "parent",
    details: { student_name: student.name, student_uid: studentUid },
    performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
  });

  return new Response(JSON.stringify({ success: true, message: `✅ تم إعادة تعيين كلمة مرور ولي أمر ${student.name} — كلمة المرور الجديدة هي رقم هاتفه` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ (طلب) إعادة تعيين كلمة مرور الطالب نفسه (مش ولي الأمر) — المدرس أو المساعد بصلاحية
// نفس منطق handleParent بالظبط، بس بيصفّر password_hash الطالب لـ null بدل ما يحط هاش جديد —
// عشان يرجع نفس سلوك أول تسجيل دخول (login's "!user.password_hash" branch) اللي بيقبل UID الكارت
// كباسورد أول مرة تلقائياً، فمفيش داعي نكرر منطق التوليد هنا
// ============================================
async function handleStudent(supabase: any, payload: TokenPayload, body: any) {
  if (payload.role !== "teacher" && payload.role !== "assistant") {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const finalClientId = payload.clientId || payload.teacherId;
  const { studentUid } = body;

  if (payload.role === "assistant") {
    const { data: assistantRow } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
    if (!assistantRow?.permissions?.reset_parent_password) {
      return new Response(JSON.stringify({ success: false, message: "⛔ ليس لديك صلاحية لإعادة تعيين كلمة مرور الطالب" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }
  if (!studentUid) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: student, error: studentError } = await supabase.from("students").select("name, teacher_id").eq("uid", studentUid).maybeSingle();
  if (studentError || !student) {
    return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (student.teacher_id !== finalClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error: updateError } = await supabase.from("students").update({ password_hash: null, must_change_password: true }).eq("uid", studentUid);
  if (updateError) {
    return new Response(JSON.stringify({ success: false, message: updateError.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  await supabase.from("activity_logs").insert({
    client_id: finalClientId, teacher_id: finalClientId,
    action_type: "reset_student_password", entity_type: "student",
    details: { student_name: student.name, student_uid: studentUid },
    performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
  });

  return new Response(JSON.stringify({ success: true, message: `✅ تم إعادة تعيين كلمة مرور ${student.name} — هيدخل بكود الكارت (UID) كباسورد أول مرة، وهيتطلب منه يغيّرها بعدها` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ إعادة تعيين كلمة مرور مدرس (الأدمن الرئيسي بس)
// ============================================
async function handleTeacher(supabase: any, payload: TokenPayload, body: any) {
  requireAdmin(payload);
  const { clientId, newPassword } = body;
  if (!clientId || !newPassword) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (newPassword.length < 4) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ كلمة المرور قصيرة جداً" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const hashedPassword = await hashPassword(newPassword);
  const { error: updateError } = await supabase.from("teachers").update({ password_hash: hashedPassword, must_change_password: true }).eq("client_id", clientId);
  if (updateError) {
    return new Response(JSON.stringify({ success: false, message: updateError.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  await supabase.from("activity_logs").insert({
    client_id: clientId, teacher_id: clientId, action_type: "reset_password", entity_type: "teacher", entity_id: clientId,
    details: { by_admin: true }, performer_id: "admin_action", performer_role: "system", performer_name: "الإدارة",
  });

  return new Response(JSON.stringify({ success: true, message: `✅ تم إعادة تعيين كلمة المرور للمدرس ${clientId} بنجاح. سيُطلب منه تغييرها عند تسجيل الدخول.` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ إعادة تعيين كلمة مرور سنتر (الأدمن الرئيسي بس) — Aug 2026، نفس منطق handleTeacher بالظبط
// ============================================
async function handleCenter(supabase: any, payload: TokenPayload, body: any) {
  requireAdmin(payload);
  const { clientId, newPassword } = body;
  if (!clientId || !newPassword) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (newPassword.length < 4) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ كلمة المرور قصيرة جداً" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const hashedPassword = await hashPassword(newPassword);
  const { error: updateError } = await supabase.from("centers").update({ password_hash: hashedPassword, must_change_password: true }).eq("client_id", clientId);
  if (updateError) {
    return new Response(JSON.stringify({ success: false, message: updateError.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  await supabase.from("activity_logs").insert({
    client_id: clientId, action_type: "reset_password", entity_type: "center", entity_id: clientId,
    details: { by_admin: true }, performer_id: "admin_action", performer_role: "system", performer_name: "الإدارة",
  });

  return new Response(JSON.stringify({ success: true, message: `✅ تم إعادة تعيين كلمة المرور للسنتر ${clientId} بنجاح. سيُطلب منه تغييرها عند تسجيل الدخول.` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    const body = await req.json();
    const action = body.action;

    if (action === "assistant") return await handleAssistant(supabase, payload, body);
    if (action === "parent") return await handleParent(supabase, payload, body);
    if (action === "student") return await handleStudent(supabase, payload, body);
    if (action === "teacher") return await handleTeacher(supabase, payload, body);
    if (action === "center") return await handleCenter(supabase, payload, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
