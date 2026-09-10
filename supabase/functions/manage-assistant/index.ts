// supabase/functions/manage-assistant/index.ts
// ✅ دالة موحّدة تجمع add-assistant + update-assistant + delete-assistant بـ "action" parameter
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
  "Access-Control-Max-Age": "86400",
};

export interface TokenPayload {
  sub: string; clientId?: string; teacherId?: string; role: "teacher" | "assistant" | "parent"; name: string; exp: number;
}

export class AuthError extends Error {
  status: number; code?: string;
  constructor(message: string, status = 401, code?: string) { super(message); this.status = status; this.code = code; }
}

async function getKey() {
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) throw new Error("⚠️ JWT_SECRET غير مضبوط في متغيرات البيئة");
  return await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
}

async function licenseCheckClient() {
  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2.38.4");
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

async function checkLicenseActive(teacherClientId: string): Promise<{ active: boolean; reason?: string }> {
  if (teacherClientId === "master_admin") return { active: true };
  const supabase = await licenseCheckClient();
  const { data: teacher, error } = await supabase.from("teachers").select("is_active, expiry_date").eq("client_id", teacherClientId).maybeSingle();
  if (error || !teacher) return { active: false, reason: "الحساب غير موجود" };
  if (teacher.is_active === false) return { active: false, reason: "الحساب معطّل" };
  if (teacher.expiry_date) {
    const todayCLA = new Date().toISOString().split("T")[0];
    if (teacher.expiry_date < todayCLA) return { active: false, reason: "انتهت صلاحية الترخيص" };
  }
  return { active: true };
}

export async function verifyToken(req: Request): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) throw new AuthError("⚠️ التوكن مطلوب", 401);
  const token = authHeader.substring(7);
  const key = await getKey();
  let payload: TokenPayload;
  try { payload = (await verify(token, key, "HS256")) as unknown as TokenPayload; }
  catch (_e) { throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401); }
  if (payload.role === "teacher" || payload.role === "assistant") {
    const ownerId = payload.clientId || payload.teacherId;
    if (ownerId) {
      const license = await checkLicenseActive(ownerId);
      if (!license.active) throw new AuthError(`⛔ ${license.reason || "انتهت صلاحية الترخيص"} — يرجى التواصل مع الإدارة`, 402, "LICENSE_EXPIRED");
    }
  }
  return payload;
}

export function ownerClientId(payload: TokenPayload): string {
  const id = payload.clientId || payload.teacherId;
  if (!id) throw new AuthError("⚠️ التوكن لا يحتوي على clientId", 401);
  return id;
}

export function requireOwnClientId(payload: TokenPayload, requestedClientId?: string | null) {
  const tokenClientId = ownerClientId(payload);
  if (requestedClientId && requestedClientId !== tokenClientId) throw new AuthError("⛔ غير مصرح لك بمشاهدة بيانات هذا المدرس", 403);
  return tokenClientId;
}

export function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

export async function requireTeacherPlanPermission(clientId: string, permKey: string): Promise<void> {
  if (clientId === "master_admin") return;
  const supabase = await licenseCheckClient();
  const { data: teacher } = await supabase.from("teachers").select("permissions").eq("client_id", clientId).maybeSingle();
  const perms = teacher?.permissions || {};
  if (perms[permKey] === false) throw new AuthError("⛔ هذه الميزة غير متاحة في باقتك الحالية، تواصل مع الإدارة لتفعيلها", 403, "PLAN_RESTRICTED");
}

/**
 * ✅ Batch 21: يتأكد إن المساعد عنده صلاحية محددة منحها له المدرس. لا تأثير على المدرس نفسه
 * (دايماً مسموح له). دي أول مرة الدالة دي تتعرّف في manage-assistant — الملف ده كان دايماً
 * بيرفض أي مساعد بشكل قاطع (role check مش permission check)، فاحتجنا نعرّفها هنا زي باقي
 * الدوال اللي بتستخدمها.
 */
async function requireAssistantPermission(payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const supabase = await licenseCheckClient();
  const { data: assistant } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) throw new AuthError("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس", 403);
}

/**
 * ✅ Batch 21: حماية ضد تصعيد الصلاحيات — مساعد معاه "إضافة/تعديل فريق عمل" ميقدرش يمنح مساعد
 * (نفسه أو حد تاني) صلاحية هو نفسه مش حاصل عليها من المدرس. من غير الحماية دي، مساعد كان
 * هيقدر يمنح نفسه أي صلاحية في النظام (زي "حذف طلاب" أو "الدخل الشهري") لمجرد إن معاه صلاحية
 * تعديل فريق العمل. المدرس نفسه معفى من الفحص ده (بيقدر يمنح أي صلاحية زي ما كان دايماً).
 */
async function assertNoPermissionEscalation(payload: TokenPayload, requestedPermissions: Record<string, unknown> | undefined): Promise<void> {
  if (payload.role !== "assistant" || !requestedPermissions) return;
  const supabase = await licenseCheckClient();
  const { data: caller } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const callerPerms = caller?.permissions || {};
  const escalated = Object.keys(requestedPermissions).filter(
    (key) => requestedPermissions[key] === true && callerPerms[key] !== true
  );
  if (escalated.length > 0) {
    throw new AuthError(`⛔ لا يمكنك منح صلاحية لا تملكها أنت نفسك (${escalated.join("، ")})`, 403);
  }
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

async function handleAdd(supabase: any, payload: TokenPayload, body: any) {
  // ✅ Batch 21: بدل الرفض القاطع لأي مساعد، بقى مربوط بصلاحية "إضافة فريق عمل" (add_staff) —
  // زي ما طلب الحساب: المساعد يقدر يضيف مساعدين تانيين لو المدرس منحه الصلاحية دي، مع حماية
  // ضد تصعيد الصلاحيات (assertNoPermissionEscalation تحت) عشان ميقدرش يمنح صلاحية مش معاه هو
  await requireAssistantPermission(payload, "add_staff");
  const { teacherId, username, name, permissions } = body;
  if (!teacherId || !username || !name) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const finalTeacherId = requireOwnClientId(payload, teacherId);
  await requireTeacherPlanPermission(finalTeacherId, "can_manage_assistants");
  await assertNoPermissionEscalation(payload, permissions);

  const { data: teacher, error: teacherError } = await supabase.from("teachers").select("client_id, permissions").eq("client_id", finalTeacherId).maybeSingle();
  if (teacherError || !teacher) {
    return new Response(JSON.stringify({ success: false, message: "❌ المدرس غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const teacherPerms = teacher.permissions || {};
  if (teacherPerms.can_manage_assistants === false) {
    return new Response(JSON.stringify({ success: false, message: "⛔ باقتك الحالية لا تسمح بإضافة مساعدين، تواصل مع الإدارة" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ عدد المساعدين بقى غير محدود (Aug 2026) — العمود max_assistants لسه موجود في الجدول لأسباب توافق تاريخية بس مش بيتقرأ أو يتكتب هنا خالص

  const { data: existing } = await supabase.from("assistants").select("id").eq("username", username).maybeSingle();
  if (existing) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ اسم المستخدم "${username}" مأخوذ بالفعل` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let tempPassword = "";
  for (let i = 0; i < 8; i++) tempPassword += chars.charAt(Math.floor(Math.random() * chars.length));
  const hashedPassword = await hashPassword(tempPassword);

  const { data, error } = await supabase.from("assistants").insert({
    teacher_id: finalTeacherId, username, name, password_hash: hashedPassword, must_change_password: true, is_active: true,
    permissions: permissions || {
      view_students: true, add_students: false, edit_students: false, delete_students: false,
      record_grades: false, record_payments: false, view_reports: false,
      manage_attendance: false, manage_groups: false, reset_parent_password: false,
      manage_books: false, send_messages: false, manage_conversations: false, manage_exams: false,
      view_financial: false, view_activity_log: false, view_staff: false,
      add_staff: false, edit_staff: false, delete_staff: false,
    }
  }).select();

  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ Batch 21: لو منفّذ الإجراء مساعد (add_staff)، نسجّله كمنفّذ فعلي (assistant_id = هو نفسه،
  // performer_role "assistant") بدل ما يتسجّل زي ما لو المدرس نفسه هو اللي عمله — عشان سجل
  // النشاطات يكون دقيق (assistant_id هنا معناها "المساعد المنفّذ"، زي باقي دوال النظام مثل
  // manage-payment، مش "المساعد المضاف" اللي كانت الكود القديم بيسجّله غلط)
  const isAssistantActor = payload.role === "assistant";
  await supabase.from("activity_logs").insert({
    teacher_id: finalTeacherId, assistant_id: isAssistantActor ? payload.sub : null, action_type: "add_assistant",
    entity_type: "assistant", entity_id: data[0]?.id?.toString() || null,
    details: { username, name, permissions: permissions || {} },
    performer_id: isAssistantActor ? payload.sub : finalTeacherId,
    performer_role: isAssistantActor ? "assistant" : "teacher",
    performer_name: payload.name || (isAssistantActor ? "مساعد" : "مدرس"),
  });

  return new Response(JSON.stringify({ success: true, message: `✅ تم إضافة المساعد "${name}" بنجاح`, data: { ...data[0], tempPassword } }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  // ✅ Batch 21: مربوط بصلاحية "تعديل فريق عمل" (edit_staff) بدل الرفض القاطع، مع حماية تصعيد
  // الصلاحيات تحت
  await requireAssistantPermission(payload, "edit_staff");
  const tokenClientId = ownerClientId(payload);
  await requireTeacherPlanPermission(tokenClientId, "can_manage_assistants");
  const { assistantId, name, isActive, permissions } = body;
  await assertNoPermissionEscalation(payload, permissions);

  if (!assistantId || !name) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: oldData, error: fetchError } = await supabase.from("assistants").select("name, is_active, permissions, teacher_id, username").eq("id", assistantId).maybeSingle();
  if (fetchError || !oldData) {
    return new Response(JSON.stringify({ success: false, message: "❌ المساعد غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldData.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بتعديل هذا المساعد" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  // ✅ Batch 23 (بند 1): مساعد معاه صلاحية تعديل فريق العمل ميقدرش يعدّل حسابه هو نفسه بيها —
  // ده بيمنعه يفعّل/يعطّل حسابه أو يغيّر صلاحياته هو بنفسه (assertNoPermissionEscalation بتمنع
  // منح صلاحية أعلى مما هو حاصل عليها، لكن مكانش فيه حماية ضد تعديل صلاحياته الحالية بأي شكل تاني)
  if (payload.role === "assistant" && String(payload.sub) === String(assistantId)) {
    return new Response(JSON.stringify({ success: false, message: "⛔ لا يمكنك تعديل حسابك أنت بنفسك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const updateData = { name, is_active: isActive !== undefined ? isActive : true, permissions: permissions || oldData.permissions };
  const { error } = await supabase.from("assistants").update(updateData).eq("id", assistantId);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const changes: any = {};
  if (oldData.name !== name) changes.name = { old: oldData.name, new: name };
  if (oldData.is_active !== isActive) changes.is_active = { old: oldData.is_active, new: isActive };
  if (JSON.stringify(oldData.permissions) !== JSON.stringify(permissions)) changes.permissions = { old: oldData.permissions, new: permissions };

  // ✅ Batch 21: تسجيل المنفّذ الفعلي (مساعد أو مدرس) بدل ما يتسجّل زي ما لو المدرس دايماً هو المنفّذ
  const isAssistantActor2 = payload.role === "assistant";
  await supabase.from("activity_logs").insert({
    teacher_id: oldData.teacher_id, assistant_id: isAssistantActor2 ? payload.sub : null, action_type: "update_assistant",
    entity_type: "assistant", entity_id: assistantId.toString(),
    details: { username: oldData.username || "غير معروف", changes },
    performer_id: isAssistantActor2 ? payload.sub : oldData.teacher_id,
    performer_role: isAssistantActor2 ? "assistant" : "teacher",
    performer_name: payload.name || (isAssistantActor2 ? "مساعد" : "مدرس"),
  });

  return new Response(JSON.stringify({ success: true, message: "✅ تم تحديث بيانات المساعد" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  // ✅ Batch 21: مربوط بصلاحية "حذف فريق عمل" (delete_staff) بدل الرفض القاطع
  await requireAssistantPermission(payload, "delete_staff");
  const tokenClientId = ownerClientId(payload);
  await requireTeacherPlanPermission(tokenClientId, "can_manage_assistants");
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
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بحذف هذا المساعد" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  // ✅ Batch 23 (بند 1): مساعد معاه صلاحية حذف فريق العمل ميقدرش يحذف حسابه هو نفسه بيها
  if (payload.role === "assistant" && String(payload.sub) === String(assistantId)) {
    return new Response(JSON.stringify({ success: false, message: "⛔ لا يمكنك حذف حسابك أنت بنفسك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error } = await supabase.from("assistants").delete().eq("id", assistantId);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ Batch 21: تسجيل المنفّذ الفعلي (مساعد أو مدرس) بدل ما يتسجّل زي ما لو المدرس دايماً هو المنفّذ
  const isAssistantActor3 = payload.role === "assistant";
  await supabase.from("activity_logs").insert({
    teacher_id: assistant.teacher_id, assistant_id: isAssistantActor3 ? payload.sub : null, action_type: "delete_assistant",
    entity_type: "assistant", entity_id: assistantId.toString(),
    details: { username: assistant.username, name: assistant.name },
    performer_id: isAssistantActor3 ? payload.sub : assistant.teacher_id,
    performer_role: isAssistantActor3 ? "assistant" : "teacher",
    performer_name: payload.name || (isAssistantActor3 ? "مساعد" : "مدرس"),
  });

  return new Response(JSON.stringify({ success: true, message: "✅ تم حذف المساعد" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الطريقة غير مسموحة" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  try {
    const payload = await verifyToken(req);
    const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
    const supabase = createClient(supabaseUrl, supabaseKey);

    let body: any;
    try { body = await req.json(); }
    catch (_e) {
      return new Response(JSON.stringify({ success: false, message: "الطلب يجب أن يحتوي على JSON صالح" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const action = body.action;
    if (action === "add") return await handleAdd(supabase, payload, body);
    if (action === "update") return await handleUpdate(supabase, payload, body);
    if (action === "delete") return await handleDelete(supabase, payload, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
