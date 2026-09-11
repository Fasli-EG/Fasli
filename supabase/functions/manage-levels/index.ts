// supabase/functions/manage-levels/index.ts
// ✅ Aug 2026 (تعديل جوهري): دالة جديدة — إدارة "المراحل الدراسية" (زي "الصف الأول الثانوي")
// اللي كل مدرس (سنتر أو مش سنتر) يقدر يعرّفها، يربطها بمجموعاته، ورابط التسجيل العام
// يستخدمها عشان ولي الأمر يختار مرحلة دراسية بدل ما يختار/يكتب اسم مجموعة مباشرة —
// المدرس أو المساعد بيحدد المجموعة الفعلية وقت الموافقة على الطلب.
// ✅ الفرق الأساسي عن manage-instructor-names: الميزة دي مش مقصورة على حسابات السنتر —
// أي مدرس عنده صلاحية إدارة المجموعات (can_manage_groups / manage_groups) يقدر يستخدمها،
// فبنستخدم نفس نمط الصلاحيات اللي في manage-group بدل requireIsCenter.
// نفس شكل CRUD بالظبط (list/add/update/delete) — manage-instructor-names هو القالب الأصلي لنفس
// الفكرة ("كيان مسمّى صغير مربوط بحساب المدرس")، فدالة جديدة هنا متسقة مع سابقة موجودة فعلاً،
// مش مخالفة لقاعدة "تجنب إنشاء دوال جديدة".
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

export const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
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

export function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ✅ نفس صلاحية إدارة المجموعات المستخدمة في manage-group — مش مقصورة على حسابات السنتر
export async function requireTeacherPlanPermission(clientId: string, permKey: string): Promise<void> {
  if (clientId === "master_admin") return;
  const supabase = await licenseCheckClient();
  const { data: teacher } = await supabase.from("teachers").select("permissions").eq("client_id", clientId).maybeSingle();
  const perms = teacher?.permissions || {};
  if (perms[permKey] === false) throw new AuthError("⛔ هذه الميزة غير متاحة في باقتك الحالية، تواصل مع الإدارة لتفعيلها", 403, "PLAN_RESTRICTED");
}

export async function requireAssistantPermission(payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const supabase = await licenseCheckClient();
  const { data: assistant } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) throw new AuthError("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس", 403);
}

function jsonRes(body: any, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleList(supabase: any, payload: TokenPayload) {
  const clientId = ownerClientId(payload);
  await requireTeacherPlanPermission(clientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");
  const { data, error } = await supabase.from("education_levels").select("*").eq("teacher_id", clientId).order("created_at", { ascending: true });
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, data: data || [] });
}

async function handleAdd(supabase: any, payload: TokenPayload, body: any) {
  const clientId = ownerClientId(payload);
  await requireTeacherPlanPermission(clientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");
  const name = (body.name || "").trim();
  if (!name) return jsonRes({ success: false, message: "⚠️ اسم المرحلة الدراسية مطلوب" }, 400);

  const { data: existing } = await supabase.from("education_levels").select("id").eq("teacher_id", clientId).eq("name", name).maybeSingle();
  if (existing) return jsonRes({ success: false, message: `⚠️ المرحلة "${name}" موجودة بالفعل` }, 400);

  const { data, error } = await supabase.from("education_levels").insert({ teacher_id: clientId, name, is_active: true }).select();
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, message: `✅ تم إضافة "${name}"`, data: data[0] });
}

async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  const clientId = ownerClientId(payload);
  await requireTeacherPlanPermission(clientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");
  const { id, name, isActive } = body;
  if (!id) return jsonRes({ success: false, message: "⚠️ id مطلوب" }, 400);

  const { data: row } = await supabase.from("education_levels").select("teacher_id").eq("id", id).maybeSingle();
  if (!row) return jsonRes({ success: false, message: "❌ المرحلة غير موجودة" }, 404);
  if (row.teacher_id !== clientId) return jsonRes({ success: false, message: "⛔ غير مصرح لك بتعديل هذه المرحلة" }, 403);

  const updateData: any = {};
  if (name !== undefined && name !== null && String(name).trim()) updateData.name = String(name).trim();
  if (isActive !== undefined) updateData.is_active = isActive;

  const { error } = await supabase.from("education_levels").update(updateData).eq("id", id);
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, message: "✅ تم التحديث" });
}

async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  const clientId = ownerClientId(payload);
  await requireTeacherPlanPermission(clientId, "can_manage_groups");
  await requireAssistantPermission(payload, "manage_groups");
  const { id } = body;
  if (!id) return jsonRes({ success: false, message: "⚠️ id مطلوب" }, 400);

  const { data: row } = await supabase.from("education_levels").select("teacher_id, name").eq("id", id).maybeSingle();
  if (!row) return jsonRes({ success: false, message: "❌ المرحلة غير موجودة" }, 404);
  if (row.teacher_id !== clientId) return jsonRes({ success: false, message: "⛔ غير مصرح لك بحذف هذه المرحلة" }, 403);

  // ✅ الحذف بيشيل المرحلة بس — level_id في groups/registration_requests بيرجع NULL تلقائياً
  // (ON DELETE SET NULL في الـ migration)، فمفيش بيانات تاريخية بتتفقد
  const { error } = await supabase.from("education_levels").delete().eq("id", id);
  if (error) return jsonRes({ success: false, message: error.message }, 500);
  return jsonRes({ success: true, message: `✅ تم حذف "${row.name}"` });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  if (req.method !== "POST") {
    return jsonRes({ success: false, message: "⚠️ الطريقة غير مسموحة" }, 405);
  }

  try {
    const payload = await verifyToken(req);
    const supabaseUrl = Deno.env.get("SUPABASE_URL") || "";
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
    const supabase = createClient(supabaseUrl, supabaseKey);

    let body: any = {};
    try { body = await req.json(); }
    catch (_e) {
      return jsonRes({ success: false, message: "الطلب يجب أن يحتوي على JSON صالح" }, 400);
    }

    const action = body.action;
    if (action === "list") return await handleList(supabase, payload);
    if (action === "add") return await handleAdd(supabase, payload, body);
    if (action === "update") return await handleUpdate(supabase, payload, body);
    if (action === "delete") return await handleDelete(supabase, payload, body);

    return jsonRes({ success: false, message: "⚠️ action غير معروفة — لازم تكون list أو add أو update أو delete" }, 400);
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return jsonRes({ success: false, message }, 500);
  }
});
