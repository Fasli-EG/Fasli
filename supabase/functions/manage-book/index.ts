// supabase/functions/manage-book/index.ts
// ✅ دالة موحّدة تجمع add-book + update-book + delete-book بـ "action" parameter
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

export async function requireAssistantPermission(payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const supabase = await licenseCheckClient();
  const { data: assistant } = await supabase.from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) throw new AuthError("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس", 403);
}

async function getPerformerName(supabase: any, assistantId: any, assistantName: any, teacherId: string) {
  if (assistantId) return assistantName || "مساعد";
  const { data: t } = await supabase.from("teachers").select("name").eq("client_id", teacherId).maybeSingle();
  return t?.name || "مدرس";
}

async function handleAdd(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_books");
  await requireAssistantPermission(payload, "manage_books");

  const { teacherId, name, price, assistantId, assistantName } = body;
  if (!teacherId || !name || price === undefined) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (tokenClientId !== teacherId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بهذه العملية" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: book, error: insertError } = await supabase.from("books").insert({ teacher_id: teacherId, name, price: Number(price) }).select().single();
  if (insertError) {
    return new Response(JSON.stringify({ success: false, message: `فشل إضافة المذكرة: ${insertError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const performerId = assistantId || teacherId;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = await getPerformerName(supabase, assistantId, assistantName, teacherId);

  await supabase.from("activity_logs").insert({
    client_id: teacherId, teacher_id: teacherId, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "add_book", entity_type: "book", entity_id: String(book.id),
    details: { book_name: name, price: Number(price) },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  return new Response(JSON.stringify({ success: true, message: "تم إضافة المذكرة بنجاح", data: book }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleUpdate(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_books");
  await requireAssistantPermission(payload, "manage_books");

  const { bookId, name, price, assistantId, assistantName } = body;
  if (!bookId || !name || price === undefined) {
    return new Response(JSON.stringify({ success: false, message: "جميع الحقول مطلوبة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: oldBook, error: fetchError } = await supabase.from("books").select("*").eq("id", bookId).single();
  if (fetchError || !oldBook) {
    return new Response(JSON.stringify({ success: false, message: "المذكرة غير موجودة" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (oldBook.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه المذكرة ليست تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: updatedBook, error: updateError } = await supabase.from("books").update({ name, price: Number(price) }).eq("id", bookId).select().single();
  if (updateError) {
    return new Response(JSON.stringify({ success: false, message: `فشل تحديث المذكرة: ${updateError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const performerId = assistantId || oldBook.teacher_id;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = await getPerformerName(supabase, assistantId, assistantName, oldBook.teacher_id);
  const changes: any = {};
  if (name !== oldBook.name) changes.name = { old: oldBook.name, new: name };
  if (Number(price) !== oldBook.price) changes.price = { old: oldBook.price, new: Number(price) };

  await supabase.from("activity_logs").insert({
    client_id: oldBook.teacher_id, teacher_id: oldBook.teacher_id, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "edit_book", entity_type: "book", entity_id: String(bookId),
    details: { book_name: oldBook.name, changes },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  return new Response(JSON.stringify({ success: true, message: "تم تحديث المذكرة بنجاح", data: updatedBook }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleDelete(supabase: any, payload: TokenPayload, body: any) {
  const tokenClientId = payload.clientId || payload.teacherId;
  await requireTeacherPlanPermission(tokenClientId, "can_manage_books");
  await requireAssistantPermission(payload, "manage_books");

  const { bookId, assistantId, assistantName } = body;
  if (!bookId) {
    return new Response(JSON.stringify({ success: false, message: "معرف المذكرة مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: book, error: fetchError } = await supabase.from("books").select("*").eq("id", bookId).single();
  if (fetchError || !book) {
    return new Response(JSON.stringify({ success: false, message: "المذكرة غير موجودة" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (book.teacher_id !== tokenClientId) {
    return new Response(JSON.stringify({ success: false, message: "⛔ هذه المذكرة ليست تابعاً لك" }),
      { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { error: deleteError } = await supabase.from("books").delete().eq("id", bookId);
  if (deleteError) {
    return new Response(JSON.stringify({ success: false, message: `فشل حذف المذكرة: ${deleteError.message}` }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const performerId = assistantId || book.teacher_id;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = await getPerformerName(supabase, assistantId, assistantName, book.teacher_id);

  await supabase.from("activity_logs").insert({
    client_id: book.teacher_id, teacher_id: book.teacher_id, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "delete_book", entity_type: "book", entity_id: String(bookId),
    details: { book_name: book.name, price: book.price },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  return new Response(JSON.stringify({ success: true, message: "تم حذف المذكرة بنجاح" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

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
    console.error("❌ خطأ في manage-book:", error);
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي في الخادم";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
