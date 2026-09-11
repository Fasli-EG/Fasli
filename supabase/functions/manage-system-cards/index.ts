// supabase/functions/manage-system-cards/index.ts
// ✅ دالة موحّدة تجمع revoke-system-card + toggle-card-active + return-card-to-stock + assign-cards-to-teacher
// action: revoke | toggleActive | returnToStock | assign
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, TokenPayload, AuthError, verifyToken } from "../_shared/auth.ts";

function requireAdmin(payload: TokenPayload) {
  if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
    throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
  }
}

/**
 * ✅ (تصحيح باج) صاحب سنتر أو الأدمن الرئيسي — لعمليات تخصيص/عرض الكروت المسموحة للسنتر.
 * كانت بتفحص role === "center_owner" اللي مش قيمة حقيقية أبداً — بعد إلغاء حساب السنتر
 * المنفصل، صاحب السنتر بيسجّل دخول بـ role: "teacher" عادي (نفس منطق detectRole في login)،
 * وبيتفرّق عن مدرس عادي بوجود صف ليه في جدول centers (بنفس الـ client_id) — بالظبط
 * نفس النمط المستخدم في manage-center.ts. ownCenterId/requireOwnCenterTeacher تحت أصلاً
 * بيرفضوا (404 "السنتر غير موجود") أي مدرس عادي مالوش صف في centers، فده الحد الحقيقي للصلاحية.
 */
function requireAdminOrCenterOwner(payload: TokenPayload): boolean {
  if (payload.role === "teacher" && payload.clientId === "master_admin") return false; // false = أدمن كامل الصلاحية
  if (payload.role === "teacher" && payload.clientId) return true; // true = يُفترض صاحب سنتر — هيتأكد فعليًا من جدول centers تحت
  throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
}

/** ✅ يتأكد إن teacherId المطلوب فعلاً تابع لسنتر صاحب الحساب، ويرجّع centerId بتاعه */
async function requireOwnCenterTeacher(supabase: any, payload: TokenPayload, teacherId: string): Promise<number> {
  const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
  if (!center) throw new AuthError("السنتر غير موجود", 404);
  const { data: teacher } = await supabase.from("teachers").select("center_id").eq("client_id", teacherId).maybeSingle();
  if (!teacher || teacher.center_id !== center.id) throw new AuthError("⛔ هذا المدرس ليس تابعاً لسنترك", 403);
  return center.id;
}

/** ✅ يرجّع centerId بتاع صاحب السنتر الحالي */
async function ownCenterId(supabase: any, payload: TokenPayload): Promise<number> {
  const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
  if (!center) throw new AuthError("السنتر غير موجود", 404);
  return center.id;
}

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

function extractCardIds(body: any): number[] {
  return Array.isArray(body.cardIds) ? body.cardIds : (body.cardId ? [body.cardId] : []);
}

async function handleRevoke(supabase: any, body: any) {
  const cardIds = extractCardIds(body);
  if (cardIds.length === 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تحدد كارت واحد على الأقل" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { error, count } = await supabase.from("system_cards").delete({ count: "exact" }).in("id", cardIds);
  if (error) {
    console.error("❌ فشل إلغاء الكروت:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: `✅ تم إلغاء ${count} كارت بنجاح` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleToggleActive(supabase: any, body: any) {
  const { isActive } = body;
  const cardIds = extractCardIds(body);
  if (cardIds.length === 0 || typeof isActive !== "boolean") {
    return new Response(JSON.stringify({ success: false, message: "⚠️ cardId/cardIds و isActive مطلوبين" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { error, count } = await supabase.from("system_cards").update({ is_active: isActive }, { count: "exact" }).in("id", cardIds);
  if (error) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: isActive ? `✅ تم تفعيل ${count} كارت` : `✅ تم تعطيل ${count} كارت` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleReturnToStock(supabase: any, body: any) {
  const cardIds = extractCardIds(body);
  if (cardIds.length === 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تحدد كارت واحد على الأقل" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { error, count } = await supabase.from("system_cards")
    .update({ status: "in_stock", teacher_id: null, student_uid: null, is_active: false, assigned_at: null, linked_at: null }, { count: "exact" })
    .in("id", cardIds);
  if (error) {
    console.error("❌ فشل إرجاع الكروت للمخزون:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: `✅ تم إرجاع ${count} كارت للمخزون` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ✅ صاحب سنتر بيوزّع كارت من "بركة" سنتره (اتخصص للسنتر ككل من الأدمن مسبقاً) على مدرس بعينه تابع له.
// بيختلف عن تخصيص الأدمن العادي: هنا الكارت أصلاً status='assigned' + center_id مضبوط، مش 'in_stock'.
async function handleCenterAssignToTeacher(supabase: any, payload: TokenPayload, body: any) {
  const { cardIds, teacherId } = body;
  if (!teacherId || !Array.isArray(cardIds) || cardIds.length === 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تحدد مدرس وقائمة cardIds" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const centerId = await requireOwnCenterTeacher(supabase, payload, teacherId);
  const { error, count } = await supabase.from("system_cards")
    .update({ teacher_id: teacherId, assigned_at: new Date().toISOString() }, { count: "exact" })
    .in("id", cardIds).eq("center_id", centerId).eq("status", "assigned").is("teacher_id", null);
  if (error) {
    console.error("❌ فشل توزيع كروت السنتر على المدرس:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  if (!count) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ مفيش كروت من دول متاحة في بركة السنتر (لازم تكون غير موزّعة على مدرس بالفعل)" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: `✅ تم توزيع ${count} كارت على المدرس` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ✅ صاحب سنتر يرجّع كارت موزّع على مدرس تابع له لبركة السنتر المشتركة تاني (من غير ما يخرج من السنتر نفسه)
async function handleCenterUnassignFromTeacher(supabase: any, payload: TokenPayload, body: any) {
  const cardIds = extractCardIds(body);
  if (cardIds.length === 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تحدد كارت واحد على الأقل" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const centerId = await ownCenterId(supabase, payload);
  const { error, count } = await supabase.from("system_cards")
    .update({ teacher_id: null }, { count: "exact" })
    .in("id", cardIds).eq("center_id", centerId).eq("status", "assigned");
  if (error) {
    console.error("❌ فشل إرجاع الكروت لبركة السنتر:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: `✅ تم إرجاع ${count} كارت لبركة السنتر المشتركة` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ✅ صاحب سنتر يشوف كل كروت سنتره (سواء في البركة المشتركة أو موزّعة على مدرسين بعينهم)
async function handleListCenterCards(supabase: any, payload: TokenPayload) {
  const centerId = await ownCenterId(supabase, payload);
  const { data: cards, error } = await supabase
    .from("system_cards")
    .select("id, card_uid, status, teacher_id, student_uid, is_active, scanned_at, assigned_at, linked_at")
    .eq("center_id", centerId)
    .order("scanned_at", { ascending: false });
  if (error) {
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const studentUids = [...new Set((cards || []).map((c: any) => c.student_uid).filter(Boolean))];
  const teacherIds = [...new Set((cards || []).map((c: any) => c.teacher_id).filter(Boolean))];
  const [{ data: students }, { data: teachers }] = await Promise.all([
    studentUids.length > 0 ? supabase.from("students").select("uid, name").in("uid", studentUids) : Promise.resolve({ data: [] }),
    teacherIds.length > 0 ? supabase.from("teachers").select("client_id, name").in("client_id", teacherIds) : Promise.resolve({ data: [] }),
  ]);
  const studentNames: Record<string, string> = {};
  (students || []).forEach((s: any) => { studentNames[s.uid] = s.name; });
  const teacherNames: Record<string, string> = {};
  (teachers || []).forEach((t: any) => { teacherNames[t.client_id] = t.name; });

  const result = (cards || []).map((c: any) => ({
    id: c.id, cardUid: c.card_uid, status: c.status, isActive: c.is_active,
    teacherId: c.teacher_id, teacherName: c.teacher_id ? (teacherNames[c.teacher_id] || c.teacher_id) : null,
    studentUid: c.student_uid, studentName: c.student_uid ? (studentNames[c.student_uid] || "طالب محذوف") : null,
    scannedAt: c.scanned_at, assignedAt: c.assigned_at, linkedAt: c.linked_at,
    inPool: c.teacher_id === null,
  }));
  return new Response(JSON.stringify({ success: true, data: result }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

async function handleAssign(supabase: any, body: any) {
  const { cardIds, teacherId, centerId } = body;
  if ((!teacherId && !centerId) || !Array.isArray(cardIds) || cardIds.length === 0) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تحدد مدرس أو سنتر، وقائمة cardIds" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ التخصيص لسنتر كامل — الكارت بيبقى متاح لكل المدرسين التابعين للسنتر ده، مش مدرس واحد بس
  if (centerId) {
    const { data: center } = await supabase.from("centers").select("id").eq("id", centerId).maybeSingle();
    if (!center) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ السنتر غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { error, count } = await supabase.from("system_cards")
      .update({ center_id: centerId, teacher_id: null, status: "assigned", assigned_at: new Date().toISOString() }, { count: "exact" })
      .in("id", cardIds).eq("status", "in_stock");
    if (error) {
      console.error("❌ فشل تخصيص الكروت للسنتر:", error);
      return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, message: `✅ تم تخصيص ${count} كارت للسنتر (متاح لكل مدرسيه)` }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const { data: teacher } = await supabase.from("teachers").select("client_id").eq("client_id", teacherId).maybeSingle();
  if (!teacher) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ المدرس غير موجود" }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { error, count } = await supabase.from("system_cards")
    .update({ teacher_id: teacherId, status: "assigned", assigned_at: new Date().toISOString() }, { count: "exact" })
    .in("id", cardIds).eq("status", "in_stock");
  if (error) {
    console.error("❌ فشل تخصيص الكروت:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: `✅ تم تخصيص ${count} كارت للمدرس` }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    // ✅ isCenterOwner = true يعني الحساب سنتر (مقيّد بسنتره بس) — false يعني أدمن رئيسي بصلاحية كاملة
    const isCenterOwner = requireAdminOrCenterOwner(payload);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    const body = await req.json();
    const action = body.action;

    // ✅ أفعال صاحب السنتر — مقيّدة بسنتره فقط، ومحظورة على أي حد تاني حتى لو أدمن
    if (isCenterOwner) {
      if (action === "listCenterCards") return await handleListCenterCards(supabase, payload);
      if (action === "assign") return await handleCenterAssignToTeacher(supabase, payload, body);
      if (action === "unassignFromTeacher") return await handleCenterUnassignFromTeacher(supabase, payload, body);
      return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة أو غير متاحة لحساب السنتر" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "revoke") return await handleRevoke(supabase, body);
    if (action === "toggleActive") return await handleToggleActive(supabase, body);
    if (action === "returnToStock") return await handleReturnToStock(supabase, body);
    if (action === "assign") return await handleAssign(supabase, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
