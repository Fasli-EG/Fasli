// supabase/functions/get-student-full-profile/index.ts
// ✅ دالة موحّدة تجمع get-student-info + get-student-grades + get-student-payments +
// get-student-attendance + get-student-books في استجابة واحدة — بدل 5 طلبات شبكة منفصلة، طلب واحد بس
// (تحسين أداء حقيقي، مش بس توفير في عدد الدوال — الصلاحية بتتفحص مرة واحدة، والبيانات بتتجاب بالتوازي)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
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

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const { studentUid, parentPhone } = await req.json();
    if (!studentUid) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: student, error: studentError } = await supabase
      .from("students").select("*, teachers!inner(name, conversations_enabled)").eq("uid", studentUid).maybeSingle();
    if (studentError || !student) {
      return new Response(JSON.stringify({ success: false, message: "الطالب غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ فحص صلاحية موحّد لكل الأنواع الثلاثة — بيتفحص مرة واحدة بس بدل 5 مرات منفصلة
    if (payload.role === "parent") {
      if (!parentPhone) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (payload.phone !== parentPhone || student.parent_phone !== parentPhone) {
        return new Response(JSON.stringify({ success: false, message: "غير مصرح لك بمشاهدة هذا الطالب" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    } else if (payload.role === "student") {
      if (payload.sub !== studentUid) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بمشاهدة بيانات طالب تاني" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    } else if (payload.role === "teacher" || payload.role === "assistant") {
      const tokenClientId = payload.clientId || payload.teacherId;
      if (student.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ هذا الطالب ليس تابعاً لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    } else {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ كل بيانات الطالب بتتجاب بالتوازي في نفس الدالة — طلب شبكة واحد بس بدل 4 منفصلين
    const [gradesRes, paymentsRes, attendanceRes, bookPaymentsRes, groupLinksRes] = await Promise.all([
      supabase.from("grades").select("*").eq("student_uid", studentUid).order("created_at", { ascending: false }),
      supabase.from("payments").select("*").eq("student_uid", studentUid).order("created_at", { ascending: false }),
      supabase.from("attendance").select("*").eq("student_uid", studentUid).order("date", { ascending: false }),
      supabase.from("book_payments").select("id, amount, paid_at, group_name, book_id, books:book_id (id, name, price, file_url)").eq("student_uid", studentUid),
      supabase.from("student_group_links").select("group_name").eq("student_uid", studentUid),
    ]);

    // ✅ (طلب) لازم نرجّع كل المجموعات اللي الطالب فيها (الأساسية + المربوطة) عشان صفحة تفاصيل
    // الطالب تقدر تعرض فلتر مجموعات كامل، حتى لو مجموعة معينة لسه معملهاش أي درجات/حضور/مدفوعات
    const allGroups = Array.from(new Set([
      student.group_name,
      ...((groupLinksRes.data || []).map((l: any) => l.group_name)),
    ].filter(Boolean)));

    // ✅ (طلب) group_name بيتضاف هنا عشان صفحات تفاصيل الطالب (مدرس/طالب/ولي أمر) تقدر تفصل
    // بيانات المذكرات حسب المجموعة برضه، زي الدرجات والحضور والمدفوعات — لطالب مرتبط بأكتر من مجموعة
    const books = (bookPaymentsRes.data || []).map((item: any) => ({
      id: item.id, book_name: item.books?.name || "مذكرة غير معروفة", price: item.books?.price || 0,
      amount: item.amount || 0, paid_at: item.paid_at, file_url: item.books?.file_url || null,
      group_name: item.group_name || null,
      status: item.amount >= (item.books?.price || 0) ? "مدفوع بالكامل" : "دفعة جزئية",
    }));

    return new Response(JSON.stringify({
      success: true,
      data: {
        info: { uid: student.uid, name: student.name, phone: student.phone, group_name: student.group_name, groups: allGroups, teacher_name: student.teachers?.name || "غير محدد", conversations_enabled: student.teachers?.conversations_enabled !== false },
        grades: gradesRes.data || [],
        payments: paymentsRes.data || [],
        attendance: attendanceRes.data || [],
        books,
      },
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في get-student-full-profile:", error);
    const message = error instanceof Error ? error.message : "خطأ غير معروف";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
