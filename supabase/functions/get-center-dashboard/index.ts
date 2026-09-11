// supabase/functions/get-center-dashboard/index.ts
// ✅ لوحة تحكم صاحب السنتر — إجماليات دايماً، وتفاصيل إضافية بس لو المدرس سمح بمشاركتها
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
};

interface TokenPayload { sub: string; clientId?: string; role: string; name: string; }

async function verifyToken(req: Request): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) throw new Error("⚠️ التوكن مطلوب");
  const token = authHeader.substring(7);
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) throw new Error("⚠️ JWT_SECRET غير مضبوط");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return (await verify(token, key, "HS256")) as unknown as TokenPayload;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    if (payload.role !== "center_owner") {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const { data: center } = await supabase.from("centers").select("*").eq("client_id", payload.clientId).maybeSingle();
    if (!center) {
      return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: teachers } = await supabase
      .from("teachers").select("client_id, name, student_count, is_active, expiry_date, center_sharing_permissions")
      .eq("center_id", center.id);

    if (!teachers || teachers.length === 0) {
      return new Response(JSON.stringify({ success: true, data: { center, teachers: [], summary: { totalTeachers: 0, totalStudents: 0, totalRevenueThisMonth: 0 } } }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const teacherIds = teachers.map((t: any) => t.client_id);
    const now = new Date();
    const rangeStart = new Date(Date.UTC(now.getFullYear(), now.getMonth(), 1)).toISOString();
    const rangeEnd = new Date(Date.UTC(now.getFullYear(), now.getMonth() + 1, 1)).toISOString();

    const { data: payments } = await supabase.from("payments").select("teacher_id, amount").in("teacher_id", teacherIds).gte("created_at", rangeStart).lt("created_at", rangeEnd);
    const { data: bookPayments } = await supabase.from("book_payments").select("teacher_id, amount").in("teacher_id", teacherIds).gte("paid_at", rangeStart).lt("paid_at", rangeEnd);

    const revenueByTeacher: Record<string, number> = {};
    (payments || []).forEach((p: any) => { revenueByTeacher[p.teacher_id] = (revenueByTeacher[p.teacher_id] || 0) + Number(p.amount); });
    (bookPayments || []).forEach((p: any) => { revenueByTeacher[p.teacher_id] = (revenueByTeacher[p.teacher_id] || 0) + Number(p.amount); });

    // ✅ متوسط مستوى طلاب كل مدرس (نفس حساب مخطط نمو الطالب الفردي: score/max_score%) —
    // بس للمدرسين اللي سمحوا صراحة بمشاركة التفاصيل الأكاديمية، وإلا بيفضل null (مش صفر) في الواجهة
    const academicSharingIds = teachers.filter((t: any) => t.center_sharing_permissions?.share_academic_details === true).map((t: any) => t.client_id);
    const avgGradeByTeacher: Record<string, number> = {};
    if (academicSharingIds.length > 0) {
      const { data: gradesRows } = await supabase
        .from("grades").select("teacher_id, score, max_score").in("teacher_id", academicSharingIds);
      const sumByTeacher: Record<string, { total: number; count: number }> = {};
      (gradesRows || []).forEach((g: any) => {
        if (!g.max_score || g.max_score <= 0) return;
        if (!sumByTeacher[g.teacher_id]) sumByTeacher[g.teacher_id] = { total: 0, count: 0 };
        sumByTeacher[g.teacher_id].total += (Number(g.score) / Number(g.max_score)) * 100;
        sumByTeacher[g.teacher_id].count += 1;
      });
      Object.keys(sumByTeacher).forEach((tid) => {
        avgGradeByTeacher[tid] = Math.round((sumByTeacher[tid].total / sumByTeacher[tid].count) * 10) / 10;
      });
    }

    // ✅ كل مدرس بيرجع بس المعلومات اللي هو سامحها — الإجمالي المالي والعدد دايماً ظاهرين
    // (حق إداري أساسي)، لكن التفاصيل الدقيقة (زي أسماء الطلاب) محتاجة موافقة المدرس صراحة
    const teachersData = teachers.map((t: any) => {
      const sharesAcademicDetails = t.center_sharing_permissions?.share_academic_details === true;
      return {
        clientId: t.client_id,
        name: t.name,
        studentCount: t.student_count,
        isActive: t.is_active,
        revenueThisMonth: revenueByTeacher[t.client_id] || 0,
        sharesFinancialDetails: t.center_sharing_permissions?.share_financial_details === true,
        sharesAcademicDetails,
        sharesAttendanceDetails: t.center_sharing_permissions?.share_attendance_details === true,
        avgGradePercent: sharesAcademicDetails ? (avgGradeByTeacher[t.client_id] ?? null) : null,
      };
    });

    const summary = {
      totalTeachers: teachers.length,
      totalStudents: teachers.reduce((sum: number, t: any) => sum + (t.student_count || 0), 0),
      totalRevenueThisMonth: teachersData.reduce((sum: number, t: any) => sum + t.revenueThisMonth, 0),
    };

    return new Response(JSON.stringify({ success: true, data: { center, teachers: teachersData, summary } }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
