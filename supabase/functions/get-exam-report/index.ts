// supabase/functions/get-exam-report/index.ts
// ✅ تقرير المدرس الكامل عن اختبار معيّن: مين امتحن، مين لا، مين انتهى وقته، ودرجة كل واحد
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
};

interface TokenPayload { sub: string; clientId?: string; teacherId?: string; role: string; name: string; }

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
    const tokenClientId = payload.clientId || payload.teacherId;
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const { examId } = await req.json();
    const { data: exam } = await supabase.from("online_exams").select("*").eq("id", examId).maybeSingle();
    if (!exam || exam.teacher_id !== tokenClientId) {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ كل طلاب المجموعة (عشان نعرف مين لسه ما امتحنش خالص، مش بس اللي امتحنوا)
    // ✅ محاولات التدريب مستبعدة هنا بالكامل — التقرير ده رسمي وبيعكس المحاولة الرسمية بس
    const { data: groupStudents } = await supabase.from("students").select("uid, name").eq("teacher_id", tokenClientId).eq("group_name", exam.group_name);
    const { data: attempts } = await supabase.from("exam_attempts").select("*").eq("exam_id", examId).eq("mode", "official");

    const attemptsByUid: Record<string, any> = {};
    (attempts || []).forEach((a: any) => { attemptsByUid[a.student_uid] = a; });

    const report = (groupStudents || []).map((s: any) => {
      const attempt = attemptsByUid[s.uid];
      if (!attempt) return { studentUid: s.uid, studentName: s.name, status: "لسه ماامتحنش", score: null, totalPossible: null, startedAt: null, finishedAt: null };
      const statusLabel = attempt.status === "completed" ? "خلّص الاختبار" : (attempt.status === "timed_out" ? "انتهى وقته وهو بيمتحن" : "لسه بيمتحن دلوقتي");
      return {
        studentUid: s.uid, studentName: s.name, status: statusLabel,
        score: attempt.score, totalPossible: attempt.total_possible,
        startedAt: attempt.started_at, finishedAt: attempt.finished_at,
      };
    });

    const summary = {
      totalStudents: (groupStudents || []).length,
      took: (attempts || []).length,
      didNotTake: (groupStudents || []).length - (attempts || []).length,
      timedOut: (attempts || []).filter((a: any) => a.status === "timed_out").length,
      avgScore: attempts && attempts.length > 0
        ? Math.round((attempts.reduce((sum: number, a: any) => sum + (a.score || 0), 0) / attempts.filter((a: any) => a.score !== null).length) * 10) / 10
        : 0,
    };

    return new Response(JSON.stringify({ success: true, data: { exam, report, summary } }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
