// supabase/functions/get-at-risk-students/index.ts
// ✅ نظام إنذار مبكر — بيحلل نمط الحضور والسداد لكل طالب، ويكتشف مين معرّض للتسرّب قبل ما يحصل فعلياً
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, verifyToken, authErrorResponse } from "../_shared/auth.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    if (payload.role !== "teacher" && payload.role !== "assistant") {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const tokenClientId = payload.clientId || payload.teacherId;
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const { data: students } = await supabase.from("students").select("uid, name, group_name, parent_phone").eq("teacher_id", tokenClientId);
    if (!students || students.length === 0) {
      return new Response(JSON.stringify({ success: true, data: [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const uids = students.map((s: any) => s.uid);
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();

    const [{ data: recentAttendance }, { data: olderAttendance }, { data: recentPayments }] = await Promise.all([
      supabase.from("attendance").select("student_uid, status, created_at").in("student_uid", uids).gte("created_at", thirtyDaysAgo),
      supabase.from("attendance").select("student_uid, status, created_at").in("student_uid", uids).gte("created_at", sixtyDaysAgo).lt("created_at", thirtyDaysAgo),
      supabase.from("payments").select("student_uid, amount, total_amount, created_at").in("student_uid", uids).order("created_at", { ascending: false }),
    ]);

    const results: any[] = [];

    for (const student of students) {
      const reasons: string[] = [];
      let riskScore = 0;

      // ✅ إشارة 1: نسبة الحضور في آخر 30 يوم مقارنة بالـ30 يوم اللي قبلها — تراجع واضح = إشارة خطر
      const recentRecords = (recentAttendance || []).filter((a: any) => a.student_uid === student.uid);
      const olderRecords = (olderAttendance || []).filter((a: any) => a.student_uid === student.uid);

      const recentPresentRate = recentRecords.length > 0
        ? recentRecords.filter((a: any) => a.status === "present").length / recentRecords.length : null;
      const olderPresentRate = olderRecords.length > 0
        ? olderRecords.filter((a: any) => a.status === "present").length / olderRecords.length : null;

      if (recentPresentRate !== null && olderPresentRate !== null && (olderPresentRate - recentPresentRate) > 0.25) {
        riskScore += 2;
        reasons.push(`نسبة الحضور نزلت من ${Math.round(olderPresentRate * 100)}% لـ ${Math.round(recentPresentRate * 100)}%`);
      } else if (recentPresentRate !== null && recentPresentRate < 0.5 && recentRecords.length >= 3) {
        riskScore += 1;
        reasons.push(`نسبة الحضور في آخر شهر ${Math.round(recentPresentRate * 100)}% بس`);
      }

      // ✅ إشارة 2: مفيش أي حضور خالص في آخر 30 يوم (بينما كان بيحضر قبل كده)
      if (recentRecords.length === 0 && olderRecords.length > 0) {
        riskScore += 2;
        reasons.push("مفيش أي حضور مسجّل في آخر شهر");
      }

      // ✅ إشارة 3: تأخر واضح في السداد — آخر دفعة كانت جزئية أو من فترة طويلة
      const studentPayments = (recentPayments || []).filter((p: any) => p.student_uid === student.uid);
      if (studentPayments.length > 0) {
        const lastPayment = studentPayments[0];
        const isPartial = Number(lastPayment.amount) < Number(lastPayment.total_amount);
        const daysSinceLastPayment = (Date.now() - new Date(lastPayment.created_at).getTime()) / (1000 * 60 * 60 * 24);
        if (isPartial) { riskScore += 1; reasons.push("آخر دفعة كانت جزئية ومحصّلتش بالكامل"); }
        if (daysSinceLastPayment > 45) { riskScore += 1; reasons.push(`آخر سداد كان من ${Math.round(daysSinceLastPayment)} يوم`); }
      }

      if (riskScore >= 2) {
        results.push({
          studentUid: student.uid, studentName: student.name, groupName: student.group_name,
          parentPhone: student.parent_phone, riskScore, reasons,
        });
      }
    }

    results.sort((a, b) => b.riskScore - a.riskScore);

    return new Response(JSON.stringify({ success: true, data: results }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    return authErrorResponse(error);
  }
});
