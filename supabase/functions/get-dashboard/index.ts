// supabase/functions/get-dashboard/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, AuthError, verifyToken, authErrorResponse } from "../_shared/auth.ts";

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const payload = await verifyToken(req);

    const tokenClientId = payload.clientId || payload.teacherId;
    if (!tokenClientId) {
      console.error("❌ التوكن لا يحتوي على clientId");
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ التوكن لا يحتوي على clientId" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { clientId } = await req.json();

    if (clientId && clientId !== tokenClientId) {
      console.error(`❌ clientId غير متطابق: ${clientId} != ${tokenClientId}`);
      return new Response(
        JSON.stringify({ success: false, message: "⛔ غير مصرح لك بمشاهدة بيانات هذا المدرس" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const finalClientId = tokenClientId;

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    const today = new Date().toISOString().split("T")[0];
    const sevenDaysAgoPre = new Date();
    sevenDaysAgoPre.setDate(sevenDaysAgoPre.getDate() - 6);
    const sevenDaysAgoStrPre = sevenDaysAgoPre.toISOString().split("T")[0];
    const oneHourAgoPre = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    // ✅ تحسين أداء: الاستعلامات السبعة دي مستقلة عن بعض (مفيش واحد محتاج نتيجة التاني)
    // فكانت بتتنفذ واحد ورا التاني بالتتابع (7 round-trips) رغم إنهم يقدروا يتنفذوا مع بعض.
    // Promise.all بيبعتهم كلهم مرة واحدة، فزمن التنفيذ الكلي بقى = أبطأ استعلام لوحده
    // بدل مجموع الكل — get-dashboard ده بيتنادى في كل تحميل للوحة التحكم.
    const [
      { data: teacher, error: teacherError },
      { count: totalStudents, error: countError },
      { data: todayAttendance, error: attendanceError },
      { data: groupsData, error: groupsError },
      { data: groupRows, error: groupRowsError },
      { data: weekAttendance, error: weekAttError },
      { data: activities, error: activitiesError },
    ] = await Promise.all([
      supabase.from("teachers").select("*").eq("client_id", finalClientId).single(),
      supabase.from("students").select("id", { count: "exact", head: true })
        .eq("teacher_id", finalClientId).is("archived_at", null),
      supabase.from("attendance").select("student_uid, status")
        .eq("teacher_id", finalClientId).eq("date", today),
      supabase.from("students").select("group_name")
        .eq("teacher_id", finalClientId).not("group_name", "is", null).is("archived_at", null),
      supabase.from("groups").select("name").eq("teacher_id", finalClientId),
      supabase.from("attendance").select("date")
        .eq("teacher_id", finalClientId).eq("status", "present").gte("date", sevenDaysAgoStrPre),
      supabase.from("activity_logs")
        .select(`id, action_type, details, performer_id, performer_role, performer_name, created_at`)
        .eq("client_id", finalClientId)
        .gte("created_at", oneHourAgoPre)
        .or("performer_role.is.null,performer_role.neq.admin")
        .or("performer_id.is.null,performer_id.neq.master_admin")
        .order("created_at", { ascending: false })
        .limit(50),
    ]);

    if (teacherError || !teacher) {
      console.error("❌ المدرس غير موجود:", teacherError);
      return new Response(
        JSON.stringify({ success: false, message: "المدرس غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
    if (countError) throw new Error(`فشل جلب عدد الطلاب: ${countError.message}`);
    if (attendanceError) throw new Error(`فشل جلب حضور اليوم: ${attendanceError.message}`);
    if (groupsError) throw new Error(`فشل جلب المجموعات: ${groupsError.message}`);
    if (groupRowsError) throw new Error(`فشل جلب جدول المجموعات: ${groupRowsError.message}`);
    if (weekAttError) console.error("خطأ في جلب حضور آخر 7 أيام:", weekAttError);
    if (activitiesError) console.error("❌ خطأ في جلب النشاطات:", activitiesError);

    // ✅ Batch 24 (بند 1): بعد ما بقى مسموح للطالب يحضر أكتر من حصة في نفس اليوم (كل حصة صف
    // حضور منفصل)، عدّ الصفوف الخام هنا كان بيضخّم الرقم — طالب حضر حصتين النهاردة كان بيتحسب
    // 2 في "حضور اليوم" بدل 1. دلوقتي بنعدّ الطلاب المتفرّدين، وأي طالب حضر ولو حصة واحدة
    // النهاردة بيتحسب "حاضر" حتى لو معاه صف غياب لحصة تانية في نفس اليوم
    const statusByStudent = new Map<string, string>();
    (todayAttendance || []).forEach((a: any) => {
      const prev = statusByStudent.get(a.student_uid);
      if (prev !== "present") statusByStudent.set(a.student_uid, a.status);
    });
    const presentToday = Array.from(statusByStudent.values()).filter((s) => s === "present").length;
    const absentToday = Array.from(statusByStudent.values()).filter((s) => s === "absent").length;

    const groupCounts: Record<string, number> = {};
    (groupsData || []).forEach((s: any) => {
      const name = s.group_name || "بدون مجموعة";
      groupCounts[name] = (groupCounts[name] || 0) + 1;
    });

    // ✅ إصلاح (Aug 2026): عدد المجموعات كان بيتحسب من أسماء مجموعات الطلاب بس، فأي مجموعة اتعملت
    // فعلاً في جدول groups بس لسه معندهاش طلاب (زي مجموعة جديدة فاضية) كانت مش بتتحسب خالص —
    // نضيفها هنا بعدد 0 طالب، بنفس منطق الدمج المستخدم في manage-group's handleListDetailed
    (groupRows || []).forEach((g: any) => {
      if (!(g.name in groupCounts)) groupCounts[g.name] = 0;
    });

    const groups = Object.keys(groupCounts);
    const groupCountsArray = Object.values(groupCounts);

    const dayCounts: Record<string, number> = {};
    (weekAttendance || []).forEach((r: any) => {
      dayCounts[r.date] = (dayCounts[r.date] || 0) + 1;
    });

    const weeklyData = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split("T")[0];
      weeklyData.push({ date: dateStr, count: dayCounts[dateStr] || 0 });
    }

    const formattedActivities = activities || [];

    // ✅ مقارنة تاريخ بتاريخ بس (بدون وقت)، عشان المدرس يفضل له اليوم كامل لحد آخره
    // — مقارنة timestamp كانت بتعتبره منتهي من أول ثانية في يوم الانتهاء نفسه
    const todayDashStr = new Date().toISOString().split("T")[0];
    const in7DaysStr = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString().split("T")[0];

    const responseData = {
      teacher: {
        ...teacher,
        licenseStatus: teacher.is_active 
          ? (teacher.expiry_date && teacher.expiry_date < todayDashStr
              ? "expired" 
              : teacher.expiry_date && teacher.expiry_date < in7DaysStr
                ? "expiring_soon" 
                : "active")
          : "inactive",
        daysRemaining: teacher.expiry_date 
          ? Math.ceil((new Date(teacher.expiry_date + "T00:00:00Z").getTime() - new Date(todayDashStr + "T00:00:00Z").getTime()) / (1000 * 60 * 60 * 24))
          : null,
      },
      totalStudents: totalStudents || 0,
      todayAttendance: presentToday,
      absentToday: absentToday,
      groupsCount: groups.length,
      groups: groups,
      groupCounts: groupCountsArray,
      weeklyAttendance: weeklyData,
      recentActivities: formattedActivities,
    };

    return new Response(
      JSON.stringify({ success: true, data: responseData }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في get-dashboard:", error);
    return new Response(
      JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

