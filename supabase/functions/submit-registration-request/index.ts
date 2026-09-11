// supabase/functions/submit-registration-request/index.ts
// ✅ دالة عامة (بدون توكن) — أي حد يقدر يقدّم طلب انضمام من رابط عام للمدرس، من غير تسجيل دخول
// ✅ Aug 2026 (تعديل جوهري — تأمين الرابط + دعم مدرسين متعددين تابعين لنفس السنتر):
//   1) الرابط العام بقى بيحمل registration_token عشوائي طويل بدل client_id القابل للتخمين.
//      الدالة دي بقت بتدوّر على المدرس بالتوكن، مش بكود المدرس القصير. (قرار: قطع فوري —
//      الروابط القديمة بصيغة ?teacher=<client_id> بقت مش شغالة، لأن الهدف الأساسي من التعديل
//      هو إقفال ثغرة تخمين الكود، وأي رابط قديم اتشارك أصلاً معرّض لنفس المشكلة. لازم كل مدرس
//      يعيد مشاركة رابطه الجديد من صفحة "إعدادات الحساب".)
//   2) اتضاف action جديد "lookup" (لسه عامة/من غير توكن دخول) بترجع اسم المدرس + هل هو سنتر
//      وليه أسماء مدرسين مفعّلة ولا لأ — عشان register.html يبني الفورم صح قبل الإرسال، من غير
//      ما نحتاج ننشئ Edge Function جديدة تماماً لمجرد الاستعلام ده.
//   3) لو المدرس ده حساب سنتر (is_center) وعنده أسماء مدرسين (instructor_names)، ولي الأمر بيقدر
//      يختار مدرس واحد أو أكتر من مدرسين السنتر — كل اختيار بيتسجل كطلب منفصل (instructor_name_id
//      مختلف) عشان صاحب السنتر يقدر يقبل/يرفض كل طلب لوحده.
//   4) اتضاف حقل "رقم هاتف الطالب" (studentPhone) منفصل عن رقم هاتف ولي الأمر.
//   5) اتشال اختيار "المجموعة" من فورم التسجيل خالص — المجموعة بقت بتتحدد من المدرس وقت
//      الموافقة على الطلب مش من ولي الأمر وقت التسجيل، فمنطق "قائمة الانتظار" اللي كان مبني على
//      امتلاء مجموعة معينة اتشال من هنا (كل الطلبات الجديدة بتتسجل status="pending").
// ✅ إضافة (المرحلة الدراسية): كل مدرس (سنتر أو مش سنتر) يقدر يعرّف "مراحل دراسية" (education_levels)
// ورابط التسجيل بقى بيعرض قائمة اختيار مرحلة دراسية (levelId) بدل ما يختار/يكتب مجموعة مباشرة —
// ده بُعد منفصل تماماً عن اختيار "المدرس" (instructorNameIds) لحسابات السنتر: طلب واحد ممكن
// يحمل الاثنين مع بعض (instructor_name_id لكل صف + level_id ثابت على كل الصفوف المتولدة من نفس
// التقديم). لو المدرس معندوش أي مرحلة دراسية مفعّلة، الحقل ده بيفضل اختياري (مش هيمنع التسجيل)
// عشان مانفرضش على كل مدرس قديم يعرّف مراحل الأول عشان رابطه يشتغل.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, apikey, x-client-info",
};

function jsonRes(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  try {
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");
    const body = await req.json();
    const action = body.action || "submit";

    // ✅ action=lookup: استعلام عام (من غير توكن دخول) عشان صفحة التسجيل تعرف اسم المدرس، وهل
    // لازم تعرض قائمة اختيار أسماء مدرسين السنتر قبل ما تعرض فورم التسجيل نفسه
    if (action === "lookup") {
      const { token } = body;
      if (!token) return jsonRes({ success: false, message: "⚠️ الرابط ده ناقص — لازم يكون فيه توكن التسجيل" }, 400);

      const { data: teacher } = await supabase.from("teachers")
        .select("client_id, name, is_active, is_center").eq("registration_token", token).maybeSingle();
      if (!teacher || !teacher.is_active) {
        return jsonRes({ success: false, message: "⚠️ رابط التسجيل ده مش متاح حالياً" }, 404);
      }

      let instructors: { id: number; name: string }[] = [];
      if (teacher.is_center) {
        const { data } = await supabase.from("instructor_names").select("id, name").eq("teacher_id", teacher.client_id).eq("is_active", true).order("created_at", { ascending: true });
        instructors = data || [];
      }

      // ✅ (المرحلة الدراسية) لكل مدرس، سنتر أو مش سنتر — بيرجع فاضي لو المدرس لسه معرّفش أي مرحلة
      const { data: levelsData } = await supabase.from("education_levels").select("id, name").eq("teacher_id", teacher.client_id).eq("is_active", true).order("created_at", { ascending: true });
      const levels: { id: number; name: string }[] = levelsData || [];

      return jsonRes({ success: true, teacherName: teacher.name, isCenter: !!teacher.is_center, instructors, levels });
    }

    const { token, studentName, studentPhone, parentName, parentPhone, instructorNameIds, levelId, notes } = body;

    if (!token || !studentName || !parentPhone) {
      return jsonRes({ success: false, message: "⚠️ الاسم ورقم الهاتف مطلوبين" }, 400);
    }

    // ✅ نتأكد إن رابط المدرس ده فعلاً موجود ومفعّل، عن طريق التوكن العشوائي بدل كود المدرس القابل للتخمين
    const { data: teacher } = await supabase.from("teachers")
      .select("client_id, name, is_active, is_center").eq("registration_token", token).maybeSingle();
    if (!teacher || !teacher.is_active) {
      return jsonRes({ success: false, message: "⚠️ رابط التسجيل ده مش متاح حالياً" }, 404);
    }
    const teacherId = teacher.client_id;

    // ✅ لو المدرس ده سنتر وعنده أسماء مدرسين مفعّلة، لازم ولي الأمر يكون اختار واحد على الأقل
    let activeInstructorIds: number[] = [];
    if (teacher.is_center) {
      const { data: instructors } = await supabase.from("instructor_names").select("id").eq("teacher_id", teacherId).eq("is_active", true);
      activeInstructorIds = (instructors || []).map((i: any) => i.id);
    }

    const requestedInstructorIds: number[] = Array.isArray(instructorNameIds)
      ? instructorNameIds.map((v: any) => Number(v)).filter((v: number) => activeInstructorIds.includes(v))
      : [];

    if (activeInstructorIds.length > 0 && requestedInstructorIds.length === 0) {
      return jsonRes({ success: false, message: "⚠️ اختر مدرس واحد على الأقل من مدرسي السنتر" }, 400);
    }

    // ✅ (المرحلة الدراسية) بُعد منفصل عن اختيار المدرس — لازم تتحقق إنها تابعة لنفس المدرس ومفعّلة،
    // لكن بس لو المدرس أصلاً عنده مراحل مفعّلة (وإلا يفضل الحقل اختياري عشان مانكسرش روابط قديمة)
    const { data: activeLevels } = await supabase.from("education_levels").select("id").eq("teacher_id", teacherId).eq("is_active", true);
    const activeLevelIds: number[] = (activeLevels || []).map((l: any) => l.id);
    let normalizedLevelId: number | null = null;
    if (activeLevelIds.length > 0) {
      if (levelId === undefined || levelId === null || levelId === "") {
        return jsonRes({ success: false, message: "⚠️ اختر المرحلة الدراسية" }, 400);
      }
      const candidateLevelId = Number(levelId);
      if (!activeLevelIds.includes(candidateLevelId)) {
        return jsonRes({ success: false, message: "❌ المرحلة الدراسية غير موجودة أو غير تابعة لهذا المدرس" }, 404);
      }
      normalizedLevelId = candidateLevelId;
    } else if (levelId !== undefined && levelId !== null && levelId !== "") {
      // ✅ مدرس معندوش مراحل مفعّلة، أي levelId متبعت اتجاهل بأمان (مش حالة خطأ)
      normalizedLevelId = null;
    }

    // ✅ حماية بسيطة من التكرار: نفس رقم الهاتف بنفس اسم الطالب عند نفس المدرس (ولنفس اسم المدرس
    // المختار لو موجود)، لو فيه طلب معلّق أو قائمة انتظار بالفعل مانكررهوش
    const instructorSlots: (number | null)[] = requestedInstructorIds.length > 0 ? requestedInstructorIds : [null];
    const rowsToInsert: Record<string, unknown>[] = [];

    for (const instructorNameId of instructorSlots) {
      let dupQuery = supabase.from("registration_requests")
        .select("id").eq("teacher_id", teacherId).eq("parent_phone", parentPhone).eq("student_name", studentName)
        .in("status", ["pending", "waitlisted"]);
      dupQuery = instructorNameId === null ? dupQuery.is("instructor_name_id", null) : dupQuery.eq("instructor_name_id", instructorNameId);
      const { data: existing } = await dupQuery.maybeSingle();
      if (existing) continue;

      rowsToInsert.push({
        teacher_id: teacherId, student_name: studentName, student_phone: studentPhone || null,
        parent_name: parentName || null, parent_phone: parentPhone, notes: notes || null,
        instructor_name_id: instructorNameId, level_id: normalizedLevelId, status: "pending",
      });
    }

    if (rowsToInsert.length === 0) {
      return jsonRes({ success: false, message: "⚠️ عندك طلب معلّق بالفعل بنفس البيانات، استني رد المدرس" }, 400);
    }

    const { error } = await supabase.from("registration_requests").insert(rowsToInsert);
    if (error) throw new Error(error.message);

    const message = `✅ تم إرسال طلبك بنجاح، وهيتم التواصل معاك من مدرس ${teacher.name} قريباً`;

    return jsonRes({ success: true, message, waitlisted: false });
  } catch (error) {
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return jsonRes({ success: false, message }, 500);
  }
});
