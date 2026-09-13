// supabase/functions/bulk-import-students/index.ts
// ✅ استيراد جماعي للطلاب من إكسل — الملف بيتقرا في المتصفح، وقائمة الطلاب بتتبعت هنا دفعة واحدة
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, TokenPayload, AuthError, verifyToken } from "../_shared/auth.ts";
import { provisionAuthUser, deleteAuthUser } from "../_shared/authProvision.ts";

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

function generateUid(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let uid = "";
  for (let i = 0; i < 8; i++) uid += chars.charAt(Math.floor(Math.random() * chars.length));
  return uid;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  try {
    const payload = await verifyToken(req);
    if (payload.role !== "teacher" && payload.role !== "assistant") {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const tokenClientId = payload.clientId || payload.teacherId;
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    // ✅ (مراجعة أمان) الاستيراد الجماعي كان بيتحقق من إن التوكن مدرس أو مساعد بس، من غير ما
    // يتأكد إن المساعد معاه صلاحية "إضافة طلاب" فعلاً — نفس صلاحية add_students المستخدمة في
    // إضافة الطالب الواحد (manage-student). كان ممكن مساعد ملوش صلاحية إضافة طلاب يستورد
    // 500 طالب دفعة واحدة عن طريق النداء المباشر للدالة دي.
    if (payload.role === "assistant") {
      const { data: assistantRow } = await supabase
        .from("assistants").select("permissions, teacher_id").eq("id", payload.sub).maybeSingle();
      if (!assistantRow || assistantRow.teacher_id !== tokenClientId || assistantRow.permissions?.add_students !== true) {
        return new Response(JSON.stringify({ success: false, message: "⛔ ليس لديك صلاحية إضافة طلاب" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }

    const { students } = await req.json();
    if (!Array.isArray(students) || students.length === 0) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ لازم تحدد طالب واحد على الأقل" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (students.length > 500) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ الحد الأقصى 500 طالب في المرة الواحدة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: teacher } = await supabase.from("teachers").select("client_id, max_students, student_count").eq("client_id", tokenClientId).maybeSingle();
    if (!teacher) {
      return new Response(JSON.stringify({ success: false, message: "المدرس غير موجود" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (teacher.max_students > 0 && teacher.student_count + students.length > teacher.max_students) {
      return new Response(JSON.stringify({ success: false, message: `⚠️ عدد الطلاب اللي هتضيفيهم هيتخطى الحد الأقصى المسموح (${teacher.max_students})` }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const results: { row: number; name: string; status: string; uid?: string; reason?: string }[] = [];
    const phoneRegex = /^01[0125][0-9]{8}$/;

    // ✅ تحسين أداء: النسخة القديمة كانت بتعمل لغاية 5 استعلامات فحص UID + استعلام فحص ولي أمر
    // لكل صف — يعني لغاية ~3000 round-trip لملف 500 طالب. دلوقتي: تحقق أساسي من الحقول (بلا
    // استعلامات) في تمريرة أولى، بعدين استعلام واحد مجمّع لأرقام أولياء الأمور كلهم، والـ UID
    // بيتولّد ويتحط في الـ insert على طول من غير فحص مسبق (فرصة تصادم عشوائي من 36^8 احتمال
    // ضئيلة جداً — لو حصل نادراً بيتعمل محاولة واحدة بس بـ UID جديد قبل ما الصف يُعتبر فاشل).
    type Candidate = { rowNum: number; name: string; parentPhone: string; phone: string | null; groupName: string };
    const candidates: Candidate[] = [];
    for (let i = 0; i < students.length; i++) {
      const row = students[i];
      const rowNum = i + 2; // ✅ صف 1 في الإكسل هو العناوين، فأول طالب فعلي بيبدأ من صف 2
      const name = String(row.name || "").trim();
      const parentPhone = String(row.parentPhone || "").trim();
      const phone = row.phone ? String(row.phone).trim() : null;
      const groupName = String(row.groupName || "").trim();

      if (!name || !parentPhone || !groupName) {
        results.push({ row: rowNum, name: name || "(بدون اسم)", status: "failed", reason: "بيانات ناقصة (الاسم/رقم ولي الأمر/المجموعة)" });
        continue;
      }
      if (!phoneRegex.test(parentPhone)) {
        results.push({ row: rowNum, name, status: "failed", reason: "رقم هاتف ولي الأمر غير صحيح" });
        continue;
      }
      if (phone && !phoneRegex.test(phone)) {
        results.push({ row: rowNum, name, status: "failed", reason: "رقم هاتف الطالب غير صحيح" });
        continue;
      }
      candidates.push({ rowNum, name, parentPhone, phone, groupName });
    }

    // ✅ (طلب) لو أي مجموعة وصلت لحدها الأقصى (max_students)، لازم نرفض إضافة طلاب جدد ليها —
    // حتى وسط استيراد جماعي فيه كذا صف بيستهدفوا نفس المجموعة. بنحسب المساحة المتبقية لكل
    // مجموعة مرة واحدة قبل الحلقة (استعلام واحد لكل الطلاب + استعلام واحد لكل الروابط، بدل
    // استعلامين منفصلين لكل مجموعة)، وبعدين بننقصها صف بصف كل ما صف ينجح.
    const distinctGroupNames = [...new Set(candidates.map((c) => c.groupName))];
    const remainingCapacity: Record<string, number> = {}; // مفيش مفتاح للمجموعة = بلا حد أقصى
    if (distinctGroupNames.length > 0) {
      const { data: groupRows } = await supabase
        .from("groups").select("name, max_students").eq("teacher_id", tokenClientId).in("name", distinctGroupNames);
      const cappedGroupNames = (groupRows || []).filter((g) => g.max_students > 0).map((g) => g.name);
      const countByGroup: Record<string, number> = {};
      if (cappedGroupNames.length > 0) {
        const [{ data: primaryRows }, { data: linkedRows }] = await Promise.all([
          supabase.from("students").select("group_name").eq("teacher_id", tokenClientId).in("group_name", cappedGroupNames),
          supabase.from("student_group_links").select("group_name").eq("teacher_id", tokenClientId).in("group_name", cappedGroupNames),
        ]);
        (primaryRows || []).forEach((r: any) => { countByGroup[r.group_name] = (countByGroup[r.group_name] || 0) + 1; });
        (linkedRows || []).forEach((r: any) => { countByGroup[r.group_name] = (countByGroup[r.group_name] || 0) + 1; });
      }
      for (const g of groupRows || []) {
        if (!g.max_students || g.max_students <= 0) continue;
        remainingCapacity[g.name] = g.max_students - (countByGroup[g.name] || 0);
      }
    }

    // فحص أولياء الأمور الموجودين مسبقًا باستعلام واحد مجمّع بدل استعلام لكل صف
    const distinctParentPhones = [...new Set(candidates.map((c) => c.parentPhone))];
    const existingParentSet = new Set<string>();
    if (distinctParentPhones.length > 0) {
      const { data: existingParents } = await supabase.from("parents").select("phone").in("phone", distinctParentPhones);
      (existingParents || []).forEach((p: any) => existingParentSet.add(p.phone));
    }
    const newParentPhonesInBatch = new Set<string>();

    for (const c of candidates) {
      const { rowNum, name, parentPhone, phone, groupName } = c;

      if (groupName in remainingCapacity && remainingCapacity[groupName] <= 0) {
        results.push({ row: rowNum, name, status: "failed", reason: `المجموعة "${groupName}" وصلت للحد الأقصى لعدد الطلاب` });
        continue;
      }

      let newParentAuthUserId: string | null = null;
      if (!existingParentSet.has(parentPhone) && !newParentPhonesInBatch.has(parentPhone)) {
        try {
          newParentAuthUserId = await provisionAuthUser({
            phone: parentPhone,
            password: parentPhone,
            appMetadata: { role: "parent", phone: parentPhone, sub: parentPhone, name: `ولي أمر ${name}` },
          });
          const { error: parentInsertError } = await supabase.from("parents").insert({
            phone: parentPhone, name: `ولي أمر ${name}`, auth_user_id: newParentAuthUserId, must_change_password: true, is_active: true,
          });
          if (parentInsertError) throw new Error(parentInsertError.message);
          newParentPhonesInBatch.add(parentPhone);
          existingParentSet.add(parentPhone);
        } catch (parentError) {
          if (newParentAuthUserId) await deleteAuthUser(newParentAuthUserId);
          const msg = parentError instanceof Error ? parentError.message : "فشل إنشاء ولي الأمر";
          results.push({ row: rowNum, name, status: "failed", reason: msg });
          continue;
        }
      }

      let uid = generateUid();
      let insertError = (await supabase.from("students").insert({
        uid, name, phone: phone || null, parent_phone: parentPhone, group_name: groupName, teacher_id: tokenClientId,
      })).error;

      // تصادم UID عشوائي (احتمال ضئيل جداً من 36^8) — محاولة واحدة إضافية بـ UID جديد قبل الاستسلام
      if (insertError?.message?.includes("duplicate")) {
        uid = generateUid();
        insertError = (await supabase.from("students").insert({
          uid, name, phone: phone || null, parent_phone: parentPhone, group_name: groupName, teacher_id: tokenClientId,
        })).error;
      }

      if (insertError) {
        results.push({ row: rowNum, name, status: "failed", reason: insertError.message.includes("duplicate") ? "الطالب موجود بالفعل" : "فشل الحفظ" });
        continue;
      }

      if (groupName in remainingCapacity) remainingCapacity[groupName]--;
      results.push({ row: rowNum, name, status: "success", uid });
    }

    const successCount = results.filter(r => r.status === "success").length;
    if (successCount > 0) {
      const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", tokenClientId);
      await supabase.from("teachers").update({ student_count: count }).eq("client_id", tokenClientId);

      await supabase.from("activity_logs").insert({
        client_id: tokenClientId, teacher_id: tokenClientId, action_type: "bulk_import_students",
        entity_type: "student", details: { total: students.length, success: successCount, failed: students.length - successCount },
        performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
      });
    }

    return new Response(JSON.stringify({
      success: true,
      message: `✅ تم استيراد ${successCount} من أصل ${students.length} طالب`,
      results, successCount, failedCount: students.length - successCount,
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ في bulk-import-students:", error);
    const message = error instanceof Error ? error.message : "خطأ غير معروف";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
