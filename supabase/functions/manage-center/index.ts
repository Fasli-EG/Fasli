// supabase/functions/manage-center/index.ts
// ✅ إدارة السنترات (جانب الأدمن الرئيسي فقط + إعدادات مشاركة المدرس مع سنتره)
// action: listCenters | create | update | delete | assignTeacher | getMySharingStatus | updateSharingPermissions
//
// ✅ تنظيف: الملف ده كان فيه كمان 14 action تانية بتتحقق من payload.role === "center_owner" —
// قيمة دور مستحيلة، محدش JWT بيتصدر بيها فعليًا (الأدوار الحقيقية: teacher/assistant/parent/student
// — صاحب السنتر بيدخل بدور "teacher" عادي ومعاه is_center=true بس). يعني الـ14 action دي كانت
// مرفوضة 403 دايمًا لأي حد، ومحدش حتى بيستخدمها أصلًا: كانت مخصصة لصفحات center-*.html اللي
// اتحذفت بالكامل (الفيتشر الحقيقي بقى مبني في صفحات المدرس العادي — groups.html/staff.html
// وinstructor_names، شغال ومتحقق منه). اتشالت هنا نهائيًا بدل ما تفضل كود ميت.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders, TokenPayload, verifyToken } from "../_shared/auth.ts";

const ITERATIONS = 100_000;
function toHex(bytes: Uint8Array): string { return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(""); }
async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, keyMaterial, 256);
  return new Uint8Array(bits);
}
async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2(password, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${toHex(salt)}$${toHex(hashBytes)}`;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const body = await req.json();
    const action = body.action;

    // ✅ الأدمن يشوف كل السنترات الموجودة، عشان يقدر يضم مدرس لأي واحد فيهم
    if (action === "listCenters") {
      if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: centersList } = await supabase.from("centers")
        .select("id, client_id, name, owner_name, max_students, max_teachers, expiry_date, is_active, created_at")
        .order("name");
      const centerIds = (centersList || []).map((c: any) => c.id);
      const { data: teacherCounts } = centerIds.length > 0
        ? await supabase.from("teachers").select("center_id").in("center_id", centerIds)
        : { data: [] };
      const countByCenter: Record<string, number> = {};
      (teacherCounts || []).forEach((t: any) => { countByCenter[t.center_id] = (countByCenter[t.center_id] || 0) + 1; });
      const enriched = (centersList || []).map((c: any) => ({ ...c, teacherCount: countByCenter[c.id] || 0 }));
      return new Response(JSON.stringify({ success: true, data: enriched }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ إنشاء سنتر جديد — بس المشرف الرئيسي (master_admin) يقدر يعمل ده، زي إضافة مدرس بالظبط
    // ✅ Aug 2026: السنتر بقى بيتعامل زي المدرس تماماً وقت الإنشاء — حدود تشغيلية بس (بدون نظام صلاحيات خاص بيه):
    // عدد طلاب أقصى (موزّع لاحقاً على مدرسيه)، عدد مدرسين أقصى، تاريخ انتهاء ترخيص.
    if (action === "create") {
      if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { clientId, name, ownerName, maxStudents, maxTeachers, expiryDate } = body;
      if (!clientId || !name || !ownerName) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: existing } = await supabase.from("centers").select("id").eq("client_id", clientId).maybeSingle();
      if (existing) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ الكود ده مستخدم بالفعل" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const defaultHash = await hashPassword(clientId);
      const { data, error } = await supabase.from("centers").insert({
        client_id: clientId, name, owner_name: ownerName, password_hash: defaultHash, must_change_password: true,
        max_students: Number(maxStudents) || 0, max_teachers: Number(maxTeachers) || 0, expiry_date: expiryDate || null,
      }).select().single();
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم إنشاء السنتر بنجاح", data }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ Aug 2026: تعديل حدود السنتر التشغيلية من الماستر أدمن (اسم/مالك/سقف طلاب/سقف مدرسين/تاريخ انتهاء/تفعيل)
    if (action === "update") {
      if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { clientId, name, ownerName, maxStudents, maxTeachers, expiryDate, isActive } = body;
      if (!clientId) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ clientId مطلوب" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const updateData: any = {
        max_students: Number(maxStudents) || 0, max_teachers: Number(maxTeachers) || 0, expiry_date: expiryDate || null,
      };
      if (name) updateData.name = name;
      if (ownerName) updateData.owner_name = ownerName;
      if (isActive !== undefined) updateData.is_active = isActive === true;
      const { error } = await supabase.from("centers").update(updateData).eq("client_id", clientId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم تحديث بيانات السنتر" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ حذف سنتر نهائياً — بس الأدمن الرئيسي، وبس لو السنتر مفيهوش أي مدرسين لسه (حماية من حذف عرضي
    // لسنتر شغال بمدرسين وطلاب حقيقيين — لازم الماستر يشيل/يحذف مدرسيه الأول لو عايز يحذف السنتر)
    if (action === "delete") {
      if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { clientId } = body;
      if (!clientId) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ clientId مطلوب" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id, name").eq("client_id", clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { count: teacherCount } = await supabase.from("teachers").select("client_id", { count: "exact", head: true }).eq("center_id", center.id);
      if ((teacherCount || 0) > 0) {
        return new Response(JSON.stringify({ success: false, message: `⛔ السنتر ده لسه فيه ${teacherCount} مدرس — احذف أو انقل مدرسيه الأول قبل حذف السنتر نفسه` }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { error } = await supabase.from("centers").delete().eq("client_id", clientId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: `✅ تم حذف السنتر "${center.name}" نهائياً` }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ ضم مدرس لسنتر — بس الأدمن الرئيسي يقدر يعمل الربط ده حالياً (حماية من ضم نفسك لسنتر غلط)
    if (action === "assignTeacher") {
      if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { teacherClientId, centerId } = body;
      const { error } = await supabase.from("teachers").update({ center_id: centerId || null }).eq("client_id", teacherClientId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: centerId ? "✅ تم ضم المدرس للسنتر" : "✅ تم فصل المدرس عن السنتر" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ المدرس نفسه يقدر يتحكم في إيه اللي صاحب السنتر يشوفه بالتفصيل
    // ✅ المدرس يسأل عن حالته: هل هو تابع لسنتر أصلاً، وإيه إعدادات المشاركة الحالية بتاعته
    if (action === "getMySharingStatus") {
      if (payload.role !== "teacher") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: teacher } = await supabase
        .from("teachers").select("center_id, center_sharing_permissions, centers(name)").eq("client_id", payload.clientId).maybeSingle();
      return new Response(JSON.stringify({
        success: true,
        belongsToCenter: !!teacher?.center_id,
        centerName: (teacher as any)?.centers?.name || null,
        permissions: teacher?.center_sharing_permissions || {},
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "updateSharingPermissions") {
      if (payload.role !== "teacher") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { permissions } = body;
      const { error } = await supabase.from("teachers").update({ center_sharing_permissions: permissions }).eq("client_id", payload.clientId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم تحديث إعدادات المشاركة" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "حدث خطأ داخلي";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
