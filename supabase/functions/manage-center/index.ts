// supabase/functions/manage-center/index.ts
// ✅ إدارة السنترات (جانب الأدمن الرئيسي + صاحب السنتر) — action: create | assignTeacher | removeTeacher | listTeachers
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
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

// ✅ (طلب) لو المجموعة وصلت للحد الأقصى لعدد الطلاب (max_students)، لازم نرفض أي عملية إضافة
// أو نقل ليها — نفس المنطق المستخدم في manage-student/transfer-student/manage-group بالظبط.
async function checkGroupCapacity(supabase: any, teacherId: string, groupName: string): Promise<{ ok: boolean; message?: string }> {
  const { data: group } = await supabase.from("groups").select("max_students").eq("teacher_id", teacherId).eq("name", groupName).maybeSingle();
  const maxStudents = group?.max_students;
  if (!maxStudents || maxStudents <= 0) return { ok: true };

  const { count: primaryCount } = await supabase
    .from("students").select("uid", { count: "exact", head: true }).eq("teacher_id", teacherId).eq("group_name", groupName);
  const { count: linkedCount } = await supabase
    .from("student_group_links").select("id", { count: "exact", head: true }).eq("teacher_id", teacherId).eq("group_name", groupName);
  const currentCount = (primaryCount || 0) + (linkedCount || 0);

  if (currentCount >= maxStudents) {
    return { ok: false, message: `⚠️ المجموعة "${groupName}" وصلت للحد الأقصى لعدد الطلاب (${maxStudents}) — لازم تزود الحد الأقصى أو تختار مجموعة تانية` };
  }
  return { ok: true };
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
    // ✅ صاحب السنتر بنفسه ينشئ مدرس جديد تحت سنتره — بدون الحاجة للماستر أدمن خالص
    // ✅ Aug 2026: بيحدد كمان صلاحيات المدرس الجديد وعدد طلابه، مقيّد بحدود السنتر (max_teachers / max_students)
    // اللي حدّدها الماستر وقت إنشاء السنتر — لا يوجد حد لعدد المساعدين (أُلغي نهائياً، انظر manage-assistant)
    if (action === "createTeacher") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { clientId, name, maxStudents, permissions: requestedPermissions } = body;
      if (!clientId || !name) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (clientId === "master_admin") {
        return new Response(JSON.stringify({ success: false, message: "⛔ الكود ده محجوز" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: center } = await supabase.from("centers").select("id, max_teachers, max_students").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: existing } = await supabase.from("teachers").select("client_id").eq("client_id", clientId).maybeSingle();
      if (existing) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ الكود ده مستخدم بالفعل" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ فحص حد عدد المدرسين اللي حدّده الماستر للسنتر ده (0 = غير محدود)
      const { count: currentTeacherCount } = await supabase.from("teachers").select("client_id", { count: "exact", head: true }).eq("center_id", center.id);
      if (center.max_teachers && center.max_teachers > 0 && (currentTeacherCount || 0) >= center.max_teachers) {
        return new Response(JSON.stringify({ success: false, message: `⛔ وصلت للحد الأقصى لعدد المدرسين في سنترك (${center.max_teachers})` }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const newTeacherMaxStudents = Number(maxStudents) || 0;

      // ✅ لو السنتر عنده سقف إجمالي لعدد الطلاب، لازم توزيع الطلاب بين المدرسين يبقى برقم واضح (مش "غير محدود")
      // ومجموع كل حدود المدرسين الحاليين + المدرس الجديد ميتعداش سقف السنتر
      if (center.max_students && center.max_students > 0) {
        if (newTeacherMaxStudents <= 0) {
          return new Response(JSON.stringify({ success: false, message: "⚠️ سنترك عنده سقف لعدد الطلاب، لازم تحدد عدد طلاب واضح لكل مدرس (مش 0 / غير محدود)" }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        const { data: centerTeachers } = await supabase.from("teachers").select("max_students").eq("center_id", center.id);
        const usedByOthers = (centerTeachers || []).reduce((sum: number, t: any) => sum + (t.max_students || 0), 0);
        if (usedByOthers + newTeacherMaxStudents > center.max_students) {
          const remaining = Math.max(0, center.max_students - usedByOthers);
          return new Response(JSON.stringify({ success: false, message: `⛔ ده هيتخطى سقف الطلاب الكلي لسنترك (${center.max_students}) — المتبقي المتاح للتوزيع: ${remaining} طالب` }),
            { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }

      const defaultHash = await hashPassword(clientId);
      const deviceSecretBytes = crypto.getRandomValues(new Uint8Array(16));
      const deviceSecret = Array.from(deviceSecretBytes).map((b) => b.toString(16).padStart(2, "0")).join("");

      // ✅ المدرس ده بيتربط بالسنتر مباشرة من لحظة إنشائه (مش محتاج خطوة ضم منفصلة زي الأدمن)
      const { data: teacher, error } = await supabase.from("teachers").insert({
        client_id: clientId, name, password_hash: defaultHash, must_change_password: true, is_active: true,
        max_students: newTeacherMaxStudents, student_count: 0, device_secret: deviceSecret, center_id: center.id,
        // ✅ Aug 2026 (تصحيح): مفيش نظام صلاحيات جزئي للمدرس — كل مدرس (سواء عند الماستر أو عند سنتر)
        // بيتضاف بكل الصلاحيات مفعّلة تلقائياً. requestedPermissions اتشالت من الواجهة ومبتتبعتش تاني.
        permissions: {
          can_manage_students: true, can_manage_groups: true, can_manage_grades: true, can_manage_payments: true,
          can_manage_books: true, can_send_messages: true, can_view_reports: true, can_view_financial: true,
          can_use_backup: true, can_manage_assistants: true, can_use_rfid: true,
          // ✅ Aug 2026 (تصحيح): نفس الغياب اللي اتصحح في admin-manage-teacher — can_create_exams
          // كان ناقص هنا كمان، فأي مدرس بيضيفه صاحب سنتر كان بياخد 403 على أي أكشن اختبارات إلكترونية
          can_create_exams: true,
        },
      }).select().single();

      if (error) {
        return new Response(JSON.stringify({ success: false, message: error.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      return new Response(JSON.stringify({ success: true, message: `✅ تم إضافة المدرس ${name} للسنتر بنجاح`, data: teacher }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ صاحب السنتر يقدر يشوف/يعطّل مدرسيه (بدون تعديل صلاحيات الباقة، ده حق الماستر أدمن بس)
    if (action === "toggleTeacherActive") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { teacherClientId, isActive } = body;
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      const { data: teacher } = await supabase.from("teachers").select("center_id").eq("client_id", teacherClientId).maybeSingle();
      if (!center || !teacher || teacher.center_id !== center.id) {
        return new Response(JSON.stringify({ success: false, message: "⛔ هذا المدرس ليس تابعاً لسنترك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      await supabase.from("teachers").update({ is_active: isActive === true }).eq("client_id", teacherClientId);
      return new Response(JSON.stringify({ success: true, message: isActive ? "✅ تم تفعيل المدرس" : "✅ تم تعطيل المدرس" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

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

    // ✅ صاحب السنتر يشوف كل المدرسين التابعين له
    if (action === "listTeachers") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: teachers } = await supabase
        .from("teachers").select("client_id, name, student_count, max_students, permissions, is_active, center_sharing_permissions").eq("center_id", center.id);
      return new Response(JSON.stringify({ success: true, data: teachers || [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "setBranding") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { brandLogoUrl, brandColor } = body;
      const updates: any = {};
      if (brandLogoUrl !== undefined) updates.brand_logo_url = brandLogoUrl || null;
      if (brandColor !== undefined) updates.brand_color = brandColor || null;
      const { error } = await supabase.from("centers").update(updates).eq("client_id", payload.clientId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم حفظ الشعار/اللون بنجاح" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ صاحب السنتر يعدّل اسم مدرس تابع له. لا حذف حقيقي — نفس منطق الأرشفة بدل الحذف المتبع
    // في باقي المشروع (convention #6/الأرشفة)، فتعطيل الحساب (toggleTeacherActive الموجودة) هو البديل الآمن.
    // ✅ Aug 2026: بقى ممكن كمان تعديل عدد طلاب المدرس وصلاحياته (مش بس الاسم)، بنفس فحص سقف السنتر
    if (action === "updateTeacher") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { teacherClientId, name, maxStudents, permissions: updatedPermissions } = body;
      if (!teacherClientId || !name) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ teacherClientId و name مطلوبين" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id, max_students").eq("client_id", payload.clientId).maybeSingle();
      const { data: teacher } = await supabase.from("teachers").select("center_id, max_students").eq("client_id", teacherClientId).maybeSingle();
      if (!center || !teacher || teacher.center_id !== center.id) {
        return new Response(JSON.stringify({ success: false, message: "⛔ هذا المدرس ليس تابعاً لسنترك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const updateData: any = { name };
      if (maxStudents !== undefined) {
        const newMax = Number(maxStudents) || 0;
        if (center.max_students && center.max_students > 0) {
          if (newMax <= 0) {
            return new Response(JSON.stringify({ success: false, message: "⚠️ سنترك عنده سقف لعدد الطلاب، لازم تحدد عدد طلاب واضح لكل مدرس (مش 0 / غير محدود)" }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
          const { data: centerTeachers } = await supabase.from("teachers").select("client_id, max_students").eq("center_id", center.id);
          const usedByOthers = (centerTeachers || []).filter((t: any) => t.client_id !== teacherClientId).reduce((sum: number, t: any) => sum + (t.max_students || 0), 0);
          if (usedByOthers + newMax > center.max_students) {
            const remaining = Math.max(0, center.max_students - usedByOthers);
            return new Response(JSON.stringify({ success: false, message: `⛔ ده هيتخطى سقف الطلاب الكلي لسنترك (${center.max_students}) — المتبقي المتاح للتوزيع: ${remaining} طالب` }),
              { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
          }
        }
        updateData.max_students = newMax;
      }
      if (updatedPermissions !== undefined) updateData.permissions = updatedPermissions;

      const { error } = await supabase.from("teachers").update(updateData).eq("client_id", teacherClientId);
      if (error) throw new Error(error.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم تحديث بيانات المدرس" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ صاحب السنتر يشوف كل طلاب كل مدرسيه في قائمة واحدة موحّدة.
    // ✅ قرار تصميمي: عرض قائمة الطلاب (الاسم/المجموعة) بيُعتبر حق إداري أساسي لصاحب السنتر
    // (زي تفعيل/تعطيل المدرس بالظبط)، ومش محتاج موافقة صريحة من المدرس — بعكس التفاصيل
    // الأكاديمية/المالية/الحضور (share_academic_details إلخ) اللي فعلاً محتاجة موافقة صريحة.
    // لو ده مايناسبش سياسة المنتج الفعلية، سهل نضيف علم مشاركة جديد (share_roster) ونقيّد بيه هنا.
    if (action === "listAllStudents") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: teachers } = await supabase.from("teachers").select("client_id, name").eq("center_id", center.id);
      if (!teachers || teachers.length === 0) {
        return new Response(JSON.stringify({ success: true, data: [] }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const teacherIds = teachers.map((t: any) => t.client_id);
      const teacherNames: Record<string, string> = {};
      teachers.forEach((t: any) => { teacherNames[t.client_id] = t.name; });

      const { data: students, error } = await supabase
        .from("students").select("uid, name, group_name, teacher_id, phone, parent_phone")
        .in("teacher_id", teacherIds).is("archived_at", null).order("name");
      if (error) throw new Error(error.message);

      const result = (students || []).map((s: any) => ({
        uid: s.uid, name: s.name, groupName: s.group_name, phone: s.phone, parentPhone: s.parent_phone,
        teacherClientId: s.teacher_id, teacherName: teacherNames[s.teacher_id] || s.teacher_id,
      }));
      return new Response(JSON.stringify({ success: true, data: result }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ نقل طالب من مدرس لمدرس تاني داخل نفس السنتر — بينقل معاه كل بياناته المرتبطة
    // (درجات، مدفوعات، سداد مذكرات، حضور، وربط الكارت لو موجود)، بنفس أسلوب transfer-student
    // (نقل مجموعة لمجموعة) بس هنا بين مدرسين. لازم المجموعة الجديدة تكون موجودة فعلاً عند المدرس التاني.
    if (action === "moveStudent") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { studentUid, fromTeacherClientId, toTeacherClientId, newGroupName } = body;
      if (!studentUid || !fromTeacherClientId || !toTeacherClientId || !newGroupName) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid و fromTeacherClientId و toTeacherClientId و newGroupName مطلوبين" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (fromTeacherClientId === toTeacherClientId) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ اختر مدرس مختلف عن المدرس الحالي" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: bothTeachers } = await supabase
        .from("teachers").select("client_id, center_id, max_students, student_count")
        .in("client_id", [fromTeacherClientId, toTeacherClientId]);
      const fromTeacher = (bothTeachers || []).find((t: any) => t.client_id === fromTeacherClientId);
      const toTeacher = (bothTeachers || []).find((t: any) => t.client_id === toTeacherClientId);
      if (!fromTeacher || fromTeacher.center_id !== center.id || !toTeacher || toTeacher.center_id !== center.id) {
        return new Response(JSON.stringify({ success: false, message: "⛔ المدرسين لازم يكونوا تابعين لسنترك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (toTeacher.max_students > 0 && toTeacher.student_count >= toTeacher.max_students) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ المدرس الوجهة وصل للحد الأقصى لعدد الطلاب" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: student } = await supabase.from("students").select("name, teacher_id").eq("uid", studentUid).maybeSingle();
      if (!student || student.teacher_id !== fromTeacherClientId) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب غير موجود عند المدرس المحدد" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: targetGroup } = await supabase
        .from("groups").select("id").eq("teacher_id", toTeacherClientId).eq("name", newGroupName).maybeSingle();
      if (!targetGroup) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ المجموعة المحددة غير موجودة عند المدرس الوجهة — أنشئها أولاً" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const capacity = await checkGroupCapacity(supabase, toTeacherClientId, newGroupName);
      if (!capacity.ok) {
        return new Response(JSON.stringify({ success: false, message: capacity.message }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const studentsUpdate = await supabase.from("students")
        .update({ teacher_id: toTeacherClientId, group_name: newGroupName }).eq("uid", studentUid);
      if (studentsUpdate.error) {
        return new Response(JSON.stringify({ success: false, message: "فشل نقل الطالب: " + studentsUpdate.error.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      await Promise.all([
        supabase.from("grades").update({ teacher_id: toTeacherClientId, group_name: newGroupName }).eq("student_uid", studentUid),
        supabase.from("payments").update({ teacher_id: toTeacherClientId, group_name: newGroupName }).eq("student_uid", studentUid),
        supabase.from("book_payments").update({ teacher_id: toTeacherClientId, group_name: newGroupName }).eq("student_uid", studentUid),
        supabase.from("attendance").update({ teacher_id: toTeacherClientId, group_name: newGroupName }).eq("student_uid", studentUid),
        supabase.from("system_cards").update({ teacher_id: toTeacherClientId }).eq("student_uid", studentUid).eq("teacher_id", fromTeacherClientId),
      ]);

      const [{ count: fromCount }, { count: toCount }] = await Promise.all([
        supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", fromTeacherClientId).is("archived_at", null),
        supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", toTeacherClientId).is("archived_at", null),
      ]);
      await Promise.all([
        supabase.from("teachers").update({ student_count: fromCount }).eq("client_id", fromTeacherClientId),
        supabase.from("teachers").update({ student_count: toCount }).eq("client_id", toTeacherClientId),
      ]);

      await supabase.from("activity_logs").insert({
        client_id: toTeacherClientId, teacher_id: toTeacherClientId,
        action_type: "center_move_student", entity_type: "student", entity_id: studentUid,
        details: { student_name: student.name, from_teacher: fromTeacherClientId, to_teacher: toTeacherClientId, new_group: newGroupName },
        performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
      });

      return new Response(JSON.stringify({ success: true, message: `✅ تم نقل ${student.name} بنجاح، مع كل بياناته` }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ صاحب السنتر يشوف تفصيل مالي مجمّع شهري لكل مدرس (للتقارير القابلة للتصدير) —
    // نفس بيانات get-center-dashboard (إيراد الشهر الحالي) لكن بامتداد لعدة شهور لو طُلب
    if (action === "getFinancialReport") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: teachers } = await supabase.from("teachers").select("client_id, name, center_sharing_permissions").eq("center_id", center.id);
      if (!teachers || teachers.length === 0) {
        return new Response(JSON.stringify({ success: true, data: [] }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const teacherIds = teachers.map((t: any) => t.client_id);

      const now = new Date();
      const rangeStart = new Date(Date.UTC(now.getFullYear(), now.getMonth(), 1)).toISOString();
      const rangeEnd = new Date(Date.UTC(now.getFullYear(), now.getMonth() + 1, 1)).toISOString();

      // ✅ expenses.expense_date عمود من نوع date — يُقارن كنص YYYY-MM-DD وليس كـ timestamp (قاعدة #2)
      const rangeStartDate = rangeStart.split("T")[0];
      const rangeEndDate = rangeEnd.split("T")[0];
      const [{ data: payments }, { data: bookPayments }, { data: expenses }] = await Promise.all([
        supabase.from("payments").select("teacher_id, amount").in("teacher_id", teacherIds).gte("created_at", rangeStart).lt("created_at", rangeEnd),
        supabase.from("book_payments").select("teacher_id, amount").in("teacher_id", teacherIds).gte("paid_at", rangeStart).lt("paid_at", rangeEnd),
        supabase.from("expenses").select("teacher_id, amount").in("teacher_id", teacherIds).gte("expense_date", rangeStartDate).lt("expense_date", rangeEndDate),
      ]);

      const revenueByTeacher: Record<string, number> = {};
      (payments || []).forEach((p: any) => { revenueByTeacher[p.teacher_id] = (revenueByTeacher[p.teacher_id] || 0) + Number(p.amount); });
      (bookPayments || []).forEach((p: any) => { revenueByTeacher[p.teacher_id] = (revenueByTeacher[p.teacher_id] || 0) + Number(p.amount); });
      const expensesByTeacher: Record<string, number> = {};
      (expenses || []).forEach((e: any) => { expensesByTeacher[e.teacher_id] = (expensesByTeacher[e.teacher_id] || 0) + Number(e.amount); });

      // ✅ المصروفات (زي تفاصيل الدخل الدقيقة) بتتطلب موافقة share_financial_details صراحة —
      // بدونها بيفضل الإيراد الإجمالي ظاهر (زي لوحة السنتر الأساسية) لكن الأرباح الصافية مخفية
      const result = teachers.map((t: any) => {
        const sharesFinancial = t.center_sharing_permissions?.share_financial_details === true;
        const revenue = revenueByTeacher[t.client_id] || 0;
        const expensesTotal = sharesFinancial ? (expensesByTeacher[t.client_id] || 0) : null;
        return {
          teacherClientId: t.client_id, teacherName: t.name,
          revenueThisMonth: revenue,
          expensesThisMonth: expensesTotal,
          netProfitThisMonth: expensesTotal !== null ? revenue - expensesTotal : null,
          sharesFinancialDetails: sharesFinancial,
        };
      });

      return new Response(JSON.stringify({ success: true, data: result }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ============================================
    // ✅ صاحب السنتر: عرض حصص "النهاردة" اللي اتنشأت لكل مدرسيه في مكان واحد (قراءة فقط)
    // ✅ Aug 2026 (Phase I follow-up 10): بيقرأ دلوقتي من الجدول الجديد attendance_sessions
    // (حصص يومية فعلية) بدل الجدول القديم group_sessions (جدول أسبوعي متكرر) اللي اتلغى خالص —
    // من غير أي تعديل على صلاحيات الإنشاء/الحذف (لسه بتاعة المدرس بس عن طريق manage-group-sessions)
    // ============================================
    if (action === "listGroupSessions") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: teachers } = await supabase.from("teachers").select("client_id, name").eq("center_id", center.id);
      if (!teachers || teachers.length === 0) {
        return new Response(JSON.stringify({ success: true, data: [] }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const teacherIds = teachers.map((t: any) => t.client_id);
      const teacherNames: Record<string, string> = {};
      teachers.forEach((t: any) => { teacherNames[t.client_id] = t.name; });

      const cairoNow = new Date(new Date().toLocaleString("en-US", { timeZone: "Africa/Cairo" }));
      const today = cairoNow.toISOString().split("T")[0];

      const { data: sessions, error: sessionsError } = await supabase
        .from("attendance_sessions").select("id, teacher_id, group_name, session_label, instructor_name, absence_threshold_minutes, created_at")
        .in("teacher_id", teacherIds).eq("session_date", today).order("created_at", { ascending: false });
      if (sessionsError) {
        return new Response(JSON.stringify({ success: false, message: sessionsError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const result = (sessions || []).map((s: any) => ({
        id: s.id,
        teacherClientId: s.teacher_id,
        teacherName: teacherNames[s.teacher_id] || s.teacher_id,
        groupName: s.group_name,
        sessionLabel: s.session_label,
        instructorName: s.instructor_name,
        absenceThresholdMinutes: s.absence_threshold_minutes,
        createdAt: s.created_at,
      }));

      return new Response(JSON.stringify({ success: true, data: result }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ (طلب) لازم كارت "تسجيل طالب جديد" في center-students.html يطبّق نفس منطق تسجيل الطالب في
    // students.html — يعني تختار المدرس الأول وبعدين تظهرلك مجموعاته الموجودة فعلاً (مش تكتب اسم مجموعة
    // بنفسك بالغلط). بترجع كل مجموعات كل مدرسين السنتر مع اسم المدرس التابعة له، بنفس منطق دمج
    // جدول groups + أسماء مجموعات الطلاب اللي manage-group's handleListDetailed أصلاً بيستخدمه
    if (action === "listGroups") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: teachers } = await supabase.from("teachers").select("client_id, name").eq("center_id", center.id);
      if (!teachers || teachers.length === 0) {
        return new Response(JSON.stringify({ success: true, data: [] }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const teacherIds = teachers.map((t: any) => t.client_id);
      const teacherNames: Record<string, string> = {};
      teachers.forEach((t: any) => { teacherNames[t.client_id] = t.name; });

      const { data: groupRows, error: groupRowsError } = await supabase
        .from("groups").select("name, teacher_id").in("teacher_id", teacherIds);
      if (groupRowsError) {
        return new Response(JSON.stringify({ success: false, message: groupRowsError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: studentRows, error: studentRowsError } = await supabase
        .from("students").select("group_name, teacher_id").in("teacher_id", teacherIds).not("group_name", "is", null);
      if (studentRowsError) {
        return new Response(JSON.stringify({ success: false, message: studentRowsError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const seen = new Set<string>();
      const result: { teacherClientId: string; teacherName: string; groupName: string }[] = [];
      const addGroup = (teacherClientId: string, groupName: string) => {
        const key = teacherClientId + "|" + groupName;
        if (seen.has(key)) return;
        seen.add(key);
        result.push({ teacherClientId, teacherName: teacherNames[teacherClientId] || teacherClientId, groupName });
      };
      (groupRows || []).forEach((g: any) => addGroup(g.teacher_id, g.name));
      (studentRows || []).forEach((s: any) => addGroup(s.teacher_id, s.group_name));
      result.sort((a, b) => a.teacherName.localeCompare(b.teacherName, "ar") || a.groupName.localeCompare(b.groupName, "ar"));

      return new Response(JSON.stringify({ success: true, data: result }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ صاحب السنتر يسجل طالب جديد بنفسه ويوزعه على أي مدرس تابع لسنتره مباشرة
    // (نفس منطق manage-student/handleAdd لكن بدون قيد "المدرس بيضيف لنفسه فقط")
    if (action === "createStudent") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { teacherClientId, groupName, uid, name, phone, parentPhone } = body;
      if (!teacherClientId || !groupName || !uid || !name || !parentPhone) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة: teacherClientId, groupName, uid, name, parentPhone" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: teacher } = await supabase
        .from("teachers").select("client_id, name, center_id, max_students, student_count").eq("client_id", teacherClientId).maybeSingle();
      if (!teacher || teacher.center_id !== center.id) {
        return new Response(JSON.stringify({ success: false, message: "⛔ المدرس المحدد ليس تابعاً لسنترك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (teacher.max_students > 0 && teacher.student_count >= teacher.max_students) {
        return new Response(JSON.stringify({ success: false, message: `تم الوصول إلى الحد الأقصى لعدد طلاب هذا المدرس (${teacher.max_students})` }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const capacity = await checkGroupCapacity(supabase, teacherClientId, groupName);
      if (!capacity.ok) {
        return new Response(JSON.stringify({ success: false, message: capacity.message }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: existingStudent } = await supabase.from("students").select("uid").eq("uid", uid).maybeSingle();
      if (existingStudent) {
        return new Response(JSON.stringify({ success: false, message: "UID موجود مسبقاً" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: existingParent } = await supabase.from("parents").select("phone").eq("phone", parentPhone).maybeSingle();
      let tempPassword = "";
      if (!existingParent) {
        tempPassword = parentPhone;
        const hashedPassword = await hashPassword(tempPassword);
        const { error: insertParentError } = await supabase
          .from("parents").insert({ phone: parentPhone, name: `ولي أمر ${name}`, password_hash: hashedPassword, must_change_password: true, is_active: true });
        if (insertParentError) {
          return new Response(JSON.stringify({ success: false, message: `فشل إنشاء ولي الأمر: ${insertParentError.message}` }),
            { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }

      const { data: student, error: insertError } = await supabase
        .from("students").insert({ uid, name, phone: phone || null, parent_phone: parentPhone, group_name: groupName, teacher_id: teacherClientId }).select().single();
      if (insertError) throw new Error(`فشل إضافة الطالب: ${insertError.message}`);

      // ✅ الكارت ممكن يكون أصلاً موزّع على المدرس ده تحديداً، أو لسه في "بركة" السنتر المشتركة (مش موزّع لحد).
      // في الحالة التانية بنوزّعه على المدرس تلقائياً كجزء من نفس عملية تسجيل الطالب.
      const { data: matchingCard } = await supabase
        .from("system_cards").select("id, teacher_id, center_id").eq("card_uid", uid).eq("status", "assigned").eq("is_active", true).is("student_uid", null).maybeSingle();
      if (matchingCard && (matchingCard.teacher_id === teacherClientId || (matchingCard.teacher_id === null && matchingCard.center_id === center.id))) {
        await supabase.from("system_cards").update({
          student_uid: uid, linked_at: new Date().toISOString(),
          ...(matchingCard.teacher_id === null ? { teacher_id: teacherClientId, assigned_at: new Date().toISOString() } : {}),
        }).eq("id", matchingCard.id);
      }

      const { count } = await supabase.from("students").select("id", { count: "exact", head: true }).eq("teacher_id", teacherClientId).is("archived_at", null);
      await supabase.from("teachers").update({ student_count: count }).eq("client_id", teacherClientId);

      await supabase.from("activity_logs").insert({
        client_id: teacherClientId, teacher_id: teacherClientId,
        action_type: "center_add_student", entity_type: "student", entity_id: String(student.id),
        details: { student_id: student.id, student_uid: uid, student_name: name, group_name: groupName, parent_phone: parentPhone, phone: phone || null, added_by_center: payload.clientId },
        performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
      });

      return new Response(JSON.stringify({ success: true, message: "تم إضافة الطالب بنجاح", data: student, tempPassword, parentExists: !!existingParent }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ ربط طالب موجود بمدرس إضافي (بالإضافة لمدرسه الأساسي) — الطالب يظهر عند أكتر من مدرس
    // في نفس الوقت. لا يغيّر teacher_id الأساسي للطالب، بس بيضيفه لجدول student_teacher_links.
    if (action === "linkStudentToTeacher") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { studentUid, teacherClientId, groupName } = body;
      if (!studentUid || !teacherClientId) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid و teacherClientId مطلوبين" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: student } = await supabase.from("students").select("uid, name, teacher_id").eq("uid", studentUid).maybeSingle();
      if (!student) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (student.teacher_id === teacherClientId) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب أصلاً تابع لهذا المدرس" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: ownerTeacher } = await supabase.from("teachers").select("client_id, center_id").eq("client_id", student.teacher_id).maybeSingle();
      const { data: targetTeacher } = await supabase.from("teachers").select("client_id, center_id").eq("client_id", teacherClientId).maybeSingle();
      if (!ownerTeacher || ownerTeacher.center_id !== center.id || !targetTeacher || targetTeacher.center_id !== center.id) {
        return new Response(JSON.stringify({ success: false, message: "⛔ المدرسين لازم يكونوا تابعين لسنترك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: existingLink } = await supabase
        .from("student_teacher_links").select("id").eq("student_uid", studentUid).eq("teacher_id", teacherClientId).maybeSingle();
      if (existingLink) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب مربوط بالفعل بهذا المدرس" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { error: linkError } = await supabase.from("student_teacher_links").insert({
        student_uid: studentUid, teacher_id: teacherClientId, group_name: groupName || null, linked_by_center_id: center.id,
      });
      if (linkError) {
        return new Response(JSON.stringify({ success: false, message: "فشل الربط: " + linkError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      await supabase.from("activity_logs").insert({
        client_id: teacherClientId, teacher_id: teacherClientId,
        action_type: "center_link_student", entity_type: "student", entity_id: studentUid,
        details: { student_name: student.name, primary_teacher: student.teacher_id, linked_teacher: teacherClientId },
        performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
      });
      return new Response(JSON.stringify({ success: true, message: `✅ تم ربط ${student.name} بالمدرس بنجاح` }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ فك ربط طالب من مدرس إضافي (بدون التأثير على مدرسه الأساسي)
    if (action === "unlinkStudentFromTeacher") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { studentUid, teacherClientId } = body;
      if (!studentUid || !teacherClientId) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid و teacherClientId مطلوبين" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { error: delError } = await supabase
        .from("student_teacher_links").delete().eq("student_uid", studentUid).eq("teacher_id", teacherClientId).eq("linked_by_center_id", center.id);
      if (delError) {
        return new Response(JSON.stringify({ success: false, message: "فشل فك الربط: " + delError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ success: true, message: "✅ تم فك الربط بنجاح" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ عرض كل روابط الطلاب متعددي المدرسين داخل السنتر
    if (action === "listStudentLinks") {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: center } = await supabase.from("centers").select("id").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: links, error: linksError } = await supabase
        .from("student_teacher_links").select("id, student_uid, teacher_id, group_name, created_at").eq("linked_by_center_id", center.id).order("created_at", { ascending: false });
      if (linksError) throw new Error(linksError.message);
      return new Response(JSON.stringify({ success: true, data: links || [] }),
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
