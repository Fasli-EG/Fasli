// supabase/functions/bulk-import-students/index.ts
// ✅ استيراد جماعي للطلاب من إكسل — الملف بيتقرا في المتصفح، وقائمة الطلاب بتتبعت هنا دفعة واحدة
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
};

interface TokenPayload { sub: string; clientId?: string; teacherId?: string; role: string; name: string; }

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

    // ✅ (طلب) لو أي مجموعة وصلت لحدها الأقصى (max_students)، لازم نرفض إضافة طلاب جدد ليها —
    // حتى وسط استيراد جماعي فيه كذا صف بيستهدفوا نفس المجموعة. بنحسب المساحة المتبقية لكل
    // مجموعة مرة واحدة قبل الحلقة، وبعدين بننقصها صف بصف كل ما صف ينجح، عشان صفين في نفس
    // الملف يستهدفوا نفس المجموعة الممتلئة ما يعدّوش الحد الأقصى مع بعض.
    const distinctGroupNames = [...new Set(students.map((r: any) => String(r.groupName || "").trim()).filter(Boolean))];
    const remainingCapacity: Record<string, number> = {}; // مفيش مفتاح للمجموعة = بلا حد أقصى
    if (distinctGroupNames.length > 0) {
      const { data: groupRows } = await supabase
        .from("groups").select("name, max_students").eq("teacher_id", tokenClientId).in("name", distinctGroupNames);
      for (const g of groupRows || []) {
        if (!g.max_students || g.max_students <= 0) continue;
        const { count: primaryCount } = await supabase
          .from("students").select("uid", { count: "exact", head: true }).eq("teacher_id", tokenClientId).eq("group_name", g.name);
        const { count: linkedCount } = await supabase
          .from("student_group_links").select("id", { count: "exact", head: true }).eq("teacher_id", tokenClientId).eq("group_name", g.name);
        remainingCapacity[g.name] = g.max_students - ((primaryCount || 0) + (linkedCount || 0));
      }
    }

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
      if (groupName in remainingCapacity && remainingCapacity[groupName] <= 0) {
        results.push({ row: rowNum, name, status: "failed", reason: `المجموعة "${groupName}" وصلت للحد الأقصى لعدد الطلاب` });
        continue;
      }

      let uid = generateUid();
      let uidAttempts = 0;
      while (uidAttempts < 5) {
        const { data: existingStudent } = await supabase.from("students").select("uid").eq("uid", uid).maybeSingle();
        if (!existingStudent) break;
        uid = generateUid();
        uidAttempts++;
      }

      const { data: existingParent } = await supabase.from("parents").select("phone").eq("phone", parentPhone).maybeSingle();
      if (!existingParent) {
        const hashedPassword = await hashPassword(parentPhone);
        await supabase.from("parents").insert({
          phone: parentPhone, name: `ولي أمر ${name}`, password_hash: hashedPassword, must_change_password: true, is_active: true,
        });
      }

      const { error: insertError } = await supabase.from("students").insert({
        uid, name, phone: phone || null, parent_phone: parentPhone, group_name: groupName, teacher_id: tokenClientId,
      });

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
