// supabase/functions/get-notifications/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

import { corsHeaders, AuthError, verifyToken, ownerClientId, requireParentPhone, requireAssistantPermission, authErrorResponse } from "../_shared/auth.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SERVICE_ROLE غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });

  try {
    const payload = await verifyToken(req);
    const body = await req.json().catch(() => ({} as any));

    // ============================================
    // محادثة ثنائية الاتجاه مع ولي أمر طالب محدد — سجل رسائل ثريد كامل + تعليمه كمقروء لطرف القراءة
    // ============================================
    if (body?.mode === "conversation" && body?.studentUid) {
      if (payload.role === "parent") {
        const parentPhone = requireParentPhone(payload);
        const { data, error } = await supabase
          .from("conversation_messages").select("*")
          .eq("student_uid", body.studentUid).eq("parent_phone", parentPhone)
          .order("created_at", { ascending: true });
        if (error) throw new Error(error.message);
        const unreadIds = (data || []).filter((m: any) => m.sender_role !== "parent" && !m.is_read_by_parent).map((m: any) => m.id);
        if (unreadIds.length > 0) await supabase.from("conversation_messages").update({ is_read_by_parent: true }).in("id", unreadIds);
        return new Response(JSON.stringify({ success: true, data: data || [] }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (payload.role === "teacher" || payload.role === "assistant") {
        // ✅ Batch 23 (بند 8): قراءة ثريد المحادثة بقت مربوطة بصلاحية manage_conversations —
        // قبل كده أي مساعد كان يقدر يقرا محادثات أي طالب من غير أي تحقق صلاحية خالص
        await requireAssistantPermission(payload, "manage_conversations");
        const finalClientId = ownerClientId(payload);
        const { data, error } = await supabase
          .from("conversation_messages").select("*")
          .eq("student_uid", body.studentUid).eq("teacher_id", finalClientId)
          .order("created_at", { ascending: true });
        if (error) throw new Error(error.message);
        const unreadIds = (data || []).filter((m: any) => m.sender_role === "parent" && !m.is_read_by_teacher).map((m: any) => m.id);
        if (unreadIds.length > 0) await supabase.from("conversation_messages").update({ is_read_by_teacher: true }).in("id", unreadIds);
        return new Response(JSON.stringify({ success: true, data: data || [] }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
    }

    // ============================================
    // صندوق وارد المحادثات (جانب المدرس/المساعد) — آخر رسالة + عدد غير المقروء لكل طالب راسل أو اتراسل
    // ============================================
    if (body?.mode === "conversationInbox") {
      if (payload.role !== "teacher" && payload.role !== "assistant") throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
      // ✅ Batch 23 (بند 8): صندوق وارد المحادثات بقى مربوط بصلاحية manage_conversations للمساعد
      await requireAssistantPermission(payload, "manage_conversations");
      const finalClientId = ownerClientId(payload);

      const { data: messages, error } = await supabase
        .from("conversation_messages").select("*")
        .eq("teacher_id", finalClientId)
        .order("created_at", { ascending: false });
      if (error) throw new Error(error.message);

      const { data: students } = await supabase.from("students").select("uid, name").eq("teacher_id", finalClientId);
      const nameByUid = new Map<string, string>((students || []).map((s: any) => [s.uid, s.name]));

      const threads = new Map<string, any>();
      (messages || []).forEach((m: any) => {
        if (!threads.has(m.student_uid)) {
          threads.set(m.student_uid, {
            studentUid: m.student_uid,
            studentName: nameByUid.get(m.student_uid) || "طالب",
            lastMessage: m.message,
            lastMessageAt: m.created_at,
            lastSenderRole: m.sender_role,
            unreadCount: 0,
          });
        }
        if (m.sender_role === "parent" && !m.is_read_by_teacher) {
          threads.get(m.student_uid).unreadCount += 1;
        }
      });

      return new Response(JSON.stringify({ success: true, data: Array.from(threads.values()) }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    let query = supabase.from("notifications").select("*").order("created_at", { ascending: false }).limit(60);

    if (payload.role === "parent") {
      const parentPhone = requireParentPhone(payload);
      // ✅ (طلب) عزل إشعارات ولي الأمر عن إشعارات الطالب — نفس الصف كان بيتقرا قبل كده من
      // الاثنين لو فيه student_uid + parent_phone مع بعض. audience.is.null للتوافق مع
      // الصفوف القديمة قبل إضافة العمود ده (كانت بتتبعت لولي الأمر بس أصلاً)
      query = query.eq("parent_phone", parentPhone).or("audience.eq.parent,audience.is.null");
    } else if (payload.role === "assistant") {
      query = query.eq("assistant_id", payload.sub);
    } else if (payload.role === "student") {
      // ✅ (طلب) نفس العزل من ناحية الطالب — الصفوف القديمة (قبل audience) كانت دايماً
      // موجّهة لولي الأمر أصلاً مش للطالب، فمعندناش صفوف قديمة "للطالب" ناقصة العمود —
      // بالتالي هنا بس audience = student بالظبط، من غير احتمال null
      query = query.eq("student_uid", payload.sub).eq("audience", "student");
    } else if (payload.role === "teacher") {
      // ✅ صندوق وارد المدرس (Aug 2026) — إعلانات صاحب السنتر لمدرسيه + رسائل أولياء الأمور الجديدة فقط،
      // مش كل حركة النظام (عمود teacher_id مستخدم أصلاً كـ"المدرس المالك" في كل الإشعارات التانية،
      // فلازم نقيّد بـ type كمان عشان منرجّعش لمدرس إشعارات كل أولياء أمور/مساعدين طلابه بالغلط)
      const finalClientId = ownerClientId(payload);
      query = query.eq("teacher_id", finalClientId).in("type", ["center_teacher_message", "parent_message"]);
    } else {
      throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
    }

    const { data, error } = await query;

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const unreadCount = (data || []).filter((n: any) => !n.is_read).length;

    return new Response(JSON.stringify({ success: true, data: data || [], unreadCount }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
