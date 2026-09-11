// supabase/functions/manage-push-token/index.ts
// ✅ دالة موحّدة تجمع register-push-token + unregister-push-token — action: register | unregister
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, TokenPayload, AuthError, verifyToken } from "../_shared/auth.ts";

function requireParentPhone(payload: TokenPayload): string {
  if (payload.role !== "parent" || !payload.phone) throw new AuthError("⚠️ التوكن غير صالح لولي أمر", 401);
  return payload.phone;
}

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

function resolveRecipient(payload: TokenPayload): { recipientType: string; recipientId: string } {
  // ✅ (طلب) كان الطالب مش متعامل معاه هنا خالص — بيقع في شرط "else" الأخير وبيتسجل توكنه
  // كـ"teacher" برقم teacherId (معرّف المدرس التابع له)! ده بيخلط توكنات الطلاب بتوكنات
  // المدرس نفسه في push_tokens، فمفيش إشعار حقيقي كان ممكن يوصل للطالب أصلاً حتى لو
  // Firebase كانت شغالة، وممكن كمان يبعت إشعارات المدرس غلط لجهاز الطالب
  if (payload.role === "parent") return { recipientType: "parent", recipientId: requireParentPhone(payload) };
  if (payload.role === "assistant") return { recipientType: "assistant", recipientId: String(payload.sub) };
  if (payload.role === "student") return { recipientType: "student", recipientId: String(payload.sub) };
  return { recipientType: "teacher", recipientId: payload.clientId || payload.teacherId || "" };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    const { action, token, platform } = await req.json();
    if (!token) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ token مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { recipientType, recipientId } = resolveRecipient(payload);

    if (action === "register") {
      const { error } = await supabase.from("push_tokens").upsert(
        { recipient_type: recipientType, recipient_id: recipientId, token, platform: platform || "android", updated_at: new Date().toISOString() },
        { onConflict: "recipient_type,recipient_id,token" }
      );
      if (error) {
        console.error("❌ فشل تسجيل توكن الإشعارات:", error);
        return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ success: true, message: "✅ تم تسجيل الجهاز للإشعارات" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "unregister") {
      const { error } = await supabase.from("push_tokens").delete()
        .eq("recipient_type", recipientType).eq("recipient_id", recipientId).eq("token", token);
      if (error) {
        console.error("❌ فشل حذف توكن الإشعارات:", error);
        return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ success: true, message: "✅ تم إلغاء تسجيل الجهاز من الإشعارات" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
