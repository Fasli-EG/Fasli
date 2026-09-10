// supabase/functions/upload-book-file/index.ts
// ✅ رفع ملف PDF فعلي لمذكرة موجودة، وحذفه لو حبيت تستبدليه
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
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

// ✅ الحد الأقصى لحجم الملف — 8 ميجا (حد معقول لملف PDF مذكرة، وأقل من حد الطلبات المسموح بيه للدوال)
const MAX_FILE_SIZE_BYTES = 8 * 1024 * 1024;

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

    const body = await req.json();
    const action = body.action;

    if (action === "upload") {
      const { bookId, fileName, fileBase64 } = body;
      if (!bookId || !fileName || !fileBase64) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (!fileName.toLowerCase().endsWith(".pdf")) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ لازم يكون الملف بصيغة PDF" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: book } = await supabase.from("books").select("teacher_id, file_url").eq("id", bookId).maybeSingle();
      if (!book || book.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ فك تشفير base64 والتأكد من حجم الملف قبل الرفع، عشان منستهلكش تخزين بملف ضخم بالغلط
      const base64Data = fileBase64.includes(",") ? fileBase64.split(",")[1] : fileBase64;
      const binaryData = Uint8Array.from(atob(base64Data), (c) => c.charCodeAt(0));
      if (binaryData.length > MAX_FILE_SIZE_BYTES) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ حجم الملف أكبر من الحد المسموح (8 ميجا)" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ✅ لو فيه ملف قديم مرفوع للمذكرة دي، نحذفه الأول قبل ما نرفع الجديد
      if (book.file_url) {
        const oldPath = book.file_url.split("/book-files/")[1];
        if (oldPath) await supabase.storage.from("book-files").remove([oldPath]);
      }

      const storagePath = `${tokenClientId}/${bookId}-${Date.now()}.pdf`;
      const { error: uploadError } = await supabase.storage.from("book-files").upload(storagePath, binaryData, {
        contentType: "application/pdf", upsert: true,
      });
      if (uploadError) throw new Error(uploadError.message);

      const { data: publicUrlData } = supabase.storage.from("book-files").getPublicUrl(storagePath);

      await supabase.from("books").update({ file_url: publicUrlData.publicUrl, file_name: fileName }).eq("id", bookId);

      return new Response(JSON.stringify({ success: true, message: "✅ تم رفع الملف بنجاح", fileUrl: publicUrlData.publicUrl }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "delete") {
      const { bookId } = body;
      const { data: book } = await supabase.from("books").select("teacher_id, file_url").eq("id", bookId).maybeSingle();
      if (!book || book.teacher_id !== tokenClientId) {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (book.file_url) {
        const oldPath = book.file_url.split("/book-files/")[1];
        if (oldPath) await supabase.storage.from("book-files").remove([oldPath]);
      }
      await supabase.from("books").update({ file_url: null, file_name: null }).eq("id", bookId);
      return new Response(JSON.stringify({ success: true, message: "✅ تم حذف الملف" }),
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
