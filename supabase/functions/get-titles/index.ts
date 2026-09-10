// supabase/functions/get-titles/index.ts
// ✅ دالة موحّدة تجمع get-payment-titles + get-exams — type: payment | exam
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

function requireOwnClientId(payload: TokenPayload, requestedClientId?: string | null): string {
  const tokenClientId = payload.clientId || payload.teacherId;
  if (!tokenClientId) throw new AuthError("⚠️ التوكن لا يحتوي على clientId", 401);
  if (requestedClientId && requestedClientId !== tokenClientId) throw new AuthError("⛔ غير مصرح لك بمشاهدة بيانات هذا المدرس", 403);
  return tokenClientId;
}

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders, status: 200 });
  try {
    const payload = await verifyToken(req);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");

    const { clientId, type, groupName } = await req.json();
    if (!clientId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ clientId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const finalClientId = requireOwnClientId(payload, clientId);

    if (type === "payment") {
      const { data, error } = await supabase.from("payment_titles").select("title, default_amount").eq("teacher_id", finalClientId).order("title");
      if (error) {
        return new Response(JSON.stringify({ success: false, message: error.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ success: true, data: (data || []).map((r: any) => ({ title: r.title, defaultAmount: r.default_amount })) }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (type === "exam") {
      // ✅ (طلب) أسماء الامتحانات بقت مرتبطة بمجموعة معيّنة — لو groupName اتبعت، نرجّع بس امتحانات
      // المجموعة دي (عشان امتحانات مجموعة متتلخبطش مع مجموعة تانية)؛ من غيرها بنرجّع كل الامتحانات
      // (يُستخدم في فلتر عرض "كل المجموعات" مثلاً)
      let query = supabase.from("exam_titles").select("title, default_max_score, group_name").eq("teacher_id", finalClientId).order("title");
      if (groupName) query = query.eq("group_name", groupName);
      const { data, error } = await query;
      if (error) {
        return new Response(JSON.stringify({ success: false, message: error.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ success: true, data: (data || []).map((r: any) => ({ title: r.title, defaultMaxScore: r.default_max_score, groupName: r.group_name })) }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: false, message: "⚠️ type غير معروف — لازم يكون payment أو exam" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    const message = error instanceof Error ? error.message : "خطأ غير معروف";
    return new Response(JSON.stringify({ success: false, message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
