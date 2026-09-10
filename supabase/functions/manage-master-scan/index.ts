// supabase/functions/manage-master-scan/index.ts
// ✅ دالة موحّدة تجمع start-master-scan-mode + stop-master-scan-mode + get-master-scan-status
// action: start | stop | status — كلها بمصادقة أدمن (JWT)، بعكس submit-master-card-scan اللي فضلت منفصلة (مصادقة جهاز)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
};

interface TokenPayload { sub: string; clientId?: string; role: string; name: string; }

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

function requireAdmin(payload: TokenPayload) {
  if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
    throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
  }
}

function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    requireAdmin(payload);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    const { action } = await req.json();

    if (action === "start") {
      await supabase.from("master_scan_mode").update({ is_active: true, last_scanned_uid: null }).eq("id", 1);
      return new Response(JSON.stringify({ success: true, message: "✅ وضع الاستقبال مفعّل — مرّغ الكروت على البورد" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "stop") {
      await supabase.from("master_scan_mode").update({ is_active: false }).eq("id", 1);
      return new Response(JSON.stringify({ success: true, message: "✅ تم إيقاف وضع الاستقبال" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (action === "status") {
      const { data: mode } = await supabase.from("master_scan_mode").select("*").eq("id", 1).maybeSingle();
      const { count } = await supabase.from("system_cards").select("id", { count: "exact", head: true }).eq("status", "in_stock");
      return new Response(JSON.stringify({
        success: true, isActive: !!mode?.is_active, lastScannedUid: mode?.last_scanned_uid || null, inStockCount: count || 0,
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
