import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { create, verify, getNumericDate } from "https://deno.land/x/djwt@v3.0.1/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const jwtSecret = Deno.env.get("JWT_SECRET")!;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const supabase = createClient(supabaseUrl, supabaseServiceKey);
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرّح" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const token = authHeader.replace("Bearer ", "");
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(jwtSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
    );
    const payload: any = await verify(token, key);

    const tokenClientId = payload.clientId || payload.teacherId;
    if (!tokenClientId || (payload.role !== "teacher" && payload.role !== "assistant")) {
      return new Response(JSON.stringify({ success: false, message: "⛔ التوكن غير صالح" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { title, defaultAmount } = await req.json();
    const cleanTitle = (title || "").trim();

    if (!cleanTitle) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ أدخل اسم البند" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (defaultAmount === undefined || isNaN(Number(defaultAmount)) || Number(defaultAmount) < 0) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ أدخل سعراً صحيحاً" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: existing } = await supabase
      .from("payment_titles").select("id").eq("teacher_id", tokenClientId).eq("title", cleanTitle).maybeSingle();

    if (existing) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ فيه بند بنفس الاسم ده موجود بالفعل" }),
        { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data, error } = await supabase
      .from("payment_titles")
      .insert({ teacher_id: tokenClientId, title: cleanTitle, default_amount: Number(defaultAmount) })
      .select().single();

    if (error) {
      return new Response(JSON.stringify({ success: false, message: "❌ " + error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ تم إنشاء بند السداد بنجاح", data }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (error) {
    console.error("❌ خطأ:", error);
    return new Response(JSON.stringify({ success: false, message: "❌ حدث خطأ غير متوقع" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
