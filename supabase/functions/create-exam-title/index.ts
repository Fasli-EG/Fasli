import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { verify } from "https://deno.land/x/djwt@v3.0.1/mod.ts";

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

    const { title, maxScore, groupName } = await req.json();
    const cleanTitle = (title || "").trim();

    if (!cleanTitle) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ أدخل اسم الامتحان" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (maxScore === undefined || isNaN(Number(maxScore)) || Number(maxScore) <= 0) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ أدخل درجة نهائية صحيحة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // ✅ (طلب) اسم الامتحان لازم يتحدد لمجموعة معيّنة، عشان امتحانات كل مجموعة تفضل منفصلة عن التانية
    if (!groupName) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ اختر المجموعة أولاً" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ التكرار بقى مسموح لو المجموعة مختلفة — نفس الاسم في مجموعتين مختلفتين امتحانين منفصلين تماماً
    const { data: existing } = await supabase
      .from("exam_titles").select("id").eq("teacher_id", tokenClientId).eq("title", cleanTitle).eq("group_name", groupName).maybeSingle();

    if (existing) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ فيه امتحان بنفس الاسم ده موجود بالفعل في هذه المجموعة" }),
        { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data, error } = await supabase
      .from("exam_titles")
      .insert({ teacher_id: tokenClientId, title: cleanTitle, default_max_score: Number(maxScore), group_name: groupName })
      .select().single();

    if (error) {
      return new Response(JSON.stringify({ success: false, message: "❌ " + error.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ تم إنشاء الامتحان بنجاح", data }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (error) {
    console.error("❌ خطأ:", error);
    return new Response(JSON.stringify({ success: false, message: "❌ حدث خطأ غير متوقع" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
