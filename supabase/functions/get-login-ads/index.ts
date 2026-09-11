// supabase/functions/get-login-ads/index.ts
// عام (بدون تسجيل دخول) — بيرجّع كل الصور الإعلانية + ألبومات الصور العامة في صفحة تسجيل الدخول
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

import { corsHeaders } from "../_shared/auth.ts";

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } }
    );

    const [{ data: ads, error: adsError }, { data: albums, error: albumsError }, { data: albumImages, error: imagesError }, { data: portalBannerRows, error: portalBannersError }] = await Promise.all([
      supabase.from("login_ads").select("id, image_url, link_url").order("sort_order", { ascending: true }),
      supabase.from("photo_albums").select("id, title, description, sort_order, is_background").order("sort_order", { ascending: true }),
      supabase.from("photo_album_images").select("id, album_id, image_url, sort_order").order("sort_order", { ascending: true }),
      // ✅ Batch 33 (بند 1): لافتة إعلانية بأكتر من صورة لكل جمهور، بتتقلّب تلقائياً
      supabase.from("portal_banners").select("id, audience, image_url, link_url, sort_order").order("sort_order", { ascending: true }),
    ]);

    if (adsError || albumsError || imagesError || portalBannersError) {
      return new Response(JSON.stringify({ success: false, message: (adsError || albumsError || imagesError || portalBannersError)?.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const portalBanners: Record<string, any[]> = { parent: [], student: [], teacher: [], assistant: [] };
    (portalBannerRows || []).forEach((b: any) => {
      if (portalBanners[b.audience]) portalBanners[b.audience].push(b);
    });

    // ✅ نجمع صور كل ألبوم جواه مباشرة، عشان الواجهة تستقبل شكل جاهز من غير ما تلف على البيانات بنفسها
    const albumsWithImages = (albums || []).map((album: any) => ({
      ...album,
      images: (albumImages || []).filter((img: any) => img.album_id === album.id),
    }));

    // ✅ ألبومات الخلفية بيتجمّع صورها في مصفوفة واحدة بسيطة كمان (للاستخدام كخلفية في صفحة الدخول)
    // بس بنسيب albums كاملة (فيها is_background) عشان لوحة الأدمن بتستخدم نفس الدالة دي لعرض كل الألبومات
    const backgroundImages = albumsWithImages
      .filter((a: any) => a.is_background)
      .flatMap((a: any) => a.images.map((img: any) => img.image_url));

    return new Response(JSON.stringify({ success: true, data: ads || [], albums: albumsWithImages, backgroundImages, portalBanners }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
