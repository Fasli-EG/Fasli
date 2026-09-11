// supabase/functions/manage-login-ad/index.ts
// ✅ دالة موحّدة تجمع add-login-ad + delete-login-ad — action: add | delete
// كل واحدة منهم أصلاً بتدعم 3 أنواع (type: ad | album | album_image)، محافظين على المنطق ده بالكامل
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { corsHeaders, TokenPayload, AuthError, verifyToken } from "../_shared/auth.ts";

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

// ============================================
// ⭐ العملية 0: رفع ملف فعلي (صورة/فيديو) لتخزين Supabase Storage، بدل رابط نصي يدوي
// ✅ Batch 24 (بند 7): الماستر كان بيلزق رابط صورة/فيديو جاهز يدوياً — دلوقتي بيرفع الملف
// نفسه من جهازه زي ما بيحصل بالظبط مع شعار المدرس (uploadLogo) وملفات المذكرات (upload-book-file)
// ============================================
const ALLOWED_IMAGE_EXTS: Record<string, string> = {
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp", gif: "image/gif",
};
const ALLOWED_VIDEO_EXTS: Record<string, string> = {
  mp4: "video/mp4", webm: "video/webm", mov: "video/quicktime",
};
const MAX_IMAGE_SIZE_BYTES = 3 * 1024 * 1024; // 3 ميجا للصور
const MAX_VIDEO_SIZE_BYTES = 20 * 1024 * 1024; // 20 ميجا للفيديو (فيديو خلفية قصير بيتكرر)

async function handleUpload(supabase: any, body: any) {
  const { fileBase64, fileExt } = body;
  if (!fileBase64 || !fileExt) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ الملف مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const cleanExt = String(fileExt).toLowerCase().replace(/^\./, "");
  const isVideo = !!ALLOWED_VIDEO_EXTS[cleanExt];
  const contentType = ALLOWED_IMAGE_EXTS[cleanExt] || ALLOWED_VIDEO_EXTS[cleanExt];
  if (!contentType) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ صيغة الملف غير مدعومة (المسموح: png, jpg, jpeg, webp, gif للصور — mp4, webm, mov للفيديو)" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const base64Data = fileBase64.includes(",") ? fileBase64.split(",")[1] : fileBase64;
  const binaryData = Uint8Array.from(atob(base64Data), (c: string) => c.charCodeAt(0));
  const maxSize = isVideo ? MAX_VIDEO_SIZE_BYTES : MAX_IMAGE_SIZE_BYTES;
  if (binaryData.length > maxSize) {
    return new Response(JSON.stringify({ success: false, message: `⚠️ حجم الملف أكبر من الحد المسموح (${isVideo ? "20" : "3"} ميجا)` }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  const storagePath = `login-media/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${cleanExt}`;
  const { error: uploadError } = await supabase.storage.from("login-media").upload(storagePath, binaryData, {
    contentType, upsert: true,
  });
  if (uploadError) {
    console.error("❌ فشل رفع الملف:", uploadError);
    // ✅ لو الـ bucket نفسه مش موجود (لسه ما اتعملش يدوي في Supabase Storage)، بنوضح ده صراحة
    // بدل رسالة عامة — أكتر سبب شائع لفشل الرفع فور تفعيل الميزة دي لأول مرة
    const rawMessage = (uploadError as any)?.message || "";
    const bucketMissing = /bucket/i.test(rawMessage) && /not found|does not exist/i.test(rawMessage);
    const friendlyMessage = bucketMissing
      ? "⚠️ مساحة تخزين الملفات (login-media) لسه مش متعملة على السيرفر — لازم تتعمل يدوياً من Supabase Storage كـ bucket عام (Public) الأول"
      : `⚠️ فشل رفع الملف: ${rawMessage || "حاول مرة أخرى"}`;
    return new Response(JSON.stringify({ success: false, message: friendlyMessage }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { data: publicUrlData } = supabase.storage.from("login-media").getPublicUrl(storagePath);

  return new Response(JSON.stringify({ success: true, message: "✅ تم رفع الملف بنجاح", url: publicUrlData.publicUrl }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 1: إضافة (إعلان عادي، أو ألبوم جديد، أو صورة لألبوم)
// ============================================
async function handleAdd(supabase: any, body: any) {
  const type = body.type || "ad";

  if (type === "album") {
    const { title, description, isBackground } = body;
    if (!title) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ اسم الألبوم مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { count } = await supabase.from("photo_albums").select("id", { count: "exact", head: true });
    const { data: album, error } = await supabase.from("photo_albums")
      .insert({ title, description: description || null, sort_order: count || 0, is_background: isBackground === true }).select().single();
    if (error) {
      console.error("❌ فشل إنشاء الألبوم:", error);
      return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, message: "✅ تم إنشاء الألبوم بنجاح", data: album }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (type === "album_image") {
    const { albumId, imageUrl } = body;
    if (!albumId || !imageUrl) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ الألبوم ورابط الصورة مطلوبين" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // ✅ Batch 23 (بند 12): خلفية صفحة تسجيل الدخول بتسمح بأي عدد من الصور تتقلّب ورا بعضها،
    // لكن بفيديو واحد بس (لو الألبوم ده ألبوم خلفية) — لو حاول يضيف فيديو تاني وفيه واحد
    // موجود بالفعل، بيترفض بدل ما يتجمّع أكتر من فيديو في نفس دورة العرض من غير داعي
    const isVideoUrl = (url: string) => /\.(mp4|webm|ogg|mov)(\?.*)?$/i.test(url);
    if (isVideoUrl(imageUrl)) {
      const { data: album } = await supabase.from("photo_albums").select("is_background").eq("id", albumId).maybeSingle();
      if (album?.is_background) {
        const { data: existingItems } = await supabase.from("photo_album_images").select("image_url").eq("album_id", albumId);
        const hasVideo = (existingItems || []).some((i: any) => isVideoUrl(i.image_url));
        if (hasVideo) {
          return new Response(JSON.stringify({ success: false, message: "⚠️ يُسمح بفيديو خلفية واحد بس — احذف الفيديو الحالي الأول لو عايز تستبدله" }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }
    }
    const { count } = await supabase.from("photo_album_images").select("id", { count: "exact", head: true }).eq("album_id", albumId);
    const { data: image, error } = await supabase.from("photo_album_images")
      .insert({ album_id: albumId, image_url: imageUrl, sort_order: count || 0 }).select().single();
    if (error) {
      console.error("❌ فشل إضافة صورة الألبوم:", error);
      return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, message: "✅ تم إضافة الصورة للألبوم", data: image }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ Batch 33 (بند 1): لافتة إعلانية بأكتر من صورة لكل جمهور (ولي أمر/طالب/مدرس/مساعد)،
  // كل صورة برابطها الخاص، بتتقلّب تلقائياً — نفس منطق login_ads بالظبط، بس بجدول مستقل
  // ومعزول بعمود audience لأن كل جمهور له لافتته الخاصة تماماً
  if (type === "portal_banner") {
    const { audience, imageUrl, linkUrl } = body;
    const validAudiences = ["parent", "student", "teacher", "assistant"];
    if (!audience || !validAudiences.includes(audience)) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ audience غير صحيح" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (!imageUrl) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ رابط الصورة مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { count } = await supabase.from("portal_banners").select("id", { count: "exact", head: true }).eq("audience", audience);
    const { data: banner, error } = await supabase.from("portal_banners")
      .insert({ audience, image_url: imageUrl, link_url: linkUrl || null, sort_order: count || 0 }).select().single();
    if (error) {
      console.error("❌ فشل إضافة لافتة إعلانية:", error);
      return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, message: "✅ تم إضافة اللافتة بنجاح", data: banner }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ إضافة صورة إعلانية عادية (السلوك الأصلي)
  const { imageUrl, linkUrl } = body;
  if (!imageUrl) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ رابط الصورة مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { count } = await supabase.from("login_ads").select("id", { count: "exact", head: true });
  const { data: ad, error } = await supabase.from("login_ads")
    .insert({ image_url: imageUrl, link_url: linkUrl || null, sort_order: count || 0 }).select().single();
  if (error) {
    console.error("❌ فشل إضافة الصورة الإعلانية:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: "✅ تم إضافة الصورة بنجاح", data: ad }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ============================================
// ⭐ العملية 2: حذف (إعلان عادي، أو ألبوم، أو صورة من ألبوم)
// ============================================
async function handleDelete(supabase: any, body: any) {
  const type = body.type || "ad";

  if (type === "album") {
    const { albumId } = body;
    if (!albumId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ albumId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { error } = await supabase.from("photo_albums").delete().eq("id", albumId);
    if (error) {
      console.error("❌ فشل حذف الألبوم:", error);
      return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, message: "✅ تم حذف الألبوم بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (type === "album_image") {
    const { imageId } = body;
    if (!imageId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ imageId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // ✅ Batch 24 (بند 7): لو الصورة/الفيديو ده مرفوع كملف فعلي (مش رابط خارجي)، نحذفه من التخزين
    // كمان عشان منسيبش ملفات يتيمة في الـ storage
    const { data: imgRow } = await supabase.from("photo_album_images").select("image_url").eq("id", imageId).maybeSingle();
    if (imgRow?.image_url) await removeIfInternalStorage(supabase, imgRow.image_url);
    const { error } = await supabase.from("photo_album_images").delete().eq("id", imageId);
    if (error) {
      console.error("❌ فشل حذف الصورة:", error);
      return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, message: "✅ تم حذف الصورة بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (type === "portal_banner") {
    const { bannerId } = body;
    if (!bannerId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ bannerId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { data: bannerRow } = await supabase.from("portal_banners").select("image_url").eq("id", bannerId).maybeSingle();
    if (bannerRow?.image_url) await removeIfInternalStorage(supabase, bannerRow.image_url);
    const { error } = await supabase.from("portal_banners").delete().eq("id", bannerId);
    if (error) {
      console.error("❌ فشل حذف اللافتة:", error);
      return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, message: "✅ تم حذف اللافتة بنجاح" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ✅ حذف صورة إعلانية عادية (السلوك الأصلي)
  const { adId } = body;
  if (!adId) {
    return new Response(JSON.stringify({ success: false, message: "⚠️ adId مطلوب" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  const { data: adRow } = await supabase.from("login_ads").select("image_url").eq("id", adId).maybeSingle();
  if (adRow?.image_url) await removeIfInternalStorage(supabase, adRow.image_url);
  const { error } = await supabase.from("login_ads").delete().eq("id", adId);
  if (error) {
    console.error("❌ فشل حذف الصورة الإعلانية:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
  return new Response(JSON.stringify({ success: true, message: "✅ تم حذف الصورة بنجاح" }),
    { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}

// ✅ حذف best-effort لملف مرفوع فعلياً على bucket "login-media" (لو الرابط خارجي بيتجاهل بأمان)
async function removeIfInternalStorage(supabase: any, url: string) {
  try {
    const marker = "/login-media/";
    const idx = url.indexOf(marker);
    if (idx === -1) return;
    const path = url.substring(idx + marker.length);
    if (path) await supabase.storage.from("login-media").remove([path]);
  } catch (_e) { /* حذف الملف القديم اختياري — مش بيوقف عملية الحذف */ }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  try {
    const payload = await verifyToken(req);
    requireAdmin(payload);
    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
      { auth: { autoRefreshToken: false, persistSession: false } });

    const body = await req.json();
    const action = body.action;

    if (action === "upload") return await handleUpload(supabase, body);
    if (action === "add") return await handleAdd(supabase, body);
    if (action === "delete") return await handleDelete(supabase, body);

    return new Response(JSON.stringify({ success: false, message: "⚠️ action غير معروفة" }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    console.error("❌ خطأ غير متوقع:", error);
    return new Response(JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
