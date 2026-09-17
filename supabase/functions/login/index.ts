// supabase/functions/login/index.ts
// ============================================
// ✅ (هجرة Supabase Auth) دخول موحّد لكل الأدوار (مدرس/مساعد/ولي أمر/طالب) عن طريق Supabase
// Auth الحقيقي بدل التوكن المخصص القديم — نفس شكل الاستجابة (role/data/token/...) بالظبط
// عشان الفرونت إند (21 صفحة) ميحتاجش أي تعديل، بس التوكن دلوقتي توكن Supabase Auth حقيقي.
// ============================================
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";
import { corsHeaders } from "../_shared/auth.ts";
import { provisionAuthUser, signInAuthUser, syntheticEmailFor, ensureMinPasswordLength } from "../_shared/authProvision.ts";

// ============================================
// (من _shared/rateLimit.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// ============================================
export interface RateLimitOptions {
  maxAttempts?: number;   // الحد الأقصى للمحاولات قبل الحظر (افتراضي 5)
  lockMinutes?: number;   // مدة الحظر بالدقائق (افتراضي 15)
}

function adminClient() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

/** يتحقق هل المفتاح محظور حالياً. يرجّع رسالة عربية جاهزة لو محظور. */
export async function checkRateLimit(
  key: string,
  opts: RateLimitOptions = {}
): Promise<{ blocked: boolean; message?: string }> {
  const supabase = adminClient();
  const { data } = await supabase
    .from("login_attempts")
    .select("attempts, locked_until")
    .eq("username", key)
    .maybeSingle();

  if (data?.locked_until && new Date(data.locked_until) > new Date()) {
    const minutes = Math.ceil((new Date(data.locked_until).getTime() - Date.now()) / 60000);
    return { blocked: true, message: `⛔ تم حظر المحاولات مؤقتاً، حاول بعد ${minutes} دقيقة` };
  }
  return { blocked: false };
}

/** يسجّل محاولة فاشلة، ويحظر المفتاح تلقائياً لو تخطى الحد الأقصى */
export async function registerFailedAttempt(key: string, opts: RateLimitOptions = {}) {
  const maxAttempts = opts.maxAttempts ?? 5;
  const lockMinutes = opts.lockMinutes ?? 15;

  const supabase = adminClient();
  const { data } = await supabase
    .from("login_attempts")
    .select("attempts")
    .eq("username", key)
    .maybeSingle();

  const attempts = (data?.attempts || 0) + 1;
  const lockedUntil = attempts >= maxAttempts ? new Date(Date.now() + lockMinutes * 60 * 1000).toISOString() : null;

  await supabase.from("login_attempts").upsert({
    username: key,
    attempts,
    locked_until: lockedUntil,
    last_attempt: new Date().toISOString(),
  });
}

/** يصفّر عداد المحاولات عند النجاح */
export async function clearAttempts(key: string) {
  const supabase = adminClient();
  await supabase.from("login_attempts").delete().eq("username", key);
}

const supabaseUrl = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
if (!supabaseKey) {
  throw new Error("⚠️ SUPABASE_SERVICE_ROLE_KEY غير مضبوط في متغيرات البيئة");
}
const supabase = createClient(supabaseUrl, supabaseKey);

// ✅ اكتشاف نوع الحساب تلقائياً على الـ4 جداول كلها — بعد إلغاء تبويبي "الطاقم"/"الأسرة" في
// صفحة الدخول، مبقاش عندنا تلميح "group" من الفرونت إند نضيّق بيه البحث، فبنجرب بترتيب ثابت:
// مدرس (client_id) → مساعد (username) → ولي أمر (phone) → طالب (uid)، أول تطابق بيكسب.
// ⚠️ الترتيب ده بيفترض عدم تصادم قيمة بين الجداول الأربعة (كل جدول متفرّد لوحده بس، مفيش
// تفرّد مضمون عبر الجداول) — مقبول في حجم نظام زي فَصلي، مش سوق متعدد المستأجرين ضخم.
async function detectRole(username: string): Promise<string | null> {
  // ✅ Aug 2026 (تعديل جوهري): جدول centers ومفهوم "حساب سنتر منفصل" اتلغى تماماً —
  // السنتر بقى مجرد صف في جدول teachers عليه علامة is_center، فبيتكشف عادي هنا زي أي مدرس.
  const { data: teacher } = await supabase.from("teachers").select("client_id").eq("client_id", username).maybeSingle();
  if (teacher) return "teacher";
  const { data: assistant } = await supabase.from("assistants").select("username").eq("username", username).maybeSingle();
  if (assistant) return "assistant";
  const { data: parent } = await supabase.from("parents").select("phone").eq("phone", username).maybeSingle();
  if (parent) return "parent";
  const { data: student } = await supabase.from("students").select("uid").eq("uid", username).maybeSingle();
  if (student) return "student";
  return null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ success: false, message: "⚠️ الطريقة غير مسموحة" }),
      { status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    const body = await req.json();
    const { username, password } = body;
    let role = body.role;

    if (!username || !password) {
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ جميع الحقول مطلوبة" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ✅ الواجهة الجديدة بتبعت "username"+"password" بس (بلا "role"/"group") — نكتشف نوع الحساب تلقائياً
    if (!role) {
      role = await detectRole(username);
      if (!role) {
        return new Response(
          JSON.stringify({ success: false, message: "⚠️ الحساب غير مسجّل في المنظومة" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
    }

    // ✅ حماية من محاولات التخمين المتكررة
    const rateLimit = await checkRateLimit(`${role}:${username}`);
    if (rateLimit.blocked) {
      return new Response(
        JSON.stringify({ success: false, message: rateLimit.message }),
        { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    let table = "";
    let idField = "";
    if (role === "teacher") { table = "teachers"; idField = "client_id"; }
    else if (role === "assistant") { table = "assistants"; idField = "username"; }
    else if (role === "parent") { table = "parents"; idField = "phone"; }
    else if (role === "student") { table = "students"; idField = "uid"; }
    else {
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ دور غير معروف" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { data: user, error: userError } = await supabase
      .from(table)
      .select("*")
      .eq(idField, username)
      .maybeSingle();

    // ✅ رسالة موحّدة سواء المستخدم مش موجود أو كلمة المرور غلط، عشان محدش يقدر يكتشف
    // أكواد مدرسين/مساعدين حقيقية بمجرد تجربة تسجيل الدخول (Account Enumeration)
    const genericFailResponse = async () => {
      await registerFailedAttempt(`${role}:${username}`);
      return new Response(
        JSON.stringify({ success: false, message: "⚠️ بيانات الدخول غير صحيحة" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    };

    if (userError || !user) {
      return await genericFailResponse();
    }

    // ============================================
    // ✅ (هجرة Supabase Auth) التحقق من الهوية وإصدار الجلسة — بديل التحقق اليدوي من password_hash
    // ============================================
    let accessToken: string;
    let refreshToken: string;

    if (role === "student" && !user.auth_user_id) {
      // ✅ دخول الطالب أول مرة: مفيش حساب Supabase Auth متعمل لسه — بيدخل بكود الكارت (UID)
      // كاسم مستخدم وكلمة مرور مع بعض. لو مطابقين، ننشئ حساب Supabase Auth دلوقتي.
      if (password !== username) {
        return await genericFailResponse();
      }
      const email = syntheticEmailFor("student", username);
      // ✅ Supabase Auth بيرفض أي باسورد أقل من 6 حروف — كود الكارت (UID) ممكن يكون أقصر (كروت
      // فيزيائية قديمة مثلاً)، فبنحشوه لحد 6 حروف داخليًا بس. الطالب نفسه بيكتب الـUID الحقيقي
      // زي ما هو دايماً (المقارنة password !== username فوق بتتم عليه هو، مش على النسخة المحشوة)
      const internalPassword = ensureMinPasswordLength(username);
      let authUserId: string | null = null;
      try {
        authUserId = await provisionAuthUser({
          email,
          password: internalPassword,
          appMetadata: { role: "student", clientId: user.teacher_id, sub: username, name: user.name },
        });
      } catch (provisionErr) {
        const msg = provisionErr instanceof Error ? provisionErr.message : "⚠️ فشل إنشاء حساب الدخول";
        // ✅ (أمان حرج) خطوة إنشاء حساب Auth وخطوة ربطه بصف الطالب (تحت) مش عملية واحدة ذرية —
        // لو نداءين "أول دخول" حصلوا في نفس اللحظة بالظبط (نفس UID)، أولهم بينجح ويعمل الحساب،
        // وتاني واحد كان بيوصله "already been registered" ويفشل نهائيًا، ويسيب صف الطالب
        // auth_user_id=null للأبد رغم إن الحساب الحقيقي موجود فعلاً — يبقى مفيش أي طريقة تاني
        // يدخل بيها. بدل ما نستسلم، لو الرسالة تحديدًا إن الإيميل مسجّل بالفعل، نجرب نسجّل دخول
        // بنفس الإيميل/الباسورد المحسوبين (اللي المفروض النداء التاني اللي فاز استخدمهم بالظبط)،
        // ولو نجح نكمّل ربط الصف بيه بدل ما نرمي خطأ
        let recovered = false;
        if (msg.includes("already been registered") || msg.includes("already registered")) {
          const { data: recoverData } = await signInAuthUser({ email, password: internalPassword });
          if (recoverData?.session) {
            authUserId = recoverData.session.user.id;
            recovered = true;
          }
        }
        if (!recovered) {
          return new Response(JSON.stringify({ success: false, message: msg }),
            { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
      }
      if (!authUserId) return await genericFailResponse();
      await supabase.from("students").update({ auth_user_id: authUserId, must_change_password: true }).eq("uid", username);
      user.auth_user_id = authUserId;
      user.must_change_password = true;

      const { data: signInData, error: signInError } = await signInAuthUser({ email, password: internalPassword });
      if (signInError || !signInData.session) return await genericFailResponse();
      accessToken = signInData.session.access_token;
      refreshToken = signInData.session.refresh_token;
    } else if (!user.auth_user_id) {
      // ✅ حساب من النظام القديم (اختباري) لسه متعملوش حساب Supabase Auth — بيتعامل زي حساب
      // غير موجود، لازم يتعاد إنشاؤه بالنظام الجديد
      return await genericFailResponse();
    } else {
      const email = role === "parent" ? undefined : syntheticEmailFor(role as "teacher" | "assistant" | "student", username);
      const phone = role === "parent" ? user.phone : undefined;
      const { data: signInData, error: signInError } = await signInAuthUser({ email, phone, password });
      if (signInError || !signInData.session) return await genericFailResponse();
      accessToken = signInData.session.access_token;
      refreshToken = signInData.session.refresh_token;
    }

    // التحقق من حالة الترخيص للمدرس — بدل رفض الدخول، نسمح بيه ونعلّم الاستجابة
    // عشان الفرونت إند يحوّله لصفحة قفل مخصصة (بدل رسالة خطأ عادية)
    let licenseExpired = false;
    let licenseReason = "";
    let contactWhatsapp: string | null = null;
    let contactPhone: string | null = null;
    let contactAudience = "admin"; // admin = تواصل مع الإدارة | teacher = تواصل مع المدرس نفسه

    const loadAdminContact = async () => {
      const { data } = await supabase
        .from("system_settings").select("whatsapp_number, phone_number").eq("id", 1).maybeSingle();
      contactWhatsapp = data?.whatsapp_number || null;
      contactPhone = data?.phone_number || null;
      contactAudience = "admin";
    };

    const loadTeacherContact = async (teacherClientId: string) => {
      const { data } = await supabase
        .from("teachers").select("contact_whatsapp, contact_phone").eq("client_id", teacherClientId).maybeSingle();
      contactWhatsapp = data?.contact_whatsapp || null;
      contactPhone = data?.contact_phone || null;
      contactAudience = "teacher";
    };

    if (role === "teacher") {
      if (!user.is_active) {
        licenseExpired = true;
        licenseReason = "الحساب غير مفعل";
      } else if (user.expiry_date) {
        // ✅ مقارنة نصية بين تاريخين فقط (بدون وقت)، عشان المدرس يفضل له اليوم كامل لحد آخره
        // مهما كان فرق التوقيت — مقارنة timestamp كانت بتعتبره منتهي من أول ثانية في يوم الانتهاء نفسه
        const todayStr = new Date().toISOString().split("T")[0];
        if (user.expiry_date < todayStr) {
          licenseExpired = true;
          licenseReason = "انتهت صلاحية الترخيص";
        }
      }
      if (licenseExpired) await loadAdminContact();
    }

    if (role === "assistant" && !user.is_active) {
      if (user.teacher_id) await loadTeacherContact(user.teacher_id);
      return new Response(
        JSON.stringify({ success: false, message: "⛔ الحساب غير مفعل", contactWhatsapp, contactPhone, contactAudience }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (role === "parent" && !user.is_active) {
      const { data: linkedStudent } = await supabase
        .from("students").select("teacher_id").eq("parent_phone", username).limit(1).maybeSingle();
      if (linkedStudent?.teacher_id) await loadTeacherContact(linkedStudent.teacher_id);
      return new Response(
        JSON.stringify({ success: false, message: "⛔ الحساب غير مفعل", contactWhatsapp, contactPhone, contactAudience }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ✅ نجح تسجيل الدخول: نصفّر محاولات الفشل
    await clearAttempts(`${role}:${username}`);

    // ✅ (تصحيح) ولي الأمر والطالب مابقوش بياخدوا شعار/لون المدرس خالص من دلوقتي — بيفضلوا
    // دايمًا على الهوية الافتراضية لفَصلي بغض النظر عن تخصيص المدرس. الشعار/اللون بتاع
    // المدرس بيفضل يوصل بس للمدرس نفسه، وللمساعد (شعار المدرس + لون المساعد الخاص بيه تحت).

    let teacherName = "";
    let assistantBrandLogoUrl: string | null = null;
    let assistantBrandColor: string | null = null;
    let assistantIsCenter = false;
    if (role === "assistant" && user.teacher_id) {
      const { data: teacher, error: teacherError } = await supabase
        .from("teachers")
        .select("name, is_active, expiry_date, contact_whatsapp, contact_phone, brand_logo_url, brand_color, center_id, is_center")
        .eq("client_id", user.teacher_id)
        .maybeSingle();
      if (!teacherError && teacher) {
        teacherName = teacher.name;
        if (!teacher.is_active) {
          licenseExpired = true;
          licenseReason = "حساب المدرس غير مفعل";
        } else if (teacher.expiry_date) {
          const todayStr2 = new Date().toISOString().split("T")[0];
          if (teacher.expiry_date < todayStr2) {
            licenseExpired = true;
            licenseReason = "انتهت صلاحية ترخيص المدرس";
          }
        }
        if (licenseExpired) {
          contactWhatsapp = teacher.contact_whatsapp || null;
          contactPhone = teacher.contact_phone || null;
          contactAudience = "teacher";
        }
        // ✅ (تصحيح) الشعار بس هو اللي بيتوارث من المدرس (أو السنتر لو مفيش شعار خاص بالمدرس) —
        // اللون بقى مستقل تمامًا، كل مساعد بيحدد لونه الخاص بيه من إعداداته (user.brand_color
        // تحت، من جدول assistants نفسه)
        assistantBrandLogoUrl = teacher.brand_logo_url || null;
        assistantBrandColor = user.brand_color || null;
        // ✅ Batch 22: كانت isCenter بترجع للمدرس بس (role === "teacher") — المساعد ماكانش بيوصله
        // العلَم ده خالص، فتبويب "مدرّسو السنتر" في staff.html كان بيفضل مختفي للمساعد حتى لو
        // معاه صلاحية "عرض/إضافة/تعديل فريق العمل" الكاملة، لأن isCenterAccount في الفرونت إند
        // كانت دايماً false للمساعد (sessionStorage.isCenter مكانش بيتحط أصلاً)
        assistantIsCenter = teacher.is_center === true;
        if (!assistantBrandLogoUrl && teacher.center_id) {
          const { data: centerBrand } = await supabase.from("centers").select("brand_logo_url").eq("id", teacher.center_id).maybeSingle();
          if (centerBrand?.brand_logo_url) assistantBrandLogoUrl = centerBrand.brand_logo_url;
        }
      }
    }

    const forceChange = user.must_change_password || false;
    // ✅ إيميل الاسترجاع الإجباري للحسابات الجديدة (الحسابات القديمة قبل هذا التحديث اتحسبت
    // "متوافقة قديمًا" وقت الترحيل، فمش بتتأثر) — بيتطلب في كل تسجيل دخول لحد ما يتأكد
    const needsRecoveryEmail = user.recovery_email_verified === false;

    const responseData: any = { name: user.name };
    if (role === "teacher") {
      responseData.clientId = user.client_id;
      responseData.maxStudents = user.max_students;
      responseData.expiryDate = user.expiry_date;
      responseData.isActive = user.is_active;
      responseData.studentCount = user.student_count || 0;
      responseData.isAdmin = user.client_id === "master_admin";

      // ✅ لو المدرس عنده شعار/لون خاص بيه بيتقدّم على شعار السنتر (لو تابع لسنتر)
      let brandLogoUrl = user.brand_logo_url || null;
      let brandColor = user.brand_color || null;
      if ((!brandLogoUrl || !brandColor) && user.center_id) {
        const { data: centerBrand } = await supabase.from("centers").select("brand_logo_url, brand_color").eq("id", user.center_id).maybeSingle();
        if (centerBrand) {
          if (!brandLogoUrl) brandLogoUrl = centerBrand.brand_logo_url || null;
          if (!brandColor) brandColor = centerBrand.brand_color || null;
        }
      }
      responseData.brandLogoUrl = brandLogoUrl;
      responseData.brandColor = brandColor;
      // ✅ Aug 2026 (تعديل جوهري): بديل مفهوم "حساب السنتر المنفصل" — الفرونت إند بيستخدم العلَم ده
      // عشان يعرض للمدرس (اللي هو سنتر) إدارة "أسماء المدرسين" التابعين له
      responseData.isCenter = user.is_center === true;
    } else if (role === "assistant") {
      responseData.id = user.id;
      responseData.username = user.username;
      responseData.permissions = user.permissions || {};
      responseData.teacherId = user.teacher_id;
      responseData.teacherName = teacherName || "مدرس";
      responseData.brandLogoUrl = assistantBrandLogoUrl;
      responseData.brandColor = assistantBrandColor;
      responseData.isCenter = assistantIsCenter;
    } else if (role === "parent") {
      responseData.phone = user.phone;
      // ✅ (تصحيح) ولي الأمر بيفضل على الهوية البصرية الافتراضية لفَصلي دايمًا — مبقاش بياخد
      // شعار/لون المدرس خالص
    } else if (role === "student") {
      responseData.uid = user.uid;
      responseData.groupName = user.group_name;
      responseData.teacherId = user.teacher_id;
      // ✅ (تصحيح) نفس المنطق — الطالب بيفضل على الهوية الافتراضية دايمًا
    }

    // ✅ تسجيل نشاط الدخول — كان مفقود بالكامل رغم إن الفلتر بيسمح باختياره
    if (role === "teacher" || role === "assistant") {
      const logTeacherId = role === "teacher" ? user.client_id : user.teacher_id;
      supabase.from("activity_logs").insert({
        client_id: logTeacherId,
        teacher_id: logTeacherId,
        action_type: "login",
        entity_type: role,
        entity_id: role === "teacher" ? user.client_id : String(user.id),
        assistant_id: role === "assistant" ? user.id : null,
        performer_id: role === "teacher" ? user.client_id : String(user.id),
        performer_role: role,
        performer_name: user.name,
      }).then(({ error }: any) => { if (error) console.error("⚠️ فشل تسجيل نشاط الدخول:", error.message); });
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: "✅ تم تسجيل الدخول بنجاح",
        role,
        forceChange,
        needsRecoveryEmail,
        licenseExpired,
        licenseReason,
        contactWhatsapp,
        contactPhone,
        contactAudience,
        token: accessToken,
        refreshToken,
        data: responseData,
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("❌ خطأ عام:", error);
    return new Response(
      JSON.stringify({ success: false, message: "⚠️ حدث خطأ غير متوقع، حاول مرة أخرى" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
