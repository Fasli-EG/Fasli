// supabase/functions/send-bulk-message/index.ts
// المدرس/المساعد يبعت رسالة جماعية لأولياء أمور مجموعة كاملة، أو لأولياء أمور الطلاب الغايبين النهاردة فقط
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

// ============================================
// (من _shared/auth.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// ============================================
// ============================================
// موديول موحّد للتحقق من هوية المستخدم (JWT)
// يُستورد في كل دالة تحتاج تأكيد هوية بدل تكرار الكود
// ============================================
import { verify } from "https://deno.land/x/djwt@v2.8/mod.ts";

export const corsHeaders = {
  "Access-Control-Allow-Origin": "https://fasli-eg.github.io",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info",
  "Access-Control-Max-Age": "86400",
};

export interface TokenPayload {
  sub: string;
  clientId?: string;
  teacherId?: string;
  username?: string;
  phone?: string;
  role: "teacher" | "assistant" | "parent";
  name: string;
  exp: number;
}

export class AuthError extends Error {
  status: number;
  code?: string;
  constructor(message: string, status = 401, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function getKey() {
  const JWT_SECRET = Deno.env.get("JWT_SECRET");
  if (!JWT_SECRET) {
    throw new Error("⚠️ JWT_SECRET غير مضبوط في متغيرات البيئة");
  }
  return await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

/** عميل Supabase بصلاحيات كاملة، مخصص لفحص الترخيص فقط (بدون تكرار الاستيراد في كل دالة) */
async function licenseCheckClient() {
  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2.38.4");
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

/**
 * يتحقق من حالة ترخيص المدرس (نشط + لم تنتهِ صلاحيته).
 * يُستخدم تلقائياً جوه verifyToken لكل توكن مدرس/مساعد، فيغطي المساعدين تلقائياً
 * (توكن المساعد بيتحقق من ترخيص المدرس بتاعه نفسه).
 */
async function checkLicenseActive(teacherClientId: string): Promise<{ active: boolean; reason?: string }> {
  if (teacherClientId === "master_admin") return { active: true };

  const supabase = await licenseCheckClient();
  const { data: teacher, error } = await supabase
    .from("teachers")
    .select("is_active, expiry_date")
    .eq("client_id", teacherClientId)
    .maybeSingle();

  if (error || !teacher) return { active: false, reason: "الحساب غير موجود" };
  if (teacher.is_active === false) return { active: false, reason: "الحساب معطّل" };

  if (teacher.expiry_date) {
    const todayCLA = new Date().toISOString().split("T")[0];
    if (teacher.expiry_date < todayCLA) return { active: false, reason: "انتهت صلاحية الترخيص" };
  }

  return { active: true };
}

/**
 * يتحقق من صحة الـ Authorization header ويرجّع بيانات التوكن.
 * يرمي AuthError (401) لو التوكن غير موجود/غير صالح/منتهي.
 * يرمي AuthError (402, code=LICENSE_EXPIRED) لو ترخيص المدرس (أو مدرس المساعد) منتهي/معطّل.
 * مرّر skipLicenseCheck:true فقط للدوال العامة اللي المفروض تشتغل حتى لو الترخيص منتهي (نادر جداً).
 */
export async function verifyToken(req: Request, opts?: { skipLicenseCheck?: boolean }): Promise<TokenPayload> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new AuthError("⚠️ التوكن مطلوب", 401);
  }
  const token = authHeader.substring(7);
  const key = await getKey();
  let payload: TokenPayload;
  try {
    payload = (await verify(token, key, "HS256")) as unknown as TokenPayload;
  } catch (_e) {
    throw new AuthError("⚠️ التوكن غير صالح أو منتهي الصلاحية", 401);
  }

  if (!opts?.skipLicenseCheck && (payload.role === "teacher" || payload.role === "assistant")) {
    const ownerId = payload.clientId || payload.teacherId;
    if (ownerId) {
      const license = await checkLicenseActive(ownerId);
      if (!license.active) {
        throw new AuthError(
          `⛔ ${license.reason || "انتهت صلاحية الترخيص"} — يرجى التواصل مع الإدارة`,
          402,
          "LICENSE_EXPIRED"
        );
      }
    }
  }

  return payload;
}

/**
 * يتحقق من هوية جهاز قارئ الكروت (ESP32) عن طريق سر خاص بكل مدرس،
 * بديل عن التوكن العادي لأن الجهاز مش عنده تسجيل دخول. يرجّع بيانات المدرس لو صح.
 */
export async function verifyDeviceSecret(clientId: string, deviceSecret: string): Promise<void> {
  if (!clientId || !deviceSecret) {
    throw new AuthError("⚠️ بيانات الجهاز ناقصة (clientId أو deviceSecret)", 401);
  }
  const supabase = await licenseCheckClient();
  const { data: teacher, error } = await supabase
    .from("teachers")
    .select("device_secret, is_active, expiry_date")
    .eq("client_id", clientId)
    .maybeSingle();

  if (error || !teacher || !teacher.device_secret) {
    throw new AuthError("⛔ جهاز غير معروف", 401);
  }
  if (teacher.device_secret !== deviceSecret) {
    throw new AuthError("⛔ سر الجهاز غير صحيح", 401);
  }
  if (teacher.is_active === false) {
    throw new AuthError("⛔ حساب المدرس معطّل", 402, "LICENSE_EXPIRED");
  }
  if (teacher.expiry_date) {
    const today = new Date().toISOString().split("T")[0];
    if (teacher.expiry_date < today) {
      throw new AuthError("⛔ انتهت صلاحية الترخيص", 402, "LICENSE_EXPIRED");
    }
  }
}

/** يرجّع معرّف "المدرس المالك" للحساب (نفس clientId للمدرس، أو teacherId للمساعد) */
export function ownerClientId(payload: TokenPayload): string {
  const id = payload.clientId || payload.teacherId;
  if (!id) throw new AuthError("⚠️ التوكن لا يحتوي على clientId", 401);
  return id;
}

/** يتأكد إن التوكن (مدرس أو مساعد تابع له) مصرح له بالوصول لبيانات clientId المطلوب */
export function requireOwnClientId(payload: TokenPayload, requestedClientId?: string | null) {
  const tokenClientId = ownerClientId(payload);
  if (requestedClientId && requestedClientId !== tokenClientId) {
    throw new AuthError("⛔ غير مصرح لك بمشاهدة بيانات هذا المدرس", 403);
  }
  return tokenClientId;
}

/** يتأكد إن التوكن ده لحساب المشرف الرئيسي (master_admin) */
export function requireAdmin(payload: TokenPayload) {
  if (payload.role !== "teacher" || payload.clientId !== "master_admin") {
    throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
  }
}

/** يتأكد إن التوكن لحساب ولي أمر برقم هاتف محدد */
export function requireParentPhone(payload: TokenPayload, requestedPhone?: string | null) {
  if (payload.role !== "parent" || !payload.phone) {
    throw new AuthError("⛔ غير مصرح بهذه العملية", 403);
  }
  if (requestedPhone && requestedPhone !== payload.phone) {
    throw new AuthError("⛔ غير مصرح لك بمشاهدة بيانات هذا الطالب", 403);
  }
  return payload.phone;
}

/**
 * يتأكد إن باقة المدرس (المُحدّدة من الأدمن) فيها الميزة المطلوبة.
 * لو المفتاح مش موجود في permissions (مدرس قديم قبل إضافة الميزة دي) بنسمح افتراضياً (توافق مع الحسابات القديمة).
 * لا تُستدعى لحساب master_admin.
 */
export async function requireTeacherPlanPermission(clientId: string, permKey: string): Promise<void> {
  if (clientId === "master_admin") return;
  const supabase = await licenseCheckClient();
  const { data: teacher } = await supabase
    .from("teachers").select("permissions").eq("client_id", clientId).maybeSingle();
  const perms = teacher?.permissions || {};
  if (perms[permKey] === false) {
    throw new AuthError("⛔ هذه الميزة غير متاحة في باقتك الحالية، تواصل مع الإدارة لتفعيلها", 403, "PLAN_RESTRICTED");
  }
}

/**
 * يتأكد إن المساعد عنده صلاحية محددة منحها له المدرس. لا تأثير على المدرس نفسه (دايماً مسموح له).
 */
export async function requireAssistantPermission(payload: TokenPayload, permKey: string): Promise<void> {
  if (payload.role !== "assistant") return;
  const supabase = await licenseCheckClient();
  const { data: assistant } = await supabase
    .from("assistants").select("permissions").eq("id", payload.sub).maybeSingle();
  const perms = assistant?.permissions || {};
  if (perms[permKey] !== true) {
    throw new AuthError("⛔ ليس لديك صلاحية لهذا الإجراء، تواصل مع المدرس", 403);
  }
}

/** يحوّل AuthError لـ Response جاهزة */
export function authErrorResponse(error: unknown) {
  const status = error instanceof AuthError ? error.status : 500;
  const code = error instanceof AuthError ? error.code : undefined;
  const message = error instanceof Error ? error.message : "⚠️ خطأ غير معروف";
  return new Response(
    JSON.stringify({ success: false, message, ...(code ? { code } : {}) }),
    { status, headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

// ============================================
// (من _shared/push.ts — مدموج مباشرة لأن Dashboard لا يدعم الاستيراد بين الدوال)
// ============================================
// إرسال إشعارات Push حقيقية عبر Firebase Cloud Messaging (HTTP v1 API)
// محتاج متغير بيئة اسمه FIREBASE_SERVICE_ACCOUNT فيه محتوى ملف الـ Service Account JSON كامل كنص

interface ServiceAccount {
  client_email: string;
  private_key: string;
  project_id: string;
}

let cachedAccessToken: { token: string; expiresAt: number } | null = null;

function base64url(input: ArrayBuffer | string): string {
  let bytes: Uint8Array;
  if (typeof input === "string") {
    bytes = new TextEncoder().encode(input);
  } else {
    bytes = new Uint8Array(input);
  }
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function getAccessToken(sa: ServiceAccount): Promise<string> {
  if (cachedAccessToken && cachedAccessToken.expiresAt > Date.now() + 60_000) {
    return cachedAccessToken.token;
  }

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };

  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;

  // ✅ نجهّز المفتاح الخاص للتوقيع (PEM -> CryptoKey)
  const pemBody = sa.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  const binaryKey = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryKey.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, new TextEncoder().encode(unsigned));
  const jwt = `${unsigned}.${base64url(signature)}`;

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  const tokenData = await tokenRes.json();
  if (!tokenRes.ok || !tokenData.access_token) {
    console.error("❌ فشل الحصول على access token من Firebase:", tokenData);
    throw new Error("فشل مصادقة Firebase");
  }

  cachedAccessToken = { token: tokenData.access_token, expiresAt: Date.now() + tokenData.expires_in * 1000 };
  return tokenData.access_token;
}

/**
 * يبعت إشعار Push حقيقي لكل الأجهزة المسجّلة لمستخدم معيّن (ولي أمر أو مساعد أو مدرس).
 * أي فشل هنا بيتسجّل في السيرفر بس، ومايوقفش العملية الأساسية (زي تسجيل حضور أو دفعة).
 */
export async function sendPushToRecipient(
  supabase: any,
  recipientType: "parent" | "assistant" | "teacher" | "student",
  recipientId: string,
  title: string,
  body: string
): Promise<void> {
  try {
    const saJson = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
    if (!saJson) return; // Firebase لسه مش متفعّل، نتجاهل بهدوء

    const { data: tokens } = await supabase
      .from("push_tokens")
      .select("id, token")
      .eq("recipient_type", recipientType)
      .eq("recipient_id", recipientId);

    if (!tokens || tokens.length === 0) return;

    const sa: ServiceAccount = JSON.parse(saJson);
    const accessToken = await getAccessToken(sa);

    for (const row of tokens) {
      const res = await fetch(
        `https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            message: {
              token: row.token,
              notification: { title, body },
              android: { priority: "high", notification: { sound: "default", channel_id: "fasli_notifications" } },
            },
          }),
        }
      );

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        // ✅ لو التوكن بقى غير صالح (اتفصل التطبيق أو اتمسح)، نمسحه من القائمة عشان منحاولش نبعتله تاني
        if (errData?.error?.status === "NOT_FOUND" || errData?.error?.status === "INVALID_ARGUMENT") {
          await supabase.from("push_tokens").delete().eq("id", row.id);
        } else {
          console.error("⚠️ فشل إرسال Push notification:", errData);
        }
      }
    }
  } catch (error) {
    console.error("⚠️ خطأ غير متوقع في إرسال Push notification:", error);
  }
}

// ✅ (مراجعة أداء) نسخة مجمّعة من sendPushToRecipient للإرسال الجماعي (رسالة لمجموعة/مركز
// كامل) — كانت بترسل نداء استعلام push_tokens مستقل لكل مستلم (ممكن يوصل لمئات النداءات
// لقاعدة البيانات في رسالة واحدة لمركز كبير)، دلوقتي بتجيب توكنات كل المستلمين بنداء واحد
// بس وتوزّعهم بعدين في الميموري. نداءات FCM نفسها (لكل توكن) لسه بتحصل واحد واحد لأن FCM
// HTTP v1 API مبيدعمش إرسال جماعي في نداء واحد.
export async function sendPushToManyRecipients(
  supabase: any,
  recipientType: "parent" | "assistant" | "teacher" | "student",
  items: { recipientId: string; title: string; body: string }[]
): Promise<void> {
  try {
    if (items.length === 0) return;
    const saJson = Deno.env.get("FIREBASE_SERVICE_ACCOUNT");
    if (!saJson) return; // Firebase لسه مش متفعّل، نتجاهل بهدوء

    const recipientIds = [...new Set(items.map((i) => i.recipientId))];
    const { data: tokens } = await supabase
      .from("push_tokens")
      .select("id, token, recipient_id")
      .eq("recipient_type", recipientType)
      .in("recipient_id", recipientIds);

    if (!tokens || tokens.length === 0) return;

    const tokensByRecipient = new Map<string, { id: string; token: string }[]>();
    tokens.forEach((row: any) => {
      const list = tokensByRecipient.get(row.recipient_id) || [];
      list.push({ id: row.id, token: row.token });
      tokensByRecipient.set(row.recipient_id, list);
    });

    const sa: ServiceAccount = JSON.parse(saJson);
    const accessToken = await getAccessToken(sa);

    for (const item of items) {
      const recipientTokens = tokensByRecipient.get(item.recipientId);
      if (!recipientTokens || recipientTokens.length === 0) continue;

      for (const row of recipientTokens) {
        const res = await fetch(
          `https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`,
          {
            method: "POST",
            headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
            body: JSON.stringify({
              message: {
                token: row.token,
                notification: { title: item.title, body: item.body },
                android: { priority: "high", notification: { sound: "default", channel_id: "fasli_notifications" } },
              },
            }),
          }
        );

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          if (errData?.error?.status === "NOT_FOUND" || errData?.error?.status === "INVALID_ARGUMENT") {
            await supabase.from("push_tokens").delete().eq("id", row.id);
          } else {
            console.error("⚠️ فشل إرسال Push notification:", errData);
          }
        }
      }
    }
  } catch (error) {
    console.error("⚠️ خطأ غير متوقع في إرسال Push notification (مجمّع):", error);
  }
}

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
    const body = await req.json();

    // ============================================
    // محادثة ثنائية الاتجاه مع ولي أمر طالب محدد (بديل داخل التطبيق عن واتساب)
    // ============================================
    if (body.mode === "conversation") {
      const { studentUid, message: convMessage } = body;
      if (!studentUid || !convMessage) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid و message مطلوبين" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      if (payload.role === "parent") {
        const parentPhone = requireParentPhone(payload);
        const { data: student } = await supabase
          .from("students").select("uid, name, teacher_id, parent_phone").eq("uid", studentUid).maybeSingle();
        if (!student || student.parent_phone !== parentPhone) {
          return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح لك بمراسلة مدرس هذا الطالب" }),
            { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        const { error: insertError } = await supabase.from("conversation_messages").insert({
          teacher_id: student.teacher_id, parent_phone: parentPhone, student_uid: studentUid,
          sender_role: "parent", sender_name: payload.name || "ولي أمر", message: convMessage,
          is_read_by_teacher: false, is_read_by_parent: true,
        });
        if (insertError) throw new Error(insertError.message);
        // ✅ Batch 23 (بند 9): عنوان الإشعار كان بيعرض اسم حساب ولي الأمر نفسه (غالبًا رقم الهاتف
        // أو اسم غير مفيد للمدرس)، واسم الطالب كان بيتحط في الآخر بين قوسين كتفصيلة إضافية. المدرس
        // بيتعامل بأسماء الطلاب مش بأسماء أولياء أمورهم، فالعنوان بقى معتمد على اسم الطالب هو
        // الأساس ("رسالة جديدة بخصوص [اسم الطالب]") بدل اسم ولي الأمر
        const parentSenderName = payload.name || "ولي أمر";
        const notifTitle = student.name ? `رسالة جديدة من ولي أمر ${student.name}` : `رسالة جديدة من ${parentSenderName}`;
        await supabase.from("notifications").insert({
          teacher_id: student.teacher_id, type: "parent_message", title: notifTitle,
          message: convMessage, student_uid: studentUid, parent_phone: parentPhone,
          details: { sender_name: parentSenderName, sender_role: "parent", student_name: student.name, parent_phone: parentPhone },
        }).then(({ error }: any) => { if (error) console.error("⚠️ فشل إشعار المدرس بالرسالة:", error.message); });
        await sendPushToRecipient(supabase, "teacher", student.teacher_id, notifTitle, convMessage);
        // ✅ Batch 23 (بند 8): رسالة ولي الأمر كانت بتوصل للمدرس بس — أي مساعد معاه صلاحية
        // "إدارة المحادثات" لازم يشوفها برضه في جرس الإشعارات بتاعه (نفس منطق صندوق الوارد،
        // بس ده تنبيه فوري). بنبعت إشعار مستقل لكل مساعد نشط عنده الصلاحية دي فعلاً
        // ✅ (طلب) كان الجزء ده كله fire-and-forget (من غير await) قبل الـ return مباشرة — في
        // بيئة Edge Function ده بيعمل race حقيقي: أحيانًا كتير الدالة كانت بترجع الرد وتقفل
        // قبل ما إشعار المدرس (أو المساعدين) يتسجّل فعليًا في قاعدة البيانات، فالإشعار كان
        // "بيتبعت" من غير ما يوصل فعلاً. دلوقتي كل نداء إدراج إشعار بقى await قبل الـ return.
        const { data: assistants, error: assistantsErr } = await supabase
          .from("assistants").select("id, permissions").eq("teacher_id", student.teacher_id).eq("is_active", true);
        if (!assistantsErr && assistants && assistants.length > 0) {
          const eligible = assistants.filter((a: any) => a.permissions?.manage_conversations === true);
          if (eligible.length > 0) {
            const assistantNotifRows = eligible.map((a: any) => ({
              teacher_id: student.teacher_id, assistant_id: a.id, type: "parent_message", title: notifTitle,
              message: convMessage, student_uid: studentUid, parent_phone: parentPhone,
              details: { sender_name: parentSenderName, sender_role: "parent", student_name: student.name, parent_phone: parentPhone },
            }));
            await supabase.from("notifications").insert(assistantNotifRows)
              .then(({ error }: any) => { if (error) console.error("⚠️ فشل إشعار المساعدين بالرسالة:", error.message); });
          }
        }
        return new Response(JSON.stringify({ success: true, message: "✅ تم إرسال رسالتك" }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      if (payload.role === "teacher" || payload.role === "assistant") {
        const finalClientId = ownerClientId(payload);
        // ✅ Batch 23 (بند 8): إدارة المحادثات (الرد على ولي الأمر) بقت صلاحية مستقلة عن
        // "الرسائل الجماعية" (send_messages) — مساعد ممكن يكون عنده واحدة من الاتنين، مش لازم
        // الاتنين مع بعض
        await requireAssistantPermission(payload, "manage_conversations");
        const { data: student } = await supabase
          .from("students").select("uid, teacher_id, parent_phone").eq("uid", studentUid).eq("teacher_id", finalClientId).maybeSingle();
        if (!student || !student.parent_phone) {
          return new Response(JSON.stringify({ success: false, message: "⚠️ الطالب غير موجود أو مفيش رقم ولي أمر مسجّل له" }),
            { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        const { error: insertError } = await supabase.from("conversation_messages").insert({
          teacher_id: finalClientId, parent_phone: student.parent_phone, student_uid: studentUid,
          sender_role: payload.role, sender_name: payload.name || "المدرس", message: convMessage,
          is_read_by_teacher: true, is_read_by_parent: false,
        });
        if (insertError) throw new Error(insertError.message);
        // ✅ (طلب) إشعار داخل التطبيق لولي الأمر (جرس الإشعارات) بتفاصيل أوضح لمصدر الرسالة
        const { data: senderTeacherInfo } = await supabase.from("teachers").select("name").eq("client_id", finalClientId).maybeSingle();
        const teacherSenderName = payload.name || senderTeacherInfo?.name || "المدرس";
        // ✅ (طلب) نفس تصحيح الـ race أعلاه — await قبل الـ return عشان الإشعار يتضمن وصوله فعلاً
        await supabase.from("notifications").insert({
          teacher_id: finalClientId, type: "teacher_message", title: `رسالة جديدة من ${teacherSenderName}`, audience: "parent",
          message: convMessage, student_uid: studentUid, parent_phone: student.parent_phone,
          details: { sender_name: teacherSenderName, sender_role: payload.role },
        }).then(({ error }: any) => { if (error) console.error("⚠️ فشل إشعار ولي الأمر بالرسالة:", error.message); });
        await sendPushToRecipient(supabase, "parent", student.parent_phone, `رسالة جديدة من ${teacherSenderName}`, convMessage);
        return new Response(JSON.stringify({ success: true, message: "✅ تم إرسال الرسالة" }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
        { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ============================================
    // ✅ (طلب) حذف محادثة كاملة مع ولي أمر طالب معين — يقدر المدرس/المساعد (بصلاحية إدارة
    // المحادثات) يحذفها في أي وقت من داخل صفحة الرسائل، مش لازم ينتظر إعادة تهيئة النظام
    // ============================================
    if (body.mode === "conversation_delete") {
      const { studentUid: deleteStudentUid } = body;
      if (!deleteStudentUid) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ studentUid مطلوب" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (payload.role !== "teacher" && payload.role !== "assistant") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      await requireAssistantPermission(payload, "manage_conversations");
      const finalClientId = ownerClientId(payload);
      const { error: deleteError } = await supabase
        .from("conversation_messages").delete()
        .eq("teacher_id", finalClientId).eq("student_uid", deleteStudentUid);
      if (deleteError) throw new Error(deleteError.message);
      return new Response(JSON.stringify({ success: true, message: "✅ تم حذف المحادثة" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ============================================
    // ✅ رسالة جماعية من صاحب السنتر — لكل أولياء أمور طلاب مدرسيه (أو مدرس واحد بعينه لو حدده)
    // نطاق مستقل تماماً عن مسار المدرس اللي فوق، عشان منلمسوش المنطق الموجود والمُختبر
    // ============================================
    if (body.centerScope === true) {
      if (payload.role !== "center_owner") {
        return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح بهذه العملية" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { message: centerMessage, title: centerTitle, teacherClientId: onlyTeacherId, recipientType: centerRecipientType } = body;
      if (!centerMessage) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ message مطلوب" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: center } = await supabase.from("centers").select("id, name").eq("client_id", payload.clientId).maybeSingle();
      if (!center) {
        return new Response(JSON.stringify({ success: false, message: "السنتر غير موجود" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      const { data: centerTeachers } = await supabase.from("teachers").select("client_id").eq("center_id", center.id);
      let teacherIds = (centerTeachers || []).map((t: any) => t.client_id);
      if (onlyTeacherId) {
        if (!teacherIds.includes(onlyTeacherId)) {
          return new Response(JSON.stringify({ success: false, message: "⛔ هذا المدرس ليس تابعاً لسنترك" }),
            { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        teacherIds = [onlyTeacherId];
      }
      if (teacherIds.length === 0) {
        return new Response(JSON.stringify({ success: false, message: "لا يوجد مدرسين لإرسال الرسالة لطلابهم" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // ============================================
      // ✅ إعلان داخلي للمدرسين أنفسهم (بدل أولياء أمورهم) — Aug 2026
      // نطاق منفصل تماماً عن مسار مراسلة أولياء الأمور تحت، بيستخدم عمود teacher_id كمعرّف مستلم مباشر
      // (type='center_teacher_message' هو اللي بيميّزه في get-notifications/mark-notification-read)
      // ============================================
      if (centerRecipientType === "teachers") {
        const senderName = `إدارة ${center.name}`;
        const finalTitle = centerTitle || "إعلان من إدارة السنتر";
        const teacherRows = teacherIds.map((tid: string) => ({
          teacher_id: tid,
          type: "center_teacher_message",
          title: finalTitle,
          message: `من: ${senderName}\n\n${centerMessage}`,
          details: { center_id: center.id, sender_name: senderName },
        }));

        const { error: teacherInsertError } = await supabase.from("notifications").insert(teacherRows);
        if (teacherInsertError) {
          return new Response(JSON.stringify({ success: false, message: teacherInsertError.message }),
            { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }
        sendPushToManyRecipients(supabase, "teacher", teacherIds.map((tid: string) => (
          { recipientId: tid, title: finalTitle, body: `من: ${senderName}\n\n${centerMessage}` }
        )));

        await supabase.from("activity_logs").insert({
          client_id: payload.clientId, teacher_id: teacherIds[0],
          action_type: "center_teacher_message", details: { recipients: teacherRows.length, scoped_teacher: onlyTeacherId || "all" },
          performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
        });

        return new Response(JSON.stringify({
          success: true,
          message: `✅ تم إرسال الإعلان لـ ${teacherRows.length} مدرس`,
          data: { recipients: teacherRows.length },
        }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: centerStudents, error: centerStudentsError } = await supabase
        .from("students").select("uid, name, parent_phone, teacher_id").in("teacher_id", teacherIds).is("archived_at", null)
        .not("parent_phone", "is", null);
      if (centerStudentsError) {
        return new Response(JSON.stringify({ success: false, message: centerStudentsError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (!centerStudents || centerStudents.length === 0) {
        return new Response(JSON.stringify({ success: false, message: "لا يوجد أولياء أمور مطابقين للاختيار" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const senderName = `إدارة ${center.name}`;
      const finalTitle = centerTitle || "إعلان من إدارة السنتر";
      const rows = centerStudents.map((s: any) => ({
        teacher_id: s.teacher_id,
        parent_phone: s.parent_phone,
        student_uid: s.uid,
        type: "bulk_message",
        audience: "parent",
        title: finalTitle,
        message: `من: ${senderName} — بخصوص: ${s.name}\n\n${centerMessage}`,
        details: { center_id: center.id, student_name: s.name, sender_name: senderName },
      }));

      const { error: insertError } = await supabase.from("notifications").insert(rows);
      if (insertError) {
        return new Response(JSON.stringify({ success: false, message: insertError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      sendPushToManyRecipients(supabase, "parent", centerStudents.map((s: any) => (
        { recipientId: s.parent_phone, title: finalTitle, body: `من: ${senderName} — بخصوص: ${s.name}\n\n${centerMessage}` }
      )));

      await supabase.from("activity_logs").insert({
        client_id: payload.clientId, teacher_id: teacherIds[0],
        action_type: "center_bulk_message", details: { recipients: rows.length, scoped_teacher: onlyTeacherId || "all" },
        performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
      });

      return new Response(JSON.stringify({
        success: true,
        message: `✅ تم إرسال الرسالة لـ ${rows.length} ولي أمر`,
        data: { recipients: rows.length },
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { clientId, recipientType } = body;

    if (!clientId) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ clientId مطلوب" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const finalClientId = requireOwnClientId(payload, clientId);
    await requireTeacherPlanPermission(finalClientId, "can_send_messages");

    // ============================================
    // إرسال لمساعدين (المدرس بس)
    // ============================================
    if (recipientType === "assistants") {
      if (payload.role !== "teacher") {
        return new Response(JSON.stringify({ success: false, message: "⛔ إرسال إشعارات للمساعدين متاح للمدرس بس" }),
          { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { assistantIds, message: assistantMessage, title: assistantTitle } = body;

      if (!Array.isArray(assistantIds) || assistantIds.length === 0 || !assistantMessage) {
        return new Response(JSON.stringify({ success: false, message: "⚠️ assistantIds و message مطلوبين" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const { data: assistants, error: assistantsError } = await supabase
        .from("assistants")
        .select("id, name")
        .eq("teacher_id", finalClientId)
        .in("id", assistantIds);

      if (assistantsError) {
        return new Response(JSON.stringify({ success: false, message: assistantsError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      if (!assistants || assistants.length === 0) {
        return new Response(JSON.stringify({ success: false, message: "لا يوجد مساعدين مطابقين للاختيار" }),
          { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const senderName = payload.name || "المدرس";
      const finalTitle = assistantTitle || "رسالة من المدرس";
      const rows = assistants.map((a: any) => ({
        teacher_id: finalClientId,
        assistant_id: String(a.id),
        type: "bulk_message",
        title: finalTitle,
        message: `من: ${senderName}\n\n${assistantMessage}`,
        details: { sender_name: senderName },
      }));

      const { error: insertError } = await supabase.from("notifications").insert(rows);
      if (insertError) {
        return new Response(JSON.stringify({ success: false, message: insertError.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      sendPushToManyRecipients(supabase, "assistant", assistants.map((a: any) => (
        { recipientId: String(a.id), title: finalTitle, body: `من: ${senderName}\n\n${assistantMessage}` }
      )));

      await supabase.from("activity_logs").insert({
        client_id: finalClientId, teacher_id: finalClientId, action_type: "bulk_message",
        details: { recipients: rows.length, target: "assistants" },
        performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
      });

      return new Response(JSON.stringify({
        success: true,
        message: `✅ تم إرسال الرسالة لـ ${rows.length} مساعد`,
        data: { recipients: rows.length }
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ============================================
    // إرسال لأولياء أمور مجموعة (زي ما كانت)
    // ============================================
    await requireAssistantPermission(payload, "send_messages");
    const { groupName, target, studentUids, message, title, paymentTitle, bookId } = body;

    if (!groupName || !message) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ groupName و message مطلوبين" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: groupStudents, error: studentsError } = await supabase
      .from("students")
      .select("uid, name, parent_phone")
      .eq("teacher_id", finalClientId)
      .eq("group_name", groupName);

    if (studentsError) {
      return new Response(JSON.stringify({ success: false, message: studentsError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (!groupStudents || groupStudents.length === 0) {
      return new Response(JSON.stringify({ success: false, message: "لا يوجد طلاب في هذه المجموعة" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    let targetStudents = groupStudents;

    if (target === "absent_today") {
      const today = new Date().toISOString().split("T")[0];
      const uids = groupStudents.map((s: any) => s.uid);
      const { data: presentToday } = await supabase
        .from("attendance")
        .select("student_uid")
        .in("student_uid", uids)
        .eq("date", today)
        .eq("status", "present");
      const presentSet = new Set((presentToday || []).map((a: any) => a.student_uid));
      targetStudents = groupStudents.filter((s: any) => !presentSet.has(s.uid));
    } else if (target === "students" && Array.isArray(studentUids) && studentUids.length > 0) {
      const uidSet = new Set(studentUids);
      targetStudents = groupStudents.filter((s: any) => uidSet.has(s.uid));
    } else if (target === "unpaid_payment" && paymentTitle) {
      const uids = groupStudents.map((s: any) => s.uid);
      const { data: paymentsData } = await supabase
        .from("payments")
        .select("student_uid, amount, total_amount")
        .in("student_uid", uids)
        .eq("title", paymentTitle);
      const paidMap = new Map<string, { amount: number; total: number }>();
      (paymentsData || []).forEach((p: any) => paidMap.set(p.student_uid, { amount: p.amount, total: p.total_amount }));
      targetStudents = groupStudents.filter((s: any) => {
        const record = paidMap.get(s.uid);
        return !record || record.amount < record.total;
      });
    } else if (target === "unpaid_book" && bookId) {
      const { data: bookRow } = await supabase.from("books").select("price").eq("id", bookId).maybeSingle();
      const bookPrice = bookRow?.price || 0;
      const { data: bookPaymentsData } = await supabase
        .from("book_payments").select("student_uid, amount").eq("book_id", bookId);
      const paidMap = new Map<string, number>();
      (bookPaymentsData || []).forEach((p: any) => paidMap.set(p.student_uid, p.amount));
      targetStudents = groupStudents.filter((s: any) => (paidMap.get(s.uid) || 0) < bookPrice);
    }
    // target === "group" (أو أي قيمة تانية) => كل طلاب المجموعة

    targetStudents = targetStudents.filter((s: any) => !!s.parent_phone);

    if (targetStudents.length === 0) {
      return new Response(JSON.stringify({ success: false, message: "لا يوجد أولياء أمور مطابقين للاختيار" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ✅ الرسالة توصل ولي الأمر باسم المدرس دايماً (حتى لو المساعد اللي بعتها)،
    // عشان منتفاداش لبس لو فيه مدرسين مختلفين عندهم مساعدين بنفس الاسم
    let senderName = payload.name || "المدرس";
    if (payload.role === "assistant") {
      const { data: teacherRow } = await supabase
        .from("teachers").select("name").eq("client_id", finalClientId).maybeSingle();
      senderName = teacherRow?.name || "المدرس";
    }
    const finalTitle = title || "رسالة جديدة";
    const rows = targetStudents.map((s: any) => ({
      teacher_id: finalClientId,
      parent_phone: s.parent_phone,
      student_uid: s.uid,
      type: "bulk_message",
      audience: "parent",
      title: finalTitle,
      message: `من: ${senderName} — بخصوص: ${s.name}\n\n${message}`,
      details: { group_name: groupName, student_name: s.name, sender_name: senderName },
    }));

    const { error: insertError } = await supabase.from("notifications").insert(rows);
    if (insertError) {
      return new Response(JSON.stringify({ success: false, message: insertError.message }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    sendPushToManyRecipients(supabase, "parent", targetStudents.map((s: any) => (
      { recipientId: s.parent_phone, title: finalTitle, body: `من: ${senderName} — بخصوص: ${s.name}\n\n${message}` }
    )));

    await supabase.from("activity_logs").insert({
      client_id: finalClientId, teacher_id: finalClientId, action_type: "bulk_message",
      details: { group_name: groupName, recipients: rows.length, target: target || "group" },
      performer_id: payload.sub, performer_role: payload.role, performer_name: payload.name,
    });

    return new Response(JSON.stringify({
      success: true,
      message: `✅ تم إرسال الرسالة لـ ${rows.length} ولي أمر`,
      data: { recipients: rows.length }
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    if (error instanceof AuthError) return authErrorResponse(error);
    return new Response(JSON.stringify({ success: false, message: error.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
