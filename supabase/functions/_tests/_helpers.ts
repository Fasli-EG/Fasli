// supabase/functions/_tests/_helpers.ts
// ============================================
// أدوات مشتركة لاختبارات Deno بتشتغل ضد بيئة staging حقيقية (مش mocking) —
// نفس فلسفة الاختبار الحي اللي اتعمل يدوياً على الإنتاج، بس آلي وقابل للتكرار.
//
// طريقة التشغيل:
//   1. اتأكد إن ملف .env.test.local موجود (مش متتبّع في git) وفيه:
//        STAGING_URL=https://<project-ref>.supabase.co
//        STAGING_JWT_SECRET=...
//      (القيم موجودة في secrets-do-not-upload/supabase-staging-credentials.txt)
//   2. deno test --allow-net --allow-env --env-file=.env.test.local supabase/functions/_tests/
// ============================================

export const STAGING_URL = Deno.env.get("STAGING_URL") ?? "https://tahcnxuppewkexphevvq.supabase.co";
const JWT_SECRET = Deno.env.get("STAGING_JWT_SECRET");

function base64url(bytes: Uint8Array): string {
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** يمضي توكن HS256 بنفس شكل _shared/auth.ts بالظبط، لتوليد توكنات اختبار بدون المرور بـ login */
export async function mintToken(payload: Record<string, unknown>): Promise<string> {
  if (!JWT_SECRET) {
    throw new Error("⚠️ STAGING_JWT_SECRET غير مضبوط — شوف تعليمات _helpers.ts");
  }
  const header = { alg: "HS256", typ: "JWT" };
  const enc = new TextEncoder();
  const h = base64url(enc.encode(JSON.stringify(header)));
  const p = base64url(enc.encode(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, ...payload })));
  const signingInput = `${h}.${p}`;
  const key = await crypto.subtle.importKey("raw", enc.encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(signingInput)));
  return `${signingInput}.${base64url(sig)}`;
}

/** توكن master_admin — بيبايباس فحص الترخيص تلقائياً (نفس سلوك checkLicenseActive الحقيقي) */
export function adminToken(): Promise<string> {
  return mintToken({ sub: "master_admin", clientId: "master_admin", role: "teacher", name: "QA Admin" });
}

export function teacherToken(clientId: string, name = "QA Teacher"): Promise<string> {
  return mintToken({ sub: clientId, clientId, role: "teacher", name });
}

export function studentToken(uid: string, name = "QA Student"): Promise<string> {
  return mintToken({ sub: uid, role: "student", name });
}

export function parentToken(phone: string, name = "QA Parent"): Promise<string> {
  return mintToken({ sub: phone, phone, role: "parent", name });
}

/** استدعاء فانكشن على staging. من غير token بيبعت الطلب من غير Authorization header خالص (لاختبار الرفض) */
export async function callFn(name: string, token: string | null, body?: Record<string, unknown>): Promise<{ status: number; json: any }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${STAGING_URL}/functions/v1/${name}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body ?? {}),
  });
  let json: any = null;
  try { json = await res.json(); } catch { /* بعض الردود ممكن تبقى فاضية */ }
  return { status: res.status, json };
}

/** كل الفانكشنز اللي بتتحقق من verifyToken (يعني لازم ترفض طلب من غير توكن بـ 401) */
export const AUTH_GATED_FUNCTIONS = [
  "admin-get-students-for-teacher", "admin-get-teacher", "admin-get-teachers",
  "admin-manage-card-registration", "admin-manage-teacher", "admin-regenerate-device-secret",
  "bulk-import-students", "change-password", "check-student-uid",
  "create-exam-title", "create-payment-title", "delete-activity-log",
  "generate-report", "get-activity-logs", "get-assistants", "get-at-risk-students",
  "get-book-payment", "get-book-status", "get-books", "get-dashboard",
  "get-device-secret", "get-exam-report", "get-exams", "get-exams-for-student",
  "get-financial-summary", "get-grades", "get-groups", "get-latest-rfid-scan",
  "get-master-device-secret", "get-notifications", "get-parent-children",
  "get-payment-titles", "get-payments", "get-student-full-profile", "get-students",
  "get-teacher-contact", "get-titles", "get-today-attendance",
  "list-system-cards", "manage-assistant", "manage-backup", "manage-book",
  "manage-book-payment", "manage-card-registration", "manage-center", "manage-exam",
  "manage-expense", "manage-grade", "manage-group", "manage-group-sessions",
  "manage-instructor-names", "manage-levels", "manage-login-ad", "manage-master-scan",
  "manage-password-reset", "manage-payment", "manage-push-token", "manage-registration-requests",
  "manage-student", "manage-system-cards", "mark-notification-read",
  "reset-system", "send-bulk-message", "take-exam", "teacher-list-my-cards",
  "transfer-student", "update-admin-profile", "update-system-settings", "update-teacher-contact",
  "upload-book-file",
] as const;

/** فانكشنز عامة عن قصد (مش بتستخدم verifyToken) — مستثناة من اختبار "رفض بدون توكن" */
export const PUBLIC_OR_DEVICE_AUTH_FUNCTIONS = [
  "login", // ده أصلاً طريقة الحصول على توكن
  "get-login-ads", "get-system-settings", // عامة صراحةً — بتتستخدم في صفحة تسجيل الدخول قبل ما يكون فيه توكن أصلاً
  "submit-registration-request", // تسجيل ولي أمر ذاتي، محمي بـ registration_token عشوائي مش JWT
  "submit-rfid-scan", "submit-master-card-scan", "teacher-start-new-student-scan", // أجهزة ESP32، بتستخدم device secret
  "card-action-mode", // بيقبل توكن مدرس/مساعد أو device secret حسب الحالة
  "check-scheduled-exams", "check-session-absences", // cron جobs، بتقبل x-cron-secret بدل توكن مستخدم
  "record-attendance", // بيتحقق من وجود clientId/uid في الجسم الأول (يحدد مسار الأوث: سر جهاز أو توكن)، قبل أي فحص توكن — له اختبار مخصص تحت
] as const;
