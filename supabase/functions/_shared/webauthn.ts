// supabase/functions/_shared/webauthn.ts
// ============================================
// هيلبر مشترك للدخول بالبصمة/الوجه (WebAuthn) — يُستخدم في الـ4 فانكشنز المخصصة له فقط.
// ============================================
export {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "jsr:@simplewebauthn/server@14";

/** اسم "الجهة المعتمِدة" (Relying Party) اللي بيتعرض للمستخدم وقت تسجيل البصمة */
export const RP_NAME = "فَصلي";
/** هوية الجهة المعتمِدة — لازم يطابق الدومين اللي الموقع شغال عليه بالظبط (من غير مسار) */
export const RP_ID = "fasli-eg.github.io";
/** الأصل (origin) اللي المفروض الطلبات توصل منه — يُستخدم في التحقق من كل رد بصمة */
export const ORIGIN = "https://fasli-eg.github.io";

/** يحوّل Uint8Array لنص base64url عشان نخزّنه في عمود text */
export function bufferToBase64url(buf: Uint8Array): string {
  let str = "";
  for (const b of buf) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** عكس bufferToBase64url — بيرجّع Uint8Array من النص المخزّن */
export function base64urlToBuffer(b64url: string): Uint8Array {
  const pad = (4 - (b64url.length % 4)) % 4;
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  const str = atob(b64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
}

/** أقصى عمر لأي challenge قبل ما يُعتبر منتهي الصلاحية (بالميلي ثانية) */
export const CHALLENGE_MAX_AGE_MS = 5 * 60 * 1000;
