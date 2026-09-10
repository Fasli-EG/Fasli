// supabase/functions/_shared/password.ts
// ============================================
// هاش كلمات المرور: PBKDF2-SHA256 (native Web Crypto API)
// اخترنا PBKDF2 بدل bcrypt لأنه مدعوم أصلاً في Deno/Supabase Edge Functions
// بدون أي مكتبة WASM خارجية قد تفشل في بيئة الإنتاج.
// ============================================

const ITERATIONS = 100_000;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

/** مقارنة بزمن ثابت لمنع timing attacks */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** هاش SHA-256 بسيط (النظام القديم) — لأغراض التوافق الخلفي فقط */
async function legacySha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(hashBuffer));
}

/** ينشئ هاش جديد بصيغة pbkdf2$<iterations>$<salt>$<hash> */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hashBytes = await pbkdf2(password, salt, ITERATIONS);
  return `pbkdf2$${ITERATIONS}$${toHex(salt)}$${toHex(hashBytes)}`;
}

/**
 * يتحقق من كلمة المرور مقابل الهاش المخزّن (يدعم الصيغة الجديدة pbkdf2 والقديمة sha256 hex).
 * needsRehash=true تعني إن كلمة المرور صحيحة لكن مخزّنة بالصيغة القديمة الأضعف،
 * فيُستحسن استبدالها بهاش pbkdf2 جديد فوراً (ترقية شفافة تلقائية عند أول تسجيل دخول ناجح).
 */
export async function verifyPassword(
  password: string,
  storedHash: string
): Promise<{ valid: boolean; needsRehash: boolean }> {
  if (storedHash.startsWith("pbkdf2$")) {
    const parts = storedHash.split("$");
    if (parts.length !== 4) return { valid: false, needsRehash: false };
    const [, iterStr, saltHex, hashHex] = parts;
    const iterations = parseInt(iterStr, 10);
    const salt = fromHex(saltHex);
    const computed = await pbkdf2(password, salt, iterations);
    const valid = timingSafeEqual(toHex(computed), hashHex);
    return { valid, needsRehash: false };
  }

  // صيغة قديمة: SHA-256 hex بدون salt
  const legacy = await legacySha256(password);
  const valid = timingSafeEqual(legacy, storedHash);
  return { valid, needsRehash: valid }; // لو صحّت، نرقّيها فوراً بعد الاستخدام
}
