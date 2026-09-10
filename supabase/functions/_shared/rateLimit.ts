// supabase/functions/_shared/rateLimit.ts
// ============================================
// حماية عامة من الاستخدام المتكرر/التخمين (rate limiting)
// يعتمد على جدول login_attempts (key, attempts, locked_until, last_attempt)
// نفس الجدول يُستخدم لأي مفتاح (login أو change-password...) بادئة مختلفة فقط
// ============================================
// اسم مستعار فريد عمداً لتفادي أي تعارض مع "createClient" في الملفات اللي بتدمج هذا الموديول
import { createClient as _createRateLimitClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

export interface RateLimitOptions {
  maxAttempts?: number;   // الحد الأقصى للمحاولات قبل الحظر (افتراضي 5)
  lockMinutes?: number;   // مدة الحظر بالدقائق (افتراضي 15)
}

function adminClient() {
  const url = Deno.env.get("DATABASE_URL") || Deno.env.get("SUPABASE_URL") || "";
  const key = Deno.env.get("SERVICE_ROLE") || Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
  return _createRateLimitClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
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
