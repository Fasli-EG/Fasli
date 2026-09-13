// supabase/functions/_shared/authProvision.ts
// ============================================
// هيلبر مشترك لإنشاء/حذف/تسجيل دخول حسابات Supabase Auth — يُستخدم في كل مكان بينشئ
// مدرس/مساعد/ولي أمر/طالب جديد، بدل التكرار اليدوي في كل فانكشن على حدة.
// ============================================
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.38.4";

function adminClient() {
  const url = Deno.env.get("SUPABASE_URL") || Deno.env.get("DATABASE_URL") || "";
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE") || "";
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
}

export interface ProvisionAuthUserParams {
  email?: string;
  phone?: string;
  password: string;
  appMetadata: Record<string, unknown>;
}

/** ينشئ مستخدم Supabase Auth جديد ويرجّع الـUUID بتاعه. يرمي خطأ لو فشل الإنشاء. */
export async function provisionAuthUser(params: ProvisionAuthUserParams): Promise<string> {
  const supabase = adminClient();
  const { data, error } = await supabase.auth.admin.createUser({
    email: params.email,
    phone: params.phone,
    password: params.password,
    email_confirm: params.email ? true : undefined,
    phone_confirm: params.phone ? true : undefined,
    app_metadata: params.appMetadata,
  });
  if (error || !data.user) {
    throw new Error(`⚠️ فشل إنشاء حساب الدخول: ${error?.message || "خطأ غير معروف"}`);
  }
  return data.user.id;
}

/** يحذف مستخدم Supabase Auth — عند حذف الحساب المقابل في الجدول، أو للتراجع لو فشلت خطوة تانية بعد الإنشاء مباشرة */
export async function deleteAuthUser(authUserId: string | null | undefined): Promise<void> {
  if (!authUserId) return;
  const supabase = adminClient();
  await supabase.auth.admin.deleteUser(authUserId).catch(() => {});
}

/** يحدّث app_metadata لمستخدم موجود (مفيد لو احتجنا نصلّح/نكمّل بيانات بعد الإنشاء) */
export async function updateAuthUserMetadata(authUserId: string, appMetadata: Record<string, unknown>): Promise<void> {
  const supabase = adminClient();
  await supabase.auth.admin.updateUserById(authUserId, { app_metadata: appMetadata });
}

/** يحدّث الإيميل/التليفون/app_metadata لمستخدم موجود — يُستخدم مثلاً لما ولي أمر يغيّر رقمه
 * فنحدّث نفس حساب Supabase Auth بدل ما ننشئ حساب جديد ونفقد ربطه بأي جلسات/سجلات قديمة */
export async function updateAuthUserContact(
  authUserId: string,
  updates: { email?: string; phone?: string; appMetadata?: Record<string, unknown> }
): Promise<void> {
  const supabase = adminClient();
  const { error } = await supabase.auth.admin.updateUserById(authUserId, {
    email: updates.email,
    phone: updates.phone,
    app_metadata: updates.appMetadata,
  });
  if (error) throw new Error(`⚠️ فشل تحديث بيانات الحساب: ${error.message}`);
}

/** يغيّر باسورد مستخدم موجود — البديل الجديد لكتابة password_hash يدوياً */
export async function updateAuthUserPassword(authUserId: string, newPassword: string): Promise<void> {
  const supabase = adminClient();
  const { error } = await supabase.auth.admin.updateUserById(authUserId, { password: newPassword });
  if (error) throw new Error(`⚠️ فشل تغيير كلمة المرور: ${error.message}`);
}

/** يسجّل دخول مستخدم موجود بالإيميل أو التليفون + الباسورد، ويرجّع الجلسة (access_token/refresh_token) */
export async function signInAuthUser(params: { email?: string; phone?: string; password: string }) {
  const supabase = adminClient();
  const credentials = params.email
    ? { email: params.email, password: params.password }
    : { phone: params.phone as string, password: params.password };
  return await supabase.auth.signInWithPassword(credentials);
}

/** اتفاقية الإيميل/التليفون الصناعي الموحّدة لكل الأدوار (المصدر الوحيد لهذا المنطق) */
export function syntheticEmailFor(role: "teacher" | "assistant" | "student", identifier: string): string {
  const prefix = role === "teacher" ? "t" : role === "assistant" ? "a" : "s";
  return `${prefix}_${identifier}@fasli.internal`;
}
