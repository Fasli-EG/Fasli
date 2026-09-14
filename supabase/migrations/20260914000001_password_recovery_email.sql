-- ============================================
-- استرجاع كلمة المرور الذاتي لكل الأدوار (غير الماستر أدمن، اللي بيستخدم Supabase الجاهز
-- لأن إيميله حقيقي أصلاً) — إيميل اختياري لكل حساب يضيفه صاحبه بنفسه من إعدادات حسابه،
-- وجدول توكنات استرجاع لمرة واحدة (صالح ساعة) بيتبعت عليه عن طريق Resend مباشرة.
-- ============================================

alter table teachers add column if not exists recovery_email text;
alter table assistants add column if not exists recovery_email text;
alter table parents add column if not exists recovery_email text;
alter table students add column if not exists recovery_email text;

create table if not exists password_reset_tokens (
  id bigint generated always as identity primary key,
  auth_user_id uuid not null,
  token_hash text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_password_reset_tokens_auth_user_id on password_reset_tokens(auth_user_id);
