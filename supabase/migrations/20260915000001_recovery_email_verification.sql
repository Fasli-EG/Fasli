-- ============================================
-- إيميل الاسترجاع بقى إجباري لأول تسجيل دخول للحسابات الجديدة (كل الأدوار)، ولازم يتأكد
-- برمز عشوائي بيتبعت على الإيميل نفسه قبل ما يقدر المستخدم يكمل استخدام النظام عادي.
-- الحسابات الموجودة قبل هذا التحديث بتتحسب "متوافقة قديمًا" (true) عشان محدش يتقفل فجأة
-- من حساب كان شغال عادي من قبل — بس أي حساب جديد من دلوقتي بياخد false الافتراضية.
-- ============================================

alter table teachers add column if not exists recovery_email_verified boolean not null default false;
alter table assistants add column if not exists recovery_email_verified boolean not null default false;
alter table parents add column if not exists recovery_email_verified boolean not null default false;
alter table students add column if not exists recovery_email_verified boolean not null default false;

update teachers set recovery_email_verified = true;
update assistants set recovery_email_verified = true;
update parents set recovery_email_verified = true;
update students set recovery_email_verified = true;

-- رموز التأكيد المؤقتة (6 أرقام) لإيميل الاسترجاع، مشتركة بين كل الأدوار
create table if not exists recovery_email_codes (
  id bigint generated always as identity primary key,
  role text not null check (role in ('teacher', 'assistant', 'parent', 'student')),
  identifier text not null, -- client_id / assistant id / phone / uid حسب الدور
  email text not null,
  code_hash text not null,
  attempts integer not null default 0,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_recovery_email_codes_lookup on recovery_email_codes (role, identifier);

alter table recovery_email_codes enable row level security;
-- ✅ مفيش أي policy هنا عن قصد (زي password_reset_tokens) — الوصول كله عن طريق service_role
-- في Edge Functions، فـanon/authenticated ميقدروش يوصلوا للجدول ده مباشرة.
