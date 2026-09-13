-- ============================================
-- الدخول بالبصمة/الوجه (WebAuthn/Passkeys) — موحّد لكل الأدوار
-- ============================================
-- webauthn_credentials: مفتاح عام واحد لكل جهاز مسجَّل، مربوط بـauth_user_id (UUID حقيقي في
-- auth.users)، مش بأي معرّف عمل (client_id/username/phone/uid) — عشان يفضل شغال حتى لو
-- المعرّف ده اتغيّر بعدين.
-- webauthn_challenges: تخزين مؤقت (single-use) للـchallenge بتاع كل محاولة تسجيل/دخول، بيتمسح
-- فور التحقق منه (نجح أو فشل) — مفيش داعي لتنظيف دوري لأن كل صف بيتمسح فور استخدامه.

create table if not exists webauthn_credentials (
  id bigint generated always as identity primary key,
  auth_user_id uuid not null,
  credential_id text not null unique,
  public_key text not null,
  counter bigint not null default 0,
  device_type text,
  backed_up boolean not null default false,
  transports text[],
  device_name text,
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);
create index if not exists webauthn_credentials_auth_user_id_idx on webauthn_credentials(auth_user_id);

create table if not exists webauthn_challenges (
  id bigint generated always as identity primary key,
  challenge text not null,
  auth_user_id uuid,
  purpose text not null check (purpose in ('register', 'login')),
  created_at timestamptz not null default now()
);

alter table webauthn_credentials enable row level security;
alter table webauthn_challenges enable row level security;
-- ✅ مفيش أي "create policy" هنا عن قصد (زي باقي الجداول) — كل الوصول عن طريق Edge Functions
-- بـservice_role اللي بيتخطى RLS دايمًا، فـanon/authenticated ميقدروش يوصلوا للجدولين دول مباشرة.
