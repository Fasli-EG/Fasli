-- جدول تتبع محاولات الدخول الفاشلة (لحماية login من التخمين المتكرر - brute force)
-- شغّل هذا الملف مرة واحدة في Supabase SQL Editor قبل رفع دالة login الجديدة

create table if not exists login_attempts (
  username text primary key,
  attempts int not null default 0,
  locked_until timestamptz,
  last_attempt timestamptz default now()
);

-- تنظيف دوري اختياري (تقدر تعمله بـ pg_cron لو متاح عندك)
-- delete from login_attempts where last_attempt < now() - interval '7 days';
