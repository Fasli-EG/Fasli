-- ============================================
-- تفعيل Row Level Security على كل الجداول (طبقة حماية إضافية)
-- ============================================
-- كل الدوال الخلفية (Edge Functions) بتستخدم service_role key، وهو دايماً
-- بيتخطى RLS بغض النظر عن أي policy موجودة أو مش موجودة.
-- يعني تفعيل RLS هنا مش هيأثر على شغل النظام الحالي إطلاقاً.
--
-- الفايدة: لو أي دالة (حالياً أو مستقبلاً) رجعت تستخدم anon key بالغلط
-- (زي نمط "SERVICE_ROLE || ANON_KEY" الموجود في بعض الدوال القديمة كـ fallback
-- في حالة نسيان ضبط SERVICE_ROLE) — من غير RLS، anon key بيبقى ليه صلاحية
-- قراءة/كتابة كاملة على الجدول (سلوك Supabase الافتراضي). مع RLS مفعّل وبدون
-- أي policy، أي طلب من anon/authenticated هيترفض تلقائياً (deny by default)،
-- وبيفضل بس service_role قادر يوصل - وهو المستخدم فعلياً من الدوال.

alter table teachers enable row level security;
alter table assistants enable row level security;
alter table parents enable row level security;
alter table students enable row level security;
alter table grades enable row level security;
alter table payments enable row level security;
alter table books enable row level security;
alter table book_payments enable row level security;
alter table attendance enable row level security;
alter table activity_logs enable row level security;
alter table login_attempts enable row level security;

-- شغّل السطر ده بس لو عندك جدول groups منفصل (بعض النسخ بتستخدمه، البعض بيشتق المجموعات من عمود group_name في students)
-- alter table groups enable row level security;

-- ✅ مفيش أي "create policy" هنا عن قصد = رفض افتراضي كامل لـ anon/authenticated.
-- service_role دايماً بيتخطى RLS فمش محتاج policy خاصة بيه.
