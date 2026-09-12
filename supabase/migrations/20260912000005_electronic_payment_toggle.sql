-- ✅ (طلب) رفع إيصال الدفع (الحل المجاني) لازم يكون اختياري بقرار المدرس، مش شغال تلقائي —
-- افتراضيًا معطّل (false) لحد ما المدرس يفعّله بنفسه من إعدادات الحساب.
alter table teachers add column if not exists electronic_payment_enabled boolean not null default false;
