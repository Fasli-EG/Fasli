-- تخصيص الشعار واللون الأساسي لكل مدرس أو سنتر (NULL = الشعار/اللون الافتراضي لفَصلي).
-- المدرس المستقل بيحدد الشعار/اللون بتاعه هو، والمدرس التابع لسنتر بيرث شعار السنتر
-- تلقائياً لو مالوش شعار خاص بيه (يُحل في دالة login وقت تسجيل الدخول).
ALTER TABLE teachers ADD COLUMN IF NOT EXISTS brand_logo_url text;
ALTER TABLE teachers ADD COLUMN IF NOT EXISTS brand_color text;
ALTER TABLE centers ADD COLUMN IF NOT EXISTS brand_logo_url text;
ALTER TABLE centers ADD COLUMN IF NOT EXISTS brand_color text;
