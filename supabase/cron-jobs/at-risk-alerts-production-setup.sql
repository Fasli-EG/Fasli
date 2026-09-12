-- ============================================
-- تفعيل الجدولة اليومية لتنبيهات "الطالب المعرّض للخطر" — الإنتاج فقط
-- ============================================
-- ⚠️ الملف ده مش migration عادية (عن قصد مش في مجلد supabase/migrations/) — لازم يتشغّل مرة
-- واحدة يدوياً من Supabase Dashboard → SQL Editor على مشروع الإنتاج (yxkyxxzcnxpxefodfxnl) بس.
--
-- السبب إنه مش migration عادية: لو اتحط في مجلد migrations/ العادي، أي "db push" لبيئة
-- staging (اللي بتستخدم نفس مجلد الـmigrations بالظبط) هيطبّق نفس الجدولة دي هناك كمان —
-- ومعناه staging هيبتدي يستدعي فانكشن الإنتاج الحقيقية دوريًا ويبعت تنبيهات حقيقية لمدرسين
-- حقيقيين من بيئة اختبار! فالخطوة دي اتعزلت عمداً برة نظام الـmigrations الآلي.
--
-- طريقة التشغيل: افتح https://supabase.com/dashboard/project/yxkyxxzcnxpxefodfxnl/sql/new،
-- استبدل <AT_RISK_CRON_SECRET> تحت بالقيمة الحقيقية (موجودة في
-- secrets-do-not-upload/at-risk-cron-secret.txt على جهاز التطوير)، والصق الكود كامل، وشغّله
-- — مرة واحدة بس، مش محتاج تتكرر.

create extension if not exists pg_cron with schema extensions;
create extension if not exists pg_net with schema extensions;

select cron.schedule(
  'check-at-risk-alerts-daily',
  '0 6 * * *', -- الساعة 6 صباحاً UTC = 8 صباحاً بتوقيت القاهرة، كل يوم
  $$
  select net.http_post(
    url := 'https://yxkyxxzcnxpxefodfxnl.supabase.co/functions/v1/check-at-risk-alerts',
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-cron-secret', '<AT_RISK_CRON_SECRET>'),
    body := jsonb_build_object('systemRun', true)
  );
  $$
);

-- ✅ للتأكد إن الجدولة اتسجّلت صح بعد التشغيل:
-- select * from cron.job where jobname = 'check-at-risk-alerts-daily';

-- ✅ لو حبيت تشيل الجدولة دي في أي وقت:
-- select cron.unschedule('check-at-risk-alerts-daily');
