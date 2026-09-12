-- ✅ (تصليح) عمود attendance.time في baseline_schema.sql اتحط غلط كـ "time" (نوع SQL وقت حقيقي)
-- بدل "text" — الكود الفعلي بيولّد النص بصيغة toLocaleTimeString("ar-EG", ...) زي "٠٨:٢٠ م"
-- (أرقام عربية + ص/م)، وده مايتقبلش خالص كنوع "time" حقيقي. الباج ده ظهر بس على بيئة
-- staging (اللي schema بتاعتها اتبنيت يدوي من غير introspection حقيقي)، والإنتاج سليم
-- أصلاً لأن عموده الحقيقي "text" من الأول — اتأكد بفحص قيم حقيقية موجودة فيه.
alter table attendance alter column time type text;
