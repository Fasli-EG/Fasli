-- ============================================
-- password_hash بقى اختياري (nullable) على كل جداول الحسابات
-- ============================================
-- جزء من الهجرة لـSupabase Auth: الحسابات الجديدة من دلوقتي بتتعمل عن طريق Supabase Auth
-- (auth_user_id) وملهاش أي داعي لـpassword_hash خالص — العمود ده فضل NOT NULL على teachers
-- على الأقل (اتحط كده يدويًا على الإنتاج قبل كده، مش من خلال migration متتبّعة)، فأي إدخال
-- صف جديد من غير قيمة فيه كان بيفشل بخطأ "null value ... violates not-null constraint".
-- بنسيب العمود نفسه موجود (الحسابات القديمة لسه محتفظة بقيمته) بس نشيل القيد الإجباري بس.

alter table teachers alter column password_hash drop not null;
alter table assistants alter column password_hash drop not null;
alter table parents alter column password_hash drop not null;
alter table students alter column password_hash drop not null;
alter table centers alter column password_hash drop not null;
