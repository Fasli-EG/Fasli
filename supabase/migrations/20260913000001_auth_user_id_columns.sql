-- ============================================
-- إضافة auth_user_id لربط كل حساب بمستخدم Supabase Auth الحقيقي المقابل له
-- ============================================
-- جزء من الهجرة لـSupabase Auth: كل حساب جديد من دلوقتي هيتعمل له مستخدم في auth.users
-- (بإيميل حقيقي للماستر، وإيميل/تليفون صناعي لباقي الأدوار)، والعمود ده بيخزّن الـUUID الراجع
-- عشان نقدر نستخدمه بعدين في تصفير الباسورد (auth.admin.updateUserById) وحذف الحساب.
-- الحسابات القديمة (اختبار) هتفضل NULL هنا لحد ما تتعاد إضافتها من جديد بالنظام الجديد.

alter table teachers add column if not exists auth_user_id uuid;
alter table assistants add column if not exists auth_user_id uuid;
alter table parents add column if not exists auth_user_id uuid;
alter table students add column if not exists auth_user_id uuid;

create unique index if not exists teachers_auth_user_id_key on teachers(auth_user_id) where auth_user_id is not null;
create unique index if not exists assistants_auth_user_id_key on assistants(auth_user_id) where auth_user_id is not null;
create unique index if not exists parents_auth_user_id_key on parents(auth_user_id) where auth_user_id is not null;
create unique index if not exists students_auth_user_id_key on students(auth_user_id) where auth_user_id is not null;
