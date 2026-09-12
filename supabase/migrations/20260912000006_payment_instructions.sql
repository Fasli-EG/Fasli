-- ✅ (طلب) المدرس محتاج مكان يكتب فيه بيانات الدفع بتاعته (إنستاباي/محفظة/حساب بنكي) عشان
-- ولي الأمر يعرف يحوّل فلوسه على مين قبل ما يرفع إيصال — كانت الميزة كاملة من غير الجزء ده
alter table teachers add column if not exists payment_instapay text;
alter table teachers add column if not exists payment_wallet text;
alter table teachers add column if not exists payment_bank_details text;
