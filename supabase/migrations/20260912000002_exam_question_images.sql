-- ✅ (طلب) دعم صورة كنص السؤال — لو السؤال فيه معادلة رياضية أو رسم بياني المدرس مش
-- هيقدر يكتبه كنص عادي، فبقى يقدر يرفع صورة للسؤال بدل الكتابة (أو بالإضافة للنص).
alter table exam_questions add column if not exists question_image_url text;

-- ✅ question_text كان NOT NULL (لازم نص دايمًا) — دلوقتي السؤال ممكن يكون صورة بس من غير نص خالص
alter table exam_questions alter column question_text drop not null;

-- ✅ Bucket تخزين عام لصور أسئلة الاختبارات (public لأن الطالب لازم يشوف الصورة من غير توكن
-- تخزين منفصل — نفس فكرة book-files، بس bucket مستقل عشان الصلاحيات/التنظيف يبقوا منفصلين)
insert into storage.buckets (id, name, public)
values ('exam-question-images', 'exam-question-images', true)
on conflict (id) do nothing;
