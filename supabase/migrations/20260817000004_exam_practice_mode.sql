-- وضع تدريب حر للامتحانات: نفس أسئلة الامتحان المنشور، لكن بلا وقت ومحاولات غير محدودة،
-- ومنفصل تماماً عن المحاولة الرسمية في كل تقارير المدرس (average score, تعداد الحضور... إلخ).
alter table exam_attempts add column if not exists mode text not null default 'official';
