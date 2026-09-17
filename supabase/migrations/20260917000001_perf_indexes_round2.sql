-- ============================================
-- فحص أداء شامل (سبتمبر 2026) لقى إن جدول notifications معندوش أي index خالص رغم إنه من
-- أكتر الجداول استعلامًا (جرس الإشعارات بيتحدّث كل شوية ثواني في كل صفحة)، وإن grades.teacher_id
-- وexam_attempts.exam_id وattendance.session_id (أعمدة بتتفلتر عليها بشكل متكرر) من غير أي index
-- برضه. بتضيف indexes إضافية جنب اللي موجودة أصلاً من 20260910000001_perf_indexes.sql
-- ============================================

create index if not exists idx_notifications_teacher_id on notifications (teacher_id);
create index if not exists idx_notifications_parent_phone on notifications (parent_phone);
create index if not exists idx_notifications_student_uid on notifications (student_uid);
create index if not exists idx_notifications_assistant_id on notifications (assistant_id);

create index if not exists idx_grades_teacher_id on grades (teacher_id);
create index if not exists idx_grades_teacher_group on grades (teacher_id, group_name);

create index if not exists idx_exam_attempts_exam_id on exam_attempts (exam_id);

create index if not exists idx_attendance_session_id on attendance (session_id);

create index if not exists idx_students_teacher_group on students (teacher_id, group_name);
create index if not exists idx_payments_teacher_group on payments (teacher_id, group_name);
