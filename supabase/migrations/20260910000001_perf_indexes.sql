-- ✅ تحسين أداء: إضافة إندكسات على أعمدة الفلترة الأكثر استخدامًا في الفانكشنز
-- (get-dashboard, get-students, get-payments, get-grades, generate-report,
-- get-activity-logs, take-exam ...) — من غير رؤية على قاعدة البيانات الفعلية
-- من هنا كان مستحيل نتأكد إيه موجود بالفعل، فكل الإندكسات دي IF NOT EXISTS
-- (آمنة تمامًا تتنفذ حتى لو الإندكس موجود أصلاً، مش هتعمل تكرار ولا تفشل).
CREATE INDEX IF NOT EXISTS idx_students_teacher_id ON students (teacher_id);
CREATE INDEX IF NOT EXISTS idx_attendance_teacher_date ON attendance (teacher_id, date);
CREATE INDEX IF NOT EXISTS idx_attendance_student_uid ON attendance (student_uid);
CREATE INDEX IF NOT EXISTS idx_payments_teacher_id ON payments (teacher_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_teacher_created ON activity_logs (teacher_id, created_at);
CREATE INDEX IF NOT EXISTS idx_exam_attempts_student_uid ON exam_attempts (student_uid);
CREATE INDEX IF NOT EXISTS idx_book_payments_teacher_id ON book_payments (teacher_id);
