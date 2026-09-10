-- إضافة حد أقصى اختياري لعدد الطلاب لكل مجموعة (NULL = بدون حد).
-- بيُستخدم في تفعيل قائمة انتظار تلقائية عند تسجيل طلب انضمام عام (submit-registration-request)
-- لمجموعة وصلت لحدها الأقصى.
ALTER TABLE groups ADD COLUMN IF NOT EXISTS max_students integer;
