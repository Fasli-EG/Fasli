-- ============================================
-- إصلاح حرج: عمود center_id في system_cards موجود في نص هجرة baseline_schema.sql لكن مش
-- موجود فعليًا في قاعدة البيانات المنشورة — الجدول كان اتعمل قبل ما العمود ده يتضاف للملف،
-- و"create table if not exists" مبيعملش أي حاجة لجدول موجود بالفعل حتى لو أعمدته مختلفة.
-- النتيجة: أي استعلام بيقرا system_cards.center_id (record-attendance، manage-system-cards،
-- manage-card-registration) كان بيفشل بصمت، وده كان بيمنع تسجيل الحضور بالكارت تمامًا لما
-- "طلب كروت مسجّلة رسميًا فقط" يكون مفعّل في إعدادات النظام.
-- ============================================

alter table system_cards add column if not exists center_id bigint references centers (id) on delete cascade;
