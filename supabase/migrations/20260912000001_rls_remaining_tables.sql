-- ============================================
-- إكمال تفعيل Row Level Security على باقي الجداول (طبقة حماية إضافية)
-- ============================================
-- نفس منطق 20260101000002_rls_policies.sql بالظبط: كل الدوال الخلفية (Edge Functions) بتستخدم
-- service_role key، وهو دايماً بيتخطى RLS بغض النظر عن أي policy موجودة أو مش موجودة — يعني
-- تفعيل RLS هنا مش هيأثر على شغل النظام الحالي إطلاقاً.
--
-- الفايدة: لو أي دالة (حالياً أو مستقبلاً) رجعت تستخدم anon key بالغلط، أو لو مفتاح anon
-- اتسرّب بأي شكل، من غير RLS anon key بيبقى ليه صلاحية قراءة/كتابة كاملة على الجدول (سلوك
-- Supabase الافتراضي). مع RLS مفعّل وبدون أي policy، أي طلب من anon/authenticated هيترفض
-- تلقائياً (deny by default)، وبيفضل بس service_role قادر يوصل.
--
-- الجداول التسعة عشر الأصلية (teachers, assistants, parents, students, grades, payments, books,
-- book_payments, attendance, activity_logs, login_attempts) + conversation_messages اتغطوا
-- بالفعل في migrations سابقة. الملف ده بيغطي كل الباقي.

alter table centers enable row level security;
alter table education_levels enable row level security;
alter table instructor_names enable row level security;
alter table groups enable row level security;
alter table student_group_links enable row level security;
alter table student_teacher_links enable row level security;
alter table system_cards enable row level security;
alter table pending_card_registrations enable row level security;
alter table card_action_mode enable row level security;
alter table master_device enable row level security;
alter table master_scan_mode enable row level security;
alter table rfid_scans enable row level security;
alter table payment_titles enable row level security;
alter table expenses enable row level security;
alter table exam_titles enable row level security;
alter table online_exams enable row level security;
alter table exam_questions enable row level security;
alter table exam_target_students enable row level security;
alter table exam_attempts enable row level security;
alter table exam_answers enable row level security;
alter table attendance_sessions enable row level security;
alter table notifications enable row level security;
alter table push_tokens enable row level security;
alter table registration_requests enable row level security;
alter table login_ads enable row level security;
alter table portal_banners enable row level security;
alter table photo_albums enable row level security;
alter table photo_album_images enable row level security;
alter table system_settings enable row level security;

-- ✅ مفيش أي "create policy" هنا عن قصد = رفض افتراضي كامل لـ anon/authenticated.
-- service_role دايماً بيتخطى RLS فمش محتاج policy خاصة بيه.
