-- أعمدة system_settings الإضافية الحقيقية (إعدادات Firebase، بانرات البوابة،
-- روابط السوشيال ميديا، إلخ) — موجودة على الإنتاج فعليًا (اتضافت من الداشبورد
-- مباشرة بعد ما 20260101000003_system_settings.sql عملت الجدول بشكله المبدئي)
-- لكن مالهاش migration موثّقة، فده تسجيل توثيقي لها. كل حاجة IF NOT EXISTS —
-- آمنة تمامًا لو الأعمدة موجودة بالفعل.

alter table system_settings add column if not exists admin_name text;
alter table system_settings add column if not exists admin_whatsapp text;
alter table system_settings add column if not exists tiktok_url text;
alter table system_settings add column if not exists youtube_url text;
alter table system_settings add column if not exists desktop_download_url text;
alter table system_settings add column if not exists mobile_app_url text;
alter table system_settings add column if not exists show_download_section boolean not null default true;
alter table system_settings add column if not exists require_registered_cards boolean not null default false;
alter table system_settings add column if not exists login_credit_show boolean not null default true;
alter table system_settings add column if not exists login_credit_text text;
alter table system_settings add column if not exists firebase_api_key text;
alter table system_settings add column if not exists firebase_app_id text;
alter table system_settings add column if not exists firebase_auth_domain text;
alter table system_settings add column if not exists firebase_messaging_sender_id text;
alter table system_settings add column if not exists firebase_project_id text;
alter table system_settings add column if not exists firebase_storage_bucket text;
alter table system_settings add column if not exists firebase_vapid_key text;
alter table system_settings add column if not exists portal_banner_url text;
alter table system_settings add column if not exists portal_banner_link_url text;
alter table system_settings add column if not exists portal_banner_show_teacher boolean not null default false;
alter table system_settings add column if not exists portal_banner_teacher_url text;
alter table system_settings add column if not exists portal_banner_teacher_link_url text;
alter table system_settings add column if not exists portal_banner_show_assistant boolean not null default false;
alter table system_settings add column if not exists portal_banner_assistant_url text;
alter table system_settings add column if not exists portal_banner_assistant_link_url text;
alter table system_settings add column if not exists portal_banner_show_parent boolean not null default false;
alter table system_settings add column if not exists portal_banner_parent_url text;
alter table system_settings add column if not exists portal_banner_parent_link_url text;
alter table system_settings add column if not exists portal_banner_show_student boolean not null default false;
alter table system_settings add column if not exists portal_banner_student_url text;
alter table system_settings add column if not exists portal_banner_student_link_url text;
