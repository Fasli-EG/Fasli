-- ============================================================
-- Baseline schema reconstruction
-- ============================================================
-- الجداول الأساسية اتعملت مباشرة من Supabase Dashboard قبل ما نبدأ نستخدم
-- migrations (أول migration حقيقية تاريخها 2026-01-01 وبتفترض الجداول دي
-- موجودة أصلاً). النتيجة: مفيش سجل SQL كامل للسكيما في الكود.
--
-- ⚠️ ملاحظة أمانة مهمة: الملف ده اتبني يدويًا من قراءة كود الـ82 فانكشن
-- (أسماء الأعمدة الحقيقية المستخدمة في .select()/.insert()/.update()/.eq())
-- + الـmigrations الإضافية الموجودة فعلاً — مش ناتج pg_dump حقيقي (البيئة دي
-- من غير Docker/psql فمقدرش أشغّل pg_dump مباشرة ضد قاعدة الإنتاج).
-- يعني ممكن يكون فيه فروق بسيطة عن السكيما الحقيقية (طول varchar، CHECK
-- constraint مش واضح من الكود، إلخ). الهدف: تأسيس بيئة staging شغالة،
-- مش نسخة احتياطية دقيقة 100% لكوارث الإنتاج — لسه يستاهل نسخة احتياطية
-- حقيقية من لوحة تحكم Supabase (Database → Backups) بشكل منفصل.
--
-- كل الجداول هنا `create table if not exists` — آمنة تمامًا لو اتشغّلت على
-- قاعدة فيها الجداول دي بالفعل (زي الإنتاج): مش هتعمل حاجة.
-- ============================================================

-- ---------- الكيانات الجذرية ----------

create table if not exists teachers (
  client_id text primary key,
  name text not null,
  password_hash text,
  must_change_password boolean not null default true,
  is_active boolean not null default true,
  expiry_date date,
  max_students integer not null default 0,
  student_count integer not null default 0,
  device_secret text,
  is_center boolean not null default false,
  center_id bigint,
  permissions jsonb not null default '{}'::jsonb,
  center_sharing_permissions jsonb not null default '{}'::jsonb,
  contact_phone text,
  contact_whatsapp text,
  phone_visible boolean not null default true,
  whatsapp_visible boolean not null default true,
  conversations_enabled boolean not null default true,
  registration_token text,
  created_at timestamptz not null default now()
);

create table if not exists centers (
  id bigint generated always as identity primary key,
  client_id text not null references teachers (client_id) on delete cascade,
  name text not null,
  owner_name text,
  password_hash text,
  must_change_password boolean not null default true,
  is_active boolean not null default true,
  expiry_date date,
  max_students integer not null default 0,
  max_teachers integer not null default 0,
  created_at timestamptz not null default now()
);

-- ملاحظة: مفيش FK بين teachers.center_id و centers.id هنا عمدًا — الجدولين
-- دول من الأساس بيتعملهم `create table if not exists`، يعني لو الجدول
-- موجود بالفعل (زي الإنتاج) الـstatement بالكامل بيتخطى. أي ALTER TABLE
-- منفصل بره الـcreate كان هيتنفذ **دايمًا** حتى لو الجدول موجود، وممكن يفشل
-- لو فيه بيانات فعلية مش متسقة 100% مع الافتراض ده — التكامل ده متضمن أصلاً
-- في منطق الفانكشنز نفسها (مفيش اعتماد على enforcement من قاعدة البيانات).

create table if not exists parents (
  phone text primary key,
  name text,
  password_hash text,
  must_change_password boolean not null default true,
  is_active boolean not null default true
);

-- ---------- المجموعات والمستويات وأسماء المدرسين (السنتر) ----------

create table if not exists education_levels (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  name text not null,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists instructor_names (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  name text not null,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists groups (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  name text not null,
  level_id bigint references education_levels (id) on delete set null,
  instructor_name_id bigint references instructor_names (id) on delete set null,
  unique (teacher_id, name)
);

-- ---------- الطلاب والمساعدين ----------

create table if not exists students (
  id bigint generated always as identity primary key,
  uid text not null unique,
  teacher_id text not null references teachers (client_id) on delete cascade,
  name text not null,
  group_name text,
  phone text,
  parent_phone text,
  password_hash text,
  must_change_password boolean not null default true
);

create table if not exists student_group_links (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  student_uid text not null references students (uid) on delete cascade,
  group_name text not null,
  unique (student_uid, group_name)
);

create table if not exists student_teacher_links (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  student_uid text not null references students (uid) on delete cascade,
  group_name text,
  linked_by_center_id text references teachers (client_id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists assistants (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  username text not null unique,
  name text not null,
  password_hash text,
  must_change_password boolean not null default true,
  is_active boolean not null default true,
  permissions jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- ---------- كروت RFID ----------

create table if not exists system_cards (
  id bigint generated always as identity primary key,
  card_uid text not null unique,
  center_id bigint references centers (id) on delete cascade,
  teacher_id text references teachers (client_id) on delete set null,
  student_uid text references students (uid) on delete set null,
  status text not null default 'unassigned',
  is_active boolean not null default true,
  assigned_at timestamptz,
  linked_at timestamptz,
  scanned_at timestamptz
);

create table if not exists pending_card_registrations (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  registered_card_uid text,
  error_message text,
  requested_at timestamptz not null default now()
);

create table if not exists card_action_mode (
  teacher_id text primary key references teachers (client_id) on delete cascade,
  attendance_enabled boolean not null default false,
  payment_enabled boolean not null default false,
  book_payment_enabled boolean not null default false,
  updated_at timestamptz not null default now()
);

create table if not exists master_device (
  id bigint generated always as identity primary key,
  device_secret text
);

create table if not exists master_scan_mode (
  id bigint generated always as identity primary key,
  is_active boolean not null default false,
  last_scanned_uid text,
  last_scanned_at timestamptz
);

create table if not exists rfid_scans (
  id bigint generated always as identity primary key,
  client_id text references teachers (client_id) on delete cascade
);

-- ---------- المالية ----------

create table if not exists payment_titles (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  title text not null,
  default_amount numeric,
  unique (teacher_id, title)
);

create table if not exists payments (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  student_uid text not null references students (uid) on delete cascade,
  student_name text,
  group_name text,
  title text,
  uid text,
  amount numeric not null default 0,
  total_amount numeric,
  created_at timestamptz not null default now()
);

create table if not exists books (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  name text not null,
  price numeric not null default 0,
  file_name text,
  file_url text
);

create table if not exists book_payments (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  student_uid text not null references students (uid) on delete cascade,
  student_name text,
  group_name text,
  book_id bigint references books (id) on delete set null,
  name text,
  price numeric,
  amount numeric not null default 0,
  books jsonb,
  paid_at timestamptz not null default now()
);

create table if not exists expenses (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  category text,
  description text,
  amount numeric not null default 0,
  expense_date date not null default current_date
);

-- ---------- الدرجات والاختبارات ----------

create table if not exists grades (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  student_uid text not null references students (uid) on delete cascade,
  student_name text,
  group_name text,
  exam_name text,
  uid text,
  score numeric,
  max_score numeric,
  created_at timestamptz not null default now()
);

create table if not exists exam_titles (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  group_name text,
  title text not null,
  default_max_score numeric
);

create table if not exists online_exams (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  group_name text,
  title text not null,
  duration_minutes integer,
  is_published boolean not null default false,
  counts_toward_grade boolean not null default true,
  scheduled_at timestamptz,
  closes_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists exam_questions (
  id bigint generated always as identity primary key,
  exam_id bigint not null references online_exams (id) on delete cascade,
  question_text text not null,
  question_type text not null default 'mcq',
  options jsonb,
  correct_answer text,
  points numeric not null default 1,
  order_index integer not null default 0
);

create table if not exists exam_target_students (
  exam_id bigint not null references online_exams (id) on delete cascade,
  student_uid text not null references students (uid) on delete cascade,
  primary key (exam_id, student_uid)
);

create table if not exists exam_attempts (
  id bigint generated always as identity primary key,
  exam_id bigint not null references online_exams (id) on delete cascade,
  student_uid text not null references students (uid) on delete cascade,
  status text not null default 'in_progress',
  score numeric,
  total_possible numeric,
  finished_at timestamptz
);

create table if not exists exam_answers (
  id bigint generated always as identity primary key,
  attempt_id bigint not null references exam_attempts (id) on delete cascade,
  question_id bigint references exam_questions (id) on delete cascade,
  answer text
);

-- ---------- الحضور ----------

create table if not exists attendance_sessions (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  group_name text not null,
  session_label text,
  session_date date not null default current_date,
  duration_minutes integer,
  absence_threshold_minutes integer,
  instructor_name_id bigint references instructor_names (id) on delete set null,
  instructor_name text,
  created_by_id text,
  created_by_name text,
  created_by_role text,
  created_at timestamptz not null default now()
);

create table if not exists attendance (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  student_uid text not null references students (uid) on delete cascade,
  student_name text,
  group_name text,
  session_id bigint references attendance_sessions (id) on delete set null,
  session_label text,
  instructor_name_id bigint references instructor_names (id) on delete set null,
  instructor_name text,
  date date not null default current_date,
  time text,
  status text,
  is_absent boolean not null default false,
  is_manual boolean not null default false,
  notes text,
  created_at timestamptz not null default now()
);

-- ---------- الرسائل والإشعارات ----------

-- ملاحظة: conversation_messages متعمول لها create table if not exists كامل
-- بالفعل في 20260817000003_parent_conversations.sql (بترتيب زمني بعد الملف
-- ده) — مش متكرر هنا عمدًا عشان نسيب المصدر الحقيقي الوحيد ليها.

create table if not exists notifications (
  id bigint generated always as identity primary key,
  teacher_id text references teachers (client_id) on delete cascade,
  student_uid text references students (uid) on delete cascade,
  parent_phone text references parents (phone) on delete cascade,
  audience text,
  type text,
  title text,
  message text,
  sender_role text,
  sender_name text,
  student_name text,
  details jsonb,
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists push_tokens (
  id bigint generated always as identity primary key,
  recipient_type text not null,
  recipient_id text not null,
  token text not null,
  unique (recipient_type, recipient_id, token)
);

create table if not exists registration_requests (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  student_name text not null,
  parent_phone text,
  instructor_name_id bigint references instructor_names (id) on delete set null,
  status text not null default 'pending',
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);

-- ---------- الأمان والتدقيق ----------

-- ملاحظة: login_attempts متعمول لها create table if not exists كامل بالفعل
-- في 20260101000001_login_attempts.sql (فيها عمود last_attempt زيادة).

create table if not exists activity_logs (
  id bigint generated always as identity primary key,
  client_id text,
  teacher_id text references teachers (client_id) on delete cascade,
  assistant_id bigint references assistants (id) on delete set null,
  action_type text not null,
  entity_type text,
  entity_id text,
  performer_id text,
  performer_role text,
  performer_name text,
  details jsonb,
  created_at timestamptz not null default now()
);

-- ---------- المحتوى وإعدادات النظام ----------

create table if not exists login_ads (
  id bigint generated always as identity primary key,
  image_url text not null,
  link_url text,
  sort_order integer not null default 0
);

create table if not exists portal_banners (
  id bigint generated always as identity primary key,
  audience text not null,
  image_url text not null,
  link_url text,
  sort_order integer not null default 0
);

create table if not exists photo_albums (
  id bigint generated always as identity primary key,
  title text,
  description text,
  is_background boolean not null default false,
  sort_order integer not null default 0
);

create table if not exists photo_album_images (
  id bigint generated always as identity primary key,
  album_id bigint not null references photo_albums (id) on delete cascade,
  image_url text not null,
  sort_order integer not null default 0
);

-- ملاحظة: system_settings متعمول لها create table if not exists كامل بالفعل
-- في 20260101000003_system_settings.sql (شكل مبدئي أصغر: id/whatsapp_number/
-- phone_number/facebook_url/updated_at) — الأعمدة الإضافية الحقيقية (إعدادات
-- Firebase، بانرات البوابة، إلخ) اتضافت في migration منفصلة بعدها مباشرة
-- (20260101000004_system_settings_extra_columns.sql) بدل ما تتحط هنا، عشان
-- الترتيب الزمني يفضل صحيح (الجدول لازم يتعمل الأول قبل أي ALTER عليه).

-- ---------- إندكسات أساسية على أعمدة teacher_id/student_uid (بالإضافة لـ20260910000001_perf_indexes.sql) ----------

create index if not exists idx_groups_teacher_id on groups (teacher_id);
create index if not exists idx_students_teacher_id on students (teacher_id);
create index if not exists idx_assistants_teacher_id on assistants (teacher_id);
create index if not exists idx_payments_student_uid on payments (student_uid);
create index if not exists idx_grades_student_uid on grades (student_uid);
create index if not exists idx_attendance_student_uid on attendance (student_uid);
create index if not exists idx_activity_logs_teacher_id_created_at on activity_logs (teacher_id, created_at);
