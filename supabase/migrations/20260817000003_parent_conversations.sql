-- محادثة ثنائية الاتجاه بين المدرس (أو مساعده) وولي أمر طالب معيّن — بديل داخل التطبيق
-- عن التواصل الخارجي (واتساب/مكالمة). كل صف رسالة واحدة في المحادثة، مرتبطة بطالب محدد.
create table if not exists conversation_messages (
  id bigserial primary key,
  teacher_id text not null,
  parent_phone text not null,
  student_uid text not null,
  sender_role text not null check (sender_role in ('teacher', 'assistant', 'parent')),
  sender_name text not null,
  message text not null,
  is_read_by_teacher boolean not null default false,
  is_read_by_parent boolean not null default false,
  created_at timestamptz not null default now()
);

create index if not exists idx_conversation_messages_thread
  on conversation_messages (teacher_id, student_uid, parent_phone, created_at);

alter table conversation_messages enable row level security;
