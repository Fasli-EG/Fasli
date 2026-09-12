-- ✅ (طلب) الحل المجاني لتأكيد الدفع: ولي الأمر يحوّل يدويًا (InstaPay/محفظة) ويرفع صورة
-- الإيصال، والمدرس/المساعد يراجعها ويأكّدها من جوه النظام. جدول منفصل تمامًا عن `payments`
-- عشان صف في `payments` معناه "دفعة مؤكدة فعليًا" في كل الكود الحالي (بيطلق إشعارات فورية) —
-- خلط حالة "معلّقة لسه" فيه كان هيغيّر سلوك كل مكان بيقرأ من `payments`.
create table if not exists payment_receipts (
  id bigint generated always as identity primary key,
  teacher_id text not null references teachers (client_id) on delete cascade,
  student_uid text not null references students (uid) on delete cascade,
  group_name text,
  title text not null,
  total_amount numeric not null,
  claimed_amount numeric not null,
  receipt_path text not null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  rejection_reason text,
  reviewed_by text,
  submitted_at timestamptz not null default now(),
  reviewed_at timestamptz
);

create index if not exists idx_payment_receipts_teacher_status on payment_receipts (teacher_id, status);
create index if not exists idx_payment_receipts_student on payment_receipts (student_uid);

alter table payment_receipts enable row level security;
-- ✅ مفيش أي "create policy" هنا عن قصد = رفض افتراضي كامل لـ anon/authenticated، نفس نمط
-- 20260101000002_rls_policies.sql — service_role (المستخدم في كل الدوال) بيتخطى RLS دايمًا.

-- ✅ Bucket تخزين خاص (private) لصور الإيصالات — على عكس باقي البuckets الموجودة (كلها public)،
-- الإيصالات ممكن تحتوي تفاصيل حساب بنكي/محفظة، فبنستخدم رابط مؤقّت (signed URL) وقت العرض بس
-- بدل رابط عام دائم.
insert into storage.buckets (id, name, public)
values ('payment-receipts', 'payment-receipts', false)
on conflict (id) do nothing;
