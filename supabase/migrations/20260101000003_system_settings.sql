-- ============================================
-- إعدادات النظام العامة (بيانات تواصل قابلة للتعديل من حساب الأدمن)
-- ============================================
create table if not exists system_settings (
  id int primary key default 1,
  whatsapp_number text,      -- بصيغة دولية بدون + أو مسافات، مثال: 201143264206
  phone_number text,         -- رقم عادي للعرض، مثال: 01143264206
  facebook_url text,
  updated_at timestamptz default now(),
  constraint single_row check (id = 1)
);

insert into system_settings (id, whatsapp_number, phone_number, facebook_url)
values (1, '201143264206', '01143264206', 'https://facebook.com/classget')
on conflict (id) do nothing;

alter table system_settings enable row level security;
-- ✅ لا توجد أي policy لـ anon/authenticated عمداً — القراءة تتم فقط عبر
-- دالة get-system-settings (service_role) اللي بترجّع الحقول العامة فقط.
