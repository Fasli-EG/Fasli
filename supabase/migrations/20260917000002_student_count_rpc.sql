-- ============================================
-- فحص الأداء لقى admin-get-teachers بتجيب عمود teacher_id من جدول students كله (كل مدرسي
-- المنصة، من غير أي فلتر ولا حد أقصى) بس عشان تعدّ الطلاب لكل مدرس في الكود — استعلام بيكبر
-- مع نمو المنصة كلها مش مدرس واحد بس. Aggregate functions مقفولة على مستوى PostgREST هنا،
-- فبنعملها بفانكشن SQL بسيط بيرجّع العدّ الجاهز من قاعدة البيانات مباشرة
-- ============================================
create or replace function get_student_counts_by_teacher()
returns table (teacher_id text, student_count bigint)
language sql
security definer
set search_path = public
as $$
  select teacher_id, count(*) as student_count
  from students
  group by teacher_id;
$$;

revoke all on function get_student_counts_by_teacher() from public;
grant execute on function get_student_counts_by_teacher() to service_role;
