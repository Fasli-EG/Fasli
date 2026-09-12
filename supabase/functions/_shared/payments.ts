// supabase/functions/_shared/payments.ts
// ✅ منطق "تسجيل دفعة فعليًا في payments" المشترك بين manage-payment (تسجيل يدوي مباشر)
// و manage-payment-receipt (تأكيد إيصال مرفوع من ولي الأمر) — نفس السلوك بالظبط في الحالتين:
// نفس الإدراج في payments، نفس upsert لـ payment_titles، نفس الإشعارات والـpush. استُخرج
// كما هو من handleAdd في manage-payment/index.ts عشان الموافقة على إيصال تسلك بالظبط زي
// "تسجيل سداد" يدوي، من غير أي فرق سلوك بين المسارين.

export interface RecordPaymentsParams {
  clientId: string;
  uidsList: string[];
  title: string;
  totalAmount: number;
  amount: number;
  assistantId?: string | null;
  assistantName?: string | null;
  defaultAmount?: number;
  groupName?: string | null;
}

export interface RecordPaymentsResult {
  success: boolean;
  message: string;
  data?: any;
  skipped?: string[];
}

type SendPushFn = (
  supabase: any,
  recipientType: "parent" | "assistant" | "teacher" | "student",
  recipientId: string,
  title: string,
  body: string
) => Promise<void>;

export async function recordPayments(
  supabase: any,
  params: RecordPaymentsParams,
  sendPush: SendPushFn
): Promise<RecordPaymentsResult> {
  const { clientId, uidsList, title, totalAmount, amount, assistantId, assistantName, defaultAmount, groupName } = params;

  const { error: titleError } = await supabase.from("payment_titles").upsert(
    { teacher_id: clientId, title, default_amount: defaultAmount !== undefined ? Number(defaultAmount) : Number(totalAmount) },
    { onConflict: "teacher_id,title", ignoreDuplicates: false }
  );
  if (titleError) console.error("⚠️ فشل تسجيل بند السداد في القائمة:", titleError.message);

  const { data: notifyTeacherInfo } = await supabase.from("teachers").select("name").eq("client_id", clientId).maybeSingle();
  const teacherLabel = notifyTeacherInfo?.name ? ` — مدرس ${notifyTeacherInfo.name}` : "";
  const performerId = assistantId || clientId;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = assistantId ? (assistantName || "مساعد") : (notifyTeacherInfo?.name || "مدرس");

  const results: any[] = [];
  const loggedStudents: any[] = [];
  const skipped: string[] = [];

  const { data: myLinks } = await supabase.from("student_teacher_links").select("student_uid").eq("teacher_id", clientId);
  const linkedUidsForMe = new Set((myLinks || []).map((l: any) => l.student_uid));

  const [{ data: candidateStudents }, { data: existingPayments }, { data: groupLinks }] = await Promise.all([
    supabase.from("students").select("uid, name, group_name, teacher_id, parent_phone").in("uid", uidsList),
    supabase.from("payments").select("student_uid").in("student_uid", uidsList).eq("teacher_id", clientId).eq("title", title),
    supabase.from("student_group_links").select("student_uid, group_name").in("student_uid", uidsList),
  ]);
  const foundStudents = (candidateStudents || []).filter((s: any) => s.teacher_id === clientId || linkedUidsForMe.has(s.uid));

  const studentsByUid = new Map((foundStudents || []).map((s: any) => [s.uid, s]));
  const alreadyPaidUids = new Set((existingPayments || []).map((p: any) => p.student_uid));
  const linkedGroupsByUid = new Map<string, Set<string>>();
  (groupLinks || []).forEach((l: any) => {
    if (!linkedGroupsByUid.has(l.student_uid)) linkedGroupsByUid.set(l.student_uid, new Set());
    linkedGroupsByUid.get(l.student_uid)!.add(l.group_name);
  });

  const validStudents: any[] = [];
  for (const uid of uidsList) {
    const student = studentsByUid.get(uid);
    if (!student) { skipped.push(`${uid} (طالب غير موجود)`); continue; }
    if (alreadyPaidUids.has(uid)) { skipped.push(`${student.name} (مسدّد بالفعل)`); continue; }
    validStudents.push(student);
  }

  function resolveGroupName(student: any): string {
    if (groupName && (student.group_name === groupName || linkedGroupsByUid.get(student.uid)?.has(groupName))) {
      return groupName;
    }
    return student.group_name;
  }

  if (validStudents.length > 0) {
    const { data: insertedPayments, error: insertError } = await supabase.from("payments").insert(validStudents.map((student) => ({
      student_uid: student.uid, student_name: student.name, group_name: resolveGroupName(student),
      teacher_id: clientId, title: title, total_amount: Number(totalAmount), amount: Number(amount),
    }))).select();

    if (insertError) {
      console.error("❌ فشل إضافة الدفعات:", insertError);
    } else if (insertedPayments) {
      const isFullPaid = Number(amount) >= Number(totalAmount);
      const statusText = isFullPaid ? "مدفوع بالكامل" : (Number(amount) > 0 ? "دفعة جزئية" : "غير مدفوع");
      results.push(...insertedPayments);
      loggedStudents.push(...validStudents.map((s) => ({ name: s.name, uid: s.uid, group_name: s.group_name, status: statusText })));

      const notifRows = [
        ...validStudents.filter((s) => s.parent_phone).map((s) => ({
          teacher_id: clientId, parent_phone: s.parent_phone, student_uid: s.uid, type: "payment", title: "تسجيل دفعة", audience: "parent",
          message: `تم تسجيل دفعة "${title}" بمبلغ ${amount} ج.م لـ ${s.name} (${statusText})${teacherLabel}`,
          details: { student_name: s.name, title, amount: Number(amount), total_amount: Number(totalAmount), status: statusText },
        })),
        ...validStudents.map((s) => ({
          teacher_id: clientId, student_uid: s.uid, type: "payment", title: "تسجيل دفعة", audience: "student",
          message: `اتسجّلت دفعة "${title}" بمبلغ ${amount} ج.م على اشتراكك (${statusText})${teacherLabel}`,
          details: { title, amount: Number(amount), total_amount: Number(totalAmount), status: statusText },
        })),
      ];
      if (notifRows.length > 0) {
        await supabase.from("notifications").insert(notifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعارات الدفعات:", error.message); });
        validStudents.filter((s) => s.parent_phone).forEach((s) => {
          sendPush(supabase, "parent", s.parent_phone, "تسجيل دفعة", `تم تسجيل دفعة "${title}" بمبلغ ${amount} ج.م لـ ${s.name} (${statusText})${teacherLabel}`);
        });
        validStudents.forEach((s) => {
          sendPush(supabase, "student", s.uid, "تسجيل دفعة", `اتسجّلت دفعة "${title}" بمبلغ ${amount} ج.م على اشتراكك (${statusText})${teacherLabel}`);
        });
      }
    }
  }

  if (results.length === 0) {
    return { success: false, message: `⚠️ مفيش أي دفعة اتسجّلت: ${skipped.join("، ")}`, skipped };
  }

  const isBulk = loggedStudents.length > 1;
  await supabase.from("activity_logs").insert({
    client_id: clientId, teacher_id: clientId, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: isBulk ? "bulk_add_payment" : "add_payment", entity_type: "payment", entity_id: String(results[0].id),
    details: isBulk
      ? { title, total_amount: Number(totalAmount), amount: Number(amount), count: loggedStudents.length, students: loggedStudents }
      : { student_name: loggedStudents[0].name, student_uid: loggedStudents[0].uid, title, total_amount: Number(totalAmount), amount: Number(amount), group_name: loggedStudents[0].group_name, status: loggedStudents[0].status },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  let message = uidsList.length === 1 ? "تم تسجيل الدفعة بنجاح" : `تم تسجيل الدفعة لـ ${results.length} طالب بنجاح`;
  if (skipped.length > 0) message += ` (اتخطّى: ${skipped.join("، ")})`;

  return { success: true, message, data: results.length === 1 ? results[0] : results, skipped: skipped.length > 0 ? skipped : undefined };
}
