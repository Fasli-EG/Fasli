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

// ✅ منطق "تعديل مبلغ دفعة موجودة بالفعل" المشترك بين manage-payment (تعديل يدوي) و
// manage-payment-receipt (تأكيد إيصال يغطي باقي دفعة جزئية موجودة) — استُخرج كما هو من
// handleUpdate في manage-payment/index.ts. تأكيد إيصال على بند فيه دفعة جزئية بالفعل لازم
// يعدّل الصف الموجود (مش يحاول يضيف صف جديد، اللي كان هيترفض كـ"مسدّد بالفعل" في recordPayments).
export interface UpdatePaymentAmountParams {
  paymentId: number | string;
  tokenClientId: string;
  newAmount: number;
  assistantId?: string | null;
  assistantName?: string | null;
}

export interface UpdatePaymentAmountResult {
  success: boolean;
  message: string;
  data?: any;
  status?: number;
}

export async function updatePaymentAmount(
  supabase: any,
  params: UpdatePaymentAmountParams,
  sendPush: SendPushFn
): Promise<UpdatePaymentAmountResult> {
  const { paymentId, tokenClientId, newAmount, assistantId, assistantName } = params;

  const { data: oldPayment, error: fetchError } = await supabase
    .from("payments").select("amount, total_amount, title, student_uid, student_name, group_name, teacher_id").eq("id", paymentId).single();
  if (fetchError || !oldPayment) {
    return { success: false, message: "الدفعة غير موجودة", status: 404 };
  }
  if (oldPayment.teacher_id !== tokenClientId) {
    return { success: false, message: "⛔ هذه الدفعة ليست تابعاً لك", status: 403 };
  }

  const oldAmount = oldPayment.amount;
  if (isNaN(newAmount) || newAmount < 0) {
    return { success: false, message: "⚠️ أدخل مبلغاً صحيحاً", status: 400 };
  }
  if (newAmount > oldPayment.total_amount) {
    return { success: false, message: `⚠️ المبلغ المدفوع (${newAmount}) مايصحش يكون أكبر من قيمة الاشتراك (${oldPayment.total_amount})`, status: 400 };
  }
  if (oldAmount === newAmount) {
    return { success: true, message: "لا توجد تغييرات في المبلغ" };
  }

  const { data: updatedPayment, error: updateError } = await supabase.from("payments").update({ amount: newAmount }).eq("id", paymentId).select().single();
  if (updateError) {
    console.error("❌ فشل تحديث الدفعة:", updateError);
    return { success: false, message: `فشل تحديث الدفعة: ${updateError.message}`, status: 500 };
  }

  let teacherName = "مدرس";
  if (oldPayment.teacher_id) {
    const { data: teacher, error: teacherError } = await supabase.from("teachers").select("name").eq("client_id", oldPayment.teacher_id).maybeSingle();
    if (!teacherError && teacher) teacherName = teacher.name || "مدرس";
  }

  const performerId = assistantId || oldPayment.teacher_id;
  const performerRole = assistantId ? "assistant" : "teacher";
  const performerName = assistantId ? (assistantName || "مساعد") : teacherName;
  const wasFullPaid = oldAmount >= oldPayment.total_amount;
  const isFullPaid = newAmount >= oldPayment.total_amount;

  await supabase.from("activity_logs").insert({
    client_id: oldPayment.teacher_id, teacher_id: oldPayment.teacher_id, assistant_id: assistantId ? parseInt(assistantId) : null,
    action_type: "edit_payment", entity_type: "payment", entity_id: String(paymentId),
    details: {
      student_name: oldPayment.student_name, student_uid: oldPayment.student_uid, title: oldPayment.title, total_amount: oldPayment.total_amount,
      old_amount: oldAmount, new_amount: newAmount, group_name: oldPayment.group_name,
      changes: { amount: { old: oldAmount, new: newAmount }, status: { old: wasFullPaid ? "مدفوع بالكامل" : (oldAmount > 0 ? "دفعة جزئية" : "غير مدفوع"), new: isFullPaid ? "مدفوع بالكامل" : (newAmount > 0 ? "دفعة جزئية" : "غير مدفوع") } },
    },
    performer_id: performerId, performer_role: performerRole, performer_name: performerName,
  });

  const { data: studentForNotif } = await supabase.from("students").select("parent_phone").eq("uid", oldPayment.student_uid).maybeSingle();
  {
    const statusText = isFullPaid ? "مدفوع بالكامل" : (newAmount > 0 ? "دفعة جزئية" : "غير مدفوع");
    const editNotifRows = [
      ...(studentForNotif?.parent_phone ? [{
        teacher_id: oldPayment.teacher_id, parent_phone: studentForNotif.parent_phone, student_uid: oldPayment.student_uid, type: "payment", title: "تعديل دفعة", audience: "parent",
        message: `تم تعديل دفعة "${oldPayment.title}" لـ ${oldPayment.student_name} من ${oldAmount} ج.م إلى ${newAmount} ج.م (${statusText})`,
        details: { student_name: oldPayment.student_name, title: oldPayment.title, old_amount: oldAmount, new_amount: newAmount, total_amount: oldPayment.total_amount, status: statusText },
      }] : []),
      {
        teacher_id: oldPayment.teacher_id, student_uid: oldPayment.student_uid, type: "payment", title: "تعديل دفعة", audience: "student",
        message: `تم تعديل دفعتك "${oldPayment.title}" من ${oldAmount} ج.م إلى ${newAmount} ج.م (${statusText})`,
        details: { title: oldPayment.title, old_amount: oldAmount, new_amount: newAmount, total_amount: oldPayment.total_amount, status: statusText },
      },
    ];
    await supabase.from("notifications").insert(editNotifRows).then(({ error }: any) => { if (error) console.error("⚠️ فشل إرسال إشعار تعديل الدفعة:", error.message); });
    if (studentForNotif?.parent_phone) {
      sendPush(supabase, "parent", studentForNotif.parent_phone, "تعديل دفعة", `تم تعديل دفعة "${oldPayment.title}" لـ ${oldPayment.student_name} من ${oldAmount} ج.م إلى ${newAmount} ج.م (${statusText})`);
    }
    sendPush(supabase, "student", oldPayment.student_uid, "تعديل دفعة", `تم تعديل دفعتك "${oldPayment.title}" من ${oldAmount} ج.م إلى ${newAmount} ج.م (${statusText})`);
  }

  return { success: true, message: "تم تحديث الدفعة بنجاح", data: updatedPayment };
}
