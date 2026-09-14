// supabase/functions/_shared/email.ts
// ============================================
// إرسال إيميلات حقيقية عن طريق Resend API — منفصل تمامًا عن إعدادات SMTP المدمجة في
// Supabase Auth (اللي بتخدم رابط استرجاع الماستر أدمن بس، لأنه الحساب الوحيد بإيميل حقيقي
// في auth.users). ده بديل مباشر عن طريق API لتدفق استرجاع كلمة المرور المخصص لباقي الأدوار.
// ============================================

export async function sendEmail(params: { to: string; subject: string; html: string }): Promise<void> {
  const apiKey = Deno.env.get("RESEND_API_KEY");
  if (!apiKey) throw new Error("⚠️ خدمة إرسال الإيميلات غير مفعّلة حاليًا، حاول لاحقًا أو تواصل مع الإدارة");

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "فَصلي <onboarding@resend.dev>",
      to: [params.to],
      subject: params.subject,
      html: params.html,
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`⚠️ فشل إرسال الإيميل (${res.status}): ${text || "خطأ غير معروف"}`);
  }
}
