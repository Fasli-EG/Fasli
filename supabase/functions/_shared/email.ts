// supabase/functions/_shared/email.ts
// ============================================
// إرسال إيميلات حقيقية عن طريق حساب جيميل حقيقي (SMTP) — بديل مجاني تمامًا عن Resend،
// اللي محتاج دومين موثّق عشان يبعت لأي مستقبل غير حساب Resend نفسه. جيميل عادي (بكلمة
// مرور تطبيقات/App Password، مش كلمة المرور الحقيقية) بيبعت لأي حد من غير أي قيود دومين.
// منفصل تمامًا عن إعدادات SMTP المدمجة في Supabase Auth (اللي بتخدم رابط استرجاع
// الماستر أدمن بس، لأنه الحساب الوحيد بإيميل حقيقي في auth.users).
// ============================================
import { SMTPClient } from "https://deno.land/x/denomailer@1.6.0/mod.ts";

// ⚠️ لازم نمرّر نص عادي (text) صريح جنب الـhtml، مش نسيب denomailer يولّده تلقائيًا
// (content:"auto") — الطريقة دي بتشيل أي وسم HTML بـregex ساذج، فأي رابط جوه <a href="...">
// بيتشال بالكامل وميفضلش أي أثر ليه في نسخة النص العادي؛ ده اللي كان بيخلي رابط استرجاع
// كلمة المرور يختفي تمامًا لما عميل الإيميل يعرض نسخة النص العادي بدل الـHTML
export async function sendEmail(params: { to: string; subject: string; text: string; html: string }): Promise<void> {
  const gmailUser = Deno.env.get("GMAIL_USER");
  const gmailAppPassword = Deno.env.get("GMAIL_APP_PASSWORD");
  if (!gmailUser || !gmailAppPassword) {
    throw new Error("⚠️ خدمة إرسال الإيميلات غير مفعّلة حاليًا، حاول لاحقًا أو تواصل مع الإدارة");
  }

  const client = new SMTPClient({
    connection: {
      hostname: "smtp.gmail.com",
      port: 465,
      tls: true,
      auth: { username: gmailUser, password: gmailAppPassword },
    },
  });

  try {
    // ⚠️ اسم المرسل (from) والعنوان (subject) لازم يفضلوا إنجليزي بالكامل — denomailer
    // بيعمل تشفير غلط (RFC 2047) للعناوين اللي فيها عربي، وده كان بيخلي Gmail يفشل يفهم
    // الرسالة كلها ويعرض المصدر الخام بدل المحتوى (متأكد منها باختبار حي). محتوى الرسالة
    // نفسه (params.text/params.html) مش متأثر — بيتشفّر بشكل صحيح كجزء من الـbody
    await client.send({
      from: `Fasli <${gmailUser}>`,
      to: params.to,
      subject: params.subject,
      content: params.text,
      html: params.html,
    });
  } catch (e) {
    throw new Error(`⚠️ فشل إرسال الإيميل: ${e instanceof Error ? e.message : "خطأ غير معروف"}`);
  } finally {
    try { await client.close(); } catch (_e) { /* تجاهل */ }
  }
}
