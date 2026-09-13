// supabase/functions/bootstrap-master-admin/index.ts
// ⚠️ فانكشن مؤقتة تُستخدم مرة واحدة بس عشان تنشئ حساب الماستر أدمن في Supabase Auth
// (بداية الهجرة من نظام التوكن المخصص). لازم تتحذف فورًا بعد أول استخدام ناجح —
// npx supabase functions delete bootstrap-master-admin
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// ✅ سر عشوائي لمرة واحدة، مكتوب هنا مباشرة (مش env var) عشان الفانكشن دي عمرها قصير أصلاً —
// من غيره أي حد يعرف الرابط أثناء الفترة القصيرة دي يقدر يعمل حساب أدمن بأي إيميل
const SETUP_TOKEN = "d6b565b957390ff40a06b1245ab65b158b1c5e905f46310a";

Deno.serve(async (req) => {
  try {
    const body = await req.json();
    if (body.setupToken !== SETUP_TOKEN) {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }), { status: 403 });
    }
    const { email, password } = body;
    if (!email || !password || password.length < 8) {
      return new Response(JSON.stringify({ success: false, message: "⚠️ الإيميل مطلوب، والباسورد لازم يكون 8 حروف على الأقل" }), { status: 400 });
    }

    const supabase = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");
    const { data, error } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      app_metadata: { role: "teacher", clientId: "master_admin", isAdmin: true, name: "المشرف الرئيسي" },
    });

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }), { status: 500 });
    }

    return new Response(JSON.stringify({ success: true, message: "✅ اتعمل حساب الماستر بنجاح — امسح الفانكشن دي دلوقتي", userId: data.user?.id }), { status: 200 });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, message: String(e) }), { status: 500 });
  }
});
