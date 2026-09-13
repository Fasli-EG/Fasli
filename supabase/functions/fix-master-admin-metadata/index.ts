// ⚠️ فانكشن مؤقتة لمرة واحدة: بتصلّح app_metadata لحساب الماستر (كانت ناقصة حقل sub)
// امسحها فور نجاح الاستدعاء
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SETUP_TOKEN = "d6b565b957390ff40a06b1245ab65b158b1c5e905f46310a";
const MASTER_USER_ID = "fbb69fb0-eab5-460a-b263-9cf40796b16c";

Deno.serve(async (req) => {
  try {
    const body = await req.json();
    if (body.setupToken !== SETUP_TOKEN) {
      return new Response(JSON.stringify({ success: false, message: "⛔ غير مصرح" }), { status: 403 });
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const { data, error } = await supabase.auth.admin.updateUserById(MASTER_USER_ID, {
      app_metadata: {
        role: "teacher",
        clientId: "master_admin",
        sub: "master_admin",
        isAdmin: true,
        name: "المشرف الرئيسي",
      },
    });

    if (error) {
      return new Response(JSON.stringify({ success: false, message: error.message }), { status: 500 });
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: "✅ اتصلّح app_metadata — امسح الفانكشن دي دلوقتي",
        app_metadata: data.user?.app_metadata,
      }),
      { status: 200 }
    );
  } catch (e) {
    return new Response(JSON.stringify({ success: false, message: String(e) }), { status: 500 });
  }
});
