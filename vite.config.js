// vite.config.js
// ============================================
// خطوة بناء حقيقية (Vite) للفرونت إند، بدون أي إعادة كتابة — كل صفحة لسه شغّالة بنفس الكود
// والمنطق بالظبط. root/publicDir بيشاورا لنفس مجلد frontend/، يعني أي صفحة مش مضافة صراحةً
// في build.rollupOptions.input بتتنسخ زي ما هي حرفياً (من غير أي معالجة) — التحويل بيحصل
// صفحة صفحة، بحذر، وبالترتيب المتفق عليه (activity-log.html أول pilot).
//
// ⚠️ مهم: publicDir بيساوي root نفسه (frontend/) — لازم node_modules/package.json/
// vite.config.js يفضلوا هنا في جذر المستودع (مش جوه frontend/) عشان مايترسخوش غلط في أي نسخة
// نهائية للموقع.
import { resolve } from "path";

export default {
  root: "frontend",
  publicDir: ".",
  base: "/Fasli/", // ✅ الموقع بيتنشر على fasli-eg.github.io/Fasli (مش الجذر)، لازم كل مسارات الأصول تحسب المسار الفرعي ده
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        "activity-log": resolve(__dirname, "frontend/activity-log.html"),
      },
    },
  },
};
