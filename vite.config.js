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
        "financial": resolve(__dirname, "frontend/financial.html"),
        "admin-teachers": resolve(__dirname, "frontend/admin-teachers.html"),
        "assistant-dashboard": resolve(__dirname, "frontend/assistant-dashboard.html"),
        "change-password": resolve(__dirname, "frontend/change-password.html"),
        "dashboard": resolve(__dirname, "frontend/dashboard.html"),
        "grades": resolve(__dirname, "frontend/grades.html"),
        "groups": resolve(__dirname, "frontend/groups.html"),
        "license-locked": resolve(__dirname, "frontend/license-locked.html"),
        "login": resolve(__dirname, "frontend/login.html"),
        "messages": resolve(__dirname, "frontend/messages.html"),
        "parent-dashboard": resolve(__dirname, "frontend/parent-dashboard.html"),
        "parent-student-details": resolve(__dirname, "frontend/parent-student-details.html"),
        "payments": resolve(__dirname, "frontend/payments.html"),
        "register": resolve(__dirname, "frontend/register.html"),
        "reports": resolve(__dirname, "frontend/reports.html"),
        "staff": resolve(__dirname, "frontend/staff.html"),
        "student-details": resolve(__dirname, "frontend/student-details.html"),
        "student-portal": resolve(__dirname, "frontend/student-portal.html"),
        "students": resolve(__dirname, "frontend/students.html"),
        "take-exam": resolve(__dirname, "frontend/take-exam.html"),
        "teacher-settings": resolve(__dirname, "frontend/teacher-settings.html"),
      },
    },
  },
};
