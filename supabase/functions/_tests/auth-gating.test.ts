// supabase/functions/_tests/auth-gating.test.ts
// ============================================
// يغطي أبسط وأهم فحص لكل الفانكشنز المحمية: أي طلب من غير Authorization header
// المفروض يترفض بـ 401 (verifyToken بترمي AuthError قبل ما توصل لأي منطق تاني).
// ده مش بديل عن اختبارات المسار الأساسي (happy-path.test.ts)، لكنه بيغطي أول
// وأهم سطر دفاع في كل فانكشن، ولأي فانكشن جديد يتضاف المستقبل لازم يتضاف اسمه هنا.
// ============================================
import { assertEquals } from "https://deno.land/std@0.208.0/assert/mod.ts";
import { AUTH_GATED_FUNCTIONS, callFn } from "./_helpers.ts";

for (const fnName of AUTH_GATED_FUNCTIONS) {
  Deno.test(`${fnName}: يرفض الطلب بدون توكن (401)`, async () => {
    const { status, json } = await callFn(fnName, null, {});
    assertEquals(status, 401);
    assertEquals(json?.success, false);
  });
}

Deno.test("record-attendance: يرفض الطلب بدون توكن (401) لما clientId/uid موجودين ومفيش secret", async () => {
  const { status, json } = await callFn("record-attendance", null, { clientId: "master_admin", uid: "qa_nonexistent" });
  assertEquals(status, 401);
  assertEquals(json?.success, false);
});

Deno.test("login: بيرفض بيانات دخول غلط بدون ما يكشف إن الحساب موجود أو لأ", async () => {
  const { status, json } = await callFn("login", null, { username: "qa_nonexistent_user_xyz", password: "wrong" });
  assertEquals(json?.success, false);
  // ✅ 401/400 مقبولين، المهم إنه مايرجعش 200 لحساب مش موجود
  if (status === 200) throw new Error("login رجّع 200 لحساب مش موجود!");
});
