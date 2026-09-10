# فَصلي (Fasli) — Project Handoff

SaaS for private tutoring management. Egypt market. Arabic-only UI (RTL), **masculine grammatical form throughout — no exceptions, corrected repeatedly across the whole codebase**.

## Stack
- Backend: Supabase Edge Functions (Deno/TypeScript)
- Frontend: vanilla HTML/CSS/JS (no framework, no build step, no shared includes — every page is a standalone `.html` file with its own copy-pasted sidebar/scripts), hosted on GitHub Pages: `https://fasli-eg.github.io/Fasli/`
- DB: Supabase Postgres
- Auth: custom JWT (NOT Supabase Auth) — `JWT_SECRET` env var, HS256, `verify_jwt = false` on every function in `config.toml`
- Supabase project ref: `yxkyxxzcnxpxefodfxnl`
- Charts: Chart.js 4.4.0 via CDN (dashboard, financial). Excel export: SheetJS (`xlsx.full.min.js` v0.18.5) via CDN.

## CRITICAL conventions (read before editing anything)

1. **Env vars**: always `Deno.env.get("SUPABASE_URL")` / `Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")` directly. NEVER `DATABASE_URL`/`SERVICE_ROLE` or `X || Y` fallback chains — a historic bug had these reversed and broke auth system-wide.
2. **Date-only comparisons**: DB columns typed `date` (e.g. `expiry_date`) must compare as strings `expiry_date < today` (`YYYY-MM-DD`), never `new Date(x).getTime()`.
3. **Masculine Arabic only**. No `ي`/`ِك` feminine suffixes (اختاري→اختر, حددي→حدد, تأكدي→تأكد, متأكدة→متأكد, عايزة→عايز, etc). A full sweep was done across ~20 files in Aug 2026 (see "Fixed in this pass" below) — but **always re-check new strings you write**, this keeps regressing because it's copy-paste boilerplate across many pages.
4. **Function merging discipline**: functions are consolidated via an `action` param in the request body (e.g. `{action: 'add'|'update'|'delete', ...}`) to stay under Supabase free-tier function-count limits. **Current count: 76 active functions** (see full list below). When adding a capability, prefer extending an existing function's `action` router over creating a new function.
5. **Balance-check every file before delivering**: count `{` vs `}` after every edit (`node -e "..."` brace count on the raw file text). This has caught real bugs repeatedly.
6. **Never blanket-replace a page's shared JS/sidebar.** Every page hand-copies its sidebar and helper functions (no includes). Rule: copy the full source page, edit ONLY the specific content section + specific functions needed, leave shared boilerplate untouched. After any page edit, verify:
   - every `onclick`/`onchange` referenced function is `function`-defined in the file
   - every `getElementById` in the auto-executing load path (`window.onload` chain) has a matching `id` in the HTML
   - every permission-gated nav item (`id="navFinancial"` etc.) still exists with the exact same `id` — JS toggles visibility by ID, not position
7. **RFID card system**: reader is disabled by default (`is_enabled` bool on `card_action_mode`), teacher must explicitly enable it. `duration_minutes` is teacher-configurable via `set_at` timestamp diff.
8. **Center architecture**: `centers` table is a separate login role (`center_owner`). `teachers.center_id` (nullable) links a teacher to a center. Center owner creates/manages their own teachers directly and cards can be assigned to `center_id` (shared pool) instead of just `teacher_id`. **Note**: as of the last internal planning doc (`خطة تحسين.pdf`, Aug 2026), the "cards pooled at center level instead of per-teacher" sub-piece was marked still in progress — verify current state before assuming it's finished.
9. **Login auto-detection**: login flow uses `group: 'staff'|'family'` instead of explicit `role` — backend tries centers→teachers→assistants (staff) or parents→students (family) in sequence. Old explicit-`role` calls still work.
10. **Student self-service**: students log in with card UID as both username+password first time, forced to change-password after. `get-student-full-profile` returns info+grades+payments+attendance+books in ONE call — used by `student-details.html` (teacher view), `student-portal.html` (student's own), `parent-student-details.html` (parent view).
11. **Sandbox limits (dev environment only, not the deployed app)**: no Arabic fonts, no `pdftoppm`/`tesseract` installed by default (install via `pip install pymupdf` for PDF→image rendering without poppler if ever needed to read a scanned/image-based PDF).

## Active functions (76) — by domain

**Auth/users**: login, change-password, manage-student, manage-assistant, admin-manage-teacher, manage-password-reset, manage-push-token
**Academic**: manage-grade, manage-group, manage-group-sessions, check-session-absences, record-attendance, get-today-attendance, get-latest-rfid-scan, submit-rfid-scan, get-student-full-profile, get-students, check-student-uid, get-titles, create-payment-title, create-exam-title
**Payments/financial**: manage-payment, manage-book, manage-book-payment, get-financial-summary, manage-expense, upload-book-file
**Exams**: manage-exam, take-exam, check-scheduled-exams, get-exams-for-student, get-exam-report
**Cards/devices**: card-action-mode, manage-system-cards, manage-card-registration, admin-manage-card-registration, manage-master-scan, submit-master-card-scan, get-device-secret, get-master-device-secret, teacher-start-new-student-scan
**Center**: manage-center, get-center-dashboard
**Registration**: submit-registration-request (public, no auth), manage-registration-requests
**Reporting/admin**: generate-report, get-dashboard, get-activity-logs, delete-activity-log, admin-get-teacher(s), admin-get-students-for-teacher, get-at-risk-students, bulk-import-students
**Notifications/comms**: get-notifications, mark-notification-read, send-bulk-message, get-parent-children
**System**: get-system-settings, update-system-settings, update-teacher-contact, get-teacher-contact, update-admin-profile, manage-login-ad, list-system-cards, reset-system, manage-backup

(Full up-to-date list is always in `supabase/config.toml` — grep `^\[functions\.` there rather than trusting this doc if it's gone stale.)

## Frontend pages (25 files, all in `frontend/`)
login, dashboard, assistant-dashboard, students, student-details, student-portal, groups, grades, payments, books, financial, messages, reports, activity-log, admin-teachers, wifi-config (teacher settings hub — contact info + custom branding), change-password, license-locked, center-dashboard, exam-builder, take-exam, register (public landing), parent-dashboard, parent-student-details, `branding.js` (shared script, not a page).

**Sidebar navigation** (15 of these pages share one flat 13-item sidebar, now grouped into 4 sections — see "Navigation restructure" below): dashboard, students, groups, grades, exam-builder, payments, books, reports, financial, messages, activity-log, assistants-management, wifi-config, student-details, assistant-dashboard. `admin-teachers.html` has its own separate tab-based console. Parent/student/center pages use a lighter `.brand`/`.portal-header` layout, no sidebar.

## Key DB tables (cumulative, beyond original schema)
`group_sessions`, `exam_target_students`, `online_exams`, `exam_questions`, `exam_attempts` (+`mode` col: 'official'|'practice'), `exam_answers`, `expenses`, `centers` (+`brand_logo_url`, `brand_color`), `registration_requests` (status now includes 'waitlisted'), `conversation_messages` (new — parent↔teacher in-app thread). Modified: `students` (+password_hash, +must_change_password, +archived_at), `teachers` (+center_id, +center_sharing_permissions, +brand_logo_url, +brand_color), `system_cards` (+center_id), `card_action_mode` (+is_enabled, +duration_minutes), `books` (+file_url, +file_name), `online_exams` (+scheduled_at), `attendance` (+session_id, +is_absent), `groups` (+max_students, for the waitlist feature).

## Roadmap status — everything shipped as of Aug 2026

All 10 items from the internal priority plan (`خطة تحسين.pdf`) are done:
1. ✅ Bulk import students from Excel (SheetJS)
2. ✅ Printable/PDF student report (`student-details.html`, browser-native `window.print()` via hidden iframe, not server-side PDF — real Arabic font rendering happens in the user's browser)
3. ✅ Onboarding checklist for new teachers (`dashboard.html`)
4. ✅ Waiting list for full groups (`groups.max_students`, `registration_requests.status='waitlisted'`)
5. ✅ Custom branding — logo/primary-color per teacher or center, inherited by a teacher from their center if the teacher hasn't set their own (`branding.js`, applied via sessionStorage at login, editable in `wifi-config.html` / `center-dashboard.html`)
6. ✅ Two-way in-app parent↔teacher messaging (`conversation_messages` table, `messages.html` teacher inbox, `parent-student-details.html` parent thread — explicitly NOT WhatsApp)
7. ✅ Free untimed practice mode for exams (`exam_attempts.mode`, excluded from all teacher-facing reports/averages, unlimited retries)
8. ✅ Excel export for reports (`reports.html`, client-side `XLSX.utils.table_to_sheet`, no backend involved)
9. ✅ Teacher performance comparison for center owners (`get-center-dashboard` aggregates average student grade % per teacher, gated by each teacher's academic-sharing permission)
10. ✅ Archive students instead of hard delete (`students.archived_at`, restore/permanent-delete UI in `students.html`)

**Deferred, needs a business decision first (not a technical task)**: real payment gateway integration (Fawry/InstaPay/Vodafone Cash) — flagged to the user as a separate conversation.

## Visual redesign pass (Google Stitch integration, Aug 2026)
The user ran a design prompt through Google Stitch (AI design tool) and got back 7 unique mockup screens (Dashboard, Student List, Student Detail, Exam Builder, Exam Taking, Financial, Login) using the exact same brand hex colors as this codebase. Rather than importing Stitch's Tailwind/Material-3 code directly (incompatible with our vanilla-CSS, no-build-step architecture), the useful patterns were manually translated:

- **Sidebar reorganization**: the flat 13-item sidebar (in all 15 pages listed above) was regrouped into 4 labeled sections — 🏠 الرئيسية + رسائل جماعية (ungrouped, high-frequency), 🎓 الأكاديمية (طلاب/مجموعات/درجات/اختبارات/مذكرات/تقارير), 💰 المالية (مدفوعات/دخل شهري), ⚙️ الإعدادات (سجل نشاطات/مساعدين/إعدادات). All permission-gated element `id`s were preserved exactly. **Bonus fix**: `grades.html` was missing the "الاختبارات" link entirely (pre-existing bug) — added for consistency.
- **Stat cards**: new optional `.stat-card-icon` (colored rounded icon box) + `.stat-trend` classes added to `style.css`, reusing the existing `.badge-*` color classes for free dark-mode support. Applied to `dashboard.html` and `financial.html` (incl. a `.stat-card-featured` gold-highlight variant for the single most important number on a page, e.g. net profit).
- **`student-details.html`**: converted from a long stacked-cards page into tabs (الدرجات والتقييم / الحضور والغياب / سجل المدفوعات), reusing the pre-existing `.tabs`/`.tab-content` CSS pattern already used on `parent-student-details.html`. Printable report still pulls from all tabs regardless of which is visually active.
- **`take-exam.html`**: converted from "all questions on one scrollable page" to **one question per screen** with a progress bar and Next/Previous navigation — a deliberate, confirmed UX change, not just restyling. Answers persist in a `selectedAnswers` JS object when navigating back and forth.
- **`financial.html`**: added a donut chart (Chart.js) for expense-by-category breakdown, computed client-side from the already-fetched expenses list — no backend change needed.
- **`login.html`**: reviewed and left untouched — it already has a more sophisticated design (animated image/video showcase background, glassmorphism card, app download cards, ad carousel) than Stitch's simpler mockup, which didn't know these features existed.

Not adopted (flagged as future feature ideas, not restyling): "teacher notes" on student profile (needs a new DB table), "question bank import" in the exam builder (needs new backend logic).

## ⚠️ DEPLOYMENT CHECKLIST — nothing below is live yet
Everything in this doc reflects **local file changes only**. Before any of it works on the real deployed app:

**1. Run these 5 migrations** (in `supabase/migrations/`, in order):
```
20260817000001_group_capacity.sql
20260817000002_custom_branding.sql
20260817000003_parent_conversations.sql
20260817000004_exam_practice_mode.sql
20260817000005_student_archiving.sql
```

**2. Redeploy these 20 modified Edge Functions**:
`manage-group`, `submit-registration-request`, `manage-registration-requests`, `login`, `update-teacher-contact`, `get-teacher-contact`, `manage-center`, `send-bulk-message`, `get-notifications`, `take-exam`, `get-exams-for-student`, `get-exam-report`, `get-center-dashboard`, `get-students`, `manage-student`, `get-dashboard`, `bulk-import-students`, `manage-expense`, `record-attendance`, `manage-system-cards`

**3. New frontend file to deploy**: `branding.js` (referenced by 19 pages).

**4. No new functions were created** — still 76 total, `config.toml` unchanged.

## Known limitations / honest gaps (not oversights — deliberately scoped)
- **Student archiving** only excludes archived students from `get-students` (main list) and `get-dashboard` (headline stats). ~37 other functions still query the `students` table without an archived filter (grades entry, group membership, messaging targets, RFID scan eligibility, reports, etc.) — a full audit was out of scope for one pass. Archived students' data is never deleted, just possibly still visible in some secondary lists.
- **Parent-side conversation UI** (`parent-student-details.html`) was verified by careful code-review-against-tested-backend-contract, not full live browser E2E — that page hard-redirects to login within 1.5s on any 401, which made mocking the network reliably impossible in the test harness. The code is structurally identical to the teacher-side flow, which *was* fully E2E tested.
- **Custom branding** applies to authenticated pages only, not the public `register.html`/`login.html` pre-auth screens.
- **`reports.html`** was filed under "🎓 الأكاديمية" in the new sidebar grouping despite covering financial/attendance data too — there was no cleaner single bucket for it; easy to move later.
