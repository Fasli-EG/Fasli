\# Project Core Guidelines



\## 1. UI/UX \& Design Architecture

\- \*\*Framework\*\*: Use Tailwind CSS with Shadcn UI components located in `@/components/ui`.

\- \*\*Icons\*\*: Strictly use `lucide-react` icons.

\- \*\*Responsiveness\*\*: Always use a mobile-first approach (`sm:`, `md:`, `lg:`).

\- \*\*Interactivity\*\*: Every button/link MUST have explicit `:hover`, `:focus-visible`, and `:active` states.

\- \*\*Loading States\*\*: Never show a blank screen during async data fetching; always render a `Skeleton` component or standard spinner.

\- \*\*Micro-interactions\*\*: Use `transition-all duration-200 ease-in-out` for smooth state changes.

\- \*\*Accessibility (a11y)\*\*: Ensure all interactive elements have proper `aria-label` and `role` attributes.



\## 2. Security \& Robustness Standards

\- \*\*Input Validation\*\*: Never trust raw user input. Always validate inputs using `zod` schemas on both Client and Server.

\- \*\*XSS Prevention\*\*: Do not use `dangerouslySetInnerHTML` without proper sanitization (e.g., using `DOMPurify`).

\- \*\*Secrets \& Credentials\*\*: Never hardcode API keys, tokens, or credentials. Fetch them exclusively from `process.env`.

\- \*\*Error Handling\*\*: Wrap all server actions/API calls in `try/catch` blocks and return typed error responses.

