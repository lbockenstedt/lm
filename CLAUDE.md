# Project Guidelines (CLAUDE.md)

## Build & Development
- **Build Command:** `npm run build`
- **Install Dependencies:** `npm install`
- **Dev Server:** `npm run dev`

## Testing
- **Run All Tests:** `npm test`
- **Run Single Test:** `npm test -- <path_to_file>`
- **Test Conventions:** Use Vitest/Jest. Prefer integration tests for critical paths and unit tests for utility logic.

## Coding Standards
- **Style:** Match the existing style of the surrounding code.
- **Naming:** Follow camelCase for variables/functions, PascalCase for classes/components.
- **Documentation:** Add JSDoc to complex functions; keep comments concise and outcome-oriented.
- **Errors:** Use custom error classes for domain-specific failures.

## Background Verification
- **Run verification and status checks in background.** Verification (`verify`), status checks (`status`, `result`, `diff`), and CI checks run in background workers to keep this session responsive. Dispatch them with `ask-local submit` to a background worker rather than running inline. This allows the chat session to remain live while checks complete.
