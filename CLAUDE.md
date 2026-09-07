# CLAUDE.md — GitHub Recon Development Guide

## Project Overview

**GitHub Recon** is an enterprise-grade, multi-tenant security platform designed to detect leaked credentials, API tokens, sensitive configuration, and private keys exposed across public GitHub repositories, forks, issues, and commit histories.

### Key Architecture Components

- **Backend (`/backend`)**:
  - Node.js, Express.js, TypeScript.
  - **Prisma ORM** with SQLite (`dev.db`).
  - **GitHub REST API (Octokit)** with rate limiting, LRU in-memory blob/commit caching, and exponential backoff retry.
  - **Secret Detection Engine**: 349 detection patterns across 280 secret categories with Shannon entropy calculations and keyword proximity bonuses.
  - **Committer Intelligence**: Extracts committers for discovered files during scanning, validates via RFC 5322 rules, filters bot/noreply addresses, and persists relation records.
  - **Security Layer**: bcrypt hashing, JWT access tokens (15m), rotating httpOnly refresh cookies, TOTP 2FA, tenant isolation scopes, brute-force IP rate limiters, and production error sanitization.

- **Frontend (`/frontend`)**:
  - React 18, Vite, TypeScript, Tailwind CSS, Lucide icons, Recharts.
  - State and query caching via `@tanstack/react-query`.
  - SOC-style dark mode dashboard with real-time stats, top repositories, top files, and top committers charts.
  - Filterable findings interface with precise GitHub line navigation (`#L{lineNumber}`) and XSS-safe search term highlights.

---

## Essential Commands

### Quick Start
```bash
# Run backend and frontend concurrently (with setup / seed)
./run-local.sh
```

### Backend Commands
```bash
cd backend

# Install dependencies
npm install

# Start dev server with live reload (port 3001)
npm run dev

# Build TypeScript to dist/
npm run build

# Apply database schema
npm run db:push

# Seed superadmin and initial catalog
npm run db:seed

# Launch Prisma Studio GUI
npm run db:studio
```

### Frontend Commands
```bash
cd frontend

# Install dependencies
npm install

# Start Vite dev server (port 5173)
npm run dev

# Build production bundle to dist/
npm run build

# Preview production build
npm run preview
```

---

## Code Style & Architecture Guidelines

### Backend Conventions
1. **Multi-Tenant Isolation**:
   - Always apply `scopeFor(req)` in controllers before executing queries.
   - Tenant isolation must occur at the database query level (`where: { ...scope.domain }` or `where: { ...scope.finding }`), never post-fetch in application memory.
2. **Rate Limiting & Input Validation**:
   - Every public or credential-sensitive endpoint must use rate limiting (`loginLimiter`, `refreshLimiter`, `scanLimiter`, `apiLimiter`).
   - Clamp all pagination inputs (`pageNum = Math.max(1, parseInt(page))`, `limitNum = Math.min(max, Math.max(1, parseInt(limit)))`).
   - Combine multiple query filters using `where.AND` arrays in Prisma to avoid filter overwrite bugs.
3. **GitHub API Token & Quota Optimization**:
   - GitHub API requests are strictly budgeted (30 search requests/minute, 5,000 core requests/hour).
   - Use in-memory LRU caches (`blobCache` and `commitDetailsCache` in `github.service.ts`) to avoid re-fetching identical file blobs or commit histories.
   - Always specify explicit API headers (`Accept: application/vnd.github+json`).
4. **Committer Validation**:
   - Validate emails against RFC 5322 regex in `committerValidator.ts`.
   - Exclude GitHub bot and noreply handles (e.g., `*@users.noreply.github.com`, `dependabot[bot]`).
5. **Error Sanitization**:
   - In production (`NODE_ENV === 'production'`), never leak raw error messages or stack traces to clients on 500 status responses.

### Frontend Conventions
1. **Zero Raw HTML Injection (XSS Prevention)**:
   - Never use `dangerouslySetInnerHTML`.
   - Use React component splitting and JSX elements (`<mark>`, `<span>`) for keyword highlighting.
2. **Safe Deep Links**:
   - When referencing files on GitHub, anchor to the matched line number via `#L{lineNumber}` helper `getFileUrlWithLine(url, lineNumber)`.
3. **State Management**:
   - Use `@tanstack/react-query` for asynchronous server state with query keys reflecting all active filters.
   - Keep charts responsive with Recharts `ResponsiveContainer`.

---

## Environment Variables

| Variable | Description |
|---|---|
| `GITHUB_TOKEN` | GitHub Personal Access Token (requires `public_repo`, `read:user`) |
| `JWT_SECRET` | Secret key for signing JWT tokens (min 32 chars in production) |
| `TWO_FACTOR_ENCRYPTION_KEY` | AES-256 encryption key for TOTP secrets at rest |
| `DATABASE_URL` | SQLite path or PostgreSQL connection string (`file:./dev.db`) |
| `PORT` | Backend listening port (default: `3001`) |
| `FRONTEND_URL` | Allowed CORS origin (comma-separated if multiple) |
| `NODE_ENV` | `development` or `production` |
