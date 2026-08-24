# GitHub Recon

A multi-tenant platform for detecting sensitive information exposed in public GitHub repositories. GitHub Recon monitors your organization's domains for leaked email addresses, API keys, credentials, private keys and other secrets, then ranks what it finds by how dangerous it actually is.

<img width="1662" height="980" alt="1" src="https://github.com/user-attachments/assets/22b64f77-20c6-4381-90d2-697dd40ecc60" />


## 🚀 Key Features

- **Comprehensive scanning** — searches code, commit messages and issues across public repositories, forks and wikis.
- **280 secret types across 349 detection patterns** — AWS, GitHub, GitLab, cloud providers, payment processors, AI/ML services, databases, private keys and more. Every regex, its entropy threshold and its severity weight are browsable in the UI.
- **247 configurable search queries** — every GitHub search the scanner performs is listed, grouped and individually switchable. Turn off what you don't need and scans get proportionally cheaper.
- **Intelligent scoring** — findings are ranked CRITICAL → INFO using entropy analysis, surrounding context, commit recency and file type, so the noise sinks. The full 0-100 formula is published in the UI rather than hidden in the code.
- **Multi-tenancy** — organizations keep their data separate. Members see their own organization's domains and findings and nothing else.
- **Role-based access control** — four roles plus per-user permission overrides, all administered from the UI.
- **Secure authentication** — bcrypt password hashing, short-lived access tokens, rotating refresh tokens in httpOnly cookies, account lockout and an audit trail. See [SECURITY.md](SECURITY.md).
- **Two-factor authentication (TOTP)** — any user can add it from their account settings; super admins can mandate, disable or reset it for anyone, org admins for their own organization's users.
- **SOC-style dashboard** — dark-mode analytics, triage and reporting.

## 🛠️ Tech Stack

- **Frontend**: React 18, TypeScript, Tailwind CSS, Recharts
- **Backend**: Node.js, Express.js, TypeScript
- **Database**: SQLite with Prisma ORM
- **Auth**: JWT access tokens + rotating refresh sessions, bcrypt
- **API**: GitHub REST API (Octokit)

## 🏁 Quick Start

### Prerequisites

- Node.js v18+
- A GitHub Personal Access Token with the `public_repo` and `read:user` scopes

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/t3l3m3try/GitHub_Recon.git
   cd GitHub_Recon
   ```

2. **Configure your environment:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and add your GitHub token:
   ```env
   GITHUB_TOKEN=your_github_personal_access_token_here
   ```
   See [Configuration](#-configuration) for the optional settings.

3. **Install and run:**
   ```bash
   ./run-local.sh
   ```
   This installs dependencies, sets up the database, seeds the first administrator account (with no password yet — see below) and starts both servers.

4. **Open** [http://localhost:5173](http://localhost:5173). No password is generated or printed anywhere: on a fresh install you land directly on a one-time **setup screen** that asks you to choose the super administrator's password. Enter one that satisfies the policy shown on screen and you're signed straight in — there is nothing to copy down beforehand, and the setup screen refuses to run again once it has been completed.

   If you'd rather provision the account non-interactively (CI, scripted deploys), set `SUPER_ADMIN_PASSWORD` in `.env` before the first run instead — see [Configuration](#-configuration). In that case the seed prints the credentials once, and you're prompted to change that password at first login instead of seeing the setup screen.

## 👥 Organizations, Users and Permissions

Every domain, scan and finding belongs to an **organization**. Members of an organization share visibility of its data; no member can see another organization's data through any endpoint, including by guessing record IDs.

### Roles

| Role | Scope |
|---|---|
| **Super Admin** | Every organization. Creates organizations and users, assigns users to organizations, and edits any user's permissions. Belongs to no organization itself. |
| **Organization Admin** | One organization: its users, domains, scans and findings. |
| **Analyst** | Adds domains, runs scans and triages findings within their organization. |
| **Viewer** | Read-only access to their organization's data. |

### Permissions

Each role carries sensible defaults, and the super admin can grant or revoke individual permissions on any user from **Admin → Users → Permissions**. Overrides are stored as a *difference* against the role, so changing someone's role later re-applies that role's defaults rather than leaving stale grants behind.

Available permissions: `domain:read` `domain:write` `domain:delete` `scan:run` `scan:cancel` `finding:read` `finding:update` `finding:delete` `finding:export` `query:read` `query:write` `user:manage` `org:manage` `admin:all`

### Organization controls

Each organization has settings that act as a **ceiling** on its members — a user can never do something their organization has switched off, regardless of their individual permissions:

| Setting | Effect |
|---|---|
| `active` | Turning it off signs out every member immediately and blocks sign-in |
| `canRunScans` | Withdraws `scan:run` / `scan:cancel` from all members |
| `canExport` | Withdraws `finding:export` from all members |
| `maxDomains` | Maximum domains the organization may monitor |
| `maxUsers` | Maximum member accounts |

### Two-factor authentication

Any user can turn on TOTP-based 2FA from **account menu → Settings → Security** — scan the QR code with an authenticator app (Google Authenticator, Authy, 1Password, etc.), confirm one code, and save the ten recovery codes shown once. From then on, signing in asks for a code after the password.

Admins manage 2FA for other accounts from **Admin → Users**: super admins for anyone, org admins for users in their own organization only.

| Action | Effect |
|---|---|
| **Require** (toggle) | Mandates 2FA — the user is walked through enrollment before they can use anything else. An admin can never enroll a device on someone else's behalf; this only sets the requirement. |
| **Disable** | Turns 2FA off entirely, including any requirement. |
| **Reset** | Clears a lost-device enrollment. If 2FA was required, it still is — the user enrolls again on next sign-in. |

Turning off 2FA or regenerating recovery codes always needs both the current password and a current code, even for the account's own owner — a stolen session token alone is never enough.

### Getting started as an administrator

1. Complete the one-time setup screen (or, if you provisioned `SUPER_ADMIN_PASSWORD` yourself, sign in and set a new password).
2. Go to **Admin → Organizations → New Organization**.
3. Go to **Admin → Users → New User**, pick a role and organization. A strong temporary password is generated and shown once — hand it to the user; they must change it at first sign-in.
4. Adjust individual permissions from the shield icon on any user row.

## 🔎 Queries & Detection

The **Queries** section has three tabs, covering the two distinct stages of a scan — *what GitHub is asked* and *what the results are matched against*.

### Search Queries

All 247 GitHub searches the scanner can perform, grouped by target and macro area:

- **Code Search** — 193 queries across 16 areas (Email Discovery, Credentials & Auth, Cloud Infrastructure, Database & Storage, DevOps & CI/CD, Infrastructure as Code, Config & Secret Files, Backups, Dumps & Shell History, Secret Managers & Vaults, Package Registries & Artifacts, Payment & Fintech, Communication & SaaS, AI & Machine Learning, Monitoring & Observability, Internal Infra & Recon, Other Services)
- **Commit Search** — 30 queries across 7 areas
- **Issue Search** — 24 queries across 7 areas

Every query is individually switchable and shows the exact GitHub syntax it will send, rendered against a domain of your choice. The selection is saved per user and applies to all of that user's future scans. A target with no enabled queries is skipped entirely.

This matters for cost: each code query is paginated up to 10 pages of 100 results and re-run against forks, so a full 247-query scan is expensive against GitHub's rate limit of 30 search requests per minute. Narrowing the selection makes scans proportionally faster.

### Detection Patterns

Read-only view of the 349 regex patterns, grouped into 280 secret types, that every search result is matched against. Each entry shows its regex source and flags, its entropy threshold, the context keywords that raise its score, and an example of what it matches. Unlike queries these are not user-configurable — they define what a finding *is*.

### Detection Settings

The scoring model itself, served from the same source of truth the scanner uses so the numbers can never drift from the code:

- the always-on per-domain email pattern that runs alongside the static patterns
- false-positive suppression — the content regexes and context substrings that discard a match outright
- the 0-100 criticality formula: how many points come from secret type, entropy, surrounding context and commit recency, the keyword bonuses and comment penalty, the recency brackets, the CRITICAL/HIGH/MEDIUM/LOW/INFO thresholds, and how several secrets in one file aggregate

Both tabs require `query:read`, the same permission as the query list.

## ⚙️ Configuration

All settings are read from `.env` in the project root, or `backend/.env`. Neither is committed.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GITHUB_TOKEN` | **yes** | — | GitHub PAT used for all searches |
| `JWT_SECRET` | in production | auto-generated in dev | Signing key for access tokens; minimum 32 characters |
| `TWO_FACTOR_ENCRYPTION_KEY` | in production | auto-generated in dev | Encrypts 2FA secrets at rest; minimum 32 characters |
| `DATABASE_URL` | — | `file:./dev.db` | Prisma connection string |
| `PORT` | — | `3001` | Backend port |
| `FRONTEND_URL` | — | `http://localhost:5173` | Allowed CORS origin (credentials mode forbids a wildcard) |
| `NODE_ENV` | — | `development` | `production` enables Secure cookies and requires `JWT_SECRET` |
| `LOG_LEVEL` | — | `info` | Winston log level (`error`, `warn`, `info`, `debug`) |
| `SUPER_ADMIN_EMAIL` | — | `superadmin@localhost.local` | Email for the seeded administrator |
| `SUPER_ADMIN_USERNAME` | — | `superadmin` | Username for the seeded administrator |
| `SUPER_ADMIN_PASSWORD` | — | none — set via the first-run setup screen | Optional: provision it non-interactively instead; must satisfy the password policy |
| `SEED_ORGANIZATIONS` | — | none | Comma-separated organizations to create on first run |
| `DEFAULT_ORGANIZATION` | — | `Default Organization` | Adopts domains that have no organization |
| `AUTH_RATE_LIMIT_MAX` | — | `30` | Failed sign-ins allowed per IP per window |
| `AUTH_RATE_LIMIT_WINDOW_MS` | — | `900000` | Rate limit window |

### Generating a production JWT secret

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

## 📡 API

All endpoints live under `/api`. Every route except `/health`, `/auth/login`, `/auth/refresh`, `/auth/password-policy`, `/auth/setup-status`, `/auth/setup` and `/auth/2fa/verify` requires a valid access token, and each declares the permission it needs.

| Area | Endpoints |
|---|---|
| **Auth** | `POST /auth/login` · `POST /auth/refresh` · `POST /auth/logout` · `GET /auth/me` · `PUT /auth/profile` · `GET /auth/permissions` · `POST /auth/change-password` · `GET /auth/password-policy` · `GET /auth/setup-status` · `POST /auth/setup` |
| **Two-factor (self-service)** | `GET /auth/2fa/status` · `POST /auth/2fa/setup` · `POST /auth/2fa/enable` · `POST /auth/2fa/disable` · `POST /auth/2fa/recovery-codes/regenerate` · `POST /auth/2fa/verify` |
| **Domains** | `GET/POST /domains` · `GET/PUT/DELETE /domains/:id` |
| **Scans** | `GET/POST /scans` · `GET /scans/:id` · `GET /scans/:id/findings` · `DELETE /scans/:id` |
| **Findings** | `GET /findings` · `GET /findings/stats` · `GET /findings/export` · `GET/PUT/DELETE /findings/:id` · `POST /findings/bulk-update` |
| **Queries** | `GET/PUT /queries` · `POST /queries/reset` |
| **Detection patterns** | `GET /patterns` |
| **Admin** | `GET /admin/meta` · `GET/POST /admin/organizations` · `PUT/DELETE /admin/organizations/:id` · `GET/POST /admin/users` · `PUT/DELETE /admin/users/:id` · `POST /admin/users/:id/reset-password` · `POST /admin/users/:id/unlock` · `POST /admin/users/:id/2fa/disable` · `POST /admin/users/:id/2fa/reset` · `GET /admin/audit` |

## 🗄️ Database

```bash
cd backend
npm run db:push      # apply the schema
npm run db:seed      # ensure a super administrator exists (idempotent)
npm run db:studio    # browse the data
```

The seed never overwrites an existing account. It only prints credentials when `SUPER_ADMIN_PASSWORD` was supplied; otherwise the newly created super admin has no password at all until the one-time setup screen sets one.

## 🤝 Contributing

Contributions are welcome. Detection patterns, search queries, UI/UX and backend performance all have room to improve. Please open a pull request.

When contributing, never commit `.env` files, database files, scan results or real credentials — see [SECURITY.md](SECURITY.md).

## 📄 License

MIT License — see the LICENSE file for details.

---

**⚠️ Important**: This tool is for defensive security purposes only. Ensure you are authorized to scan the domains you monitor, and respect GitHub's Terms of Service and rate limits. Scan results contain real exposed secrets — treat the database as sensitive and never commit or share it.
