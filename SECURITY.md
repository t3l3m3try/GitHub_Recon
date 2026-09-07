# Security

GitHub Recon handles two categories of sensitive material: the credentials of its own users, and the exposed secrets it discovers while scanning. This document describes how both are protected and what operators must do.

## Reporting a vulnerability

Please open a private security advisory on the repository rather than a public issue.

## Authentication

**Passwords** are stored only as bcrypt hashes (cost factor 12). The plaintext is never written to the database, logs or API responses. Every password — whether chosen by a user or generated for them — must satisfy:

- at least 12 characters
- an uppercase letter, a lowercase letter, a digit and a symbol
- must not contain the account's username or email address
- must not contain a common password phrase

Administrator-issued passwords are generated with a CSPRNG and displayed exactly once. Accounts created or reset this way are flagged so the holder must choose a new password before any other API route will respond.

**Tokens.** Access tokens are JWTs valid for 15 minutes. Refresh tokens are 256-bit random values delivered in an `httpOnly`, `SameSite=Strict` cookie (also `Secure` when `NODE_ENV=production`); only their SHA-256 digest is stored, so a database disclosure cannot be replayed. Refresh tokens rotate on every use and the superseded value is rejected. The access token is held in browser memory only and never in `localStorage`, keeping both credentials out of reach of injected scripts.

**Permissions are re-read from the database on every request** rather than trusted from the token, so revoking a permission, deactivating an account or suspending an organization takes effect on the next request instead of when the token expires.

**Brute-force protection** operates at two levels: an account locks for 15 minutes after 5 consecutive failures, and an IP-based limiter caps *failed* sign-ins per window. Successful sign-ins are not counted, so colleagues behind a shared address cannot lock each other out. Sign-in returns an identical message whether the account is unknown or the password is wrong, and performs a hash comparison in both cases so response timing does not reveal which accounts exist.

**Two-factor authentication (TOTP)** is optional per user and can be mandated per user by a super admin (any account) or an org admin (accounts in their own organization only) — the mandate forces enrollment before anything else works, but an admin can never enroll a device on someone else's behalf. The secret is AES-256-GCM encrypted at rest under a key separate from `JWT_SECRET`, and a used TOTP code is rejected if replayed even within its own 30-second window, not just after it expires. Ten single-use recovery codes are issued on enrollment, stored only as bcrypt hashes, and shown exactly once. Disabling 2FA or regenerating recovery codes requires both the current password and a current code — a stolen access token alone cannot strip this protection. A wrong code shares the same 5-attempts/15-minute lockout as a wrong password.

**Audit trail.** Sign-ins, failures, password changes, 2FA enrollment/disable/reset, and every organization and user modification are recorded with actor, action, target and IP.

## Tenant isolation

Organizations are isolated at the query level, not by a check applied after loading a record. Every domain, scan and finding lookup is constrained by the requester's organization as part of the database query, so a record belonging to another tenant is reported as *not found* rather than *forbidden*. This applies uniformly to reads, updates, deletes, bulk operations, statistics and exports. A super administrator is deliberately unscoped.

## Secrets in the repository

The following are excluded by `.gitignore` and must never be committed:

| Path | Why |
|---|---|
| `.env`, `backend/.env` | GitHub token, JWT signing secret |
| `*.db`, `*.sqlite` | **Scan results — contains real exposed secrets in plaintext** |
| `logs/`, `*.log` | Query strings, repository names, error detail |
| `dist/`, `build/` | Build output |

The database deserves particular care. Its purpose is to accumulate real credentials found in public repositories; a copy of it is a collection of working secrets belonging to third parties. Treat it as you would a password vault: never commit it, never attach it to an issue, and store backups encrypted.

### Configuring the git remote

Do not embed a Personal Access Token in the remote URL:

```bash
# Avoid — the token sits in plaintext in .git/config and leaks into any output of `git remote -v`
git remote set-url origin https://TOKEN@github.com/owner/repo.git

# Prefer the GitHub CLI or a credential helper
gh auth login
git remote set-url origin https://github.com/owner/repo.git
```

If a token has been stored this way, rotate it — `.git/config` is easy to disclose accidentally through screenshots, screen sharing, support bundles or shell history.

## Deployment & Public Internet Hardening

For public internet deployment, ensure the following checklist is met:

1. **Secrets & Keys:**
   - Set `JWT_SECRET` and `TWO_FACTOR_ENCRYPTION_KEY` to at least 32 cryptographically random characters each. The server strictly refuses to start in `production` without both.
   - Restrict the GitHub Personal Access Token (`GITHUB_TOKEN`) to `public_repo` and `read:user` permissions only. Never assign administrative or repo write privileges.
2. **Environment & Cookies:**
   - Set `NODE_ENV=production` so that session refresh cookies are marked `Secure`, error stacks are stripped from 500 responses, and dev overrides are blocked.
   - Set `FRONTEND_URL` to your exact public frontend domain(s) (supports comma-separated list for multi-domain setups). Wildcards are disallowed when credentials are exchanged.
3. **Network & TLS:**
   - Terminate TLS (HTTPS) via a trusted reverse proxy (e.g., Nginx, Caddy, Cloudflare). Access tokens and refresh cookies are bearer credentials that must never traverse unencrypted networks.
   - If behind a reverse proxy, ensure `trust proxy` is configured in Express or the proxy strips spoofed `X-Forwarded-For` headers so IP-based rate limiting cannot be bypassed.
4. **Rate Limiting & Anti-DoS:**
   - Global API rate limiter (`apiLimiter`: 600 req / 15 min per IP) protects general endpoints against resource exhaustion.
   - Credential rate limiter (`loginLimiter`: 30 failed attempts / 15 min per IP) protects `/auth/login`, `/auth/setup`, `/auth/change-password`, and `/auth/2fa/verify`.
   - Scan burst limiter (`scanLimiter`: 10 scans / 15 min) prevents GitHub API quota exhaustion from repeated scan launches.
   - Query pagination parameters (`page`, `limit`) are clamped on both scans and findings endpoints to avoid oversized queries or memory exhaustion.
5. **Content Security & Injection Safeguards:**
   - Frontend rendering uses zero raw HTML injection (`dangerouslySetInnerHTML` is eliminated across the entire application). Search highlights use safe React JSX nodes (`<mark>`).
   - SQLite database (`dev.db`) contains plaintext findings and secret matches; file system access must be restricted (`chmod 600 dev.db`), and automated backups must be encrypted at rest.

## Threat model boundaries

The following are explicitly **not** covered:

- **Only TOTP** is supported for 2FA — no WebAuthn/hardware security keys, and no SMS or email codes.
- **Password history** is not retained; a user may reuse a previous password.
- **The super administrator has no self-service recovery.** If the last super administrator password is lost, it must be reset directly against the database.
- **SQLite** suits a single-node deployment. Concurrent multi-node writes require migrating to a networked database (e.g., PostgreSQL).
- **Rate limiting is per-process and in-memory**; behind multiple instances it should move to a shared Redis store.
