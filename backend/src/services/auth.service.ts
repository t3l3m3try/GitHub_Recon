import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import prisma from '../config/database';
import { logger } from '../utils/logger';
import { computeEffectivePermissions, Permission } from '../utils/permissions';

/**
 * Auth Service
 *
 * Credential handling rules enforced here:
 *  - Passwords are only ever stored as bcrypt hashes (cost 12); the plaintext is
 *    never logged, returned, or persisted.
 *  - Login always performs a bcrypt comparison, even for unknown accounts, so
 *    response timing does not reveal whether an email exists.
 *  - Refresh tokens are random 256-bit values; only their SHA-256 is stored, so
 *    a database leak cannot be replayed. They rotate on every use.
 *  - Repeated failures lock the account for a cool-down period.
 */

const BCRYPT_ROUNDS = 12;
const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL_DAYS = 7;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

/** Compared against when the account does not exist, to equalise login timing. */
const DUMMY_HASH = bcrypt.hashSync('mismatch-placeholder-value', BCRYPT_ROUNDS);

// ── Secrets ────────────────────────────────────────────────────────────────

let cachedSecret: string | null = null;

/**
 * The JWT signing secret. Refuses to fall back to a hard-coded default: in
 * production a missing secret is fatal, in development one is generated once
 * and persisted to backend/.env (which is git-ignored).
 */
export function getJwtSecret(): string {
  if (cachedSecret) return cachedSecret;

  const fromEnv = process.env.JWT_SECRET;
  if (fromEnv && fromEnv.length >= 32) {
    cachedSecret = fromEnv;
    return cachedSecret;
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET must be set to a value of at least 32 characters in production');
  }

  const generated = crypto.randomBytes(48).toString('base64url');
  const envPath = path.resolve(__dirname, '../../.env');
  try {
    const existing = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf-8') : '';
    if (!/^JWT_SECRET=/m.test(existing)) {
      fs.writeFileSync(
        envPath,
        `${existing}${existing && !existing.endsWith('\n') ? '\n' : ''}JWT_SECRET=${generated}\n`,
        { mode: 0o600 }
      );
      logger.warn(`No JWT_SECRET found — generated one and wrote it to ${envPath}`);
    }
  } catch (error) {
    logger.warn('Could not persist generated JWT_SECRET; tokens will not survive a restart');
  }

  process.env.JWT_SECRET = generated;
  cachedSecret = generated;
  return cachedSecret;
}

// ── Passwords ──────────────────────────────────────────────────────────────

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}

export interface PasswordCheck {
  valid: boolean;
  errors: string[];
}

/** Password policy applied to every password the system accepts. */
export function validatePasswordStrength(password: string, username?: string, email?: string): PasswordCheck {
  const errors: string[] = [];

  if (!password || password.length < 12) errors.push('Must be at least 12 characters long');
  if (password.length > 200) errors.push('Must be at most 200 characters long');
  if (!/[a-z]/.test(password)) errors.push('Must contain a lowercase letter');
  if (!/[A-Z]/.test(password)) errors.push('Must contain an uppercase letter');
  if (!/[0-9]/.test(password)) errors.push('Must contain a digit');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('Must contain a symbol');

  const lowered = (password || '').toLowerCase();
  if (username && lowered.includes(username.toLowerCase())) errors.push('Must not contain your username');
  if (email) {
    const local = email.split('@')[0]?.toLowerCase();
    if (local && local.length > 2 && lowered.includes(local)) errors.push('Must not contain your email address');
  }

  const common = ['password', 'qwerty', '123456', 'letmein', 'admin123', 'welcome', 'changeme', 'iloveyou'];
  if (common.some(c => lowered.includes(c))) errors.push('Must not contain a common password phrase');

  return { valid: errors.length === 0, errors };
}

/** Cryptographically random password that satisfies the policy above. */
export function generateStrongPassword(length = 24): string {
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const digits = '23456789';
  const symbols = '!@#$%^&*()-_=+[]{}?';
  const all = lower + upper + digits + symbols;

  const pick = (set: string) => set[crypto.randomInt(0, set.length)];
  const chars = [pick(lower), pick(upper), pick(digits), pick(symbols)];
  while (chars.length < length) chars.push(pick(all));

  // Fisher-Yates with a CSPRNG so the guaranteed characters are not positional
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// ── Tokens & sessions ──────────────────────────────────────────────────────

export interface AccessTokenPayload {
  sub: string;
  role: string;
  orgId: string | null;
}

/**
 * Access tokens deliberately carry no permission list — permissions are resolved
 * from the database on every request so that a revocation takes effect
 * immediately rather than when the token expires.
 */
export function signAccessToken(user: { id: string; role: string; orgId: string | null }): string {
  return jwt.sign(
    { sub: user.id, role: user.role, orgId: user.orgId } satisfies AccessTokenPayload,
    getJwtSecret(),
    { expiresIn: ACCESS_TOKEN_TTL }
  );
}

export function verifyAccessToken(token: string): AccessTokenPayload | null {
  try {
    return jwt.verify(token, getJwtSecret()) as AccessTokenPayload;
  } catch {
    return null;
  }
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export async function issueRefreshToken(
  userId: string,
  meta: { userAgent?: string; ip?: string } = {}
): Promise<{ token: string; expiresAt: Date }> {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);

  await prisma.session.create({
    data: {
      userId,
      tokenHash: hashToken(token),
      expiresAt,
      userAgent: meta.userAgent?.slice(0, 255),
      ip: meta.ip,
    },
  });

  return { token, expiresAt };
}

/** Look up a live session by its raw refresh token. */
export async function findValidSession(token: string) {
  if (!token) return null;
  const session = await prisma.session.findUnique({
    where: { tokenHash: hashToken(token) },
    include: { user: { include: { organization: true } } },
  });
  if (!session) return null;
  if (session.revokedAt) return null;
  if (session.expiresAt.getTime() < Date.now()) return null;
  return session;
}

export async function revokeSession(token: string): Promise<void> {
  const tokenHash = hashToken(token);
  await prisma.session.updateMany({
    where: { tokenHash, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

/** Used on password change, deactivation, or role change. */
export async function revokeAllSessions(userId: string): Promise<number> {
  const { count } = await prisma.session.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  return count;
}

export async function purgeExpiredSessions(): Promise<number> {
  const { count } = await prisma.session.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
  return count;
}

// ── Login ──────────────────────────────────────────────────────────────────

export type LoginFailure =
  | 'INVALID_CREDENTIALS'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_DISABLED'
  | 'ORG_SUSPENDED';

export interface LoginSuccess {
  ok: true;
  user: {
    id: string;
    email: string;
    username: string;
    role: string;
    orgId: string | null;
    mustChangePassword: boolean;
    organization: { id: string; name: string; slug: string } | null;
    permissions: Permission[];
  };
}

export interface LoginRejected {
  ok: false;
  reason: LoginFailure;
  retryAfterMinutes?: number;
}

/**
 * Verify credentials. Accepts either the email address or the username as the
 * identifier. Every rejection returns the same generic reason except for the
 * states the user genuinely needs to act on (locked / disabled / suspended).
 */
export async function authenticate(identifier: string, password: string): Promise<LoginSuccess | LoginRejected> {
  const id = (identifier || '').trim().toLowerCase();

  const user = await prisma.user.findFirst({
    where: { OR: [{ email: id }, { username: id }] },
    include: { organization: true },
  });

  if (!user) {
    // Still spend the time a real comparison would, to avoid user enumeration.
    await bcrypt.compare(password || '', DUMMY_HASH);
    return { ok: false, reason: 'INVALID_CREDENTIALS' };
  }

  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    const retryAfterMinutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
    return { ok: false, reason: 'ACCOUNT_LOCKED', retryAfterMinutes };
  }

  const matches = await verifyPassword(password || '', user.passwordHash);

  if (!matches) {
    const attempts = user.failedLoginAttempts + 1;
    const lock = attempts >= MAX_FAILED_ATTEMPTS;
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: lock ? 0 : attempts,
        lockedUntil: lock ? new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000) : null,
      },
    });
    if (lock) {
      logger.warn(`Account locked after ${MAX_FAILED_ATTEMPTS} failed attempts: ${user.email}`);
      return { ok: false, reason: 'ACCOUNT_LOCKED', retryAfterMinutes: LOCKOUT_MINUTES };
    }
    return { ok: false, reason: 'INVALID_CREDENTIALS' };
  }

  if (!user.active) return { ok: false, reason: 'ACCOUNT_DISABLED' };
  if (user.organization && !user.organization.active) return { ok: false, reason: 'ORG_SUSPENDED' };

  await prisma.user.update({
    where: { id: user.id },
    data: { failedLoginAttempts: 0, lockedUntil: null, lastLoginAt: new Date() },
  });

  return {
    ok: true,
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      orgId: user.orgId,
      mustChangePassword: user.mustChangePassword,
      organization: user.organization
        ? { id: user.organization.id, name: user.organization.name, slug: user.organization.slug }
        : null,
      permissions: computeEffectivePermissions(user.role, user.permissions, user.organization),
    },
  };
}

// ── Audit ──────────────────────────────────────────────────────────────────

export async function audit(entry: {
  userId?: string | null;
  actorEmail?: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  detail?: string;
  ip?: string;
  success?: boolean;
}): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        userId: entry.userId ?? null,
        actorEmail: entry.actorEmail ?? null,
        action: entry.action,
        targetType: entry.targetType,
        targetId: entry.targetId,
        detail: entry.detail,
        ip: entry.ip,
        success: entry.success ?? true,
      },
    });
  } catch (error) {
    logger.error('Failed to write audit log entry:', error);
  }
}

export const AUTH_CONSTANTS = {
  REFRESH_TOKEN_TTL_DAYS,
  ACCESS_TOKEN_TTL,
  MAX_FAILED_ATTEMPTS,
  LOCKOUT_MINUTES,
};
