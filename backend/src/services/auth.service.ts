import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import { User as PrismaUser, Organization } from '@prisma/client';
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
const TWO_FACTOR_ISSUER = 'GitHub Recon';
const TWO_FACTOR_CHALLENGE_TTL = '5m';
const RECOVERY_CODE_COUNT = 10;

/** Compared against when the account does not exist, to equalise login timing. */
const DUMMY_HASH = bcrypt.hashSync('mismatch-placeholder-value', BCRYPT_ROUNDS);

// ── Secrets ────────────────────────────────────────────────────────────────

/**
 * Reads a secret from the environment, or — outside production — generates
 * one and persists it to backend/.env (git-ignored) so it survives a restart.
 * In production a missing secret is fatal rather than silently generated,
 * since an ephemeral secret there would invalidate every token or ciphertext
 * on each redeploy.
 */
function getOrCreatePersistedSecret(envVar: string): string {
  const fromEnv = process.env[envVar];
  if (fromEnv && fromEnv.length >= 32) return fromEnv;

  if (process.env.NODE_ENV === 'production') {
    throw new Error(`${envVar} must be set to a value of at least 32 characters in production`);
  }

  const generated = crypto.randomBytes(48).toString('base64url');
  const envPath = path.resolve(__dirname, '../../.env');
  try {
    const existing = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf-8') : '';
    if (!new RegExp(`^${envVar}=`, 'm').test(existing)) {
      fs.writeFileSync(
        envPath,
        `${existing}${existing && !existing.endsWith('\n') ? '\n' : ''}${envVar}=${generated}\n`,
        { mode: 0o600 }
      );
      logger.warn(`No ${envVar} found — generated one and wrote it to ${envPath}`);
    }
  } catch (error) {
    logger.warn(`Could not persist generated ${envVar}; it will not survive a restart`);
  }

  process.env[envVar] = generated;
  return generated;
}

let cachedSecret: string | null = null;

/** The JWT signing secret for access tokens and 2FA challenge tokens. */
export function getJwtSecret(): string {
  if (!cachedSecret) cachedSecret = getOrCreatePersistedSecret('JWT_SECRET');
  return cachedSecret;
}

let cachedEncryptionKey: Buffer | null = null;

/**
 * The key used to encrypt TOTP secrets at rest. Deliberately separate from
 * JWT_SECRET so that rotating one does not also invalidate the other; any
 * length of source material is normalised to a 32-byte AES-256 key.
 */
function getTwoFactorEncryptionKey(): Buffer {
  if (!cachedEncryptionKey) {
    const raw = getOrCreatePersistedSecret('TWO_FACTOR_ENCRYPTION_KEY');
    cachedEncryptionKey = crypto.createHash('sha256').update(raw).digest();
  }
  return cachedEncryptionKey;
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
  | 'ORG_SUSPENDED'
  | 'SETUP_REQUIRED';

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
    twoFactorEnabled: boolean;
    /** True when an admin mandate is outstanding: required, but not yet enrolled. */
    twoFactorSetupRequired: boolean;
  };
}

export interface LoginRejected {
  ok: false;
  reason: LoginFailure;
  retryAfterMinutes?: number;
}

/** Shape returned by every successful-auth path (password login, 2FA verify, initial setup). */
type PresentableUser = PrismaUser & { organization: Organization | null };

function presentAuthUser(user: PresentableUser): LoginSuccess['user'] {
  return {
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
    twoFactorEnabled: user.twoFactorEnabled,
    twoFactorSetupRequired: user.twoFactorRequired && !user.twoFactorEnabled,
  };
}

/**
 * Verify credentials. Accepts either the email address or the username as the
 * identifier. Every rejection returns the same generic reason except for the
 * states the user genuinely needs to act on (locked / disabled / suspended).
 * Only checks the password — the caller is responsible for the 2FA step when
 * user.twoFactorEnabled is true.
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

  if (!user.passwordSet) {
    // Freshly-seeded super admin: the stored hash is an unusable placeholder,
    // so a real bcrypt comparison would only ever fail. Send the caller to the
    // one-time setup screen instead of a generic invalid-credentials error.
    return { ok: false, reason: 'SETUP_REQUIRED' };
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

  // The password factor is proven, so it's safe to clear the lockout counter
  // even when a second factor is still outstanding — the 2FA step reuses the
  // same counter from zero. lastLoginAt only records a *complete* sign-in.
  await prisma.user.update({
    where: { id: user.id },
    data: {
      failedLoginAttempts: 0,
      lockedUntil: null,
      ...(user.twoFactorEnabled ? {} : { lastLoginAt: new Date() }),
    },
  });

  return { ok: true, user: presentAuthUser(user) };
}

// ── First-run setup ────────────────────────────────────────────────────────

/**
 * True while a freshly-seeded super admin is waiting for its password to be
 * set. A fresh install has exactly one such account; it disappears the moment
 * setup completes, so this can never re-trigger for later installs.
 */
export async function isInitialSetupRequired(): Promise<boolean> {
  const pending = await prisma.user.findFirst({ where: { passwordSet: false } });
  return !!pending;
}

export type SetupFailure = 'NOT_REQUIRED' | 'WEAK_PASSWORD';

export interface SetupResult {
  ok: true;
  user: LoginSuccess['user'];
}

export interface SetupRejected {
  ok: false;
  reason: SetupFailure;
  errors?: string[];
}

/**
 * Claims the pending super admin account by giving it a real password. Fails
 * once setup has already been completed, so the endpoint that calls this
 * cannot be replayed to reset the account later.
 */
export async function completeInitialSetup(password: string): Promise<SetupResult | SetupRejected> {
  const pending = await prisma.user.findFirst({
    where: { passwordSet: false },
    include: { organization: true },
  });
  if (!pending) return { ok: false, reason: 'NOT_REQUIRED' };

  const check = validatePasswordStrength(password, pending.username, pending.email);
  if (!check.valid) return { ok: false, reason: 'WEAK_PASSWORD', errors: check.errors };

  const updated = await prisma.user.update({
    where: { id: pending.id },
    data: {
      passwordHash: await hashPassword(password),
      passwordSet: true,
      mustChangePassword: false,
      active: true,
      failedLoginAttempts: 0,
      lockedUntil: null,
    },
    include: { organization: true },
  });

  return { ok: true, user: presentAuthUser(updated) };
}

// ── Two-factor authentication ─────────────────────────────────────────────

/** AES-256-GCM: iv, auth tag and ciphertext are stored together, base64-joined. */
export function encryptSecret(plain: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getTwoFactorEncryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, ciphertext].map(b => b.toString('base64')).join('.');
}

export function decryptSecret(payload: string): string {
  const [ivB64, tagB64, dataB64] = payload.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', getTwoFactorEncryptionKey(), Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
}

/** A fresh base32 TOTP secret, compatible with Google Authenticator, Authy, etc. */
export function generateTwoFactorSecret(): string {
  return authenticator.generateSecret();
}

/** The otpauth:// URI an authenticator app scans to enroll the account. */
export function buildOtpAuthUrl(secret: string, accountLabel: string): string {
  return authenticator.keyuri(accountLabel, TWO_FACTOR_ISSUER, secret);
}

export async function generateQrCodeDataUrl(otpauthUrl: string): Promise<string> {
  return QRCode.toDataURL(otpauthUrl);
}

const TOTP_STEP_SECONDS = 30;

/**
 * Checks a 6-digit code against the secret and, only if it is both correct
 * and newer than the last accepted code, marks that time-step consumed.
 * ±1 step of tolerance covers clock drift between server and device; the
 * consumption check on top of that stops the same code being replayed
 * anywhere inside its own 30-second validity window.
 */
async function verifyAndConsumeTotpCode(userId: string, secret: string, code: string): Promise<boolean> {
  authenticator.options = { window: 1 };
  let delta: number | null;
  try {
    delta = authenticator.checkDelta(String(code || '').trim(), secret);
  } catch {
    delta = null;
  }
  if (delta === null || delta === undefined) return false;

  const step = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS) + delta;

  const user = await prisma.user.findUnique({ where: { id: userId }, select: { twoFactorLastUsedStep: true } });
  if (user?.twoFactorLastUsedStep != null && step <= user.twoFactorLastUsedStep) return false;

  await prisma.user.update({ where: { id: userId }, data: { twoFactorLastUsedStep: step } });
  return true;
}

/** Ten single-use codes, formatted like AB12C-3D4E5 for easy transcription. */
export function generateRecoveryCodes(count = RECOVERY_CODE_COUNT): string[] {
  return Array.from({ length: count }, () => {
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase();
    return `${raw.slice(0, 5)}-${raw.slice(5, 10)}`;
  });
}

export async function hashRecoveryCode(code: string): Promise<string> {
  return hashPassword(code.trim().toUpperCase());
}

/**
 * Verifies a 6-digit TOTP code or a recovery code and, on success, consumes
 * it — a TOTP code stops working the instant it's accepted (not just after
 * its time window expires), and a recovery code stops working after one use.
 */
export async function verifyAndConsumeTwoFactorCode(
  userId: string,
  encryptedSecret: string,
  code: string
): Promise<'totp' | 'recovery' | null> {
  const cleanCode = String(code || '').trim();

  if (/^\d{6}$/.test(cleanCode)) {
    const ok = await verifyAndConsumeTotpCode(userId, decryptSecret(encryptedSecret), cleanCode);
    return ok ? 'totp' : null;
  }

  const unused = await prisma.twoFactorRecoveryCode.findMany({ where: { userId, usedAt: null } });
  for (const candidate of unused) {
    if (await verifyPassword(cleanCode.toUpperCase(), candidate.codeHash)) {
      await prisma.twoFactorRecoveryCode.update({ where: { id: candidate.id }, data: { usedAt: new Date() } });
      return 'recovery';
    }
  }
  return null;
}

interface TwoFactorChallengePayload {
  sub: string;
  purpose: '2fa_challenge';
}

/** Short-lived token proving the password step passed; only usable at /auth/2fa/verify. */
export function signTwoFactorChallenge(userId: string): string {
  return jwt.sign(
    { sub: userId, purpose: '2fa_challenge' } satisfies TwoFactorChallengePayload,
    getJwtSecret(),
    { expiresIn: TWO_FACTOR_CHALLENGE_TTL }
  );
}

function verifyTwoFactorChallenge(token: string): string | null {
  try {
    const payload = jwt.verify(token, getJwtSecret()) as Partial<TwoFactorChallengePayload>;
    if (payload.purpose !== '2fa_challenge' || !payload.sub) return null;
    return payload.sub;
  } catch {
    return null;
  }
}

export type TwoFactorVerifyFailure =
  | 'INVALID_TOKEN'
  | 'INVALID_CODE'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_DISABLED'
  | 'ORG_SUSPENDED';

export interface TwoFactorVerifyRejected {
  ok: false;
  reason: TwoFactorVerifyFailure;
  retryAfterMinutes?: number;
}

/**
 * Completes a login that was bounced to the 2FA challenge. Accepts either a
 * 6-digit TOTP code or a recovery code, and shares the same lockout counter
 * as the password step, so guessing either one locks the account.
 */
export async function verifyTwoFactorLogin(
  challengeToken: string,
  code: string
): Promise<LoginSuccess | TwoFactorVerifyRejected> {
  const userId = verifyTwoFactorChallenge(challengeToken);
  if (!userId) return { ok: false, reason: 'INVALID_TOKEN' };

  const user = await prisma.user.findUnique({ where: { id: userId }, include: { organization: true } });
  if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) return { ok: false, reason: 'INVALID_TOKEN' };

  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    const retryAfterMinutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
    return { ok: false, reason: 'ACCOUNT_LOCKED', retryAfterMinutes };
  }

  const kind = await verifyAndConsumeTwoFactorCode(user.id, user.twoFactorSecret, code);

  if (!kind) {
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
      logger.warn(`Account locked after ${MAX_FAILED_ATTEMPTS} failed 2FA attempts: ${user.email}`);
      return { ok: false, reason: 'ACCOUNT_LOCKED', retryAfterMinutes: LOCKOUT_MINUTES };
    }
    return { ok: false, reason: 'INVALID_CODE' };
  }

  if (!user.active) return { ok: false, reason: 'ACCOUNT_DISABLED' };
  if (user.organization && !user.organization.active) return { ok: false, reason: 'ORG_SUSPENDED' };

  if (kind === 'recovery') logger.info(`Recovery code consumed at login: ${user.email}`);

  const updated = await prisma.user.update({
    where: { id: user.id },
    data: { failedLoginAttempts: 0, lockedUntil: null, lastLoginAt: new Date() },
    include: { organization: true },
  });

  return { ok: true, user: presentAuthUser(updated) };
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
