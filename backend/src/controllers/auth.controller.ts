import { Request, Response } from 'express';
import prisma from '../config/database';
import {
  AUTH_CONSTANTS,
  audit,
  authenticate,
  completeInitialSetup,
  findValidSession,
  generateStrongPassword,
  hashPassword,
  isInitialSetupRequired,
  issueRefreshToken,
  revokeAllSessions,
  revokeSession,
  signAccessToken,
  signTwoFactorChallenge,
  validatePasswordStrength,
  verifyPassword,
  verifyTwoFactorLogin,
} from '../services/auth.service';
import { PERMISSION_GROUPS, PERMISSION_LABELS, computeEffectivePermissions } from '../utils/permissions';
import { logger } from '../utils/logger';
import { Organization, User as PrismaUser } from '@prisma/client';

/**
 * Auth Controller
 *
 * The refresh token is delivered as an httpOnly cookie so that page scripts
 * cannot read it; the short-lived access token is returned in the JSON body for
 * the SPA to hold in memory only. That combination keeps the long-lived
 * credential out of reach of XSS while avoiding localStorage persistence.
 */

const REFRESH_COOKIE = 'gr_refresh';

function cookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict' as const,
    path: '/api/auth',
    maxAge: AUTH_CONSTANTS.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
  };
}

function clientIp(req: Request): string | undefined {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || undefined;
}

/** Issues the refresh cookie + access token pair that completes any sign-in. */
async function issueSession(
  res: Response,
  req: Request,
  user: { id: string; role: string; orgId: string | null }
): Promise<string> {
  const { token: refreshToken } = await issueRefreshToken(user.id, {
    userAgent: req.headers['user-agent'] as string,
    ip: clientIp(req),
  });
  const accessToken = signAccessToken({ id: user.id, role: user.role, orgId: user.orgId });
  res.cookie(REFRESH_COOKIE, refreshToken, cookieOptions());
  return accessToken;
}

/**
 * POST /api/auth/login
 * When the account has 2FA enabled, the password alone does not complete the
 * sign-in: a short-lived challenge token is returned instead, and the caller
 * must follow up at /auth/2fa/verify with a code before any session is issued.
 */
export async function login(req: Request, res: Response) {
  try {
    const { identifier, email, username, password } = req.body ?? {};
    const id = identifier || email || username;

    if (!id || !password) {
      return res.status(400).json({ error: 'Username/email and password are required' });
    }

    const result = await authenticate(String(id), String(password));
    const ip = clientIp(req);

    if (!result.ok) {
      await audit({
        actorEmail: String(id).toLowerCase(),
        action: 'auth.login',
        success: false,
        detail: result.reason,
        ip,
      });

      switch (result.reason) {
        case 'ACCOUNT_LOCKED':
          return res.status(423).json({
            error: `Too many failed attempts. Try again in ${result.retryAfterMinutes ?? AUTH_CONSTANTS.LOCKOUT_MINUTES} minutes.`,
            code: 'ACCOUNT_LOCKED',
          });
        case 'ACCOUNT_DISABLED':
          return res.status(403).json({ error: 'This account has been deactivated', code: 'ACCOUNT_DISABLED' });
        case 'ORG_SUSPENDED':
          return res.status(403).json({ error: 'Your organization has been suspended', code: 'ORG_SUSPENDED' });
        case 'SETUP_REQUIRED':
          return res.status(409).json({
            error: 'This installation has not been set up yet',
            code: 'SETUP_REQUIRED',
          });
        default:
          return res.status(401).json({ error: 'Invalid credentials', code: 'INVALID_CREDENTIALS' });
      }
    }

    if (result.user.twoFactorEnabled) {
      await audit({
        userId: result.user.id, actorEmail: result.user.email,
        action: 'auth.login_password_ok', detail: '2FA challenge issued', ip,
      });
      return res.json({
        twoFactorRequired: true,
        challengeToken: signTwoFactorChallenge(result.user.id),
      });
    }

    const accessToken = await issueSession(res, req, result.user);

    await audit({ userId: result.user.id, actorEmail: result.user.email, action: 'auth.login', ip });
    logger.info(`Login: ${result.user.email} (${result.user.role})`);

    res.json({ accessToken, user: result.user });
  } catch (error: any) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
}

/**
 * POST /api/auth/2fa/verify
 * Public — completes a login that was bounced to the 2FA challenge. Accepts
 * either a 6-digit TOTP code or a recovery code.
 */
export async function verifyTwoFactor(req: Request, res: Response) {
  try {
    const { challengeToken, code } = req.body ?? {};
    if (!challengeToken || !code) {
      return res.status(400).json({ error: 'A challenge token and code are required' });
    }

    const result = await verifyTwoFactorLogin(String(challengeToken), String(code));
    const ip = clientIp(req);

    if (!result.ok) {
      await audit({ action: 'auth.2fa_verify', success: false, detail: result.reason, ip });

      switch (result.reason) {
        case 'ACCOUNT_LOCKED':
          return res.status(423).json({
            error: `Too many failed attempts. Try again in ${result.retryAfterMinutes ?? AUTH_CONSTANTS.LOCKOUT_MINUTES} minutes.`,
            code: 'ACCOUNT_LOCKED',
          });
        case 'ACCOUNT_DISABLED':
          return res.status(403).json({ error: 'This account has been deactivated', code: 'ACCOUNT_DISABLED' });
        case 'ORG_SUSPENDED':
          return res.status(403).json({ error: 'Your organization has been suspended', code: 'ORG_SUSPENDED' });
        case 'INVALID_CODE':
          return res.status(401).json({ error: 'Invalid code', code: 'INVALID_CODE' });
        default:
          return res.status(401).json({ error: 'Sign-in expired — please log in again', code: 'INVALID_TOKEN' });
      }
    }

    const accessToken = await issueSession(res, req, result.user);

    await audit({ userId: result.user.id, actorEmail: result.user.email, action: 'auth.login', detail: '2FA', ip });
    logger.info(`Login: ${result.user.email} (${result.user.role}) via 2FA`);

    res.json({ accessToken, user: result.user });
  } catch (error: any) {
    logger.error('2FA verify error:', error);
    res.status(500).json({ error: 'Could not verify code' });
  }
}

/**
 * POST /api/auth/refresh
 * Rotates the refresh token: the presented one is revoked and a new one issued.
 */
export async function refresh(req: Request, res: Response) {
  try {
    const token = req.cookies?.[REFRESH_COOKIE];
    if (!token) {
      return res.status(401).json({ error: 'No session' });
    }

    const session = await findValidSession(token);
    if (!session) {
      res.clearCookie(REFRESH_COOKIE, { ...cookieOptions(), maxAge: undefined });
      return res.status(401).json({ error: 'Session expired' });
    }

    const user = session.user;
    if (!user.active || (user.organization && !user.organization.active)) {
      await revokeAllSessions(user.id);
      res.clearCookie(REFRESH_COOKIE, { ...cookieOptions(), maxAge: undefined });
      return res.status(403).json({ error: 'Account is no longer active' });
    }

    // Rotation: the presented token is single-use.
    await revokeSession(token);
    const { token: nextToken } = await issueRefreshToken(user.id, {
      userAgent: req.headers['user-agent'] as string,
      ip: clientIp(req),
    });

    const accessToken = signAccessToken({ id: user.id, role: user.role, orgId: user.orgId });

    res.cookie(REFRESH_COOKIE, nextToken, cookieOptions());
    res.json({
      accessToken,
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
        twoFactorEnabled: user.twoFactorEnabled,
        twoFactorSetupRequired: user.twoFactorRequired && !user.twoFactorEnabled,
      },
    });
  } catch (error: any) {
    logger.error('Refresh error:', error);
    res.status(500).json({ error: 'Could not refresh session' });
  }
}

/**
 * POST /api/auth/logout
 */
export async function logout(req: Request, res: Response) {
  try {
    const token = req.cookies?.[REFRESH_COOKIE];
    if (token) await revokeSession(token);

    if (req.user) {
      await audit({ userId: req.user.id, actorEmail: req.user.email, action: 'auth.logout', ip: clientIp(req) });
    }

    res.clearCookie(REFRESH_COOKIE, { ...cookieOptions(), maxAge: undefined });
    res.json({ message: 'Logged out' });
  } catch (error: any) {
    logger.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
}

/** Shape returned by /auth/me and /auth/profile — the caller's own full record. */
function presentSelf(user: PrismaUser & { organization: Organization | null }) {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
    orgId: user.orgId,
    mustChangePassword: user.mustChangePassword,
    lastLoginAt: user.lastLoginAt,
    organization: user.organization
      ? {
          id: user.organization.id,
          name: user.organization.name,
          slug: user.organization.slug,
          canRunScans: user.organization.canRunScans,
          canExport: user.organization.canExport,
          maxDomains: user.organization.maxDomains,
        }
      : null,
    permissions: computeEffectivePermissions(user.role, user.permissions, user.organization),
    twoFactorEnabled: user.twoFactorEnabled,
    twoFactorSetupRequired: user.twoFactorRequired && !user.twoFactorEnabled,
  };
}

/**
 * GET /api/auth/me
 */
export async function me(req: Request, res: Response) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });

  const user = await prisma.user.findUnique({
    where: { id: req.user.id },
    include: { organization: true },
  });

  if (!user) return res.status(401).json({ error: 'Account not found' });

  res.json(presentSelf(user));
}

/**
 * PUT /api/auth/profile
 * Self-service username/email update. Neither participates in
 * authorization, so no session needs to be revoked for this to take effect.
 */
export async function updateProfile(req: Request, res: Response) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    const { username, email } = req.body ?? {};
    const data: { username?: string; email?: string } = {};

    if (username !== undefined) {
      const cleanUsername = String(username).trim().toLowerCase();
      if (!/^[a-z0-9._-]{3,32}$/.test(cleanUsername)) {
        return res.status(400).json({ error: 'Username must be 3-32 characters: letters, digits, dot, underscore or hyphen' });
      }
      if (cleanUsername !== req.user.username) {
        const clash = await prisma.user.findFirst({ where: { username: cleanUsername, id: { not: req.user.id } } });
        if (clash) return res.status(409).json({ error: 'That username is already taken' });
        data.username = cleanUsername;
      }
    }

    if (email !== undefined) {
      const cleanEmail = String(email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
        return res.status(400).json({ error: 'Invalid email address' });
      }
      if (cleanEmail !== req.user.email) {
        const clash = await prisma.user.findFirst({ where: { email: cleanEmail, id: { not: req.user.id } } });
        if (clash) return res.status(409).json({ error: 'That email address is already registered' });
        data.email = cleanEmail;
      }
    }

    const current = await prisma.user.findUnique({ where: { id: req.user.id }, include: { organization: true } });
    if (!current) return res.status(401).json({ error: 'Account not found' });

    if (Object.keys(data).length === 0) {
      return res.json(presentSelf(current));
    }

    const updated = await prisma.user.update({
      where: { id: req.user.id },
      data,
      include: { organization: true },
    });

    await audit({
      userId: updated.id, actorEmail: updated.email,
      action: 'auth.update_profile', detail: JSON.stringify(Object.keys(data)), ip: clientIp(req),
    });
    logger.info(`Profile updated: ${updated.email} (${Object.keys(data).join(', ')})`);

    res.json(presentSelf(updated));
  } catch (error: any) {
    logger.error('Update profile error:', error);
    res.status(500).json({ error: 'Could not update profile' });
  }
}

/**
 * GET /api/auth/permissions
 * The caller's own effective permissions, labeled and grouped for display.
 * Unlike /admin/meta, this needs no special permission — everyone can see
 * what they themselves are allowed to do.
 */
export async function myPermissions(req: Request, res: Response) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });

  const held = new Set(req.user.permissions);
  const groups = PERMISSION_GROUPS
    .map(group => ({
      name: group.name,
      permissions: group.permissions
        .filter(p => held.has(p))
        .map(p => ({ id: p, label: PERMISSION_LABELS[p] })),
    }))
    .filter(group => group.permissions.length > 0);

  res.json({ groups });
}

/**
 * POST /api/auth/change-password
 * Requires the current password, and revokes every other session on success.
 */
export async function changePassword(req: Request, res: Response) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    const { currentPassword, newPassword } = req.body ?? {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(401).json({ error: 'Account not found' });

    const matches = await verifyPassword(String(currentPassword), user.passwordHash);
    if (!matches) {
      await audit({
        userId: user.id,
        actorEmail: user.email,
        action: 'auth.change_password',
        success: false,
        detail: 'current password incorrect',
        ip: clientIp(req),
      });
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    if (String(currentPassword) === String(newPassword)) {
      return res.status(400).json({ error: 'New password must be different from the current one' });
    }

    const check = validatePasswordStrength(String(newPassword), user.username, user.email);
    if (!check.valid) {
      return res.status(400).json({ error: 'Password does not meet requirements', requirements: check.errors });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash: await hashPassword(String(newPassword)),
        mustChangePassword: false,
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });

    // Every existing session is invalidated, including this one.
    await revokeAllSessions(user.id);

    const { token } = await issueRefreshToken(user.id, {
      userAgent: req.headers['user-agent'] as string,
      ip: clientIp(req),
    });
    const accessToken = signAccessToken({ id: user.id, role: user.role, orgId: user.orgId });

    await audit({ userId: user.id, actorEmail: user.email, action: 'auth.change_password', ip: clientIp(req) });
    logger.info(`Password changed: ${user.email}`);

    res.cookie(REFRESH_COOKIE, token, cookieOptions());
    res.json({ message: 'Password updated', accessToken });
  } catch (error: any) {
    logger.error('Change password error:', error);
    res.status(500).json({ error: 'Could not change password' });
  }
}

/**
 * GET /api/auth/password-policy
 * Lets the UI show the rules and offer a compliant suggestion.
 */
export async function passwordPolicy(_req: Request, res: Response) {
  res.json({
    minLength: 12,
    requires: ['lowercase letter', 'uppercase letter', 'digit', 'symbol'],
    forbids: ['your username', 'your email address', 'common password phrases'],
    suggestion: generateStrongPassword(),
  });
}

/**
 * GET /api/auth/setup-status
 * Public. Lets the frontend show a first-run setup screen instead of login
 * when the seeded super admin has no password yet.
 */
export async function setupStatus(_req: Request, res: Response) {
  res.json({ required: await isInitialSetupRequired() });
}

/**
 * POST /api/auth/setup
 * Public, but only succeeds once: claims the pending super admin account by
 * giving it a real password, then signs it in. Once setup has completed this
 * always returns 409, so it can never be used to reset the account later —
 * that's what /admin/users/:id/reset-password is for.
 */
export async function completeSetup(req: Request, res: Response) {
  try {
    const { password, confirmPassword } = req.body ?? {};
    if (!password || !confirmPassword) {
      return res.status(400).json({ error: 'Password and confirmation are required' });
    }
    if (String(password) !== String(confirmPassword)) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const result = await completeInitialSetup(String(password));
    if (!result.ok) {
      if (result.reason === 'NOT_REQUIRED') {
        return res.status(409).json({
          error: 'Initial setup has already been completed',
          code: 'SETUP_NOT_REQUIRED',
        });
      }
      return res.status(400).json({ error: 'Password does not meet requirements', requirements: result.errors });
    }

    const { token: refreshToken } = await issueRefreshToken(result.user.id, {
      userAgent: req.headers['user-agent'] as string,
      ip: clientIp(req),
    });
    const accessToken = signAccessToken({
      id: result.user.id,
      role: result.user.role,
      orgId: result.user.orgId,
    });

    await audit({
      userId: result.user.id,
      actorEmail: result.user.email,
      action: 'auth.initial_setup',
      ip: clientIp(req),
    });
    logger.info(`Initial setup completed: ${result.user.email}`);

    res.cookie(REFRESH_COOKIE, refreshToken, cookieOptions());
    res.json({ accessToken, user: result.user });
  } catch (error: any) {
    logger.error('Setup error:', error);
    res.status(500).json({ error: 'Could not complete setup' });
  }
}
