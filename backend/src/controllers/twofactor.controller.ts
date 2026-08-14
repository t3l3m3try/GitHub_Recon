import { Request, Response } from 'express';
import prisma from '../config/database';
import {
  audit,
  buildOtpAuthUrl,
  encryptSecret,
  generateQrCodeDataUrl,
  generateRecoveryCodes,
  generateTwoFactorSecret,
  hashRecoveryCode,
  verifyAndConsumeTwoFactorCode,
  verifyPassword,
} from '../services/auth.service';
import { logger } from '../utils/logger';

/**
 * Two-Factor Authentication (self-service)
 *
 * Everything here acts on the caller's own account — an authenticated user
 * managing their own TOTP enrollment. Admin-driven management of *other*
 * users' 2FA (require / disable / reset) lives in admin.controller.ts.
 */

function clientIp(req: Request): string | undefined {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || undefined;
}

async function saveRecoveryCodes(userId: string, codes: string[]): Promise<void> {
  await prisma.twoFactorRecoveryCode.deleteMany({ where: { userId } });
  await prisma.twoFactorRecoveryCode.createMany({
    data: await Promise.all(codes.map(async code => ({ userId, codeHash: await hashRecoveryCode(code) }))),
  });
}

/**
 * GET /api/auth/2fa/status
 */
export async function status(req: Request, res: Response) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });

  const user = await prisma.user.findUnique({ where: { id: req.user.id } });
  if (!user) return res.status(401).json({ error: 'Account not found' });

  const unusedRecoveryCodes = user.twoFactorEnabled
    ? await prisma.twoFactorRecoveryCode.count({ where: { userId: user.id, usedAt: null } })
    : 0;

  res.json({
    enabled: user.twoFactorEnabled,
    required: user.twoFactorRequired,
    enabledAt: user.twoFactorEnabledAt,
    unusedRecoveryCodes,
  });
}

/**
 * POST /api/auth/2fa/setup
 * Starts (or restarts) enrollment: generates a new secret and stores it
 * unconfirmed. Nothing here takes effect for login until /enable succeeds.
 */
export async function setup(req: Request, res: Response) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(401).json({ error: 'Account not found' });

    if (user.twoFactorEnabled) {
      return res.status(409).json({
        error: 'Two-factor authentication is already enabled — disable it first to re-enroll',
        code: 'ALREADY_ENABLED',
      });
    }

    const secret = generateTwoFactorSecret();
    await prisma.user.update({
      where: { id: user.id },
      data: { twoFactorSecret: encryptSecret(secret) },
    });

    const otpauthUrl = buildOtpAuthUrl(secret, user.email);
    const qrCodeDataUrl = await generateQrCodeDataUrl(otpauthUrl);

    res.json({ secret, otpauthUrl, qrCodeDataUrl });
  } catch (error: any) {
    logger.error('2FA setup error:', error);
    res.status(500).json({ error: 'Could not start two-factor setup' });
  }
}

/**
 * POST /api/auth/2fa/enable
 * Confirms enrollment by checking one code against the secret /setup stored,
 * then issues recovery codes — shown exactly once.
 */
export async function enable(req: Request, res: Response) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    const { code } = req.body ?? {};
    if (!code) return res.status(400).json({ error: 'A code from your authenticator app is required' });

    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(401).json({ error: 'Account not found' });

    if (user.twoFactorEnabled) {
      return res.status(409).json({ error: 'Two-factor authentication is already enabled', code: 'ALREADY_ENABLED' });
    }
    if (!user.twoFactorSecret) {
      return res.status(409).json({ error: 'Start setup first', code: 'SETUP_NOT_STARTED' });
    }

    if (!(await verifyAndConsumeTwoFactorCode(user.id, user.twoFactorSecret, String(code)))) {
      return res.status(401).json({ error: 'Incorrect code — check your authenticator app and try again' });
    }

    const recoveryCodes = generateRecoveryCodes();
    await saveRecoveryCodes(user.id, recoveryCodes);

    await prisma.user.update({
      where: { id: user.id },
      data: { twoFactorEnabled: true, twoFactorEnabledAt: new Date() },
    });

    await audit({ userId: user.id, actorEmail: user.email, action: 'auth.2fa_enable', ip: clientIp(req) });
    logger.info(`2FA enabled: ${user.email}`);

    res.json({ message: 'Two-factor authentication enabled', recoveryCodes });
  } catch (error: any) {
    logger.error('2FA enable error:', error);
    res.status(500).json({ error: 'Could not enable two-factor authentication' });
  }
}

/**
 * POST /api/auth/2fa/disable
 * Requires both the current password and a valid code (TOTP or recovery),
 * so a hijacked session alone cannot strip this protection.
 */
export async function disable(req: Request, res: Response) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    const { password, code } = req.body ?? {};
    if (!password || !code) {
      return res.status(400).json({ error: 'Your password and a current code are required' });
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(401).json({ error: 'Account not found' });

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(409).json({ error: 'Two-factor authentication is not enabled', code: 'NOT_ENABLED' });
    }

    const passwordOk = await verifyPassword(String(password), user.passwordHash);
    if (!passwordOk) return res.status(401).json({ error: 'Incorrect password' });

    if (!(await verifyAndConsumeTwoFactorCode(user.id, user.twoFactorSecret, String(code)))) {
      return res.status(401).json({ error: 'Incorrect code' });
    }

    await prisma.$transaction([
      prisma.twoFactorRecoveryCode.deleteMany({ where: { userId: user.id } }),
      prisma.user.update({
        where: { id: user.id },
        data: { twoFactorEnabled: false, twoFactorEnabledAt: null, twoFactorSecret: null, twoFactorRequired: false },
      }),
    ]);

    await audit({ userId: user.id, actorEmail: user.email, action: 'auth.2fa_disable', ip: clientIp(req) });
    logger.warn(`2FA disabled: ${user.email}`);

    res.json({ message: 'Two-factor authentication disabled' });
  } catch (error: any) {
    logger.error('2FA disable error:', error);
    res.status(500).json({ error: 'Could not disable two-factor authentication' });
  }
}

/**
 * POST /api/auth/2fa/recovery-codes/regenerate
 * Invalidates every existing recovery code and issues a fresh set.
 */
export async function regenerateRecoveryCodes(req: Request, res: Response) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });

    const { password, code } = req.body ?? {};
    if (!password || !code) {
      return res.status(400).json({ error: 'Your password and a current code are required' });
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(401).json({ error: 'Account not found' });

    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(409).json({ error: 'Two-factor authentication is not enabled', code: 'NOT_ENABLED' });
    }

    const passwordOk = await verifyPassword(String(password), user.passwordHash);
    if (!passwordOk) return res.status(401).json({ error: 'Incorrect password' });

    if (!(await verifyAndConsumeTwoFactorCode(user.id, user.twoFactorSecret, String(code)))) {
      return res.status(401).json({ error: 'Incorrect code' });
    }

    const recoveryCodes = generateRecoveryCodes();
    await saveRecoveryCodes(user.id, recoveryCodes);

    await audit({ userId: user.id, actorEmail: user.email, action: 'auth.2fa_recovery_regenerate', ip: clientIp(req) });
    logger.info(`2FA recovery codes regenerated: ${user.email}`);

    res.json({ recoveryCodes });
  } catch (error: any) {
    logger.error('2FA recovery code regeneration error:', error);
    res.status(500).json({ error: 'Could not regenerate recovery codes' });
  }
}
