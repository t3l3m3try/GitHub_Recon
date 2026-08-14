import { Request, Response, NextFunction } from 'express';
import prisma from '../config/database';
import { verifyAccessToken } from '../services/auth.service';
import {
  Permission,
  PERMISSIONS,
  ROLES,
  computeEffectivePermissions,
} from '../utils/permissions';
import { logger } from '../utils/logger';

/**
 * Authentication & Authorization Middleware
 *
 * There is no development bypass. Every protected route requires a valid,
 * unexpired access token, and the user record is re-read on each request so
 * that deactivations, role changes and permission revocations take effect
 * immediately instead of when the token expires.
 */

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        username: string;
        role: string;
        orgId: string | null;
        permissions: Permission[];
        isSuperAdmin: boolean;
        mustChangePassword: boolean;
      };
    }
  }
}

function extractToken(req: Request): string | null {
  const header = req.headers['authorization'];
  if (!header || Array.isArray(header)) return null;
  const [scheme, token] = header.split(' ');
  if (!/^Bearer$/i.test(scheme || '') || !token) return null;
  return token;
}

export async function authenticateToken(req: Request, res: Response, next: NextFunction) {
  try {
    const token = extractToken(req);
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const payload = verifyAccessToken(token);
    if (!payload?.sub) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      include: { organization: true },
    });

    if (!user || !user.active) {
      return res.status(401).json({ error: 'Account is no longer active' });
    }

    if (user.organization && !user.organization.active) {
      return res.status(403).json({ error: 'Your organization has been suspended' });
    }

    req.user = {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      orgId: user.orgId,
      permissions: computeEffectivePermissions(user.role, user.permissions, user.organization),
      isSuperAdmin: user.role === ROLES.SUPER_ADMIN,
      mustChangePassword: user.mustChangePassword,
    };

    next();
  } catch (error) {
    logger.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Authentication error' });
  }
}

/**
 * Require one or more permissions. All listed permissions must be held.
 */
export function requirePermission(...required: Permission[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const missing = required.filter(p => !req.user!.permissions.includes(p));
    if (missing.length > 0) {
      logger.warn(`Permission denied for ${req.user.email}: missing ${missing.join(', ')}`);
      return res.status(403).json({
        error: 'You do not have permission to perform this action',
        missing,
      });
    }
    next();
  };
}

export function requireSuperAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (!req.user.isSuperAdmin || !req.user.permissions.includes(PERMISSIONS.ADMIN_ALL)) {
    return res.status(403).json({ error: 'Super administrator access required' });
  }
  next();
}

/**
 * Blocks normal API use while a password change is outstanding, so a user
 * handed a temporary password cannot keep using it indefinitely. The endpoints
 * needed to actually change it are exempt (see routes/index.ts).
 */
export function blockIfPasswordChangeRequired(req: Request, res: Response, next: NextFunction) {
  if (req.user?.mustChangePassword) {
    return res.status(403).json({
      error: 'You must change your password before continuing',
      code: 'PASSWORD_CHANGE_REQUIRED',
    });
  }
  next();
}

// ── Tenant scoping ─────────────────────────────────────────────────────────

/**
 * Prisma `where` fragments that constrain a query to what the requester may see.
 * The super admin is unscoped; everyone else is pinned to their organization.
 * A user with no organization (and who is not a super admin) can see nothing.
 *
 * A super admin may additionally narrow their unscoped view to a single
 * organization by passing `?orgId=`, so cross-org dashboards can drill down
 * without losing the ability to see everything by default. The param is
 * ignored for non-super-admins — they are already pinned to their own org.
 */
export function scopeFor(req: Request) {
  const user = req.user;

  if (user?.isSuperAdmin) {
    const requestedOrgId = typeof req.query.orgId === 'string' && req.query.orgId ? req.query.orgId : null;

    if (requestedOrgId) {
      return {
        domain: { orgId: requestedOrgId } as any,
        scan: { domain: { orgId: requestedOrgId } } as any,
        finding: { scan: { domain: { orgId: requestedOrgId } } } as any,
        orgId: requestedOrgId,
        unscoped: false,
      };
    }

    return {
      domain: {} as any,
      scan: {} as any,
      finding: {} as any,
      orgId: null as string | null,
      unscoped: true,
    };
  }

  const orgId = user?.orgId ?? '__no_org__';

  return {
    domain: { orgId } as any,
    scan: { domain: { orgId } } as any,
    finding: { scan: { domain: { orgId } } } as any,
    orgId: user?.orgId ?? null,
    unscoped: false,
  };
}
