import { Request, Response } from 'express';
import prisma from '../config/database';
import {
  audit,
  generateStrongPassword,
  hashPassword,
  revokeAllSessions,
  validatePasswordStrength,
} from '../services/auth.service';
import {
  ALL_PERMISSIONS,
  ALL_ROLES,
  PERMISSION_GROUPS,
  PERMISSION_LABELS,
  Permission,
  ROLES,
  ROLE_DEFAULT_PERMISSIONS,
  ROLE_DESCRIPTIONS,
  ROLE_LABELS,
  computeEffectivePermissions,
  isValidRole,
  parseOverrides,
  serializeOverrides,
} from '../utils/permissions';
import { logger } from '../utils/logger';

/**
 * Admin Controller
 *
 * Organization and user administration. Super admins operate across every
 * tenant; org admins are confined to their own organization and cannot grant a
 * role above their own or move users between organizations.
 */

function clientIp(req: Request): string | undefined {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket.remoteAddress || undefined;
}

function slugify(name: string): string {
  return name.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
}

/** Never return password hashes or raw override JSON to a client. */
function presentUser(user: any) {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
    roleLabel: ROLE_LABELS[user.role as keyof typeof ROLE_LABELS] ?? user.role,
    orgId: user.orgId,
    organization: user.organization
      ? { id: user.organization.id, name: user.organization.name, slug: user.organization.slug, active: user.organization.active }
      : null,
    active: user.active,
    mustChangePassword: user.mustChangePassword,
    lastLoginAt: user.lastLoginAt,
    lockedUntil: user.lockedUntil,
    createdAt: user.createdAt,
    overrides: parseOverrides(user.permissions),
    effectivePermissions: computeEffectivePermissions(user.role, user.permissions, user.organization ?? null),
  };
}

/** Org admins may only touch their own organization. */
function canAdministerOrg(req: Request, orgId: string | null): boolean {
  if (req.user?.isSuperAdmin) return true;
  return Boolean(orgId) && req.user?.orgId === orgId;
}

// ── Metadata ───────────────────────────────────────────────────────────────

/**
 * GET /api/admin/meta
 * Roles, permissions and their labels, so the UI never hard-codes them.
 */
export async function getMeta(req: Request, res: Response) {
  const assignableRoles = req.user?.isSuperAdmin
    ? ALL_ROLES
    : ALL_ROLES.filter(r => r !== ROLES.SUPER_ADMIN);

  res.json({
    roles: assignableRoles.map(role => ({
      id: role,
      label: ROLE_LABELS[role],
      description: ROLE_DESCRIPTIONS[role],
      defaultPermissions: ROLE_DEFAULT_PERMISSIONS[role],
    })),
    permissions: ALL_PERMISSIONS.map(p => ({ id: p, label: PERMISSION_LABELS[p] })),
    permissionGroups: PERMISSION_GROUPS,
  });
}

// ── Organizations ──────────────────────────────────────────────────────────

/**
 * GET /api/admin/organizations
 */
export async function getOrganizations(req: Request, res: Response) {
  try {
    const where = req.user?.isSuperAdmin ? {} : { id: req.user?.orgId ?? '__none__' };

    const orgs = await prisma.organization.findMany({
      where,
      include: { _count: { select: { users: true, domains: true } } },
      orderBy: { name: 'asc' },
    });

    // Findings roll up through domain → scan, so count them per organization.
    const withCounts = await Promise.all(
      orgs.map(async org => ({
        ...org,
        findingCount: await prisma.finding.count({ where: { scan: { domain: { orgId: org.id } } } }),
      }))
    );

    res.json(withCounts);
  } catch (error: any) {
    logger.error('Error fetching organizations:', error);
    res.status(500).json({ error: 'Failed to fetch organizations' });
  }
}

/**
 * POST /api/admin/organizations   (super admin only)
 */
export async function createOrganization(req: Request, res: Response) {
  try {
    const { name, description, maxDomains, maxUsers, canRunScans, canExport } = req.body ?? {};

    if (!name || String(name).trim().length < 2) {
      return res.status(400).json({ error: 'Organization name is required (minimum 2 characters)' });
    }

    const slug = slugify(String(name));
    if (!slug) return res.status(400).json({ error: 'Organization name must contain letters or digits' });

    const clash = await prisma.organization.findFirst({
      where: { OR: [{ name: String(name).trim() }, { slug }] },
    });
    if (clash) return res.status(409).json({ error: 'An organization with that name already exists' });

    const org = await prisma.organization.create({
      data: {
        name: String(name).trim(),
        slug,
        description: description ? String(description) : null,
        maxDomains: Number.isInteger(maxDomains) ? maxDomains : undefined,
        maxUsers: Number.isInteger(maxUsers) ? maxUsers : undefined,
        canRunScans: typeof canRunScans === 'boolean' ? canRunScans : undefined,
        canExport: typeof canExport === 'boolean' ? canExport : undefined,
      },
    });

    await audit({
      userId: req.user?.id, actorEmail: req.user?.email,
      action: 'org.create', targetType: 'organization', targetId: org.id,
      detail: org.name, ip: clientIp(req),
    });
    logger.info(`Organization created: ${org.name} by ${req.user?.email}`);

    res.status(201).json(org);
  } catch (error: any) {
    logger.error('Error creating organization:', error);
    res.status(500).json({ error: 'Failed to create organization' });
  }
}

/**
 * PUT /api/admin/organizations/:id
 */
export async function updateOrganization(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const org = await prisma.organization.findUnique({ where: { id } });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    if (!canAdministerOrg(req, id)) {
      return res.status(403).json({ error: 'You can only manage your own organization' });
    }

    const { name, description, active, maxDomains, maxUsers, canRunScans, canExport } = req.body ?? {};

    // Quotas and feature toggles are the super admin's ceiling — an org admin
    // must not be able to lift the limits imposed on their own organization.
    const data: any = {};
    if (name !== undefined && String(name).trim().length >= 2) {
      data.name = String(name).trim();
      data.slug = slugify(String(name));
    }
    if (description !== undefined) data.description = description ? String(description) : null;

    if (req.user?.isSuperAdmin) {
      if (typeof active === 'boolean') data.active = active;
      if (Number.isInteger(maxDomains) && maxDomains >= 0) data.maxDomains = maxDomains;
      if (Number.isInteger(maxUsers) && maxUsers >= 1) data.maxUsers = maxUsers;
      if (typeof canRunScans === 'boolean') data.canRunScans = canRunScans;
      if (typeof canExport === 'boolean') data.canExport = canExport;
    }

    if (data.name && data.name !== org.name) {
      const clash = await prisma.organization.findFirst({
        where: { id: { not: id }, OR: [{ name: data.name }, { slug: data.slug }] },
      });
      if (clash) return res.status(409).json({ error: 'An organization with that name already exists' });
    }

    const updated = await prisma.organization.update({ where: { id }, data });

    // Suspending an organization must take immediate effect everywhere.
    if (data.active === false) {
      const members = await prisma.user.findMany({ where: { orgId: id }, select: { id: true } });
      for (const member of members) await revokeAllSessions(member.id);
      logger.warn(`Organization suspended: ${updated.name} — ${members.length} session set(s) revoked`);
    }

    await audit({
      userId: req.user?.id, actorEmail: req.user?.email,
      action: 'org.update', targetType: 'organization', targetId: id,
      detail: JSON.stringify(data), ip: clientIp(req),
    });

    res.json(updated);
  } catch (error: any) {
    logger.error('Error updating organization:', error);
    res.status(500).json({ error: 'Failed to update organization' });
  }
}

/**
 * DELETE /api/admin/organizations/:id   (super admin only)
 * Refuses while members remain, so users are never orphaned by accident.
 */
export async function deleteOrganization(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const org = await prisma.organization.findUnique({
      where: { id },
      include: { _count: { select: { users: true, domains: true } } },
    });
    if (!org) return res.status(404).json({ error: 'Organization not found' });

    if (org._count.users > 0) {
      return res.status(409).json({
        error: `Cannot delete: ${org._count.users} user(s) still belong to this organization. Reassign or delete them first.`,
      });
    }

    await prisma.organization.delete({ where: { id } });

    await audit({
      userId: req.user?.id, actorEmail: req.user?.email,
      action: 'org.delete', targetType: 'organization', targetId: id,
      detail: `${org.name} (${org._count.domains} domain(s) removed)`, ip: clientIp(req),
    });
    logger.warn(`Organization deleted: ${org.name} by ${req.user?.email}`);

    res.json({ message: 'Organization deleted' });
  } catch (error: any) {
    logger.error('Error deleting organization:', error);
    res.status(500).json({ error: 'Failed to delete organization' });
  }
}

// ── Users ──────────────────────────────────────────────────────────────────

/**
 * GET /api/admin/users
 */
export async function getUsers(req: Request, res: Response) {
  try {
    const { orgId } = req.query;

    const where: any = req.user?.isSuperAdmin ? {} : { orgId: req.user?.orgId ?? '__none__' };
    if (req.user?.isSuperAdmin && typeof orgId === 'string' && orgId) {
      where.orgId = orgId === 'none' ? null : orgId;
    }

    const users = await prisma.user.findMany({
      where,
      include: { organization: true },
      orderBy: [{ role: 'asc' }, { username: 'asc' }],
    });

    res.json(users.map(presentUser));
  } catch (error: any) {
    logger.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
}

/**
 * POST /api/admin/users
 * The generated password is returned exactly once, in this response only.
 */
export async function createUser(req: Request, res: Response) {
  try {
    const { email, username, role, orgId, password, granted, revoked, active } = req.body ?? {};

    if (!email || !username) {
      return res.status(400).json({ error: 'Email and username are required' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const cleanUsername = String(username).trim().toLowerCase();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    if (!/^[a-z0-9._-]{3,32}$/.test(cleanUsername)) {
      return res.status(400).json({ error: 'Username must be 3-32 characters: letters, digits, dot, underscore or hyphen' });
    }

    const requestedRole = role && isValidRole(role) ? role : ROLES.ANALYST;

    // Only a super admin may mint another super admin, or place users in an
    // organization other than their own.
    if (requestedRole === ROLES.SUPER_ADMIN && !req.user?.isSuperAdmin) {
      return res.status(403).json({ error: 'Only a super administrator can create another super administrator' });
    }

    let targetOrgId: string | null = req.user?.isSuperAdmin ? (orgId ? String(orgId) : null) : req.user?.orgId ?? null;

    if (requestedRole === ROLES.SUPER_ADMIN) {
      targetOrgId = null; // super admins are not tenant-scoped
    } else if (!targetOrgId) {
      return res.status(400).json({ error: 'An organization is required for non-super-admin users' });
    }

    if (targetOrgId) {
      const org = await prisma.organization.findUnique({
        where: { id: targetOrgId },
        include: { _count: { select: { users: true } } },
      });
      if (!org) return res.status(404).json({ error: 'Organization not found' });
      if (!canAdministerOrg(req, targetOrgId)) {
        return res.status(403).json({ error: 'You can only add users to your own organization' });
      }
      if (org._count.users >= org.maxUsers) {
        return res.status(409).json({ error: `Organization "${org.name}" has reached its limit of ${org.maxUsers} users` });
      }
    }

    const clash = await prisma.user.findFirst({
      where: { OR: [{ email: cleanEmail }, { username: cleanUsername }] },
    });
    if (clash) {
      return res.status(409).json({
        error: clash.email === cleanEmail ? 'That email address is already registered' : 'That username is already taken',
      });
    }

    // Either an explicit password (policy-checked) or a generated one.
    let plainPassword: string;
    let generated = false;
    if (password) {
      const check = validatePasswordStrength(String(password), cleanUsername, cleanEmail);
      if (!check.valid) {
        return res.status(400).json({ error: 'Password does not meet requirements', requirements: check.errors });
      }
      plainPassword = String(password);
    } else {
      plainPassword = generateStrongPassword();
      generated = true;
    }

    const overrides = serializeOverrides({
      granted: Array.isArray(granted) ? granted.filter((p: any) => ALL_PERMISSIONS.includes(p)) : [],
      revoked: Array.isArray(revoked) ? revoked.filter((p: any) => ALL_PERMISSIONS.includes(p)) : [],
    });

    const user = await prisma.user.create({
      data: {
        email: cleanEmail,
        username: cleanUsername,
        passwordHash: await hashPassword(plainPassword),
        role: requestedRole,
        orgId: targetOrgId,
        permissions: overrides,
        active: typeof active === 'boolean' ? active : true,
        mustChangePassword: true, // always: the creator knows this password
      },
      include: { organization: true },
    });

    await audit({
      userId: req.user?.id, actorEmail: req.user?.email,
      action: 'user.create', targetType: 'user', targetId: user.id,
      detail: `${user.email} as ${user.role}${targetOrgId ? ` in ${user.organization?.name}` : ''}`,
      ip: clientIp(req),
    });
    logger.info(`User created: ${user.email} (${user.role}) by ${req.user?.email}`);

    // temporaryPassword is surfaced once and never stored in plaintext.
    res.status(201).json({ user: presentUser(user), temporaryPassword: plainPassword, generated });
  } catch (error: any) {
    logger.error('Error creating user:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
}

/**
 * PUT /api/admin/users/:id
 * Handles role changes, organization assignment, permission overrides and
 * activation. Sessions are revoked whenever the change affects access.
 */
export async function updateUser(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const target = await prisma.user.findUnique({ where: { id }, include: { organization: true } });
    if (!target) return res.status(404).json({ error: 'User not found' });

    if (!req.user?.isSuperAdmin) {
      if (target.orgId !== req.user?.orgId) {
        return res.status(403).json({ error: 'You can only manage users in your own organization' });
      }
      if (target.role === ROLES.SUPER_ADMIN) {
        return res.status(403).json({ error: 'You cannot modify a super administrator' });
      }
    }

    const { email, username, role, orgId, active, granted, revoked } = req.body ?? {};
    const data: any = {};
    let accessChanged = false;

    if (email !== undefined) {
      const cleanEmail = String(email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
        return res.status(400).json({ error: 'Invalid email address' });
      }
      if (cleanEmail !== target.email) {
        const clash = await prisma.user.findFirst({ where: { email: cleanEmail, id: { not: id } } });
        if (clash) return res.status(409).json({ error: 'That email address is already registered' });
        data.email = cleanEmail;
      }
    }

    if (username !== undefined) {
      const cleanUsername = String(username).trim().toLowerCase();
      if (!/^[a-z0-9._-]{3,32}$/.test(cleanUsername)) {
        return res.status(400).json({ error: 'Username must be 3-32 characters: letters, digits, dot, underscore or hyphen' });
      }
      if (cleanUsername !== target.username) {
        const clash = await prisma.user.findFirst({ where: { username: cleanUsername, id: { not: id } } });
        if (clash) return res.status(409).json({ error: 'That username is already taken' });
        data.username = cleanUsername;
      }
    }

    if (role !== undefined) {
      if (!isValidRole(role)) return res.status(400).json({ error: 'Unknown role' });
      if (role === ROLES.SUPER_ADMIN && !req.user?.isSuperAdmin) {
        return res.status(403).json({ error: 'Only a super administrator can grant that role' });
      }
      if (target.role === ROLES.SUPER_ADMIN && role !== ROLES.SUPER_ADMIN) {
        const remaining = await prisma.user.count({
          where: { role: ROLES.SUPER_ADMIN, active: true, id: { not: id } },
        });
        if (remaining === 0) {
          return res.status(409).json({ error: 'Cannot demote the last active super administrator' });
        }
      }
      if (role !== target.role) {
        data.role = role;
        accessChanged = true;
        if (role === ROLES.SUPER_ADMIN) data.orgId = null;
      }
    }

    // Modular assignment: move a user between organizations.
    if (orgId !== undefined && req.user?.isSuperAdmin) {
      const nextOrgId = orgId ? String(orgId) : null;
      const effectiveRole = data.role ?? target.role;

      if (effectiveRole !== ROLES.SUPER_ADMIN) {
        if (!nextOrgId) return res.status(400).json({ error: 'An organization is required for non-super-admin users' });
        const org = await prisma.organization.findUnique({
          where: { id: nextOrgId },
          include: { _count: { select: { users: true } } },
        });
        if (!org) return res.status(404).json({ error: 'Organization not found' });
        if (nextOrgId !== target.orgId && org._count.users >= org.maxUsers) {
          return res.status(409).json({ error: `Organization "${org.name}" has reached its limit of ${org.maxUsers} users` });
        }
        if (nextOrgId !== target.orgId) {
          data.orgId = nextOrgId;
          accessChanged = true;
        }
      }
    }

    if (active !== undefined && typeof active === 'boolean' && active !== target.active) {
      if (!active && target.role === ROLES.SUPER_ADMIN) {
        const remaining = await prisma.user.count({
          where: { role: ROLES.SUPER_ADMIN, active: true, id: { not: id } },
        });
        if (remaining === 0) {
          return res.status(409).json({ error: 'Cannot deactivate the last active super administrator' });
        }
      }
      data.active = active;
      accessChanged = true;
    }

    if (granted !== undefined || revoked !== undefined) {
      const current = parseOverrides(target.permissions);
      const clean = (list: any, fallback: Permission[]): Permission[] =>
        Array.isArray(list) ? list.filter((p: any) => ALL_PERMISSIONS.includes(p)) : fallback;
      data.permissions = serializeOverrides({
        granted: clean(granted, current.granted),
        revoked: clean(revoked, current.revoked),
      });
      accessChanged = true;
    }

    if (Object.keys(data).length === 0) {
      return res.json(presentUser(target));
    }

    const updated = await prisma.user.update({
      where: { id },
      data,
      include: { organization: true },
    });

    // Anything that changes what this user may do invalidates their sessions,
    // so the new rules apply on their next request rather than in 15 minutes.
    if (accessChanged) await revokeAllSessions(id);

    await audit({
      userId: req.user?.id, actorEmail: req.user?.email,
      action: 'user.update', targetType: 'user', targetId: id,
      detail: JSON.stringify(Object.keys(data)), ip: clientIp(req),
    });
    logger.info(`User updated: ${updated.email} by ${req.user?.email} (${Object.keys(data).join(', ')})`);

    res.json(presentUser(updated));
  } catch (error: any) {
    logger.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
}

/**
 * POST /api/admin/users/:id/reset-password
 */
export async function resetUserPassword(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) return res.status(404).json({ error: 'User not found' });

    if (!req.user?.isSuperAdmin) {
      if (target.orgId !== req.user?.orgId) {
        return res.status(403).json({ error: 'You can only manage users in your own organization' });
      }
      if (target.role === ROLES.SUPER_ADMIN) {
        return res.status(403).json({ error: 'You cannot reset a super administrator’s password' });
      }
    }

    const { password } = req.body ?? {};
    let plainPassword: string;
    if (password) {
      const check = validatePasswordStrength(String(password), target.username, target.email);
      if (!check.valid) {
        return res.status(400).json({ error: 'Password does not meet requirements', requirements: check.errors });
      }
      plainPassword = String(password);
    } else {
      plainPassword = generateStrongPassword();
    }

    await prisma.user.update({
      where: { id },
      data: {
        passwordHash: await hashPassword(plainPassword),
        mustChangePassword: true,
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });

    await revokeAllSessions(id);

    await audit({
      userId: req.user?.id, actorEmail: req.user?.email,
      action: 'user.reset_password', targetType: 'user', targetId: id,
      detail: target.email, ip: clientIp(req),
    });
    logger.warn(`Password reset for ${target.email} by ${req.user?.email}`);

    res.json({ message: 'Password reset', temporaryPassword: plainPassword });
  } catch (error: any) {
    logger.error('Error resetting password:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
}

/**
 * POST /api/admin/users/:id/unlock
 */
export async function unlockUser(req: Request, res: Response) {
  try {
    const { id } = req.params;
    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) return res.status(404).json({ error: 'User not found' });

    if (!req.user?.isSuperAdmin && target.orgId !== req.user?.orgId) {
      return res.status(403).json({ error: 'You can only manage users in your own organization' });
    }

    await prisma.user.update({
      where: { id },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });

    await audit({
      userId: req.user?.id, actorEmail: req.user?.email,
      action: 'user.unlock', targetType: 'user', targetId: id, detail: target.email, ip: clientIp(req),
    });

    res.json({ message: 'Account unlocked' });
  } catch (error: any) {
    logger.error('Error unlocking user:', error);
    res.status(500).json({ error: 'Failed to unlock account' });
  }
}

/**
 * DELETE /api/admin/users/:id
 */
export async function deleteUser(req: Request, res: Response) {
  try {
    const { id } = req.params;

    if (id === req.user?.id) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }

    const target = await prisma.user.findUnique({
      where: { id },
      include: { _count: { select: { domains: true, scans: true } } },
    });
    if (!target) return res.status(404).json({ error: 'User not found' });

    if (!req.user?.isSuperAdmin) {
      if (target.orgId !== req.user?.orgId) {
        return res.status(403).json({ error: 'You can only manage users in your own organization' });
      }
      if (target.role === ROLES.SUPER_ADMIN) {
        return res.status(403).json({ error: 'You cannot delete a super administrator' });
      }
    }

    if (target.role === ROLES.SUPER_ADMIN) {
      const remaining = await prisma.user.count({ where: { role: ROLES.SUPER_ADMIN, id: { not: id } } });
      if (remaining === 0) {
        return res.status(409).json({ error: 'Cannot delete the last super administrator' });
      }
    }

    // Domains cascade from their creator, which would destroy organization data
    // belonging to everyone else. Hand them to the requester instead.
    if (target._count.domains > 0 || target._count.scans > 0) {
      await prisma.domain.updateMany({ where: { userId: id }, data: { userId: req.user!.id } });
      await prisma.scan.updateMany({ where: { userId: id }, data: { userId: req.user!.id } });
      logger.info(`Reassigned ${target._count.domains} domain(s) and ${target._count.scans} scan(s) from ${target.email} to ${req.user?.email}`);
    }

    await prisma.user.delete({ where: { id } });

    await audit({
      userId: req.user?.id, actorEmail: req.user?.email,
      action: 'user.delete', targetType: 'user', targetId: id, detail: target.email, ip: clientIp(req),
    });
    logger.warn(`User deleted: ${target.email} by ${req.user?.email}`);

    res.json({
      message: 'User deleted',
      reassigned: { domains: target._count.domains, scans: target._count.scans },
    });
  } catch (error: any) {
    logger.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
}

/**
 * GET /api/admin/audit   (super admin only)
 */
export async function getAuditLog(req: Request, res: Response) {
  try {
    const { limit = 100 } = req.query;
    const entries = await prisma.auditLog.findMany({
      orderBy: { createdAt: 'desc' },
      take: Math.min(Number(limit) || 100, 500),
    });
    res.json(entries);
  } catch (error: any) {
    logger.error('Error fetching audit log:', error);
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
}
