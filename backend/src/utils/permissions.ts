/**
 * Roles & Permissions
 *
 * Effective permissions are computed as:
 *
 *   roleDefaults(role)  ∪ overrides.granted  \  overrides.revoked   → then ANDed
 *   with what the user's organization allows (quotas/feature toggles).
 *
 * The organization acts as a ceiling: a user can never do something their
 * organization has switched off, no matter what is granted individually.
 */

export const ROLES = {
  SUPER_ADMIN: 'SUPER_ADMIN',
  ORG_ADMIN: 'ORG_ADMIN',
  ANALYST: 'ANALYST',
  VIEWER: 'VIEWER',
} as const;

export type Role = (typeof ROLES)[keyof typeof ROLES];

export const ALL_ROLES: Role[] = [ROLES.SUPER_ADMIN, ROLES.ORG_ADMIN, ROLES.ANALYST, ROLES.VIEWER];

export const ROLE_LABELS: Record<Role, string> = {
  SUPER_ADMIN: 'Super Admin',
  ORG_ADMIN: 'Organization Admin',
  ANALYST: 'Analyst',
  VIEWER: 'Viewer',
};

export const ROLE_DESCRIPTIONS: Record<Role, string> = {
  SUPER_ADMIN: 'Full control over every organization, user and permission.',
  ORG_ADMIN: 'Manages their own organization: its users, domains, scans and findings.',
  ANALYST: 'Adds domains, runs scans and triages findings within their organization.',
  VIEWER: 'Read-only access to their organization’s domains, scans and findings.',
};

export const PERMISSIONS = {
  DOMAIN_READ: 'domain:read',
  DOMAIN_WRITE: 'domain:write',
  DOMAIN_DELETE: 'domain:delete',

  SCAN_RUN: 'scan:run',
  SCAN_CANCEL: 'scan:cancel',

  FINDING_READ: 'finding:read',
  FINDING_UPDATE: 'finding:update',
  FINDING_DELETE: 'finding:delete',
  FINDING_EXPORT: 'finding:export',

  QUERY_READ: 'query:read',
  QUERY_WRITE: 'query:write',

  /// Manage users inside one's own organization
  USER_MANAGE: 'user:manage',
  /// Edit one's own organization's settings
  ORG_MANAGE: 'org:manage',
  /// Cross-tenant control: create organizations, manage any user anywhere
  ADMIN_ALL: 'admin:all',
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export const ALL_PERMISSIONS: Permission[] = Object.values(PERMISSIONS);

export const PERMISSION_LABELS: Record<Permission, string> = {
  'domain:read': 'View domains',
  'domain:write': 'Add & edit domains',
  'domain:delete': 'Delete domains',
  'scan:run': 'Start scans',
  'scan:cancel': 'Stop scans',
  'finding:read': 'View findings',
  'finding:update': 'Triage findings (verify, false-positive, notes)',
  'finding:delete': 'Delete findings',
  'finding:export': 'Export findings',
  'query:read': 'View the query catalog',
  'query:write': 'Change which queries run',
  'user:manage': 'Manage users in own organization',
  'org:manage': 'Edit own organization settings',
  'admin:all': 'Full cross-organization administration',
};

/** Permissions grouped for display in the admin UI. */
export const PERMISSION_GROUPS: { name: string; permissions: Permission[] }[] = [
  { name: 'Domains', permissions: [PERMISSIONS.DOMAIN_READ, PERMISSIONS.DOMAIN_WRITE, PERMISSIONS.DOMAIN_DELETE] },
  { name: 'Scans', permissions: [PERMISSIONS.SCAN_RUN, PERMISSIONS.SCAN_CANCEL] },
  { name: 'Findings', permissions: [PERMISSIONS.FINDING_READ, PERMISSIONS.FINDING_UPDATE, PERMISSIONS.FINDING_DELETE, PERMISSIONS.FINDING_EXPORT] },
  { name: 'Queries', permissions: [PERMISSIONS.QUERY_READ, PERMISSIONS.QUERY_WRITE] },
  { name: 'Administration', permissions: [PERMISSIONS.USER_MANAGE, PERMISSIONS.ORG_MANAGE, PERMISSIONS.ADMIN_ALL] },
];

const ORG_ADMIN_PERMISSIONS: Permission[] = [
  PERMISSIONS.DOMAIN_READ, PERMISSIONS.DOMAIN_WRITE, PERMISSIONS.DOMAIN_DELETE,
  PERMISSIONS.SCAN_RUN, PERMISSIONS.SCAN_CANCEL,
  PERMISSIONS.FINDING_READ, PERMISSIONS.FINDING_UPDATE, PERMISSIONS.FINDING_DELETE, PERMISSIONS.FINDING_EXPORT,
  PERMISSIONS.QUERY_READ, PERMISSIONS.QUERY_WRITE,
  PERMISSIONS.USER_MANAGE, PERMISSIONS.ORG_MANAGE,
];

const ANALYST_PERMISSIONS: Permission[] = [
  PERMISSIONS.DOMAIN_READ, PERMISSIONS.DOMAIN_WRITE, PERMISSIONS.DOMAIN_DELETE,
  PERMISSIONS.SCAN_RUN, PERMISSIONS.SCAN_CANCEL,
  PERMISSIONS.FINDING_READ, PERMISSIONS.FINDING_UPDATE, PERMISSIONS.FINDING_EXPORT,
  PERMISSIONS.QUERY_READ, PERMISSIONS.QUERY_WRITE,
];

const VIEWER_PERMISSIONS: Permission[] = [
  PERMISSIONS.DOMAIN_READ,
  PERMISSIONS.FINDING_READ,
  PERMISSIONS.QUERY_READ,
];

export const ROLE_DEFAULT_PERMISSIONS: Record<Role, Permission[]> = {
  SUPER_ADMIN: [...ALL_PERMISSIONS],
  ORG_ADMIN: ORG_ADMIN_PERMISSIONS,
  ANALYST: ANALYST_PERMISSIONS,
  VIEWER: VIEWER_PERMISSIONS,
};

export interface PermissionOverrides {
  granted: Permission[];
  revoked: Permission[];
}

export function parseOverrides(raw: string | null | undefined): PermissionOverrides {
  if (!raw) return { granted: [], revoked: [] };
  try {
    const parsed = JSON.parse(raw);
    const clean = (list: any): Permission[] =>
      Array.isArray(list) ? list.filter((p: any) => ALL_PERMISSIONS.includes(p)) : [];
    return { granted: clean(parsed.granted), revoked: clean(parsed.revoked) };
  } catch {
    return { granted: [], revoked: [] };
  }
}

export function serializeOverrides(overrides: PermissionOverrides): string | null {
  if (overrides.granted.length === 0 && overrides.revoked.length === 0) return null;
  return JSON.stringify(overrides);
}

export function isValidRole(role: any): role is Role {
  return ALL_ROLES.includes(role);
}

export interface OrgCapabilities {
  active: boolean;
  canRunScans: boolean;
  canExport: boolean;
}

/**
 * Resolve a user's effective permission set.
 *
 * The SUPER_ADMIN is deliberately exempt from organization gating — they belong
 * to no tenant and must remain able to administer a suspended organization.
 */
export function computeEffectivePermissions(
  role: string,
  overridesRaw: string | null | undefined,
  org: OrgCapabilities | null
): Permission[] {
  const safeRole: Role = isValidRole(role) ? role : ROLES.VIEWER;
  const overrides = parseOverrides(overridesRaw);

  const set = new Set<Permission>(ROLE_DEFAULT_PERMISSIONS[safeRole]);
  for (const p of overrides.granted) set.add(p);
  for (const p of overrides.revoked) set.delete(p);

  if (safeRole === ROLES.SUPER_ADMIN) return Array.from(set);

  // Only the super admin may ever hold cross-tenant administration.
  set.delete(PERMISSIONS.ADMIN_ALL);

  // Organization ceiling
  if (org) {
    if (!org.active) return [];
    if (!org.canRunScans) {
      set.delete(PERMISSIONS.SCAN_RUN);
      set.delete(PERMISSIONS.SCAN_CANCEL);
    }
    if (!org.canExport) {
      set.delete(PERMISSIONS.FINDING_EXPORT);
    }
  }

  return Array.from(set);
}
