import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  headers: {
    'Content-Type': 'application/json',
  },
  // Required so the httpOnly refresh cookie travels with /auth requests
  withCredentials: true,
});

/**
 * The access token is held in memory only — never in localStorage — so that a
 * script injection cannot read it. The long-lived refresh token lives in an
 * httpOnly cookie the page cannot touch, and is exchanged for a new access
 * token on boot and whenever one expires.
 */
let accessToken: string | null = null;
let onAuthLost: (() => void) | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAuthLostHandler(handler: (() => void) | null) {
  onAuthLost = handler;
}

api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

/** Single-flight refresh so concurrent 401s do not each rotate the token. */
let refreshInFlight: Promise<string | null> | null = null;

async function refreshAccessToken(): Promise<string | null> {
  if (!refreshInFlight) {
    refreshInFlight = axios
      .post<{ accessToken: string }>(`${API_BASE_URL}/api/auth/refresh`, {}, { withCredentials: true })
      .then((res) => {
        accessToken = res.data.accessToken;
        return accessToken;
      })
      .catch(() => {
        accessToken = null;
        return null;
      })
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

export { refreshAccessToken };

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    const status = error.response?.status;
    const isAuthCall = original?.url?.includes('/auth/');

    if (status === 401 && original && !original._retried && !isAuthCall) {
      original._retried = true;
      const token = await refreshAccessToken();
      if (token) {
        original.headers = original.headers ?? {};
        original.headers.Authorization = `Bearer ${token}`;
        return api(original);
      }
      onAuthLost?.();
    }

    return Promise.reject(error);
  }
);

// Types
export type Role = 'SUPER_ADMIN' | 'ORG_ADMIN' | 'ANALYST' | 'VIEWER';

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  active?: boolean;
  canRunScans?: boolean;
  canExport?: boolean;
  maxDomains?: number;
}

export interface AuthUser {
  id: string;
  email: string;
  username: string;
  role: Role;
  orgId: string | null;
  organization: OrganizationSummary | null;
  permissions: string[];
  mustChangePassword: boolean;
  lastLoginAt?: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  description?: string | null;
  active: boolean;
  maxDomains: number;
  maxUsers: number;
  canRunScans: boolean;
  canExport: boolean;
  createdAt: string;
  findingCount?: number;
  _count?: { users: number; domains: number };
}

export interface ManagedUser {
  id: string;
  email: string;
  username: string;
  role: Role;
  roleLabel: string;
  orgId: string | null;
  organization: OrganizationSummary | null;
  active: boolean;
  mustChangePassword: boolean;
  lastLoginAt?: string | null;
  lockedUntil?: string | null;
  createdAt: string;
  overrides: { granted: string[]; revoked: string[] };
  effectivePermissions: string[];
}

export interface AdminMeta {
  roles: { id: Role; label: string; description: string; defaultPermissions: string[] }[];
  permissions: { id: string; label: string }[];
  permissionGroups: { name: string; permissions: string[] }[];
}

export interface AuditEntry {
  id: string;
  userId?: string | null;
  actorEmail?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  detail?: string | null;
  ip?: string | null;
  success: boolean;
  createdAt: string;
}

export interface Domain {
  id: string;
  name: string;
  active: boolean;
  scanFrequency: string;
  lastScanAt?: string;
  createdAt: string;
  orgId?: string | null;
  organization?: OrganizationSummary | null;
  user?: { id: string; username: string } | null;
  _count?: {
    scans: number;
  };
}

export interface Scan {
  id: string;
  domainId: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  startedAt?: string;
  completedAt?: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  errorMessage?: string;
  createdAt: string;
  domain?: Domain;
  isActivelyRunning?: boolean;
  progress?: {
    percent: number;
    phase: string;
    step: number;
    totalSteps: number;
    message: string;
    findings: number;
  } | null;
}

export interface Secret {
  id: string;
  findingId: string;
  type: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  content: string;
  contentPreview: string;
  context: string;
  lineNumber?: number;
  gistId?: string;
  issueNumber?: number;
  createdAt: string;
}

export interface Finding {
  id: string;
  scanId: string;
  primaryType: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  filePath: string;
  repository: string;
  repositoryUrl: string;
  commitSha?: string;
  commitUrl?: string;
  fileUrl?: string;
  commitDate?: string;
  verified: boolean;
  falsePositive: boolean;
  acknowledged: boolean;
  score: number;
  createdAt: string;
  scan?: Scan;
  secrets: Secret[];
}

export interface CatalogQuery {
  id: string;
  label: string;
  /** Raw template with {domain} placeholders */
  template: string;
  /** Template rendered against the preview domain (falls back to the template) */
  preview: string;
  enabled: boolean;
}

export interface CatalogArea {
  id: string;
  name: string;
  description: string;
  total: number;
  enabledCount: number;
  queries: CatalogQuery[];
}

export interface CatalogTarget {
  id: 'code' | 'commits' | 'issues';
  name: string;
  description: string;
  total: number;
  enabledCount: number;
  areas: CatalogArea[];
}

export interface QueryCatalog {
  targets: CatalogTarget[];
  totals: {
    total: number;
    enabled: number;
  };
}

export interface QueryStateUpdate {
  queryId: string;
  enabled: boolean;
}


// API functions
export const domainAPI = {
  getAll: (params?: any) => api.get<Domain[]>('/domains', { params }),
  getOne: (id: string) => api.get<Domain>(`/domains/${id}`),
  create: (data: { name: string; scanFrequency?: string; orgId?: string }) =>
    api.post<Domain>('/domains', data),
  update: (id: string, data: Partial<Domain>) =>
    api.put<Domain>(`/domains/${id}`, data),
  delete: (id: string) => api.delete(`/domains/${id}`),
};

export const scanAPI = {
  getAll: (params?: any) => api.get<{ scans: Scan[]; pagination: any }>('/scans', { params }),
  getOne: (id: string) => api.get<Scan>(`/scans/${id}`),
  create: (data: { domainId: string }) => api.post<Scan>('/scans', data),
  cancel: (id: string) => api.delete(`/scans/${id}`),
  getFindings: (id: string, params?: any) =>
    api.get<{ findings: Finding[]; pagination: any }>(`/scans/${id}/findings`, { params }),
};

export const findingsAPI = {
  getAll: (params?: any) =>
    api.get<{ findings: Finding[]; pagination: any }>('/findings', { params }),
  getOne: (id: string) => api.get<Finding>(`/findings/${id}`),
  update: (id: string, data: Partial<Finding>) =>
    api.put<Finding>(`/findings/${id}`, data),
  bulkUpdate: (findingIds: string[], updates: Partial<Finding>) =>
    api.post('/findings/bulk-update', { findingIds, updates }),
  delete: (id: string) => api.delete(`/findings/${id}`),
  getStats: (params?: any) => api.get<any>('/findings/stats', { params }),
};

export const authAPI = {
  login: (identifier: string, password: string) =>
    api.post<{ accessToken: string; user: AuthUser }>('/auth/login', { identifier, password }),
  logout: () => api.post('/auth/logout'),
  me: () => api.get<AuthUser>('/auth/me'),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post<{ message: string; accessToken: string }>('/auth/change-password', {
      currentPassword,
      newPassword,
    }),
  passwordPolicy: () =>
    api.get<{ minLength: number; requires: string[]; forbids: string[]; suggestion: string }>(
      '/auth/password-policy'
    ),
  setupStatus: () => api.get<{ required: boolean }>('/auth/setup-status'),
  completeSetup: (password: string, confirmPassword: string) =>
    api.post<{ accessToken: string; user: AuthUser }>('/auth/setup', { password, confirmPassword }),
};

export const adminAPI = {
  meta: () => api.get<AdminMeta>('/admin/meta'),

  getOrganizations: () => api.get<Organization[]>('/admin/organizations'),
  createOrganization: (data: Partial<Organization>) => api.post<Organization>('/admin/organizations', data),
  updateOrganization: (id: string, data: Partial<Organization>) =>
    api.put<Organization>(`/admin/organizations/${id}`, data),
  deleteOrganization: (id: string) => api.delete(`/admin/organizations/${id}`),

  getUsers: (orgId?: string) =>
    api.get<ManagedUser[]>('/admin/users', { params: orgId ? { orgId } : undefined }),
  createUser: (data: {
    email: string;
    username: string;
    role: Role;
    orgId?: string | null;
    password?: string;
    granted?: string[];
    revoked?: string[];
  }) => api.post<{ user: ManagedUser; temporaryPassword: string; generated: boolean }>('/admin/users', data),
  updateUser: (id: string, data: Partial<{
    email: string;
    username: string;
    role: Role;
    orgId: string | null;
    active: boolean;
    granted: string[];
    revoked: string[];
  }>) => api.put<ManagedUser>(`/admin/users/${id}`, data),
  deleteUser: (id: string) => api.delete(`/admin/users/${id}`),
  resetPassword: (id: string, password?: string) =>
    api.post<{ message: string; temporaryPassword: string }>(`/admin/users/${id}/reset-password`,
      password ? { password } : {}),
  unlockUser: (id: string) => api.post(`/admin/users/${id}/unlock`),

  getAuditLog: (limit = 100) => api.get<AuditEntry[]>('/admin/audit', { params: { limit } }),
};

export const queriesAPI = {
  getAll: (domain?: string) =>
    api.get<QueryCatalog>('/queries', { params: domain ? { domain } : undefined }),
  update: (updates: QueryStateUpdate[], domain?: string) =>
    api.put<QueryCatalog>('/queries', { updates }, { params: domain ? { domain } : undefined }),
  reset: (domain?: string) =>
    api.post<QueryCatalog>('/queries/reset', {}, { params: domain ? { domain } : undefined }),
};

