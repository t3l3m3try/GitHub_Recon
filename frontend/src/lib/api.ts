import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';

const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests (if available)
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Types
export interface Domain {
  id: string;
  name: string;
  active: boolean;
  scanFrequency: string;
  lastScanAt?: string;
  createdAt: string;
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


// API functions
export const domainAPI = {
  getAll: () => api.get<Domain[]>('/domains'),
  getOne: (id: string) => api.get<Domain>(`/domains/${id}`),
  create: (data: { name: string; scanFrequency?: string }) =>
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

