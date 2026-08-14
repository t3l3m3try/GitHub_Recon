import { createContext, useContext, useState, useCallback, useMemo, ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from './AuthContext';
import { adminAPI, Organization } from '../lib/api';

/**
 * Lets a super admin narrow their otherwise-unscoped, all-organizations view
 * down to a single tenant. Everyone else is already pinned to their own org
 * by the backend, so this is a no-op for them (orgId is always '').
 */

interface OrgFilterContextValue {
  orgId: string; // '' = all organizations
  setOrgId: (orgId: string) => void;
  organizations: Organization[];
}

const OrgFilterContext = createContext<OrgFilterContextValue | null>(null);

const STORAGE_KEY = 'orgFilter';

export function OrgFilterProvider({ children }: { children: ReactNode }) {
  const { isSuperAdmin } = useAuth();
  const [orgId, setOrgIdState] = useState<string>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) || '';
    } catch {
      return '';
    }
  });

  const { data: organizations } = useQuery({
    queryKey: ['organizations-for-filter'],
    queryFn: async () => {
      const response = await adminAPI.getOrganizations();
      return response.data;
    },
    enabled: isSuperAdmin,
    staleTime: 60_000,
  });

  const setOrgId = useCallback((next: string) => {
    setOrgIdState(next);
    try {
      if (next) localStorage.setItem(STORAGE_KEY, next);
      else localStorage.removeItem(STORAGE_KEY);
    } catch {
      // Ignore storage errors (private browsing, quota, etc.)
    }
  }, []);

  const value = useMemo<OrgFilterContextValue>(
    () => ({
      orgId: isSuperAdmin ? orgId : '',
      setOrgId,
      organizations: isSuperAdmin ? organizations ?? [] : [],
    }),
    [isSuperAdmin, orgId, setOrgId, organizations]
  );

  return <OrgFilterContext.Provider value={value}>{children}</OrgFilterContext.Provider>;
}

export function useOrgFilter(): OrgFilterContextValue {
  const ctx = useContext(OrgFilterContext);
  if (!ctx) throw new Error('useOrgFilter must be used inside an OrgFilterProvider');
  return ctx;
}
