import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  ReactNode,
} from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  AuthUser,
  authAPI,
  refreshAccessToken,
  setAccessToken,
  setAuthLostHandler,
} from '../lib/api';

/**
 * Authentication state.
 *
 * The access token never leaves memory. On boot we attempt a silent refresh
 * using the httpOnly cookie, so a page reload restores the session without the
 * long-lived credential ever being readable by scripts.
 */

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  setupRequired: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  completeSetup: (password: string, confirmPassword: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  can: (permission: string) => boolean;
  canAny: (...permissions: string[]) => boolean;
  isSuperAdmin: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [setupRequired, setSetupRequired] = useState(false);
  const queryClient = useQueryClient();

  const clearSession = useCallback(() => {
    setAccessToken(null);
    setUser(null);
    queryClient.clear();
  }, [queryClient]);

  // Restore the session on first load via the refresh cookie, and check
  // whether this is a fresh install still awaiting its one-time setup.
  useEffect(() => {
    let cancelled = false;

    (async () => {
      const [token, setupCheck] = await Promise.all([
        refreshAccessToken(),
        authAPI.setupStatus().catch(() => null),
      ]);
      if (cancelled) return;

      if (setupCheck) setSetupRequired(setupCheck.data.required);

      if (!token) {
        setLoading(false);
        return;
      }

      try {
        const { data } = await authAPI.me();
        if (!cancelled) setUser(data);
      } catch {
        if (!cancelled) clearSession();
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [clearSession]);

  // A failed refresh anywhere in the app drops us back to the login screen.
  useEffect(() => {
    setAuthLostHandler(() => clearSession());
    return () => setAuthLostHandler(null);
  }, [clearSession]);

  const login = useCallback(
    async (identifier: string, password: string) => {
      const { data } = await authAPI.login(identifier, password);
      setAccessToken(data.accessToken);
      queryClient.clear();
      setUser(data.user);
    },
    [queryClient]
  );

  const completeSetup = useCallback(
    async (password: string, confirmPassword: string) => {
      const { data } = await authAPI.completeSetup(password, confirmPassword);
      setAccessToken(data.accessToken);
      queryClient.clear();
      setSetupRequired(false);
      setUser(data.user);
    },
    [queryClient]
  );

  const logout = useCallback(async () => {
    try {
      await authAPI.logout();
    } catch {
      // Even if the call fails, drop local state.
    }
    clearSession();
  }, [clearSession]);

  const refreshUser = useCallback(async () => {
    const { data } = await authAPI.me();
    setUser(data);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      setupRequired,
      login,
      completeSetup,
      logout,
      refreshUser,
      can: (permission: string) => Boolean(user?.permissions?.includes(permission)),
      canAny: (...permissions: string[]) =>
        permissions.some(p => Boolean(user?.permissions?.includes(p))),
      isSuperAdmin: user?.role === 'SUPER_ADMIN',
    }),
    [user, loading, setupRequired, login, completeSetup, logout, refreshUser]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside an AuthProvider');
  return ctx;
}

/** Permission identifiers, mirroring backend/src/utils/permissions.ts */
export const PERM = {
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
  USER_MANAGE: 'user:manage',
  ORG_MANAGE: 'org:manage',
  ADMIN_ALL: 'admin:all',
} as const;
