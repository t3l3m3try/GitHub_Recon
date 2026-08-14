import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../contexts/AuthContext';
import { authAPI } from '../lib/api';
import ChangePassword from './ChangePassword';
import TwoFactor from './TwoFactor';
import { User, ShieldCheck, Loader2, AlertTriangle, Check } from 'lucide-react';

/**
 * Account settings: profile details plus a Security section that hosts the
 * password and 2FA forms in compact form (their full-page versions are only
 * used for the forced onboarding screens).
 */

type Tab = 'profile' | 'security';

const ROLE_LABELS: Record<string, string> = {
  SUPER_ADMIN: 'Super Admin',
  ORG_ADMIN: 'Organization Admin',
  ANALYST: 'Analyst',
  VIEWER: 'Viewer',
};

export default function Settings() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab: Tab = searchParams.get('tab') === 'security' ? 'security' : 'profile';
  const [tab, setTab] = useState<Tab>(initialTab);

  const changeTab = (next: Tab) => {
    setTab(next);
    setSearchParams(next === 'security' ? { tab: 'security' } : {});
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold mb-1 page-title">Settings</h2>
        <p className="text-gray-400 text-sm">Manage your profile, password and two-factor authentication.</p>
      </div>

      <div className="flex gap-1 border-b" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
        {([
          { id: 'profile' as Tab, label: 'Profile', icon: User },
          { id: 'security' as Tab, label: 'Security', icon: ShieldCheck },
        ]).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => changeTab(id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors ${
              tab === id ? 'text-blue-400' : 'text-gray-500 hover:text-gray-300'
            }`}
            style={{ borderBottom: tab === id ? '2px solid #3B82F6' : '2px solid transparent' }}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {tab === 'profile' && <ProfileTab />}

      {tab === 'security' && (
        <div className="max-w-lg space-y-8">
          <section className="space-y-3">
            <h3 className="text-sm font-bold text-gray-200 uppercase tracking-wider">Password</h3>
            <ChangePassword compact />
          </section>
          <section className="space-y-3" style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '2rem' }}>
            <h3 className="text-sm font-bold text-gray-200 uppercase tracking-wider">Two-Factor Authentication</h3>
            <TwoFactor compact />
          </section>
        </div>
      )}
    </div>
  );
}

// ── Profile ────────────────────────────────────────────────────────────────

function ProfileTab() {
  const { user, refreshUser } = useAuth();
  const queryClient = useQueryClient();
  const [username, setUsername] = useState(user?.username ?? '');
  const [email, setEmail] = useState(user?.email ?? '');
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const { data: permissions, isLoading: permissionsLoading } = useQuery({
    queryKey: ['my-permissions'],
    queryFn: async () => (await authAPI.myPermissions()).data,
  });

  const updateMutation = useMutation({
    mutationFn: () => authAPI.updateProfile({ username, email }),
    onSuccess: async () => {
      setError(null);
      setDone(true);
      await refreshUser();
      queryClient.invalidateQueries({ queryKey: ['my-permissions'] });
      setTimeout(() => setDone(false), 2500);
    },
    onError: (err: any) => setError(err?.response?.data?.error || 'Could not update profile'),
  });

  const dirty = username.trim().toLowerCase() !== user?.username || email.trim().toLowerCase() !== user?.email;

  return (
    <div className="max-w-lg space-y-8">
      <section className="space-y-4">
        <h3 className="text-sm font-bold text-gray-200 uppercase tracking-wider">Profile</h3>

        <form
          className="card space-y-4"
          onSubmit={(e) => { e.preventDefault(); updateMutation.mutate(); }}
        >
          <div className="flex items-center gap-3 pb-2">
            <div
              className="w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold text-blue-300 shrink-0"
              style={{ background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)' }}
            >
              {user?.username?.slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0">
              <div className="text-sm font-medium text-gray-200 truncate">
                {ROLE_LABELS[user?.role ?? ''] ?? user?.role}
              </div>
              <div className="text-xs text-gray-500 truncate">
                {user?.organization?.name ?? 'No organization'}
              </div>
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Username</label>
            <input
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
            <p className="text-xs text-gray-500 mt-1">3-32 characters: letters, digits, dot, underscore or hyphen</p>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Email</label>
            <input
              className="input"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          {error && (
            <div
              className="rounded-lg p-3 flex items-start space-x-2"
              style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.25)' }}
            >
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <span className="text-red-300 text-sm">{error}</span>
            </div>
          )}

          {done && (
            <div
              className="rounded-lg p-3 flex items-center gap-2 text-emerald-300 text-sm"
              style={{ background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.25)' }}
            >
              <Check className="w-4 h-4" />
              <span>Profile updated</span>
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary w-full flex items-center justify-center gap-2"
            disabled={updateMutation.isPending || !dirty || !username || !email}
          >
            {updateMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            <span>Save Changes</span>
          </button>
        </form>
      </section>

      <section className="space-y-3" style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: '2rem' }}>
        <h3 className="text-sm font-bold text-gray-200 uppercase tracking-wider">Your Permissions</h3>
        <p className="text-gray-500 text-xs">
          Granted by your {ROLE_LABELS[user?.role ?? ''] ?? user?.role} role, plus any individual overrides an
          administrator has applied.
        </p>

        {permissionsLoading ? (
          <div className="text-gray-400 text-sm animate-subtle-pulse">Loading permissions...</div>
        ) : !permissions?.groups.length ? (
          <div className="card text-center py-6 text-gray-500 text-sm">No permissions granted.</div>
        ) : (
          <div className="card !p-0">
            {permissions.groups.map((group, i) => (
              <div
                key={group.name}
                className="p-4"
                style={i > 0 ? { borderTop: '1px solid rgba(255,255,255,0.06)' } : undefined}
              >
                <div className="text-[11px] text-gray-500 uppercase tracking-wider font-semibold mb-2">
                  {group.name}
                </div>
                <div className="flex flex-wrap gap-2">
                  {group.permissions.map(p => (
                    <span
                      key={p.id}
                      className="text-xs px-2.5 py-1 rounded-full text-gray-300"
                      style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)' }}
                    >
                      {p.label}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
