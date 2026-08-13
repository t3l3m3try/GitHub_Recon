import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  adminAPI,
  AdminMeta,
  ManagedUser,
  Organization,
  Role,
} from '../lib/api';
import { useAuth, PERM } from '../contexts/AuthContext';
import {
  Building2, Users, Plus, Trash2, Pencil, KeyRound, Unlock, Copy, Check,
  ShieldAlert, X, Loader2, AlertTriangle, ScrollText, Ban, CheckCircle2,
} from 'lucide-react';

/**
 * Admin console.
 *
 * Super admins manage every organization and user; org admins see only their
 * own organization. The server enforces both — this UI only hides what the
 * caller could not do anyway.
 */

type Tab = 'organizations' | 'users' | 'audit';

function Toggle({ checked, onChange, disabled }: { checked: boolean; onChange: () => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={onChange}
      className="w-9 h-5 rounded-full relative transition-colors disabled:opacity-40"
      style={{
        background: checked ? 'rgba(59,130,246,0.8)' : 'rgba(75,85,99,0.5)',
        border: '1px solid rgba(255,255,255,0.1)',
      }}
    >
      <span
        className="absolute top-0.5 w-3.5 h-3.5 rounded-full bg-white transition-all"
        style={{ left: checked ? '18px' : '3px' }}
      />
    </button>
  );
}

/** Shows a one-time credential and lets the operator copy it. */
function CredentialNotice({ password, onDismiss }: { password: string; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);

  return (
    <div
      className="rounded-lg p-4 space-y-3"
      style={{ background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.3)' }}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-emerald-300 font-bold text-sm">Temporary password</div>
          <div className="text-emerald-400/70 text-xs">
            Shown once. Copy it now — it is stored only as a hash and cannot be recovered. The user
            must change it at first sign-in.
          </div>
        </div>
        <button onClick={onDismiss} className="text-gray-500 hover:text-gray-300">
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="flex items-center gap-2">
        <code
          className="flex-1 px-3 py-2 rounded text-sm break-all"
          style={{ background: 'rgba(0,0,0,0.35)', fontFamily: 'ui-monospace, monospace' }}
        >
          {password}
        </code>
        <button
          className="btn btn-secondary flex items-center gap-2 whitespace-nowrap"
          onClick={() => {
            navigator.clipboard?.writeText(password);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          }}
        >
          {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
    </div>
  );
}

export default function Admin() {
  const { user, isSuperAdmin, can } = useAuth();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>(isSuperAdmin ? 'organizations' : 'users');
  const [credential, setCredential] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { data: meta } = useQuery({
    queryKey: ['admin-meta'],
    queryFn: async () => (await adminAPI.meta()).data,
  });

  const { data: orgs, isLoading: orgsLoading } = useQuery({
    queryKey: ['admin-orgs'],
    queryFn: async () => (await adminAPI.getOrganizations()).data,
    enabled: can(PERM.ORG_MANAGE),
  });

  const { data: users, isLoading: usersLoading } = useQuery({
    queryKey: ['admin-users'],
    queryFn: async () => (await adminAPI.getUsers()).data,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['admin-orgs'] });
    queryClient.invalidateQueries({ queryKey: ['admin-users'] });
  };

  const fail = (err: any) => setError(err?.response?.data?.error || 'Operation failed');

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-3xl font-bold mb-1 page-title">Administration</h2>
          <p className="text-gray-400 text-sm">
            {isSuperAdmin
              ? 'Manage every organization, its users and their permissions.'
              : `Manage users in ${user?.organization?.name ?? 'your organization'}.`}
          </p>
        </div>
      </div>

      {error && (
        <div
          className="rounded-lg p-3 flex items-start justify-between gap-3"
          style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.25)' }}
        >
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span className="text-red-300 text-sm">{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-gray-500 hover:text-gray-300">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {credential && <CredentialNotice password={credential} onDismiss={() => setCredential(null)} />}

      {/* Tabs */}
      <div className="flex gap-1 border-b" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
        {([
          ...(can(PERM.ORG_MANAGE) ? [{ id: 'organizations' as Tab, label: 'Organizations', icon: Building2 }] : []),
          { id: 'users' as Tab, label: 'Users', icon: Users },
          ...(isSuperAdmin ? [{ id: 'audit' as Tab, label: 'Audit Log', icon: ScrollText }] : []),
        ]).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
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

      {tab === 'organizations' && (
        <OrganizationsTab
          orgs={orgs ?? []}
          loading={orgsLoading}
          isSuperAdmin={isSuperAdmin}
          onChanged={invalidate}
          onError={fail}
        />
      )}

      {tab === 'users' && (
        <UsersTab
          users={users ?? []}
          orgs={orgs ?? []}
          meta={meta}
          loading={usersLoading}
          isSuperAdmin={isSuperAdmin}
          currentUserId={user?.id ?? ''}
          onChanged={invalidate}
          onCredential={setCredential}
          onError={fail}
        />
      )}

      {tab === 'audit' && <AuditTab />}
    </div>
  );
}

// ── Organizations ──────────────────────────────────────────────────────────

function OrganizationsTab({
  orgs, loading, isSuperAdmin, onChanged, onError,
}: {
  orgs: Organization[];
  loading: boolean;
  isSuperAdmin: boolean;
  onChanged: () => void;
  onError: (err: any) => void;
}) {
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<Organization | null>(null);
  const [form, setForm] = useState({ name: '', description: '', maxDomains: 10, maxUsers: 25 });

  const createMutation = useMutation({
    mutationFn: () => adminAPI.createOrganization(form),
    onSuccess: () => {
      setShowCreate(false);
      setForm({ name: '', description: '', maxDomains: 10, maxUsers: 25 });
      onChanged();
    },
    onError,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Organization> }) =>
      adminAPI.updateOrganization(id, data),
    onSuccess: () => { setEditing(null); onChanged(); },
    onError,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => adminAPI.deleteOrganization(id),
    onSuccess: onChanged,
    onError,
  });

  if (loading) return <div className="text-gray-400 animate-subtle-pulse">Loading organizations...</div>;

  return (
    <div className="space-y-4">
      {isSuperAdmin && (
        <div className="flex justify-end">
          <button className="btn btn-primary flex items-center gap-2" onClick={() => setShowCreate(true)}>
            <Plus className="w-4 h-4" />
            <span>New Organization</span>
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {orgs.map(org => (
          <div key={org.id} className="card space-y-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-bold text-white truncate">{org.name}</h3>
                  {!org.active && (
                    <span
                      className="text-[10px] px-2 py-0.5 rounded uppercase tracking-wider font-bold"
                      style={{ background: 'rgba(239,68,68,0.15)', color: '#FCA5A5' }}
                    >
                      Suspended
                    </span>
                  )}
                </div>
                {org.description && <p className="text-gray-500 text-xs mt-0.5">{org.description}</p>}
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  className="btn btn-secondary !px-2.5 !py-1.5"
                  onClick={() => setEditing(org)}
                  title="Edit organization"
                >
                  <Pencil className="w-3.5 h-3.5" />
                </button>
                {isSuperAdmin && (
                  <button
                    className="btn btn-danger !px-2.5 !py-1.5 disabled:opacity-30"
                    disabled={deleteMutation.isPending || (org._count?.users ?? 0) > 0}
                    title={
                      (org._count?.users ?? 0) > 0
                        ? 'Reassign or remove its users first'
                        : 'Delete organization'
                    }
                    onClick={() => {
                      if (confirm(`Delete organization "${org.name}"? Its domains and findings will be removed.`)) {
                        deleteMutation.mutate(org.id);
                      }
                    }}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-3 gap-2 text-center">
              {[
                { label: 'Users', value: `${org._count?.users ?? 0} / ${org.maxUsers}` },
                { label: 'Domains', value: `${org._count?.domains ?? 0} / ${org.maxDomains}` },
                { label: 'Findings', value: (org.findingCount ?? 0).toLocaleString() },
              ].map(stat => (
                <div key={stat.label} className="rounded-lg py-2" style={{ background: 'rgba(0,0,0,0.2)' }}>
                  <div className="text-sm font-bold text-gray-200">{stat.value}</div>
                  <div className="text-[10px] text-gray-500 uppercase tracking-wider">{stat.label}</div>
                </div>
              ))}
            </div>

            {isSuperAdmin && (
              <div className="space-y-2 pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                {[
                  { key: 'active' as const, label: 'Organization active', hint: 'Off signs out every member' },
                  { key: 'canRunScans' as const, label: 'Can run scans', hint: 'Off blocks scanning for all members' },
                  { key: 'canExport' as const, label: 'Can export findings', hint: 'Off removes export from all members' },
                ].map(({ key, label, hint }) => (
                  <div key={key} className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm text-gray-300">{label}</div>
                      <div className="text-[11px] text-gray-600">{hint}</div>
                    </div>
                    <Toggle
                      checked={org[key]}
                      disabled={updateMutation.isPending}
                      onChange={() => updateMutation.mutate({ id: org.id, data: { [key]: !org[key] } })}
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}

        {orgs.length === 0 && (
          <div className="card col-span-full text-center py-10 text-gray-400">
            No organizations yet.
          </div>
        )}
      </div>

      {(showCreate || editing) && (
        <Modal
          title={editing ? `Edit ${editing.name}` : 'New Organization'}
          onClose={() => { setShowCreate(false); setEditing(null); }}
        >
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (editing) {
                updateMutation.mutate({
                  id: editing.id,
                  data: {
                    name: editing.name,
                    description: editing.description,
                    maxDomains: editing.maxDomains,
                    maxUsers: editing.maxUsers,
                  },
                });
              } else {
                createMutation.mutate();
              }
            }}
          >
            <div>
              <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Name *</label>
              <input
                className="input"
                required
                value={editing ? editing.name : form.name}
                onChange={(e) =>
                  editing
                    ? setEditing({ ...editing, name: e.target.value })
                    : setForm({ ...form, name: e.target.value })
                }
                placeholder="Acme Corp"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Description</label>
              <input
                className="input"
                value={(editing ? editing.description : form.description) ?? ''}
                onChange={(e) =>
                  editing
                    ? setEditing({ ...editing, description: e.target.value })
                    : setForm({ ...form, description: e.target.value })
                }
                placeholder="Short description of the organization"
              />
            </div>
            {isSuperAdmin && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Max domains</label>
                  <input
                    className="input"
                    type="number"
                    min={0}
                    value={editing ? editing.maxDomains : form.maxDomains}
                    onChange={(e) =>
                      editing
                        ? setEditing({ ...editing, maxDomains: Number(e.target.value) })
                        : setForm({ ...form, maxDomains: Number(e.target.value) })
                    }
                  />
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Max users</label>
                  <input
                    className="input"
                    type="number"
                    min={1}
                    value={editing ? editing.maxUsers : form.maxUsers}
                    onChange={(e) =>
                      editing
                        ? setEditing({ ...editing, maxUsers: Number(e.target.value) })
                        : setForm({ ...form, maxUsers: Number(e.target.value) })
                    }
                  />
                </div>
              </div>
            )}
            <div className="flex gap-3 pt-2">
              <button
                type="button"
                className="flex-1 btn btn-secondary"
                onClick={() => { setShowCreate(false); setEditing(null); }}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="flex-1 btn btn-primary"
                disabled={createMutation.isPending || updateMutation.isPending}
              >
                {editing ? 'Save Changes' : 'Create Organization'}
              </button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
}

// ── Users ──────────────────────────────────────────────────────────────────

function UsersTab({
  users, orgs, meta, loading, isSuperAdmin, currentUserId, onChanged, onCredential, onError,
}: {
  users: ManagedUser[];
  orgs: Organization[];
  meta?: AdminMeta;
  loading: boolean;
  isSuperAdmin: boolean;
  currentUserId: string;
  onChanged: () => void;
  onCredential: (password: string) => void;
  onError: (err: any) => void;
}) {
  const [showCreate, setShowCreate] = useState(false);
  const [permissionsFor, setPermissionsFor] = useState<ManagedUser | null>(null);
  const [orgFilter, setOrgFilter] = useState<string>('all');

  const emptyForm = { email: '', username: '', role: 'ANALYST' as Role, orgId: '' };
  const [form, setForm] = useState(emptyForm);

  const createMutation = useMutation({
    mutationFn: () =>
      adminAPI.createUser({
        email: form.email,
        username: form.username,
        role: form.role,
        orgId: form.role === 'SUPER_ADMIN' ? null : form.orgId || null,
      }),
    onSuccess: (res) => {
      setShowCreate(false);
      setForm(emptyForm);
      onCredential(res.data.temporaryPassword);
      onChanged();
    },
    onError,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => adminAPI.updateUser(id, data),
    onSuccess: onChanged,
    onError,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => adminAPI.deleteUser(id),
    onSuccess: onChanged,
    onError,
  });

  const resetMutation = useMutation({
    mutationFn: (id: string) => adminAPI.resetPassword(id),
    onSuccess: (res) => { onCredential(res.data.temporaryPassword); onChanged(); },
    onError,
  });

  const unlockMutation = useMutation({
    mutationFn: (id: string) => adminAPI.unlockUser(id),
    onSuccess: onChanged,
    onError,
  });

  if (loading) return <div className="text-gray-400 animate-subtle-pulse">Loading users...</div>;

  const visible = orgFilter === 'all'
    ? users
    : users.filter(u => (orgFilter === 'none' ? !u.orgId : u.orgId === orgFilter));

  const roleColor: Record<string, string> = {
    SUPER_ADMIN: '#F87171',
    ORG_ADMIN: '#A78BFA',
    ANALYST: '#60A5FA',
    VIEWER: '#9CA3AF',
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        {isSuperAdmin ? (
          <select className="input w-auto min-w-[200px]" value={orgFilter} onChange={(e) => setOrgFilter(e.target.value)}>
            <option value="all">All organizations</option>
            <option value="none">No organization (super admins)</option>
            {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
          </select>
        ) : <div />}
        <button className="btn btn-primary flex items-center gap-2" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4" />
          <span>New User</span>
        </button>
      </div>

      <div className="card !p-0 overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              {['User', 'Role', 'Organization', 'Status', 'Last sign-in', ''].map((h, i) => (
                <th key={h + i} className="text-left px-4 py-3 text-[11px] text-gray-500 uppercase tracking-wider font-semibold whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map(u => {
              const locked = u.lockedUntil && new Date(u.lockedUntil).getTime() > Date.now();
              return (
                <tr key={u.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }} className="hover:bg-white/[0.02]">
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-200">{u.username}</div>
                    <div className="text-xs text-gray-500">{u.email}</div>
                  </td>
                  <td className="px-4 py-3">
                    <select
                      className="input !py-1 !px-2 !text-xs w-auto"
                      style={{ color: roleColor[u.role] }}
                      value={u.role}
                      disabled={u.id === currentUserId}
                      onChange={(e) => updateMutation.mutate({ id: u.id, data: { role: e.target.value } })}
                    >
                      {(meta?.roles ?? []).map(r => <option key={r.id} value={r.id}>{r.label}</option>)}
                      {!meta?.roles?.some(r => r.id === u.role) && <option value={u.role}>{u.roleLabel}</option>}
                    </select>
                  </td>
                  <td className="px-4 py-3">
                    {isSuperAdmin && u.role !== 'SUPER_ADMIN' ? (
                      <select
                        className="input !py-1 !px-2 !text-xs w-auto"
                        value={u.orgId ?? ''}
                        onChange={(e) => updateMutation.mutate({ id: u.id, data: { orgId: e.target.value } })}
                      >
                        {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
                      </select>
                    ) : (
                      <span className="text-gray-400">{u.organization?.name ?? '—'}</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Toggle
                        checked={u.active}
                        disabled={u.id === currentUserId || updateMutation.isPending}
                        onChange={() => updateMutation.mutate({ id: u.id, data: { active: !u.active } })}
                      />
                      {locked && (
                        <span className="text-[10px] text-amber-400 flex items-center gap-1">
                          <Ban className="w-3 h-3" /> locked
                        </span>
                      )}
                      {u.mustChangePassword && !locked && (
                        <span className="text-[10px] text-blue-400/80">must change pw</span>
                      )}
                      {!u.mustChangePassword && !locked && u.active && (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500/60" />
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                    {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'never'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        className="btn btn-secondary !px-2 !py-1"
                        title="Permissions"
                        onClick={() => setPermissionsFor(u)}
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                      </button>
                      {locked && (
                        <button
                          className="btn btn-secondary !px-2 !py-1"
                          title="Unlock account"
                          onClick={() => unlockMutation.mutate(u.id)}
                        >
                          <Unlock className="w-3.5 h-3.5" />
                        </button>
                      )}
                      <button
                        className="btn btn-secondary !px-2 !py-1"
                        title="Reset password"
                        onClick={() => {
                          if (confirm(`Reset the password for ${u.username}? Their sessions will end immediately.`)) {
                            resetMutation.mutate(u.id);
                          }
                        }}
                      >
                        <KeyRound className="w-3.5 h-3.5" />
                      </button>
                      <button
                        className="btn btn-danger !px-2 !py-1 disabled:opacity-30"
                        title="Delete user"
                        disabled={u.id === currentUserId}
                        onClick={() => {
                          if (confirm(`Delete ${u.username}? Their domains and scans transfer to you.`)) {
                            deleteMutation.mutate(u.id);
                          }
                        }}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {visible.length === 0 && (
              <tr><td colSpan={6} className="text-center py-10 text-gray-400">No users match this filter.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {showCreate && (
        <Modal title="New User" onClose={() => setShowCreate(false)}>
          <form
            className="space-y-4"
            onSubmit={(e) => { e.preventDefault(); createMutation.mutate(); }}
          >
            <div>
              <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Username *</label>
              <input
                className="input"
                required
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                placeholder="jane.doe"
              />
              <p className="text-xs text-gray-500 mt-1">3-32 characters: letters, digits, dot, underscore or hyphen</p>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Email *</label>
              <input
                className="input"
                type="email"
                required
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                placeholder="jane.doe@example.com"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Role *</label>
              <select
                className="input"
                value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value as Role })}
              >
                {(meta?.roles ?? []).map(r => <option key={r.id} value={r.id}>{r.label}</option>)}
              </select>
              <p className="text-xs text-gray-500 mt-1">
                {meta?.roles?.find(r => r.id === form.role)?.description}
              </p>
            </div>
            {form.role !== 'SUPER_ADMIN' && (
              <div>
                <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Organization *</label>
                {isSuperAdmin ? (
                  <select
                    className="input"
                    required
                    value={form.orgId}
                    onChange={(e) => setForm({ ...form, orgId: e.target.value })}
                  >
                    <option value="">Select an organization…</option>
                    {orgs.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
                  </select>
                ) : (
                  <div className="input text-gray-400">{orgs[0]?.name ?? 'Your organization'}</div>
                )}
              </div>
            )}
            <div
              className="rounded-lg p-3 text-xs text-gray-400"
              style={{ background: 'rgba(59,130,246,0.05)', border: '1px solid rgba(59,130,246,0.15)' }}
            >
              A strong password is generated automatically and shown once after creation. The user
              must change it at first sign-in.
            </div>
            <div className="flex gap-3 pt-2">
              <button type="button" className="flex-1 btn btn-secondary" onClick={() => setShowCreate(false)}>
                Cancel
              </button>
              <button type="submit" className="flex-1 btn btn-primary flex items-center justify-center gap-2" disabled={createMutation.isPending}>
                {createMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                <span>Create User</span>
              </button>
            </div>
          </form>
        </Modal>
      )}

      {permissionsFor && meta && (
        <PermissionEditor
          user={permissionsFor}
          meta={meta}
          onClose={() => setPermissionsFor(null)}
          onSave={(granted, revoked) => {
            updateMutation.mutate(
              { id: permissionsFor.id, data: { granted, revoked } },
              { onSuccess: () => setPermissionsFor(null) }
            );
          }}
          saving={updateMutation.isPending}
        />
      )}
    </div>
  );
}

// ── Permission editor ──────────────────────────────────────────────────────

function PermissionEditor({
  user, meta, onClose, onSave, saving,
}: {
  user: ManagedUser;
  meta: AdminMeta;
  onClose: () => void;
  onSave: (granted: string[], revoked: string[]) => void;
  saving: boolean;
}) {
  const roleDefaults = new Set(
    meta.roles.find(r => r.id === user.role)?.defaultPermissions ?? []
  );
  const [granted, setGranted] = useState<string[]>(user.overrides.granted);
  const [revoked, setRevoked] = useState<string[]>(user.overrides.revoked);

  const isOn = (p: string) => (granted.includes(p) ? true : revoked.includes(p) ? false : roleDefaults.has(p));

  const toggle = (p: string) => {
    const currentlyOn = isOn(p);
    const fromRole = roleDefaults.has(p);

    // Store only the delta against the role, so a later role change re-inherits.
    if (currentlyOn) {
      setGranted(granted.filter(x => x !== p));
      setRevoked(fromRole ? [...new Set([...revoked, p])] : revoked.filter(x => x !== p));
    } else {
      setRevoked(revoked.filter(x => x !== p));
      setGranted(fromRole ? granted.filter(x => x !== p) : [...new Set([...granted, p])]);
    }
  };

  const label = (id: string) => meta.permissions.find(p => p.id === id)?.label ?? id;
  const changes = granted.length + revoked.length;

  return (
    <Modal title={`Permissions — ${user.username}`} onClose={onClose} wide>
      <div className="space-y-4">
        <p className="text-sm text-gray-400">
          Defaults come from the <span className="text-gray-200 font-medium">{user.roleLabel}</span> role.
          Toggling stores only the difference, so changing the role later re-applies its defaults.
        </p>

        <div className="space-y-4 max-h-[50vh] overflow-y-auto pr-1">
          {meta.permissionGroups.map(group => (
            <div key={group.name}>
              <div className="text-[11px] text-gray-500 uppercase tracking-wider font-semibold mb-2">
                {group.name}
              </div>
              <div className="space-y-1">
                {group.permissions.map(p => {
                  const on = isOn(p);
                  const overridden = granted.includes(p) || revoked.includes(p);
                  return (
                    <div
                      key={p}
                      className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg"
                      style={{
                        background: 'rgba(0,0,0,0.2)',
                        borderLeft: overridden ? '2px solid rgba(59,130,246,0.7)' : '2px solid transparent',
                      }}
                    >
                      <div className="min-w-0">
                        <div className={`text-sm ${on ? 'text-gray-200' : 'text-gray-500'}`}>{label(p)}</div>
                        <code className="text-[10px] text-gray-600">{p}</code>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {overridden && (
                          <span className="text-[10px] text-blue-400 uppercase tracking-wider">
                            {granted.includes(p) ? 'granted' : 'revoked'}
                          </span>
                        )}
                        <Toggle checked={on} onChange={() => toggle(p)} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        <div className="flex gap-3 pt-2" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <button className="flex-1 btn btn-secondary" onClick={onClose}>Cancel</button>
          <button
            className="flex-1 btn btn-primary flex items-center justify-center gap-2"
            onClick={() => onSave(granted, revoked)}
            disabled={saving}
          >
            {saving && <Loader2 className="w-4 h-4 animate-spin" />}
            <span>Save{changes > 0 ? ` (${changes} override${changes === 1 ? '' : 's'})` : ''}</span>
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Audit ──────────────────────────────────────────────────────────────────

function AuditTab() {
  const { data, isLoading } = useQuery({
    queryKey: ['admin-audit'],
    queryFn: async () => (await adminAPI.getAuditLog(200)).data,
  });

  if (isLoading) return <div className="text-gray-400 animate-subtle-pulse">Loading audit log...</div>;

  return (
    <div className="card !p-0 overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
            {['When', 'Actor', 'Action', 'Detail', 'IP', ''].map((h, i) => (
              <th key={h + i} className="text-left px-4 py-3 text-[11px] text-gray-500 uppercase tracking-wider font-semibold">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {(data ?? []).map(entry => (
            <tr key={entry.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
              <td className="px-4 py-2.5 text-gray-500 text-xs whitespace-nowrap">
                {new Date(entry.createdAt).toLocaleString()}
              </td>
              <td className="px-4 py-2.5 text-gray-300 text-xs">{entry.actorEmail ?? '—'}</td>
              <td className="px-4 py-2.5">
                <code className="text-xs text-blue-400/90">{entry.action}</code>
              </td>
              <td className="px-4 py-2.5 text-gray-400 text-xs max-w-md truncate">{entry.detail ?? '—'}</td>
              <td className="px-4 py-2.5 text-gray-600 text-xs">{entry.ip ?? '—'}</td>
              <td className="px-4 py-2.5">
                {entry.success ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500/70" />
                ) : (
                  <span className="text-[10px] text-red-400 uppercase tracking-wider font-bold">failed</span>
                )}
              </td>
            </tr>
          ))}
          {(data ?? []).length === 0 && (
            <tr><td colSpan={6} className="text-center py-10 text-gray-400">No audit entries yet.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

// ── Shared ─────────────────────────────────────────────────────────────────

function Modal({
  title, children, onClose, wide,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-90 flex items-center justify-center p-4 z-50"
      onClick={onClose}
      style={{ backdropFilter: 'blur(8px)' }}
    >
      <div
        className={`card w-full ${wide ? 'max-w-2xl' : 'max-w-md'}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-bold page-title">{title}</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300">
            <X className="w-5 h-5" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
