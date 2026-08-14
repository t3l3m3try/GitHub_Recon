import { useState, useRef, useEffect } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, AlertTriangle, Globe, Shield, ListChecks,
  ShieldCheck, ChevronDown, LogOut, KeyRound, Building2,
} from 'lucide-react';
import { useAuth, PERM } from '../contexts/AuthContext';
import { useOrgFilter } from '../contexts/OrgFilterContext';

function OrgSwitcher() {
  const { orgId, setOrgId, organizations } = useOrgFilter();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const selected = organizations.find(o => o.id === orgId);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-1 text-[11px] text-gray-500 hover:text-gray-300 mt-0.5 transition-colors"
      >
        <Building2 className="w-3 h-3" />
        <span>{selected ? selected.name : 'All Organizations'}</span>
        <ChevronDown className="w-3 h-3" style={{ transform: open ? 'rotate(180deg)' : 'none' }} />
      </button>

      {open && (
        <div
          className="absolute left-0 mt-1 w-56 z-50 rounded-lg border overflow-hidden max-h-72 overflow-y-auto"
          style={{ backgroundColor: '#111827', borderColor: 'rgba(255,255,255,0.1)', boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}
        >
          <button
            onClick={() => { setOrgId(''); setOpen(false); }}
            className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs hover:bg-white/5 transition-colors"
            style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
          >
            <Globe className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-gray-300 font-medium">All Organizations</span>
            {!orgId && <span className="ml-auto text-blue-400">✓</span>}
          </button>
          {organizations.map(org => (
            <button
              key={org.id}
              onClick={() => { setOrgId(org.id); setOpen(false); }}
              className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs hover:bg-white/5 transition-colors"
              style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
            >
              <Building2 className="w-3.5 h-3.5 text-gray-500" />
              <span className="text-gray-300 truncate">{org.name}</span>
              {orgId === org.id && <span className="ml-auto text-blue-400">✓</span>}
            </button>
          ))}
          {organizations.length === 0 && (
            <div className="px-3 py-2 text-gray-500 text-xs">No organizations found</div>
          )}
        </div>
      )}
    </div>
  );
}

export default function Layout() {
  const location = useLocation();
  const { user, logout, can, isSuperAdmin } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);

  const isActive = (path: string) => location.pathname === path;

  // Navigation mirrors the permissions the API enforces, so a user is never
  // shown a section that would reject them.
  const navItems = [
    { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, permission: PERM.FINDING_READ },
    { to: '/findings', label: 'Findings', icon: AlertTriangle, permission: PERM.FINDING_READ },
    { to: '/domains', label: 'Domains', icon: Globe, permission: PERM.DOMAIN_READ },
    { to: '/queries', label: 'Queries', icon: ListChecks, permission: PERM.QUERY_READ },
    { to: '/admin', label: 'Admin', icon: ShieldCheck, permission: PERM.USER_MANAGE },
  ].filter(item => can(item.permission));

  const roleLabel: Record<string, string> = {
    SUPER_ADMIN: 'Super Admin',
    ORG_ADMIN: 'Org Admin',
    ANALYST: 'Analyst',
    VIEWER: 'Viewer',
  };

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="sticky top-0 z-50 backdrop-blur-xl" style={{
        background: 'rgba(11, 15, 25, 0.85)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
      }}>
        <div className="container mx-auto px-6 py-3">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-9 h-9 rounded-lg" style={{
                background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(139, 92, 246, 0.15))',
                border: '1px solid rgba(59, 130, 246, 0.25)',
              }}>
                <Shield className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-tight leading-none" style={{
                  background: 'linear-gradient(135deg, #F9FAFB, #9CA3AF)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                }}>
                  GITHUB RECON
                </h1>
                {isSuperAdmin ? (
                  <OrgSwitcher />
                ) : user?.organization && (
                  <div className="flex items-center gap-1 text-[11px] text-gray-500 mt-0.5">
                    <Building2 className="w-3 h-3" />
                    <span>{user.organization.name}</span>
                  </div>
                )}
              </div>
            </div>

            <nav className="flex space-x-1">
              {navItems.map(({ to, label, icon: Icon }) => (
                <Link
                  key={to}
                  to={to}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all duration-200 text-sm font-medium ${isActive(to)
                    ? 'bg-blue-500/15 text-blue-400 border border-blue-500/25'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'
                    }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{label}</span>
                </Link>
              ))}
            </nav>

            {/* Account menu */}
            <div className="relative">
              <button
                onClick={() => setMenuOpen(v => !v)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-gray-300 hover:bg-white/5 transition-colors"
              >
                <div
                  className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-blue-300"
                  style={{ background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)' }}
                >
                  {user?.username?.slice(0, 2).toUpperCase()}
                </div>
                <div className="text-left hidden sm:block">
                  <div className="text-xs font-medium leading-none">{user?.username}</div>
                  <div className="text-[10px] text-gray-500 leading-none mt-0.5">
                    {roleLabel[user?.role ?? ''] ?? user?.role}
                  </div>
                </div>
                <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
              </button>

              {menuOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setMenuOpen(false)} />
                  <div
                    className="absolute right-0 mt-2 w-60 rounded-lg z-50 overflow-hidden"
                    style={{
                      background: 'rgba(17, 24, 39, 0.98)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      boxShadow: '0 12px 32px rgba(0,0,0,0.5)',
                      backdropFilter: 'blur(12px)',
                    }}
                  >
                    <div className="px-4 py-3" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                      <div className="text-sm text-gray-200 font-medium truncate">{user?.email}</div>
                      <div className="text-[11px] text-gray-500 mt-0.5">
                        {roleLabel[user?.role ?? ''] ?? user?.role}
                        {user?.organization ? ` · ${user.organization.name}` : ''}
                      </div>
                      <div className="text-[11px] text-gray-600 mt-1">
                        {user?.permissions?.length ?? 0} permission{user?.permissions?.length === 1 ? '' : 's'}
                      </div>
                    </div>
                    <Link
                      to="/account/password"
                      onClick={() => setMenuOpen(false)}
                      className="flex items-center gap-2 px-4 py-2.5 text-sm text-gray-300 hover:bg-white/5 transition-colors"
                    >
                      <KeyRound className="w-4 h-4" />
                      <span>Change password</span>
                    </Link>
                    <button
                      onClick={() => { setMenuOpen(false); logout(); }}
                      className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-red-400 hover:bg-red-500/10 transition-colors"
                    >
                      <LogOut className="w-4 h-4" />
                      <span>Sign out</span>
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
