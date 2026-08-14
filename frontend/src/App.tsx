import React, { Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Login from './pages/Login';
import Setup from './pages/Setup';
import ChangePassword from './pages/ChangePassword';
import { AuthProvider, useAuth, PERM } from './contexts/AuthContext';
import { OrgFilterProvider } from './contexts/OrgFilterContext';

const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const Findings = React.lazy(() => import('./pages/Findings'));
const Domains = React.lazy(() => import('./pages/Domains'));
const Queries = React.lazy(() => import('./pages/Queries'));
const Admin = React.lazy(() => import('./pages/Admin'));

const Loading = ({ label = 'Loading...' }: { label?: string }) => (
  <div className="flex h-screen items-center justify-center text-gray-400 animate-subtle-pulse">{label}</div>
);

/** Renders children only when the signed-in user holds the permission. */
function RequirePermission({ permission, children }: { permission: string; children: React.ReactNode }) {
  const { can } = useAuth();
  if (!can(permission)) {
    return (
      <div className="card text-center py-12">
        <h3 className="text-lg font-bold text-gray-200 mb-1">Not available</h3>
        <p className="text-gray-500 text-sm">
          You do not have permission to view this section. Contact your administrator if you need access.
        </p>
      </div>
    );
  }
  return <>{children}</>;
}

/**
 * Gates the whole application:
 *  - fresh install, no password set → one-time setup screen
 *  - no session                     → login screen
 *  - password change due            → forced change screen (the API blocks everything else)
 *  - otherwise                      → the app
 */
function AppRoutes() {
  const { user, loading, setupRequired } = useAuth();

  if (loading) return <Loading label="Restoring session..." />;
  if (!user && setupRequired) return <Setup />;
  if (!user) return <Login />;
  if (user.mustChangePassword) return <ChangePassword forced />;

  return (
    <OrgFilterProvider>
      <Suspense fallback={<Loading />}>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route
              path="dashboard"
              element={<RequirePermission permission={PERM.FINDING_READ}><Dashboard /></RequirePermission>}
            />
            <Route
              path="findings"
              element={<RequirePermission permission={PERM.FINDING_READ}><Findings /></RequirePermission>}
            />
            <Route
              path="domains"
              element={<RequirePermission permission={PERM.DOMAIN_READ}><Domains /></RequirePermission>}
            />
            <Route
              path="queries"
              element={<RequirePermission permission={PERM.QUERY_READ}><Queries /></RequirePermission>}
            />
            <Route
              path="admin"
              element={<RequirePermission permission={PERM.USER_MANAGE}><Admin /></RequirePermission>}
            />
            <Route path="account/password" element={<ChangePassword />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Routes>
      </Suspense>
    </OrgFilterProvider>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
