import { Outlet, Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, AlertTriangle, Globe, Shield } from 'lucide-react';

export default function Layout() {
  const location = useLocation();

  const isActive = (path: string) => location.pathname === path;

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="sticky top-0 z-50 backdrop-blur-xl" style={{
        background: 'rgba(11, 15, 25, 0.85)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
      }}>
        <div className="container mx-auto px-6 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-9 h-9 rounded-lg" style={{
                background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(139, 92, 246, 0.15))',
                border: '1px solid rgba(59, 130, 246, 0.25)',
              }}>
                <Shield className="w-5 h-5 text-blue-400" />
              </div>
              <h1 className="text-xl font-bold tracking-tight" style={{
                background: 'linear-gradient(135deg, #F9FAFB, #9CA3AF)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}>
                GITHUB RECON
              </h1>
            </div>
            <nav className="flex space-x-1">
              <Link
                to="/dashboard"
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all duration-200 text-sm font-medium ${isActive('/dashboard')
                  ? 'bg-blue-500/15 text-blue-400 border border-blue-500/25'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'
                  }`}
              >
                <LayoutDashboard className="w-4 h-4" />
                <span>Dashboard</span>
              </Link>
              <Link
                to="/findings"
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all duration-200 text-sm font-medium ${isActive('/findings')
                  ? 'bg-blue-500/15 text-blue-400 border border-blue-500/25'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'
                  }`}
              >
                <AlertTriangle className="w-4 h-4" />
                <span>Findings</span>
              </Link>
              <Link
                to="/domains"
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all duration-200 text-sm font-medium ${isActive('/domains')
                  ? 'bg-blue-500/15 text-blue-400 border border-blue-500/25'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5 border border-transparent'
                  }`}
              >
                <Globe className="w-4 h-4" />
                <span>Domains</span>
              </Link>
            </nav>
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
