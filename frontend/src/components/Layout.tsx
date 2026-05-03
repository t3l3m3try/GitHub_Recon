import { Outlet, Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, AlertTriangle, Globe } from 'lucide-react';

export default function Layout() {
  const location = useLocation();

  const isActive = (path: string) => location.pathname === path;

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="neon-box-blue cyber-border-top backdrop-blur-sm bg-opacity-90 sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <AlertTriangle className="w-8 h-8 text-cyber-cyan animate-pulse" style={{ filter: 'drop-shadow(0 0 10px var(--cyber-cyan))' }} />
              <h1 className="text-3xl font-bold neon-text" style={{ fontFamily: 'Orbitron, monospace' }}>
                GITHUB RECON
              </h1>
            </div>
            <nav className="flex space-x-4">
              <Link
                to="/dashboard"
                className={`flex items-center space-x-2 px-5 py-2 rounded-sm transition-all duration-300 uppercase tracking-wider text-sm border ${isActive('/dashboard')
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-500 border-cyan-400 text-black font-bold shadow-[0_0_20px_rgba(0,255,159,0.5)]'
                  : 'border-blue-500/30 text-cyan-300 hover:border-cyan-400 hover:shadow-[0_0_15px_rgba(0,255,159,0.3)] hover-cyber'
                  }`}
                style={{ fontFamily: 'Rajdhani, sans-serif' }}
              >
                <LayoutDashboard className="w-5 h-5" />
                <span>Dashboard</span>
              </Link>
              <Link
                to="/findings"
                className={`flex items-center space-x-2 px-5 py-2 rounded-sm transition-all duration-300 uppercase tracking-wider text-sm border ${isActive('/findings')
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-500 border-cyan-400 text-black font-bold shadow-[0_0_20px_rgba(0,255,159,0.5)]'
                  : 'border-blue-500/30 text-cyan-300 hover:border-cyan-400 hover:shadow-[0_0_15px_rgba(0,255,159,0.3)] hover-cyber'
                  }`}
                style={{ fontFamily: 'Rajdhani, sans-serif' }}
              >
                <AlertTriangle className="w-5 h-5" />
                <span>Findings</span>
              </Link>
              <Link
                to="/domains"
                className={`flex items-center space-x-2 px-5 py-2 rounded-sm transition-all duration-300 uppercase tracking-wider text-sm border ${isActive('/domains')
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-500 border-cyan-400 text-black font-bold shadow-[0_0_20px_rgba(0,255,159,0.5)]'
                  : 'border-blue-500/30 text-cyan-300 hover:border-cyan-400 hover:shadow-[0_0_15px_rgba(0,255,159,0.3)] hover-cyber'
                  }`}
                style={{ fontFamily: 'Rajdhani, sans-serif' }}
              >
                <Globe className="w-5 h-5" />
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
