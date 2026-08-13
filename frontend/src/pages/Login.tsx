import { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Shield, Loader2, AlertTriangle, Eye, EyeOff } from 'lucide-react';

/**
 * Login screen. Shown whenever there is no authenticated session.
 */
export default function Login() {
  const { login } = useAuth();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier || !password) return;

    setSubmitting(true);
    setError(null);
    try {
      await login(identifier.trim(), password);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Unable to sign in. Please try again.');
      setPassword('');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <div
            className="flex items-center justify-center w-14 h-14 rounded-xl mb-4"
            style={{
              background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(139, 92, 246, 0.15))',
              border: '1px solid rgba(59, 130, 246, 0.25)',
            }}
          >
            <Shield className="w-7 h-7 text-blue-400" />
          </div>
          <h1
            className="text-2xl font-bold tracking-tight"
            style={{
              background: 'linear-gradient(135deg, #F9FAFB, #9CA3AF)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            GITHUB RECON
          </h1>
          <p className="text-gray-500 text-sm mt-1">Sign in to continue</p>
        </div>

        <form onSubmit={handleSubmit} className="card space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">
              Username or Email
            </label>
            <input
              className="input"
              autoFocus
              autoComplete="username"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              placeholder="superadmin"
              required
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Password</label>
            <div className="relative">
              <input
                className="input pr-11"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                tabIndex={-1}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
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

          <button
            type="submit"
            className="btn btn-primary w-full flex items-center justify-center space-x-2"
            disabled={submitting}
          >
            {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
            <span>{submitting ? 'Signing in...' : 'Sign In'}</span>
          </button>
        </form>

        <p className="text-center text-gray-600 text-xs mt-6">
          Accounts are issued by your administrator. After five failed attempts an account is
          locked for 15 minutes.
        </p>
      </div>
    </div>
  );
}
