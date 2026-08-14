import { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Shield, Loader2, AlertTriangle, Eye, EyeOff, KeyRound, ArrowLeft } from 'lucide-react';

/**
 * Login screen. Shown whenever there is no authenticated session.
 *
 * Two steps when the account has 2FA enabled: the password step returns a
 * short-lived challenge token instead of a session, and this component then
 * asks for a TOTP or recovery code before handing off to AuthContext.
 */
export default function Login() {
  const { login, verifyTwoFactor } = useAuth();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [code, setCode] = useState('');

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identifier || !password) return;

    setSubmitting(true);
    setError(null);
    try {
      const outcome = await login(identifier.trim(), password);
      if (outcome.twoFactorRequired) {
        setChallengeToken(outcome.challengeToken);
      }
      setPassword('');
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Unable to sign in. Please try again.');
      setPassword('');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCodeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!challengeToken || !code) return;

    setSubmitting(true);
    setError(null);
    try {
      await verifyTwoFactor(challengeToken, code);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Incorrect code. Please try again.');
      setCode('');
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
            {challengeToken ? <KeyRound className="w-7 h-7 text-blue-400" /> : <Shield className="w-7 h-7 text-blue-400" />}
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
          <p className="text-gray-500 text-sm mt-1">
            {challengeToken ? 'Enter your two-factor code' : 'Sign in to continue'}
          </p>
        </div>

        {!challengeToken ? (
          <form onSubmit={handlePasswordSubmit} className="card space-y-4">
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
        ) : (
          <form onSubmit={handleCodeSubmit} className="card space-y-4">
            <p className="text-sm text-gray-400">
              Enter the 6-digit code from your authenticator app, or one of your recovery codes.
            </p>

            <div>
              <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Code</label>
              <input
                className="input tracking-widest text-center"
                autoFocus
                autoComplete="one-time-code"
                inputMode="text"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456"
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

            <button
              type="submit"
              className="btn btn-primary w-full flex items-center justify-center space-x-2"
              disabled={submitting || !code}
            >
              {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
              <span>{submitting ? 'Verifying...' : 'Verify'}</span>
            </button>

            <button
              type="button"
              onClick={() => { setChallengeToken(null); setCode(''); setError(null); }}
              className="w-full flex items-center justify-center gap-1.5 text-gray-500 hover:text-gray-300 text-xs"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to sign in</span>
            </button>
          </form>
        )}

        <p className="text-center text-gray-600 text-xs mt-6">
          Accounts are issued by your administrator. After five failed attempts an account is
          locked for 15 minutes.
        </p>
      </div>
    </div>
  );
}
