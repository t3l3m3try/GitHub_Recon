import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '../contexts/AuthContext';
import { authAPI } from '../lib/api';
import { ShieldCheck, Loader2, AlertTriangle, Check, Eye, EyeOff } from 'lucide-react';

/**
 * One-time first-run setup. Shown instead of the login screen when the
 * seeded super admin has no password yet — there is nothing to log in with,
 * so this claims the account directly rather than asking for a current
 * password like the forced change screen does.
 */
export default function Setup() {
  const { completeSetup } = useAuth();
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [requirements, setRequirements] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const { data: policy } = useQuery({
    queryKey: ['password-policy'],
    queryFn: async () => (await authAPI.passwordPolicy()).data,
  });

  const checks = [
    { label: 'At least 12 characters', ok: password.length >= 12 },
    { label: 'A lowercase letter', ok: /[a-z]/.test(password) },
    { label: 'An uppercase letter', ok: /[A-Z]/.test(password) },
    { label: 'A digit', ok: /[0-9]/.test(password) },
    { label: 'A symbol', ok: /[^A-Za-z0-9]/.test(password) },
  ];
  const allOk = checks.every(c => c.ok) && password === confirmPassword && password.length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setRequirements([]);

    if (password !== confirmPassword) {
      setError('The two passwords do not match');
      return;
    }

    setSubmitting(true);
    try {
      await completeSetup(password, confirmPassword);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Could not complete setup');
      setRequirements(err?.response?.data?.requirements ?? []);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-6">
          <div
            className="flex items-center justify-center w-14 h-14 rounded-xl mb-4"
            style={{
              background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(139, 92, 246, 0.15))',
              border: '1px solid rgba(59, 130, 246, 0.25)',
            }}
          >
            <ShieldCheck className="w-7 h-7 text-blue-400" />
          </div>
          <h1
            className="text-2xl font-bold tracking-tight"
            style={{
              background: 'linear-gradient(135deg, #F9FAFB, #9CA3AF)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            Welcome to GITHUB RECON
          </h1>
          <p className="text-gray-500 text-sm mt-1 text-center">
            First run — set a password for the super admin account to continue.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="card space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Password</label>
            <div className="relative">
              <input
                className="input pr-11"
                type={show ? 'text' : 'password'}
                autoComplete="new-password"
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <button
                type="button"
                onClick={() => setShow(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                tabIndex={-1}
                aria-label={show ? 'Hide password' : 'Show password'}
              >
                {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {policy?.suggestion && (
              <button
                type="button"
                className="text-xs text-blue-400 hover:text-blue-300 mt-2"
                onClick={() => {
                  setPassword(policy.suggestion);
                  setConfirmPassword(policy.suggestion);
                  setShow(true);
                }}
              >
                Use a generated strong password
              </button>
            )}
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">
              Confirm Password
            </label>
            <input
              className="input"
              type={show ? 'text' : 'password'}
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-1">
            {checks.map(c => (
              <div key={c.label} className="flex items-center space-x-2 text-xs">
                <span
                  className="w-3.5 h-3.5 rounded-full flex items-center justify-center shrink-0"
                  style={{
                    background: c.ok ? 'rgba(16,185,129,0.2)' : 'rgba(107,114,128,0.15)',
                    border: `1px solid ${c.ok ? 'rgba(16,185,129,0.5)' : 'rgba(107,114,128,0.3)'}`,
                  }}
                >
                  {c.ok && <Check className="w-2.5 h-2.5 text-emerald-400" />}
                </span>
                <span className={c.ok ? 'text-emerald-400/90' : 'text-gray-500'}>{c.label}</span>
              </div>
            ))}
          </div>

          {error && (
            <div
              className="rounded-lg p-3"
              style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.25)' }}
            >
              <div className="flex items-start space-x-2">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span className="text-red-300 text-sm">{error}</span>
              </div>
              {requirements.length > 0 && (
                <ul className="text-red-400/70 text-xs mt-1 ml-6 list-disc list-inside">
                  {requirements.map(r => <li key={r}>{r}</li>)}
                </ul>
              )}
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary w-full flex items-center justify-center space-x-2"
            disabled={submitting || !allOk}
          >
            {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
            <span>{submitting ? 'Setting up...' : 'Set Password & Continue'}</span>
          </button>
        </form>

        <p className="text-center text-gray-600 text-xs mt-6">
          This screen only appears once, for the super admin account created when the
          application was installed.
        </p>
      </div>
    </div>
  );
}
