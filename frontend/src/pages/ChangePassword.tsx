import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '../contexts/AuthContext';
import { authAPI, setAccessToken } from '../lib/api';
import { KeyRound, Loader2, AlertTriangle, Check, Eye, EyeOff } from 'lucide-react';

/**
 * Forced password change.
 *
 * Shown full-screen while `mustChangePassword` is set — every other API route is
 * blocked server-side until this completes, so a temporary password handed over
 * by an administrator cannot be used for anything else.
 */
export default function ChangePassword({ forced = false }: { forced?: boolean }) {
  const { user, refreshUser, logout } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [requirements, setRequirements] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  const { data: policy } = useQuery({
    queryKey: ['password-policy'],
    queryFn: async () => (await authAPI.passwordPolicy()).data,
  });

  // Mirrors the server-side policy so the user gets immediate feedback.
  const checks = [
    { label: 'At least 12 characters', ok: newPassword.length >= 12 },
    { label: 'A lowercase letter', ok: /[a-z]/.test(newPassword) },
    { label: 'An uppercase letter', ok: /[A-Z]/.test(newPassword) },
    { label: 'A digit', ok: /[0-9]/.test(newPassword) },
    { label: 'A symbol', ok: /[^A-Za-z0-9]/.test(newPassword) },
  ];
  const allOk = checks.every(c => c.ok) && newPassword === confirmPassword && newPassword.length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setRequirements([]);

    if (newPassword !== confirmPassword) {
      setError('The two new passwords do not match');
      return;
    }

    setSubmitting(true);
    try {
      const { data } = await authAPI.changePassword(currentPassword, newPassword);
      // The server rotates every session; adopt the fresh access token.
      setAccessToken(data.accessToken);
      await refreshUser();
      setDone(true);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Could not change the password');
      setRequirements(err?.response?.data?.requirements ?? []);
    } finally {
      setSubmitting(false);
    }
  };

  const body = (
    <form onSubmit={handleSubmit} className="card space-y-4">
      {forced && (
        <div
          className="rounded-lg p-3 flex items-start space-x-2"
          style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.25)' }}
        >
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <span className="text-amber-300/90 text-sm">
            Your password was issued by an administrator and must be changed before you can use the
            platform.
          </span>
        </div>
      )}

      <div>
        <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">
          Current Password
        </label>
        <input
          className="input"
          type="password"
          autoComplete="current-password"
          value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)}
          required
        />
      </div>

      <div>
        <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">New Password</label>
        <div className="relative">
          <input
            className="input pr-11"
            type={show ? 'text' : 'password'}
            autoComplete="new-password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
          />
          <button
            type="button"
            onClick={() => setShow(v => !v)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            tabIndex={-1}
          >
            {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          </button>
        </div>
        {policy?.suggestion && (
          <button
            type="button"
            className="text-xs text-blue-400 hover:text-blue-300 mt-2"
            onClick={() => {
              setNewPassword(policy.suggestion);
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
          Confirm New Password
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
          <div className="text-red-300 text-sm">{error}</div>
          {requirements.length > 0 && (
            <ul className="text-red-400/70 text-xs mt-1 list-disc list-inside">
              {requirements.map(r => <li key={r}>{r}</li>)}
            </ul>
          )}
        </div>
      )}

      {done && (
        <div
          className="rounded-lg p-3 text-emerald-300 text-sm"
          style={{ background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.25)' }}
        >
          Password updated. All other sessions have been signed out.
        </div>
      )}

      <button
        type="submit"
        className="btn btn-primary w-full flex items-center justify-center space-x-2"
        disabled={submitting || !allOk}
      >
        {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
        <span>{submitting ? 'Updating...' : 'Change Password'}</span>
      </button>
    </form>
  );

  if (!forced) {
    return (
      <div className="space-y-6 max-w-lg">
        <div>
          <h2 className="text-3xl font-bold mb-1 page-title">Change Password</h2>
          <p className="text-gray-400 text-sm">
            Signed in as {user?.username}. Changing your password signs out every other session.
          </p>
        </div>
        {body}
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-6">
          <div
            className="flex items-center justify-center w-14 h-14 rounded-xl mb-4"
            style={{
              background: 'linear-gradient(135deg, rgba(245,158,11,0.2), rgba(239,68,68,0.15))',
              border: '1px solid rgba(245,158,11,0.25)',
            }}
          >
            <KeyRound className="w-7 h-7 text-amber-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight page-title">Set a new password</h1>
          <p className="text-gray-500 text-sm mt-1">{user?.email}</p>
        </div>
        {body}
        <button onClick={() => logout()} className="text-gray-500 hover:text-gray-300 text-xs mt-6 w-full text-center">
          Sign out instead
        </button>
      </div>
    </div>
  );
}
