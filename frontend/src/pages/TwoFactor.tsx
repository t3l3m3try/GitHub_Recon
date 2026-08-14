import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../contexts/AuthContext';
import { twoFactorAPI } from '../lib/api';
import {
  ShieldCheck, ShieldAlert, KeyRound, Loader2, AlertTriangle, Check, Copy,
  Download, RefreshCw, Ban, Eye, EyeOff,
} from 'lucide-react';

/**
 * Two-factor authentication — account settings.
 *
 * `forced` shows this full-screen when an admin has mandated 2FA and the user
 * has not yet enrolled (the API blocks everything else in that state).
 * `compact` drops the page header for embedding inside the Settings page.
 */
export default function TwoFactor({ forced = false, compact = false }: { forced?: boolean; compact?: boolean }) {
  const { refreshUser, logout } = useAuth();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const { data: status, isLoading } = useQuery({
    queryKey: ['2fa-status'],
    queryFn: async () => (await twoFactorAPI.status()).data,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['2fa-status'] });
    refreshUser();
  };

  const handleError = (err: any) => setError(err?.response?.data?.error || 'Something went wrong');

  const body = isLoading ? (
    <div className="card text-gray-400 animate-subtle-pulse">Loading two-factor status...</div>
  ) : status?.enabled ? (
    <EnabledPanel status={status} onChanged={invalidate} onError={handleError} />
  ) : (
    <EnrollPanel forced={forced} onEnrolled={invalidate} onError={handleError} />
  );

  const errorBanner = error && (
    <div
      className="rounded-lg p-3 flex items-start justify-between gap-3"
      style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.25)' }}
    >
      <div className="flex items-start gap-2">
        <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
        <span className="text-red-300 text-sm">{error}</span>
      </div>
    </div>
  );

  if (compact) {
    return (
      <div className="max-w-lg space-y-4">
        {errorBanner}
        {body}
      </div>
    );
  }

  if (!forced) {
    return (
      <div className="space-y-6 max-w-lg">
        <div>
          <h2 className="text-3xl font-bold mb-1 page-title">Two-Factor Authentication</h2>
          <p className="text-gray-400 text-sm">
            Add a second step at sign-in using an authenticator app such as Google Authenticator,
            Authy or 1Password.
          </p>
        </div>
        {errorBanner}
        {body}
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-md space-y-4">
        <div className="flex flex-col items-center mb-2">
          <div
            className="flex items-center justify-center w-14 h-14 rounded-xl mb-4"
            style={{
              background: 'linear-gradient(135deg, rgba(245,158,11,0.2), rgba(239,68,68,0.15))',
              border: '1px solid rgba(245,158,11,0.25)',
            }}
          >
            <ShieldAlert className="w-7 h-7 text-amber-400" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight page-title">Two-factor authentication required</h1>
          <p className="text-gray-500 text-sm mt-1 text-center">
            Your administrator requires this before you can use the platform.
          </p>
        </div>
        {errorBanner}
        {body}
        <button onClick={() => logout()} className="text-gray-500 hover:text-gray-300 text-xs w-full text-center">
          Sign out instead
        </button>
      </div>
    </div>
  );
}

// ── Enrollment (not yet enabled) ─────────────────────────────────────────

function EnrollPanel({
  forced, onEnrolled, onError,
}: {
  forced: boolean;
  onEnrolled: () => void;
  onError: (err: any) => void;
}) {
  const [setupData, setSetupData] = useState<{ secret: string; qrCodeDataUrl: string } | null>(null);
  const [code, setCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  const setupMutation = useMutation({
    mutationFn: () => twoFactorAPI.setup(),
    onSuccess: (res) => setSetupData(res.data),
    onError,
  });

  const enableMutation = useMutation({
    mutationFn: () => twoFactorAPI.enable(code),
    onSuccess: (res) => setRecoveryCodes(res.data.recoveryCodes),
    onError,
  });

  if (recoveryCodes) {
    return <RecoveryCodesNotice codes={recoveryCodes} onDone={onEnrolled} />;
  }

  if (!setupData) {
    return (
      <div className="card space-y-4">
        {!forced && (
          <div className="flex items-center gap-2 text-gray-400 text-sm">
            <ShieldAlert className="w-4 h-4 text-gray-500" />
            <span>Two-factor authentication is currently off for your account.</span>
          </div>
        )}
        <button
          className="btn btn-primary w-full flex items-center justify-center gap-2"
          onClick={() => setupMutation.mutate()}
          disabled={setupMutation.isPending}
        >
          {setupMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
          <span>Set Up Two-Factor Authentication</span>
        </button>
      </div>
    );
  }

  return (
    <form
      className="card space-y-4"
      onSubmit={(e) => { e.preventDefault(); enableMutation.mutate(); }}
    >
      <div>
        <div className="text-sm text-gray-300 mb-3">
          1. Scan this QR code with your authenticator app
        </div>
        <div className="flex justify-center p-4 rounded-lg" style={{ background: 'white' }}>
          <img src={setupData.qrCodeDataUrl} alt="Two-factor QR code" className="w-44 h-44" />
        </div>
      </div>

      <div>
        <div className="text-sm text-gray-300 mb-2">Or enter this key manually</div>
        <code
          className="block px-3 py-2 rounded text-xs break-all text-gray-300"
          style={{ background: 'rgba(0,0,0,0.35)', fontFamily: 'ui-monospace, monospace' }}
        >
          {setupData.secret}
        </code>
      </div>

      <div>
        <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">
          2. Enter the 6-digit code it shows
        </label>
        <input
          className="input tracking-widest text-center"
          autoFocus
          inputMode="numeric"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="123456"
          required
        />
      </div>

      <button
        type="submit"
        className="btn btn-primary w-full flex items-center justify-center gap-2"
        disabled={enableMutation.isPending || code.length < 6}
      >
        {enableMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
        <span>Confirm & Enable</span>
      </button>
    </form>
  );
}

function RecoveryCodesNotice({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  const text = codes.join('\n');

  const download = () => {
    const blob = new Blob([`GitHub Recon — two-factor recovery codes\n\n${text}\n`], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'github-recon-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="card space-y-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-emerald-400" />
        <div className="text-emerald-300 font-bold text-sm">Two-factor authentication enabled</div>
      </div>
      <div
        className="rounded-lg p-3 text-xs text-amber-300/90"
        style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.25)' }}
      >
        Save these recovery codes now — each works once, and this is the only time they're shown.
        Use one if you lose access to your authenticator app.
      </div>
      <div
        className="grid grid-cols-2 gap-2 p-3 rounded-lg text-sm"
        style={{ background: 'rgba(0,0,0,0.35)', fontFamily: 'ui-monospace, monospace' }}
      >
        {codes.map(c => <div key={c} className="text-gray-200">{c}</div>)}
      </div>
      <div className="flex gap-3">
        <button
          type="button"
          className="flex-1 btn btn-secondary flex items-center justify-center gap-2"
          onClick={() => {
            navigator.clipboard?.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          }}
        >
          {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
        <button type="button" className="flex-1 btn btn-secondary flex items-center justify-center gap-2" onClick={download}>
          <Download className="w-4 h-4" />
          <span>Download</span>
        </button>
      </div>
      <button type="button" className="btn btn-primary w-full" onClick={onDone}>
        Done
      </button>
    </div>
  );
}

// ── Enabled ────────────────────────────────────────────────────────────────

function EnabledPanel({
  status, onChanged, onError,
}: {
  status: { enabledAt: string | null; unusedRecoveryCodes: number };
  onChanged: () => void;
  onError: (err: any) => void;
}) {
  const [action, setAction] = useState<'disable' | 'regenerate' | null>(null);
  const [regeneratedCodes, setRegeneratedCodes] = useState<string[] | null>(null);

  if (regeneratedCodes) {
    return <RecoveryCodesNotice codes={regeneratedCodes} onDone={() => { setRegeneratedCodes(null); onChanged(); }} />;
  }

  if (action) {
    return (
      <ReauthPanel
        title={action === 'disable' ? 'Disable two-factor authentication' : 'Regenerate recovery codes'}
        warning={
          action === 'disable'
            ? 'This removes the second step at sign-in. You can set it up again any time.'
            : 'Your existing recovery codes stop working as soon as new ones are issued.'
        }
        confirmLabel={action === 'disable' ? 'Disable' : 'Regenerate'}
        danger={action === 'disable'}
        onCancel={() => setAction(null)}
        onSubmit={async (password, code) => {
          if (action === 'disable') {
            await twoFactorAPI.disable(password, code);
            onChanged();
            setAction(null);
          } else {
            const res = await twoFactorAPI.regenerateRecoveryCodes(password, code);
            setRegeneratedCodes(res.data.recoveryCodes);
          }
        }}
        onError={onError}
      />
    );
  }

  return (
    <div className="card space-y-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-emerald-400" />
        <div>
          <div className="text-emerald-300 font-bold text-sm">Enabled</div>
          {status.enabledAt && (
            <div className="text-gray-500 text-xs">Since {new Date(status.enabledAt).toLocaleDateString()}</div>
          )}
        </div>
      </div>

      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="text-gray-400">Unused recovery codes</span>
        <span className={status.unusedRecoveryCodes <= 2 ? 'text-amber-400' : 'text-gray-200'}>
          {status.unusedRecoveryCodes}
        </span>
      </div>

      <div className="flex gap-3 pt-2" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
        <button className="flex-1 btn btn-secondary flex items-center justify-center gap-2" onClick={() => setAction('regenerate')}>
          <RefreshCw className="w-4 h-4" />
          <span>New recovery codes</span>
        </button>
        <button className="flex-1 btn btn-danger flex items-center justify-center gap-2" onClick={() => setAction('disable')}>
          <Ban className="w-4 h-4" />
          <span>Disable</span>
        </button>
      </div>
    </div>
  );
}

/** Re-proves both factors (password + a current code) before a sensitive change. */
function ReauthPanel({
  title, warning, confirmLabel, danger, onCancel, onSubmit, onError,
}: {
  title: string;
  warning: string;
  confirmLabel: string;
  danger?: boolean;
  onCancel: () => void;
  onSubmit: (password: string, code: string) => Promise<void>;
  onError: (err: any) => void;
}) {
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [show, setShow] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await onSubmit(password, code);
    } catch (err: any) {
      onError(err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="card space-y-4">
      <div className="flex items-center gap-2">
        <KeyRound className="w-4 h-4 text-gray-400" />
        <h3 className="text-sm font-bold text-gray-200">{title}</h3>
      </div>
      <div
        className="rounded-lg p-3 text-xs"
        style={{
          background: danger ? 'rgba(239,68,68,0.06)' : 'rgba(245,158,11,0.06)',
          border: `1px solid ${danger ? 'rgba(239,68,68,0.25)' : 'rgba(245,158,11,0.25)'}`,
          color: danger ? '#FCA5A5' : '#FCD34D',
        }}
      >
        {warning}
      </div>

      <div>
        <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">Password</label>
        <div className="relative">
          <input
            className="input pr-11"
            type={show ? 'text' : 'password'}
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
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
      </div>

      <div>
        <label className="block text-sm text-gray-400 mb-2 uppercase tracking-wider">
          Authenticator code or recovery code
        </label>
        <input
          className="input"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="123456"
          required
        />
      </div>

      <div className="flex gap-3 pt-2">
        <button type="button" className="flex-1 btn btn-secondary" onClick={onCancel}>Cancel</button>
        <button
          type="submit"
          className={`flex-1 btn ${danger ? 'btn-danger' : 'btn-primary'} flex items-center justify-center gap-2`}
          disabled={submitting || !password || !code}
        >
          {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
          <span>{confirmLabel}</span>
        </button>
      </div>
    </form>
  );
}
