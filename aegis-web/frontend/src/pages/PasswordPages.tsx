import { useState, useEffect } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import { Shield, Mail, Lock, Eye, EyeOff, AlertCircle, CheckCircle, ArrowLeft } from 'lucide-react'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/utils/helpers'

// ── Forgot Password ───────────────────────────────────────────────────────────

export function ForgotPasswordPage() {
  const { forgotPassword, isLoading, error, successMsg, clearError, clearSuccess } = useAuthStore()
  const [email, setEmail]   = useState('')
  const [touched, setTouched] = useState(false)

  useEffect(() => { clearError(); clearSuccess() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const emailErr = touched && !email.includes('@') ? 'Enter a valid email' : ''
  const canSubmit = email.includes('@') && !isLoading

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setTouched(true)
    if (!canSubmit) return
    await forgotPassword(email)
  }

  return (
    <AuthCard
      title="Reset your password"
      subtitle="Enter your email and we'll send you a reset link"
    >
      {successMsg ? (
        <div className="space-y-4">
          <div className="flex items-start gap-3 bg-green-900/20 border border-green-800 rounded-lg px-4 py-3 text-sm text-green-400">
            <CheckCircle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{successMsg}</span>
          </div>
          <p className="text-aegis-muted text-xs text-center">
            Check your spam folder if you don't see it within a few minutes.
          </p>
          <Link to="/login" className="flex items-center justify-center gap-2 text-sm text-aegis-accent hover:underline">
            <ArrowLeft className="w-3.5 h-3.5" /> Back to sign in
          </Link>
        </div>
      ) : (
        <form onSubmit={handleSubmit} noValidate className="space-y-5">
          {error && <ErrorBanner message={error} />}

          <div className="space-y-1.5">
            <label className="text-sm font-medium text-[#e6edf3]" htmlFor="email">Email address</label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
              <input
                id="email" type="email" autoComplete="email" value={email}
                onChange={e => setEmail(e.target.value)}
                onBlur={() => setTouched(true)}
                placeholder="you@example.com"
                className={cn('w-full pl-10 pr-4 py-2.5 rounded-lg text-sm bg-aegis-bg border',
                  'text-[#e6edf3] placeholder:text-aegis-muted',
                  'transition-colors focus:outline-none focus:ring-2 focus:ring-aegis-accent/40',
                  emailErr ? 'border-red-700' : 'border-aegis-border focus:border-aegis-accent')}
              />
            </div>
            {emailErr && <p className="text-xs text-red-400">{emailErr}</p>}
          </div>

          <SubmitButton loading={isLoading} disabled={!canSubmit} label="Send reset link" />

          <Link to="/login" className="flex items-center justify-center gap-2 text-sm text-aegis-muted hover:text-[#e6edf3] transition-colors">
            <ArrowLeft className="w-3.5 h-3.5" /> Back to sign in
          </Link>
        </form>
      )}
    </AuthCard>
  )
}

// ── Reset Password ────────────────────────────────────────────────────────────

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams()
  const token          = searchParams.get('token') || ''
  const navigate       = useNavigate()
  const { resetPassword, isLoading, error, successMsg, clearError, clearSuccess } = useAuthStore()

  const [password, setPassword]   = useState('')
  const [confirm,  setConfirm]    = useState('')
  const [showPwd,  setShowPwd]    = useState(false)
  const [touched,  setTouched]    = useState({ password: false, confirm: false })

  useEffect(() => { clearError(); clearSuccess() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const passwordErr = touched.password && password.length < 8 ? 'Minimum 8 characters' : ''
  const confirmErr  = touched.confirm && confirm !== password ? 'Passwords do not match' : ''
  const canSubmit   = password.length >= 8 && password === confirm && !isLoading && token

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setTouched({ password: true, confirm: true })
    if (!canSubmit) return
    try {
      await resetPassword(token, password)
    } catch { /* shown from store */ }
  }

  if (!token) return (
    <AuthCard title="Invalid link" subtitle="This reset link is missing or malformed.">
      <Link to="/forgot-password" className="block w-full py-2.5 text-center text-sm text-aegis-accent hover:underline">
        Request a new reset link
      </Link>
    </AuthCard>
  )

  return (
    <AuthCard title="Set new password" subtitle="Choose a strong password for your account">
      {successMsg ? (
        <div className="space-y-4">
          <div className="flex items-start gap-3 bg-green-900/20 border border-green-800 rounded-lg px-4 py-3 text-sm text-green-400">
            <CheckCircle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{successMsg}</span>
          </div>
          <button onClick={() => navigate('/login')}
            className="w-full py-2.5 px-4 rounded-lg text-sm font-medium bg-aegis-accent text-white hover:bg-aegis-accent-hover transition-all">
            Sign in with new password
          </button>
        </div>
      ) : (
        <form onSubmit={handleSubmit} noValidate className="space-y-5">
          {error && <ErrorBanner message={error} />}

          <PasswordField
            id="password" label="New password" value={password}
            show={showPwd} onToggle={() => setShowPwd(v => !v)}
            onChange={v => setPassword(v)} onBlur={() => setTouched(t => ({ ...t, password: true }))}
            error={passwordErr} placeholder="Create a strong password"
          />

          <PasswordField
            id="confirm" label="Confirm password" value={confirm}
            show={showPwd} onToggle={() => setShowPwd(v => !v)}
            onChange={v => setConfirm(v)} onBlur={() => setTouched(t => ({ ...t, confirm: true }))}
            error={confirmErr} placeholder="Repeat your password"
          />

          <SubmitButton loading={isLoading} disabled={!canSubmit} label="Update password" />
        </form>
      )}
    </AuthCard>
  )
}

// ── Shared sub-components ─────────────────────────────────────────────────────

function AuthCard({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-aegis-bg flex items-center justify-center px-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-96 h-96 bg-aegis-accent/5 rounded-full blur-3xl" />
      </div>
      <div className="relative w-full max-w-md animate-fade-in">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-aegis-accent/10 border border-aegis-accent/20 mb-4">
            <Shield className="w-7 h-7 text-aegis-accent" />
          </Link>
          <h1 className="text-2xl font-semibold text-white">{title}</h1>
          <p className="text-aegis-muted text-sm mt-1">{subtitle}</p>
        </div>
        <div className="bg-aegis-surface border border-aegis-border rounded-2xl p-8 shadow-2xl">
          {children}
        </div>
      </div>
    </div>
  )
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-3 bg-red-900/20 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-400 animate-fade-in">
      <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
      <span>{message}</span>
    </div>
  )
}

function PasswordField({ id, label, value, show, onToggle, onChange, onBlur, error, placeholder }: {
  id: string; label: string; value: string; show: boolean
  onToggle: () => void; onChange: (v: string) => void; onBlur: () => void
  error: string; placeholder: string
}) {
  return (
    <div className="space-y-1.5">
      <label className="text-sm font-medium text-[#e6edf3]" htmlFor={id}>{label}</label>
      <div className="relative">
        <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
        <input id={id} type={show ? 'text' : 'password'} value={value}
          onChange={e => onChange(e.target.value)} onBlur={onBlur}
          placeholder={placeholder}
          className={cn('w-full pl-10 pr-10 py-2.5 rounded-lg text-sm bg-aegis-bg border',
            'text-[#e6edf3] placeholder:text-aegis-muted',
            'transition-colors focus:outline-none focus:ring-2 focus:ring-aegis-accent/40',
            error ? 'border-red-700' : 'border-aegis-border focus:border-aegis-accent')} />
        <button type="button" onClick={onToggle}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-aegis-muted hover:text-[#e6edf3] transition-colors">
          {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
        </button>
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  )
}

function SubmitButton({ loading, disabled, label }: { loading: boolean; disabled: boolean | string; label: string }) {
  return (
    <button type="submit" disabled={!!disabled}
      className={cn('w-full py-2.5 px-4 rounded-lg text-sm font-medium transition-all',
        'bg-aegis-accent text-white hover:bg-aegis-accent-hover active:scale-[0.98]',
        'disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100',
        'focus:outline-none focus:ring-2 focus:ring-aegis-accent/50')}>
      {loading ? (
        <span className="flex items-center justify-center gap-2">
          <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          Please wait…
        </span>
      ) : label}
    </button>
  )
}
