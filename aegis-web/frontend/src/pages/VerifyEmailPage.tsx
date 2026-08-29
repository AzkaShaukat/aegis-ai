import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { Shield, CheckCircle, XCircle, Loader2, Mail } from 'lucide-react'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/utils/helpers'

export default function VerifyEmailPage() {
  const [searchParams]                  = useSearchParams()
  const token                           = searchParams.get('token')
  const navigate                        = useNavigate()
  const { verifyEmail, isLoading }      = useAuthStore()

  const [status, setStatus]   = useState<'verifying' | 'success' | 'error' | 'no-token'>('verifying')
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (!token) { setStatus('no-token'); return }

    verifyEmail(token)
      .then(msg => { setStatus('success'); setMessage(msg) })
      .catch(err => { setStatus('error');   setMessage(err.message) })
  }, [token]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="min-h-screen bg-aegis-bg flex items-center justify-center px-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-96 h-96 bg-aegis-accent/5 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md text-center animate-fade-in">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-aegis-accent/10 border border-aegis-accent/20 mb-6">
          <Shield className="w-7 h-7 text-aegis-accent" />
        </div>
        <h1 className="text-2xl font-semibold text-white mb-2">Aegis AI</h1>

        <div className="bg-aegis-surface border border-aegis-border rounded-2xl p-8 shadow-2xl mt-6">
          {/* Verifying */}
          {(status === 'verifying' || isLoading) && (
            <div className="space-y-4">
              <Loader2 className="w-10 h-10 text-aegis-accent animate-spin mx-auto" />
              <p className="text-[#e6edf3] font-medium">Verifying your email…</p>
              <p className="text-aegis-muted text-sm">This will only take a moment.</p>
            </div>
          )}

          {/* Success */}
          {status === 'success' && (
            <div className="space-y-4">
              <CheckCircle className="w-12 h-12 text-green-400 mx-auto" />
              <p className="text-[#e6edf3] font-medium text-lg">Email Verified!</p>
              <p className="text-aegis-muted text-sm">{message}</p>
              <button
                onClick={() => navigate('/login')}
                className="w-full py-2.5 px-4 rounded-lg text-sm font-medium bg-aegis-accent text-white hover:bg-aegis-accent-hover transition-all mt-2"
              >
                Sign in to Aegis AI
              </button>
            </div>
          )}

          {/* Error */}
          {status === 'error' && (
            <div className="space-y-4">
              <XCircle className="w-12 h-12 text-red-400 mx-auto" />
              <p className="text-[#e6edf3] font-medium text-lg">Verification Failed</p>
              <p className="text-red-400 text-sm">{message}</p>
              <div className="space-y-2 pt-2">
                <Link to="/login" className="block w-full py-2.5 px-4 rounded-lg text-sm font-medium bg-aegis-accent text-white text-center hover:bg-aegis-accent-hover transition-all">
                  Back to Sign In
                </Link>
                <ResendSection />
              </div>
            </div>
          )}

          {/* No token */}
          {status === 'no-token' && (
            <div className="space-y-4">
              <Mail className="w-12 h-12 text-aegis-muted mx-auto" />
              <p className="text-[#e6edf3] font-medium">Check your inbox</p>
              <p className="text-aegis-muted text-sm">
                We sent a verification link to your email. Click the link in that email to activate your account.
              </p>
              <ResendSection />
              <Link to="/login" className="block text-sm text-aegis-accent hover:underline mt-2">
                Already verified? Sign in →
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ResendSection() {
  const { resendVerification, isLoading } = useAuthStore()
  const [email,      setEmail]      = useState('')
  const [sent,       setSent]       = useState(false)
  const [showInput,  setShowInput]  = useState(false)

  const handleResend = async () => {
    if (!email.includes('@')) return
    await resendVerification(email)
    setSent(true)
  }

  if (sent) return (
    <p className="text-green-400 text-sm">✅ Check your inbox for a new verification link.</p>
  )

  if (showInput) return (
    <div className="space-y-2">
      <input
        type="email"
        value={email}
        onChange={e => setEmail(e.target.value)}
        placeholder="Enter your email"
        className="w-full px-3 py-2 rounded-lg text-sm bg-aegis-bg border border-aegis-border text-[#e6edf3] placeholder:text-aegis-muted focus:outline-none focus:border-aegis-accent"
      />
      <button
        onClick={handleResend}
        disabled={isLoading || !email.includes('@')}
        className={cn(
          'w-full py-2 px-4 rounded-lg text-sm font-medium transition-all border border-aegis-border',
          'text-[#e6edf3] hover:bg-white/5 disabled:opacity-50'
        )}
      >
        {isLoading ? 'Sending…' : 'Resend verification email'}
      </button>
    </div>
  )

  return (
    <button onClick={() => setShowInput(true)} className="text-sm text-aegis-accent hover:underline">
      Didn't receive the email? Resend it
    </button>
  )
}
