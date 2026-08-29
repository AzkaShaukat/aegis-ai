import { useState, useEffect } from "react"
import { useNavigate, Link, useLocation } from "react-router-dom"
import { Shield, Mail, Lock, Eye, EyeOff, AlertCircle, Info } from "lucide-react"
import { useAuthStore } from "@/stores/authStore"
import { cn } from "@/utils/helpers"

export default function LoginPage() {
  const nav = useNavigate()
  const loc = useLocation()
  const from = (loc.state as { from?: { pathname: string } })?.from?.pathname || "/chat"
  const { login, resendVerification, isLoading, error, isAuthenticated, clearError } = useAuthStore()

  const [email,   setEmail]   = useState("")
  const [pwd,     setPwd]     = useState("")
  const [show,    setShow]    = useState(false)
  const [touched, setTouched] = useState({ email: false, pwd: false })
  const [resent,  setResent]  = useState(false)

  useEffect(() => { if (isAuthenticated) nav(from, { replace: true }) }, [isAuthenticated, nav, from])
  useEffect(() => { clearError() }, []) // eslint-disable-line

  const emailErr = touched.email && !email.includes("@") ? "Enter a valid email" : ""
  const pwdErr   = touched.pwd   && pwd.length < 8       ? "Minimum 8 characters" : ""
  const canSubmit= email.includes("@") && pwd.length >= 8 && !isLoading
  const needsVerify = !!(error?.toLowerCase().includes("verif"))

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setTouched({ email: true, pwd: true })
    if (!canSubmit) return
    clearError()
    try { await login(email, pwd) } catch {}
  }

  const handleResend = async () => {
    await resendVerification(email)
    setResent(true)
  }

  return (
    <div className="min-h-screen bg-aegis-bg flex items-center justify-center px-4">
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-96 h-96 bg-aegis-accent/5 rounded-full blur-3xl" />
      </div>
      <div className="relative w-full max-w-md animate-fade-in">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-aegis-accent/10 border border-aegis-accent/20 mb-4">
            <Shield className="w-7 h-7 text-aegis-accent" />
          </div>
          <h1 className="text-2xl font-semibold text-white">Welcome back</h1>
          <p className="text-aegis-muted text-sm mt-1">Sign in to Aegis AI</p>
        </div>

        <div className="bg-aegis-surface border border-aegis-border rounded-2xl p-8 shadow-2xl">
          <form onSubmit={submit} noValidate className="space-y-5">

            {error && !needsVerify && (
              <div className="flex items-start gap-3 bg-red-900/20 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-400">
                <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {needsVerify && !resent && (
              <div className="flex items-start gap-3 bg-yellow-900/20 border border-yellow-800 rounded-lg px-4 py-3 text-sm text-yellow-300">
                <Info className="w-4 h-4 mt-0.5 shrink-0" />
                <div className="space-y-1.5">
                  <p>{error}</p>
                  {email.includes("@") && (
                    <button type="button" onClick={handleResend} className="underline text-xs hover:text-yellow-200">
                      Resend verification email →
                    </button>
                  )}
                </div>
              </div>
            )}

            {resent && (
              <div className="bg-green-900/20 border border-green-800 rounded-lg px-4 py-3 text-sm text-green-400">
                ✅ Verification email sent! Check your inbox.
              </div>
            )}

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-[#e6edf3]" htmlFor="email">Email address</label>
              <div className="relative">
                <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
                <input id="email" type="email" autoComplete="email" value={email}
                  onChange={e => { setEmail(e.target.value); clearError() }}
                  onBlur={() => setTouched(t => ({...t, email: true}))}
                  placeholder="you@example.com"
                  className={cn("w-full pl-10 pr-4 py-2.5 rounded-lg text-sm bg-aegis-bg border text-[#e6edf3] placeholder:text-aegis-muted focus:outline-none focus:ring-2 focus:ring-aegis-accent/40 transition-colors",
                    emailErr ? "border-red-700" : "border-aegis-border focus:border-aegis-accent")} />
              </div>
              {emailErr && <p className="text-xs text-red-400">{emailErr}</p>}
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium text-[#e6edf3]" htmlFor="pwd">Password</label>
                <Link to="/forgot-password" className="text-xs text-aegis-accent hover:underline">Forgot password?</Link>
              </div>
              <div className="relative">
                <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
                <input id="pwd" type={show ? "text" : "password"} autoComplete="current-password" value={pwd}
                  onChange={e => { setPwd(e.target.value); clearError() }}
                  onBlur={() => setTouched(t => ({...t, pwd: true}))}
                  placeholder="••••••••"
                  className={cn("w-full pl-10 pr-10 py-2.5 rounded-lg text-sm bg-aegis-bg border text-[#e6edf3] placeholder:text-aegis-muted focus:outline-none focus:ring-2 focus:ring-aegis-accent/40 transition-colors",
                    pwdErr ? "border-red-700" : "border-aegis-border focus:border-aegis-accent")} />
                <button type="button" onClick={() => setShow(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-aegis-muted hover:text-[#e6edf3]">
                  {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {pwdErr && <p className="text-xs text-red-400">{pwdErr}</p>}
            </div>

            <button type="submit" disabled={!canSubmit}
              className="w-full py-2.5 rounded-lg text-sm font-medium bg-aegis-accent text-white hover:bg-aegis-accent-hover active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed transition-all focus:outline-none focus:ring-2 focus:ring-aegis-accent/50">
              {isLoading
                ? <span className="flex items-center justify-center gap-2"><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"/>Signing in…</span>
                : "Sign in"}
            </button>
          </form>

          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-aegis-border"/></div>
            <div className="relative flex justify-center text-xs"><span className="px-3 bg-aegis-surface text-aegis-muted">New to Aegis AI?</span></div>
          </div>
          <Link to="/register" className="block w-full py-2.5 rounded-lg text-sm font-medium text-center border border-aegis-border text-[#e6edf3] hover:bg-white/5 hover:border-aegis-accent/40 transition-all">
            Create a free account
          </Link>
        </div>
        <p className="text-center text-xs text-aegis-muted mt-5">🔒 Your data stays private.</p>
      </div>
    </div>
  )
}
