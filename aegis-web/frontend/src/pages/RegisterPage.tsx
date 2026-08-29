import { useState, useEffect } from "react"
import { useNavigate, Link } from "react-router-dom"
import { Shield, Mail, Lock, User, Eye, EyeOff, AlertCircle, CheckCircle } from "lucide-react"
import { useAuthStore } from "@/stores/authStore"
import { cn } from "@/utils/helpers"

function Strength({ pwd }: { pwd: string }) {
  const checks = [{ l: "8+ characters", ok: pwd.length >= 8 }, { l: "Uppercase", ok: /[A-Z]/.test(pwd) },
                  { l: "Lowercase", ok: /[a-z]/.test(pwd) }, { l: "Number", ok: /[0-9]/.test(pwd) }]
  const score = checks.filter(c => c.ok).length
  if (!pwd) return null
  return (
    <div className="space-y-2 mt-2">
      <div className="flex gap-1">
        {[0,1,2,3].map(i => <div key={i} className={cn("h-1 flex-1 rounded-full transition-all",
          i < score ? ["bg-red-500","bg-orange-500","bg-yellow-500","bg-green-500"][score-1] : "bg-aegis-border")} />)}
      </div>
      <div className="grid grid-cols-2 gap-1">
        {checks.map(c => <div key={c.l} className={cn("flex items-center gap-1.5 text-xs", c.ok ? "text-green-400" : "text-aegis-muted")}>
          <CheckCircle className={cn("w-3 h-3", !c.ok && "opacity-30")} />{c.l}
        </div>)}
      </div>
    </div>
  )
}

export default function RegisterPage() {
  const nav = useNavigate()
  const { register, isLoading, error, isAuthenticated, clearError } = useAuthStore()
  const [name, setName]    = useState("")
  const [email, setEmail]  = useState("")
  const [pwd, setPwd]      = useState("")
  const [show, setShow]    = useState(false)
  const [t, setT]          = useState({ name: false, email: false, pwd: false })
  const [verifyMsg, setVM] = useState("")

  useEffect(() => { if (isAuthenticated) nav("/chat", { replace: true }) }, [isAuthenticated, nav])
  useEffect(() => { clearError() }, []) // eslint-disable-line

  const score = [/[A-Z]/,/[a-z]/,/[0-9]/].filter(r => r.test(pwd)).length + (pwd.length >= 8 ? 1 : 0)
  const canSubmit = name.trim() && email.includes("@") && pwd.length >= 8 && score >= 2 && !isLoading

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setT({ name: true, email: true, pwd: true })
    if (!canSubmit) return
    try {
      const res = await register(email, pwd, name.trim())
      if (res.needsVerification) setVM(res.message)
    } catch {}
  }

  if (verifyMsg) return (
    <div className="min-h-screen bg-aegis-bg flex items-center justify-center px-4">
      <div className="w-full max-w-md text-center animate-fade-in">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-aegis-accent/10 border border-aegis-accent/20 mb-6">
          <Mail className="w-7 h-7 text-aegis-accent" />
        </div>
        <div className="bg-aegis-surface border border-aegis-border rounded-2xl p-8 shadow-2xl">
          <h2 className="text-xl font-semibold text-white mb-2">Check your inbox</h2>
          <p className="text-aegis-muted text-sm mb-6">{verifyMsg}</p>
          <div className="bg-aegis-bg border border-aegis-border rounded-lg p-4 text-left space-y-1.5 text-xs text-aegis-muted mb-6">
            <p className="font-medium text-[#e6edf3]">📧 Next steps:</p>
            <p>1. Open the email from Aegis AI</p>
            <p>2. Click "Verify Email Address"</p>
            <p>3. Come back here and sign in</p>
            <p className="opacity-60 mt-1">Check spam if you don&apos;t see it.</p>
          </div>
          <Link to="/login" className="block w-full py-2.5 rounded-lg text-sm font-medium text-center bg-aegis-accent text-white hover:bg-aegis-accent-hover transition-all">
            Go to Sign In
          </Link>
        </div>
      </div>
    </div>
  )

  return (
    <div className="min-h-screen bg-aegis-bg flex items-center justify-center px-4 py-8">
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-96 h-96 bg-aegis-accent/5 rounded-full blur-3xl" />
      </div>
      <div className="relative w-full max-w-md animate-fade-in">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-aegis-accent/10 border border-aegis-accent/20 mb-4">
            <Shield className="w-7 h-7 text-aegis-accent" />
          </div>
          <h1 className="text-2xl font-semibold text-white">Create account</h1>
          <p className="text-aegis-muted text-sm mt-1">Join Aegis AI — free to use</p>
        </div>
        <div className="bg-aegis-surface border border-aegis-border rounded-2xl p-8 shadow-2xl">
          <form onSubmit={submit} noValidate className="space-y-5">
            {error && <div className="flex items-start gap-3 bg-red-900/20 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-400">
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" /><span>{error}</span>
            </div>}

            {[
              { id:"name",  label:"Display name",   value:name,  set:setName,  icon:User, type:"text",     ph:"Your name",      err:t.name&&!name.trim()?"Name is required":"" },
              { id:"email", label:"Email address",   value:email, set:setEmail, icon:Mail, type:"email",    ph:"you@example.com", err:t.email&&!email.includes("@")?"Enter a valid email":"" },
            ].map(f => (
              <div key={f.id} className="space-y-1.5">
                <label className="text-sm font-medium text-[#e6edf3]" htmlFor={f.id}>{f.label}</label>
                <div className="relative">
                  <f.icon className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
                  <input id={f.id} type={f.type} value={f.value} placeholder={f.ph}
                    onChange={e => { f.set(e.target.value); clearError() }}
                    onBlur={() => setT(prev => ({...prev,[f.id]:true}))}
                    className={cn("w-full pl-10 pr-4 py-2.5 rounded-lg text-sm bg-aegis-bg border text-[#e6edf3] placeholder:text-aegis-muted focus:outline-none focus:ring-2 focus:ring-aegis-accent/40 transition-colors",
                      f.err?"border-red-700":"border-aegis-border focus:border-aegis-accent")} />
                </div>
                {f.err && <p className="text-xs text-red-400">{f.err}</p>}
              </div>
            ))}

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-[#e6edf3]" htmlFor="pwd">Password</label>
              <div className="relative">
                <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
                <input id="pwd" type={show?"text":"password"} value={pwd}
                  onChange={e => setPwd(e.target.value)} onBlur={() => setT(prev => ({...prev,pwd:true}))}
                  placeholder="Create a strong password"
                  className="w-full pl-10 pr-10 py-2.5 rounded-lg text-sm bg-aegis-bg border border-aegis-border text-[#e6edf3] placeholder:text-aegis-muted focus:outline-none focus:ring-2 focus:ring-aegis-accent/40 focus:border-aegis-accent transition-colors" />
                <button type="button" onClick={() => setShow(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-aegis-muted hover:text-[#e6edf3]">
                  {show?<EyeOff className="w-4 h-4"/>:<Eye className="w-4 h-4"/>}
                </button>
              </div>
              {t.pwd && pwd.length < 8 && <p className="text-xs text-red-400">Minimum 8 characters</p>}
              <Strength pwd={pwd} />
            </div>

            <button type="submit" disabled={!canSubmit}
              className="w-full py-2.5 rounded-lg text-sm font-medium bg-aegis-accent text-white hover:bg-aegis-accent-hover active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed transition-all">
              {isLoading?<span className="flex items-center justify-center gap-2"><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"/>Creating…</span>:"Create account"}
            </button>
          </form>

          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-aegis-border"/></div>
            <div className="relative flex justify-center text-xs"><span className="px-3 bg-aegis-surface text-aegis-muted">Already have an account?</span></div>
          </div>
          <Link to="/login" className="block w-full py-2.5 rounded-lg text-sm font-medium text-center border border-aegis-border text-[#e6edf3] hover:bg-white/5 hover:border-aegis-accent/40 transition-all">
            Sign in
          </Link>
        </div>
      </div>
    </div>
  )
}
