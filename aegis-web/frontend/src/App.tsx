import { Suspense, lazy, Component, ReactNode, ErrorInfo, useEffect, useState } from "react"
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import { Toaster } from "react-hot-toast"
import { useAuthStore } from "@/stores/authStore"
import AppShell from "@/components/Layout/AppShell"

// ── Per-route error boundary ──────────────────────────────────────────────────
class RouteError extends Component<{name:string;children:ReactNode},{err:string|null}> {
  state = { err: null as string | null }
  static getDerivedStateFromError(e: Error) { return { err: e.message } }
  componentDidCatch(e: Error, i: ErrorInfo) { console.error(`[Route:${this.props.name}]`, e, i) }
  render() {
    if (this.state.err) return (
      <div style={{padding:32,color:"#f85149",fontFamily:"monospace",background:"#0d1117",minHeight:"100vh"}}>
        <h2>❌ Error in {this.props.name}</h2>
        <pre style={{fontSize:12,color:"#f0883e",whiteSpace:"pre-wrap"}}>{this.state.err}</pre>
        <button onClick={()=>this.setState({err:null})} style={{marginTop:16,padding:"8px 16px",cursor:"pointer",borderRadius:8}}>
          Retry
        </button>
      </div>
    )
    return this.props.children
  }
}

function Safe({name,children}:{name:string;children:ReactNode}) {
  return <RouteError name={name}><Suspense fallback={<Loader/>}>{children}</Suspense></RouteError>
}

// ── Lazy pages ────────────────────────────────────────────────────────────────
const ChatPage        = lazy(() => { console.log("[Route] loading Chat…"); return import("@/pages/ChatPage") })
const LoginPage       = lazy(() => { console.log("[Route] loading Login…"); return import("@/pages/LoginPage") })
const RegisterPage    = lazy(() => { console.log("[Route] loading Register…"); return import("@/pages/RegisterPage") })
const VerifyEmailPage = lazy(() => import("@/pages/VerifyEmailPage"))
const ForgotPage      = lazy(() => import("@/pages/PasswordPages").then(m => ({ default: m.ForgotPasswordPage })))
const ResetPage       = lazy(() => import("@/pages/PasswordPages").then(m => ({ default: m.ResetPasswordPage  })))

// ── Loading screen ────────────────────────────────────────────────────────────
function Loader({ slow }: { slow?: boolean } = {}) {
  return (
    <div style={{minHeight:"100vh",background:"#0d1117",display:"flex",flexDirection:"column",
                 alignItems:"center",justifyContent:"center",gap:16}}>
      <svg width="52" height="52" viewBox="0 0 24 24" fill="none" stroke="#1f6feb" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <div style={{display:"flex",gap:6}}>
        {[0,1,2].map(i=>(
          <div key={i} style={{width:8,height:8,borderRadius:"50%",background:"#1f6feb",
            animation:"b 1s ease infinite",animationDelay:`${i*0.15}s`}}/>
        ))}
      </div>
      <style>{`@keyframes b{0%,60%,100%{transform:translateY(0)}30%{transform:translateY(-8px)}}`}</style>
      <p style={{color:"#8b949e",fontSize:13,margin:0}}>Loading Aegis AI…</p>
      {slow && (
        <div style={{marginTop:8,padding:"8px 16px",background:"#161b22",border:"1px solid #30363d",
                     borderRadius:8,fontSize:12,color:"#8b949e",textAlign:"center",maxWidth:360}}>
          Taking longer than expected. Open F12 → Console for details.<br/>
          <button onClick={()=>window.location.href="/chat"}
            style={{marginTop:8,padding:"4px 12px",cursor:"pointer",fontSize:11,borderRadius:6,
                    background:"#1f6feb",color:"white",border:"none"}}>
            Continue as guest
          </button>
        </div>
      )}
    </div>
  )
}

// ── App init ──────────────────────────────────────────────────────────────────
function AppInit() {
  const { loadUser, isRestoring } = useAuthStore()
  const [isSlow, setSlow] = useState(false)
  const [called, setCalled] = useState(false)

  useEffect(() => {
    if (called) return   // prevent StrictMode double-invoke
    setCalled(true)
    console.log("[App] Starting session restore…")
    loadUser().then(() => {
      console.log("[App] Session restore complete. isRestoring should be false now.")
    }).catch(e => {
      console.error("[App] loadUser error:", e)
    })
  }, []) // eslint-disable-line

  // Safety: if still loading after 8s, show "slow" warning
  useEffect(() => {
    if (!isRestoring) { setSlow(false); return }
    const t = setTimeout(() => {
      if (isRestoring) {
        console.warn("[App] Still loading after 8s — forcing isRestoring=false")
        setSlow(true)
        useAuthStore.setState({ isRestoring: false })
      }
    }, 8000)
    return () => clearTimeout(t)
  }, [isRestoring])

  console.log("[App] render — isRestoring:", isRestoring)

  if (isRestoring) return <Loader slow={isSlow} />

  return (
    <Routes>
      <Route path="/"                element={<Navigate to="/chat" replace />} />
      <Route path="/chat"            element={<Safe name="Chat"><AppShell><ChatPage /></AppShell></Safe>} />
      <Route path="/login"           element={<Safe name="Login">       <LoginPage       /></Safe>} />
      <Route path="/register"        element={<Safe name="Register">    <RegisterPage    /></Safe>} />
      <Route path="/verify-email"    element={<Safe name="VerifyEmail"> <VerifyEmailPage /></Safe>} />
      <Route path="/forgot-password" element={<Safe name="Forgot">      <ForgotPage      /></Safe>} />
      <Route path="/reset-password"  element={<Safe name="Reset">       <ResetPage       /></Safe>} />
      <Route path="*"                element={<Navigate to="/chat" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppInit />
      <Toaster position="bottom-right" toastOptions={{
        style:{background:"#161b22",color:"#e6edf3",border:"1px solid #21262d",borderRadius:"10px",fontSize:"13px"},
        success:{iconTheme:{primary:"#3fb950",secondary:"#161b22"}},
        error:  {iconTheme:{primary:"#f85149",secondary:"#161b22"}},
      }}/>
    </BrowserRouter>
  )
}
