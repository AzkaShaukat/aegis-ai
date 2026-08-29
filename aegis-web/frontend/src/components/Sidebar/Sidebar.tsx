import React, { useEffect, useState } from "react"
import { Link, useNavigate } from "react-router-dom"
import { LogIn, UserPlus, Shield, Link2, Mail, User,
         MessageSquare, Camera, Fingerprint } from "lucide-react"
import { useAuthStore }  from "@/stores/authStore"
import { useChatStore }  from "@/stores/chatStore"

/* ── Shared constants ──────────────────────────────────────── */
const MOD_ICON: Record<string, string> = {
  link:"🔗", qr:"📷", credential:"🔑", profile:"👤",
  deepfake:"🎭", sms_scam:"💬", sms:"💬", help:"🛡️", cyber_qa:"🤖",
}
const RISK_CLS: Record<string, string> = {
  CRITICAL:"#ef4444", HIGH:"#ef4444", FAKE:"#ef4444", DEEPFAKE:"#ef4444",
  MEDIUM:"#eab308",   WARNING:"#eab308", LIKELY_FAKE:"#eab308",
  LOW:"#22c55e",      SAFE:"#22c55e",    CLEAN:"#22c55e",
}

const SB: React.CSSProperties = {
  width: "100%", height: "100%",
  background: "#0f172a",
  borderRight: "1px solid #1e293b",
  display: "flex", flexDirection: "column",
  overflowY: "auto", overflowX: "hidden",
}

/* ── Guest sidebar ─────────────────────────────────────────── */
const FEATURES = [
  { icon: Link2,         label: "Link Scanner",      desc: "Detect phishing & malicious URLs", color: "#6366f1" },
  { icon: Mail,          label: "Breach Checker",     desc: "See if your email was leaked",     color: "#ec4899" },
  { icon: User,          label: "Profile Analyser",   desc: "Verify social media accounts",     color: "#14b8a6" },
  { icon: MessageSquare, label: "SMS Scam Detector",  desc: "Spot fraudulent text messages",    color: "#f59e0b" },
  { icon: Camera,        label: "QR Code Scanner",    desc: "Check QR codes before scanning",   color: "#22c55e" },
  { icon: Fingerprint,   label: "Deepfake Detection", desc: "Identify AI-generated media",      color: "#a855f7" },
]

function GuestContent() {
  return (
    <>
      {/* Brand */}
      <div style={{ padding:"16px 14px 12px", borderBottom:"1px solid #1e293b",
                    display:"flex", alignItems:"center", gap:10 }}>
        <div style={{ width:34, height:34, borderRadius:9, flexShrink:0,
                      background:"linear-gradient(135deg,#6366f1,#8b5cf6)",
                      display:"flex", alignItems:"center", justifyContent:"center" }}>
          <Shield size={16} color="white" />
        </div>
        <div>
          <p style={{ margin:0, fontSize:13, fontWeight:700, color:"#e2e8f0" }}>Aegis AI</p>
          <p style={{ margin:0, fontSize:10, color:"#475569" }}>Cybersecurity Assistant</p>
        </div>
      </div>

      {/* CTA */}
      <div style={{ padding:"12px 12px 0" }}>
        <div style={{ background:"linear-gradient(135deg,rgba(99,102,241,.15),rgba(139,92,246,.1))",
                      border:"1px solid rgba(99,102,241,.25)", borderRadius:12, padding:13 }}>
          <p style={{ margin:"0 0 3px", fontSize:13, fontWeight:600, color:"#e2e8f0" }}>🛡️ Stay protected</p>
          <p style={{ margin:"0 0 11px", fontSize:11, color:"#64748b", lineHeight:1.5 }}>
            Create a free account to save your scan history and track your security score.
          </p>
          <Link to="/register" style={{ display:"flex", alignItems:"center", justifyContent:"center",
            gap:6, padding:"8px", borderRadius:8, fontSize:12, fontWeight:600,
            background:"linear-gradient(135deg,#6366f1,#8b5cf6)", color:"white",
            textDecoration:"none", marginBottom:7 }}>
            <UserPlus size={12} /> Create free account
          </Link>
          <Link to="/login" style={{ display:"flex", alignItems:"center", justifyContent:"center",
            gap:6, padding:"7px", borderRadius:8, fontSize:12, fontWeight:500,
            border:"1px solid #334155", color:"#94a3b8", textDecoration:"none" }}>
            <LogIn size={12} /> Sign in
          </Link>
        </div>
      </div>

      {/* Feature list */}
      <div style={{ padding:"14px 10px 4px" }}>
        <p style={{ margin:"0 0 8px 4px", fontSize:10, fontWeight:700, textTransform:"uppercase",
                    letterSpacing:".08em", color:"#334155" }}>What you can scan</p>
        {FEATURES.map(({ icon: Icon, label, desc, color }) => (
          <div key={label} style={{ display:"flex", alignItems:"flex-start", gap:10,
            padding:"8px 6px", borderRadius:8, cursor:"default" }}
            onMouseEnter={e=>(e.currentTarget.style.background="rgba(255,255,255,.03)")}
            onMouseLeave={e=>(e.currentTarget.style.background="transparent")}
          >
            <div style={{ width:28, height:28, borderRadius:7, flexShrink:0,
              background:`${color}18`, border:`1px solid ${color}30`,
              display:"flex", alignItems:"center", justifyContent:"center" }}>
              <Icon size={13} color={color} />
            </div>
            <div>
              <p style={{ margin:0, fontSize:12, fontWeight:600, color:"#cbd5e1" }}>{label}</p>
              <p style={{ margin:0, fontSize:10, color:"#475569", lineHeight:1.4 }}>{desc}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div style={{ marginTop:"auto", padding:"10px 14px", borderTop:"1px solid #1e293b" }}>
        <p style={{ margin:0, fontSize:10, color:"#334155", textAlign:"center" }}>
          🔒 No data stored for guests · Powered by local AI
        </p>
      </div>
    </>
  )
}

/* ── Logged-in sidebar ─────────────────────────────────────── */
function AuthContent({ user, onLogout }: { user: { display_name: string; email: string }, onLogout: () => void }) {
  const { sidebarStats, loadStats, loadHistory, hasMore, messages } = useChatStore()
  const [collapsed, setCollapsed] = useState(false)

  useEffect(() => { loadStats() }, [])

  const score = sidebarStats && sidebarStats.total > 0
    ? Math.round((sidebarStats.safe / sidebarStats.total) * 100) : null
  const scoreColor = score === null ? "#6366f1"
    : score >= 70 ? "#22c55e" : score >= 40 ? "#eab308" : "#ef4444"

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100%", position:"relative" }}>
      {/* Collapse toggle */}
      <button onClick={() => setCollapsed(v => !v)}
        style={{ position:"absolute", right:6, top:10, width:22, height:22,
                 borderRadius:"50%", background:"none", border:"1px solid #334155",
                 color:"#64748b", cursor:"pointer", fontSize:14, display:"flex",
                 alignItems:"center", justifyContent:"center", zIndex:10 }}
        title={collapsed ? "Expand" : "Collapse"}>
        {collapsed ? "›" : "‹"}
      </button>

      {/* Brand */}
      <div style={{ padding:"14px 10px 12px", borderBottom:"1px solid #1e293b",
                    display:"flex", alignItems:"center", gap:8 }}>
        <span style={{ fontSize:30, flexShrink:0 }}>🛡️</span>
        {!collapsed && (
          <div style={{ minWidth:0 }}>
            <p style={{ margin:0, fontSize:20, fontWeight:700, color:"#e2e8f0" }}>Aegis AI</p>
            <p style={{ margin:0, fontSize:14, color:"#475569", overflow:"hidden",
                        textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:120 }}>
              {user.display_name || user.email}
            </p>
          </div>
        )}
      </div>

      {/* Score ring */}
      {!collapsed && score !== null && (
        <div style={{ display:"flex", flexDirection:"column", alignItems:"center", padding:"14px 0 8px", gap:4 }}>
          <svg width="100" height="100" viewBox="0 0 72 72">
            <circle cx="36" cy="36" r="30" fill="none" stroke="#1e293b" strokeWidth="7"/>
            <circle cx="36" cy="36" r="30" fill="none" stroke={scoreColor} strokeWidth="7"
              strokeDasharray={`${score * 1.885} 188.5`} strokeLinecap="round"
              transform="rotate(-90 36 36)"
              style={{ transition:"stroke-dasharray .6s ease" }} />
            <text x="36" y="40" textAnchor="middle" fontSize="16" fontWeight="700"
              fill="#e2e8f0">{score}%</text>
          </svg>
          <span style={{ fontSize:15, color:"#94a3b8" }}>
            {score >= 70 ? "Protected" : score >= 40 ? "At Risk" : "Danger"}
          </span>
        </div>
      )}

      {/* Stats */}
      {sidebarStats && sidebarStats.total > 0 && !collapsed && (
        <div style={{ display:"flex", gap:4, padding:"0 0px 0px" }}>
          {[
            { label:"Safe",  val: sidebarStats.safe,    color:"#22c55e", icon:"" },
            { label:"Warn",  val: sidebarStats.warning, color:"#eab308", icon:"" },
            { label:"Risk",  val: sidebarStats.danger,  color:"#ef4444", icon:"" },
          ].map(s => (
            <div key={s.label} style={{ flex:1, display:"flex", flexDirection:"column",
              alignItems:"center", gap:2, padding:"6px 2px", borderRadius:8,
              background:"rgba(255,255,255,.03)", border:`1px solid ${s.color}22` }}>
              <span style={{ fontSize:11 }}>{s.icon}</span>
              <strong style={{ fontSize:20, fontWeight:700, color:"#e2e8f0" }}>{s.val}</strong>
              <small style={{ fontSize:15, color:"#64748b" }}>{s.label}</small>
            </div>
          ))}
        </div>
      )}

      {/* Recent scans */}
      {!collapsed && sidebarStats && sidebarStats.recent.length > 0 && (
        <div style={{ padding:"6px 8px" }}>
          <p style={{ fontSize:18, textTransform:"uppercase", letterSpacing:".08em",
                      color:"#334155", marginBottom:6 }}>Recent Scans</p>
          {sidebarStats.recent.slice(0,8).map((s, i) => (
            <div key={i} style={{ display:"flex", alignItems:"center", gap:6,
              padding:"5px 4px", borderRadius:6 }}>
              <span style={{ fontSize:20, flexShrink:0 }}>{MOD_ICON[s.module] || "🔍"}</span>
              <div style={{ flex:1, minWidth:0 }}>
                <p style={{ margin:0, fontSize:15, color:"#475569", fontWeight:600 }}>
                  {s.module?.toUpperCase()}
                </p>
                <p style={{ margin:0, fontSize:15, color:"#334155", overflow:"hidden",
                            textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                  {s.excerpt?.slice(0,28) || "—"}
                </p>
              </div>
              <span style={{ fontSize:8, fontWeight:700, color: RISK_CLS[s.risk] || "#475569", flexShrink:0 }}>
                {s.risk?.slice(0,4)}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Collapsed icon scans */}
      {collapsed && sidebarStats?.recent.slice(0,5).map((s,i) => (
        <div key={i} style={{ fontSize:16, padding:6, textAlign:"center" }}
          title={`${s.module}: ${s.risk}`}>
          {MOD_ICON[s.module] || "🔍"}
        </div>
      ))}

      <div style={{ flex:1 }} />

      {/* Footer */}
      {!collapsed ? (
        <div style={{ padding:8, borderTop:"1px solid #1e293b" }}>
          <p style={{ fontSize:9, color:"#334155", textAlign:"center", margin:"0 0 6px" }}>
            🕐 History: 30 days
          </p>
          <button onClick={onLogout} style={{
            width:"100%", padding:7, borderRadius:6, fontSize:11,
            background:"rgba(239,68,68,.08)", border:"1px solid rgba(239,68,68,.15)",
            color:"#f87171", cursor:"pointer" }}>
            ⏻ Sign Out
          </button>
        </div>
      ) : (
        <button onClick={onLogout} style={{
          margin:"8px auto", padding:6, background:"none", border:"none",
          color:"#f87171", cursor:"pointer", fontSize:16 }} title="Sign Out">⏻</button>
      )}
    </div>
  )
}

/* ── Main Sidebar — auto-switches guest ↔ auth ─────────────── */
export function Sidebar() {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()

  const handleLogout = () => { logout(); navigate("/") }

  return (
    <aside style={SB}>
      {user
        ? <AuthContent user={user} onLogout={handleLogout} />
        : <GuestContent />
      }
    </aside>
  )
}

export default Sidebar
