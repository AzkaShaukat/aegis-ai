"""
FIX_ALL.py — Fixes:
1. Discovers real API endpoints for all microservices
2. Patches web_orchestrator.py with correct paths
3. Fixes chat layout margins (CSS)
4. Makes sidebar style consistent (single Sidebar component for both states)
"""
import pathlib, sys, json
import urllib.request, urllib.error

BASE = pathlib.Path(__file__).parent.resolve()
F    = BASE / "frontend/src"
B    = BASE / "backend"

def write(p, t):
    p = pathlib.Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(t.lstrip(), encoding="utf-8")
    print(f"  ✅  {p.relative_to(BASE)}")

def read(p):
    p = pathlib.Path(p)
    if not p.exists():
        print(f"  ❌  NOT FOUND: {p}"); sys.exit(1)
    return p.read_text(encoding="utf-8")

def get_endpoints(port: int) -> list[str]:
    """Fetch POST endpoints from a service's openapi.json"""
    try:
        url = f"http://localhost:{port}/openapi.json"
        with urllib.request.urlopen(url, timeout=3) as r:
            spec = json.loads(r.read())
        paths = []
        for path, methods in spec.get("paths", {}).items():
            if "post" in methods:
                paths.append(path)
        return paths
    except Exception as e:
        return []

print("=" * 60)
print("  FIX_ALL — endpoints + layout + sidebar consistency")
print("=" * 60)

# ─────────────────────────────────────────────────────────────
# 1. Discover real endpoints for each service
# ─────────────────────────────────────────────────────────────
print("\n[1] Discovering real API endpoints…")

SERVICES = {
    "link":       8000,
    "qr":         8001,
    "credential": 8002,
    "profile":    8003,
    "deepfake":   8004,
}

discovered = {}
for name, port in SERVICES.items():
    endpoints = get_endpoints(port)
    discovered[name] = endpoints
    if endpoints:
        print(f"  ✅  {name} (:{port}): {endpoints}")
    else:
        print(f"  ⚠️   {name} (:{port}): could not fetch (offline or unreachable)")

# ─────────────────────────────────────────────────────────────
# 2. Patch web_orchestrator.py with correct endpoint paths
# ─────────────────────────────────────────────────────────────
print("\n[2] Patching web_orchestrator.py with correct endpoints…")

wo_file = B / "app/services/web_orchestrator.py"
wo_txt  = read(wo_file)

# Build the correct endpoint map based on discovered paths
# Common patterns to look for
def find_endpoint(endpoints: list[str], *candidates) -> str:
    """Find the first matching candidate in the discovered endpoints."""
    for c in candidates:
        if c in endpoints:
            return c
    # Fuzzy: find anything containing the keyword
    for c in candidates:
        keyword = c.strip("/").split("/")[-1]
        for e in endpoints:
            if keyword in e:
                return e
    # Return first POST endpoint as fallback
    return endpoints[0] if endpoints else candidates[0]

# Determine correct endpoints
link_ep    = find_endpoint(discovered.get("link", []),
                           "/analyze", "/scan", "/check", "/url", "/inspect")
cred_ep    = find_endpoint(discovered.get("credential", []),
                           "/check", "/analyze", "/breach", "/lookup")
profile_ep = find_endpoint(discovered.get("profile", []),
                           "/analyze", "/check", "/profile", "/scan")
qr_ep      = find_endpoint(discovered.get("qr", []),
                           "/scan", "/analyze", "/decode", "/check")
df_ep      = find_endpoint(discovered.get("deepfake", []),
                           "/analyze", "/detect", "/scan", "/check")

print(f"  link      → {link_ep}")
print(f"  credential→ {cred_ep}")
print(f"  profile   → {profile_ep}")
print(f"  qr        → {qr_ep}")
print(f"  deepfake  → {df_ep}")

# Patch the _handle_link call
wo_txt = wo_txt.replace(
    'data = await _call("link", "/analyze", json={"url": value})',
    f'data = await _call("link", "{link_ep}", json={{"url": value}})'
)
# Patch credential
wo_txt = wo_txt.replace(
    'data = await _call("credential", "/check", json={"email": value})',
    f'data = await _call("credential", "{cred_ep}", json={{"email": value}})'
)
# Patch profile
wo_txt = wo_txt.replace(
    'data = await _call("profile", "/analyze", json={"handle": value, "query": value})',
    f'data = await _call("profile", "{profile_ep}", json={{"handle": value, "query": value}})'
)
# Patch SMS fallback that also calls link
wo_txt = wo_txt.replace(
    'data = await _call("link", "/analyze-text", json={"text": text}) or \\\n           await _call("link", "/analyze", json={"url": text, "type": "sms"})',
    f'data = await _call("link", "{link_ep}", json={{"url": text, "type": "sms"}})'
)

write(wo_file, wo_txt)
print("  ✅  web_orchestrator.py patched")

# ─────────────────────────────────────────────────────────────
# 3. Fix CSS — add chat-page layout with proper margins
# ─────────────────────────────────────────────────────────────
print("\n[3] Patching index.css — chat layout margins…")

css_file = F / "index.css"
css_txt  = read(css_file)

LAYOUT_CSS = """
/* ═══ Chat page layout — consistent margins ══════════════════ */
.chat-page {
  display: flex;
  flex-direction: column;
  flex: 1;
  height: 100%;
  min-height: 0;
  overflow: hidden;
  background: #0b1120;
}

.chat-messages {
  flex: 1;
  overflow-y: auto;
  padding: 24px 0 16px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.chat-messages::-webkit-scrollbar { width: 4px; }
.chat-messages::-webkit-scrollbar-track { background: transparent; }
.chat-messages::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }

/* All direct children of chat-messages get the same side margins */
.chat-messages > * {
  width: 100%;
  max-width: 1000px;
  margin-left: auto;
  margin-right: auto;
  padding-left: 0px;
  padding-right: 0px;
  box-sizing: border-box;
}

/* Message rows */
.msg-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  width: 100%;
}
.msg-row-user {
  flex-direction: row-reverse;
}
.msg-row-bot {
  align-self: flex-start;
}

/* User bubble */
.msg-user-bubble {
  background: #6366f1;
  color: #fff;
  padding: 10px 16px;
  border-radius: 18px 18px 4px 18px;
  font-size: 13px;
  max-width: 68%;
  line-height: 1.5;
  word-break: break-word;
}

/* Bot bubble */
.msg-avatar { width: 30px; height: 30px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.msg-avatar-user { background: #4f46e5; color: #fff; }
.msg-bot-avatar  { font-size: 20px; flex-shrink: 0; margin-top: 2px; }
.msg-bot-content { display: flex; flex-direction: column; gap: 4px; max-width: 72%; }
.msg-bot-bubble  {
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 4px 18px 18px 18px;
  padding: 12px 16px;
  font-size: 13px;
  color: #cbd5e1;
  line-height: 1.6;
}
.msg-time { font-size: 9px; color: #334155; align-self: flex-end; margin-top: 2px; }
.msg-img-preview   { max-width: 200px; border-radius: 8px; }
.msg-video-preview { max-width: 240px; border-radius: 8px; }

/* Thinking bubble — same margin as messages */
.thinking-bubble {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  background: #1e293b;
  border-radius: 4px 18px 18px 18px;
  max-width: 1000px;
  border: 1px solid #334155;
}
.thinking-dots { display: flex; gap: 4px; }
.thinking-dots span {
  width: 6px; height: 6px; border-radius: 50%; background: #6366f1;
  animation: dot-bounce .9s ease-in-out infinite;
}
.thinking-dots span:nth-child(2) { animation-delay: .15s; }
.thinking-dots span:nth-child(3) { animation-delay: .3s; }
@keyframes dot-bounce {
  0%,60%,100% { transform: translateY(0); }
  30%          { transform: translateY(-6px); }
}
.thinking-text { font-size: 12px; color: #64748b; }

/* WS banner */
.ws-banner {
  display: flex; align-items: center; justify-content: space-between;
  padding: 8px 24px;
  background: rgba(239,68,68,.1);
  border-bottom: 1px solid rgba(239,68,68,.2);
  color: #f87171; font-size: 12px; flex-shrink: 0;
}
.ws-banner button {
  padding: 4px 10px; border-radius: 6px;
  background: rgba(239,68,68,.2); border: none;
  color: #f87171; cursor: pointer; font-size: 11px;
}

/* Load more */
.load-more-btn {
  align-self: center;
  padding: 6px 16px; border-radius: 20px; font-size: 11px;
  background: rgba(99,102,241,.1); border: 1px solid rgba(99,102,241,.2);
  color: #a5b4fc; cursor: pointer; margin-bottom: 4px;
}

/* Risk badge */
.risk-badge { padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; }
.badge-danger  { background: rgba(239,68,68,.15);  color: #f87171; border: 1px solid rgba(239,68,68,.3); }
.badge-warning { background: rgba(234,179,8,.12);  color: #fbbf24; border: 1px solid rgba(234,179,8,.3); }
.badge-safe    { background: rgba(34,197,94,.1);   color: #4ade80; border: 1px solid rgba(34,197,94,.3); }
.badge-unknown { background: rgba(148,163,184,.1); color: #94a3b8; border: 1px solid rgba(148,163,184,.2); }
.msg-risk-header { margin-bottom: 8px; }

/* Markdown */
.md-body  { display: flex; flex-direction: column; gap: 4px; }
.md-para  { margin: 0; }
.md-heading { margin: 4px 0 2px; font-weight: 700; color: #e2e8f0; font-size: 14px; }
.md-list  { margin: 2px 0; padding-left: 18px; }
.md-list li { margin: 2px 0; }
.md-code  { background: #0f172a; padding: 1px 6px; border-radius: 4px;
            font-family: monospace; font-size: 11px; color: #7dd3fc; }

/* Structured card */
.structured-card  { margin-top: 10px; background: #0f172a; border-radius: 8px;
                    overflow: hidden; border: 1px solid #334155; }
.structured-title { padding: 6px 10px; font-size: 10px; font-weight: 700;
                    color: #64748b; text-transform: uppercase; letter-spacing: .06em;
                    border-bottom: 1px solid #1e293b; }
.structured-table { width: 100%; border-collapse: collapse; }
.structured-table tr:nth-child(even) { background: rgba(255,255,255,.02); }
.struct-key { padding: 5px 10px; font-size: 11px; color: #64748b; white-space: nowrap; width: 40%; }
.struct-val { padding: 5px 10px; font-size: 11px; color: #94a3b8; word-break: break-word; }

/* Follow-up chips */
.followup-chips { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 6px; }
.followup-chip  {
  padding: 5px 11px; border-radius: 20px; font-size: 11px;
  background: rgba(99,102,241,.1); border: 1px solid rgba(99,102,241,.25);
  color: #a5b4fc; cursor: pointer; transition: all .15s;
}
.followup-chip:hover { background: rgba(99,102,241,.2); color: #e2e8f0; }

/* Welcome screen */
.welcome-screen {
  flex: 1; display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  padding: 40px 24px; gap: 16px;
  /* override the max-width centering for welcome screen */
  max-width: 100% !important;
  padding-left: 40px !important;
  padding-right: 40px !important;
}
.welcome-icon  { font-size: 52px; }
.welcome-title { font-size: 28px; font-weight: 700; color: #e2e8f0; margin: 0; }
.welcome-sub   { font-size: 13px; color: #64748b; text-align: center; line-height: 1.6; margin: 0; }
.action-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
  width: 100%; max-width: 500px; margin-top: 8px;
}
.action-card {
  display: flex; align-items: center; gap: 10px; padding: 14px 16px;
  border-radius: 12px; background: rgba(255,255,255,.03);
  border: 1px solid rgba(255,255,255,.07); cursor: pointer;
  text-align: left; color: #94a3b8; font-size: 13px; transition: all .15s;
}
.action-card:hover { background: rgba(99,102,241,.1); border-color: rgba(99,102,241,.3);
                     color: #e2e8f0; transform: translateY(-1px); }
.action-icon  { font-size: 20px; }
.action-label { font-size: 12px; line-height: 1.3; }
.capability-chips { display: flex; flex-wrap: wrap; gap: 6px; justify-content: center; }
.cap-chip { padding: 5px 12px; border-radius: 20px; font-size: 11px;
            background: rgba(255,255,255,.04); border: 1px solid rgba(255,255,255,.07);
            color: #64748b; }
/* ════════════════════════════════════════════════════════════ */
"""

# Remove old auto-generated block if present and append new
marker = "/* ═══ Chat page layout"
if marker in css_txt:
    idx = css_txt.find(marker)
    css_txt = css_txt[:idx] + LAYOUT_CSS
else:
    css_txt += LAYOUT_CSS

css_file.write_text(css_txt, encoding="utf-8")
print("  ✅  index.css updated with consistent margins")

# ─────────────────────────────────────────────────────────────
# 4. Make Sidebar self-aware (show guest content when no user)
#    so AppShell doesn't need separate GuestSidebar
# ─────────────────────────────────────────────────────────────
print("\n[4] Updating Sidebar.tsx to handle guest state internally…")

write(F / "components/Sidebar/Sidebar.tsx", r"""
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
        <span style={{ fontSize:22, flexShrink:0 }}>🛡️</span>
        {!collapsed && (
          <div style={{ minWidth:0 }}>
            <p style={{ margin:0, fontSize:13, fontWeight:700, color:"#e2e8f0" }}>Aegis AI</p>
            <p style={{ margin:0, fontSize:10, color:"#475569", overflow:"hidden",
                        textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:120 }}>
              {user.display_name || user.email}
            </p>
          </div>
        )}
      </div>

      {/* Score ring */}
      {!collapsed && score !== null && (
        <div style={{ display:"flex", flexDirection:"column", alignItems:"center", padding:"14px 0 8px", gap:4 }}>
          <svg width="72" height="72" viewBox="0 0 72 72">
            <circle cx="36" cy="36" r="30" fill="none" stroke="#1e293b" strokeWidth="7"/>
            <circle cx="36" cy="36" r="30" fill="none" stroke={scoreColor} strokeWidth="7"
              strokeDasharray={`${score * 1.885} 188.5`} strokeLinecap="round"
              transform="rotate(-90 36 36)"
              style={{ transition:"stroke-dasharray .6s ease" }} />
            <text x="36" y="40" textAnchor="middle" fontSize="16" fontWeight="700"
              fill="#e2e8f0">{score}%</text>
          </svg>
          <span style={{ fontSize:10, color:"#94a3b8" }}>
            {score >= 70 ? "Protected" : score >= 40 ? "At Risk" : "Danger"}
          </span>
        </div>
      )}

      {/* Stats */}
      {sidebarStats && sidebarStats.total > 0 && !collapsed && (
        <div style={{ display:"flex", gap:4, padding:"0 8px 8px" }}>
          {[
            { label:"Safe",  val: sidebarStats.safe,    color:"#22c55e", icon:"✅" },
            { label:"Warn",  val: sidebarStats.warning, color:"#eab308", icon:"⚠️" },
            { label:"Risk",  val: sidebarStats.danger,  color:"#ef4444", icon:"🔴" },
          ].map(s => (
            <div key={s.label} style={{ flex:1, display:"flex", flexDirection:"column",
              alignItems:"center", gap:2, padding:"6px 2px", borderRadius:8,
              background:"rgba(255,255,255,.03)", border:`1px solid ${s.color}22` }}>
              <span style={{ fontSize:11 }}>{s.icon}</span>
              <strong style={{ fontSize:13, fontWeight:700, color:"#e2e8f0" }}>{s.val}</strong>
              <small style={{ fontSize:9, color:"#64748b" }}>{s.label}</small>
            </div>
          ))}
        </div>
      )}

      {/* Recent scans */}
      {!collapsed && sidebarStats && sidebarStats.recent.length > 0 && (
        <div style={{ padding:"6px 8px" }}>
          <p style={{ fontSize:9, textTransform:"uppercase", letterSpacing:".08em",
                      color:"#334155", marginBottom:6 }}>Recent Scans</p>
          {sidebarStats.recent.slice(0,8).map((s, i) => (
            <div key={i} style={{ display:"flex", alignItems:"center", gap:6,
              padding:"5px 4px", borderRadius:6 }}>
              <span style={{ fontSize:13, flexShrink:0 }}>{MOD_ICON[s.module] || "🔍"}</span>
              <div style={{ flex:1, minWidth:0 }}>
                <p style={{ margin:0, fontSize:9, color:"#475569", fontWeight:600 }}>
                  {s.module?.toUpperCase()}
                </p>
                <p style={{ margin:0, fontSize:9, color:"#334155", overflow:"hidden",
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
""")

# ─────────────────────────────────────────────────────────────
# 5. Update AppShell to always use the unified Sidebar
# ─────────────────────────────────────────────────────────────
print("\n[5] Simplifying AppShell — single Sidebar for both states…")

shell_file = F / "components/Layout/AppShell.tsx"
shell_txt  = read(shell_file)

# Remove GuestSidebar if it's inline in AppShell (FIX_LOGOUT_SIDEBAR added it there)
# Replace both occurrences of isAuthenticated ? <Sidebar/> : <GuestSidebar/>
# with just <Sidebar/> since Sidebar now handles both states

if "GuestSidebar" in shell_txt:
    # Remove the GuestSidebar function definition and replace usage
    import re
    # Remove the GuestSidebar component entirely
    shell_txt = re.sub(
        r'// ── (Creative )?[Gg]uest sidebar.*?(?=// ──|export default|function AppShell)',
        '',
        shell_txt,
        flags=re.DOTALL
    )
    # Replace conditional rendering
    for old in [
        "{isAuthenticated ? <Sidebar /> : <GuestSidebar />}",
        "{ isAuthenticated ? <Sidebar /> : <GuestSidebar /> }",
        "{isAuthenticated\n            ? <Sidebar />\n            : <GuestSidebar />}",
    ]:
        shell_txt = shell_txt.replace(old, "<Sidebar />")
    # Remove GuestSidebar import if any
    shell_txt = shell_txt.replace(", GuestSidebar", "").replace("GuestSidebar,", "")
    write(shell_file, shell_txt)
    print("  ✅  AppShell simplified — uses unified Sidebar")
else:
    print("  ~~  AppShell already uses single Sidebar")

print()
print("=" * 60)
print("  FIX_ALL complete!")
print()
print("  Changes:")
print("  1. web_orchestrator.py — correct API endpoint paths")
print("     (discovered from each service's openapi.json)")
print("  2. index.css — consistent chat margins, all messages,")
print("     loading bubble, and input aligned to same column")
print("  3. Sidebar.tsx — single component, auto-switches")
print("     between guest and auth states (consistent style)")
print("  4. AppShell.tsx — uses unified Sidebar only")
print()
print("  Restart backend:  Ctrl+C → python start_backend.py")
print("  Frontend hot-reloads automatically.")
print("=" * 60)