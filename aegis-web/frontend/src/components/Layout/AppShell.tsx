import { useState } from "react"
import { Link, useNavigate } from "react-router-dom"
import { Menu, X, LogIn, UserPlus, History, LogOut, ChevronDown,
         Shield, Link2, Mail, User, MessageSquare, Camera, Fingerprint } from "lucide-react"
import { Sidebar } from "@/components/Sidebar/Sidebar"
import { useAuthStore } from "@/stores/authStore"
import { cn } from "@/utils/helpers"

let HistoryModal: React.ComponentType<{ onClose: () => void }> | null = null
try { HistoryModal = require("@/components/Chat/HistoryModal").default } catch { /**/ }

// ── AppShell ──────────────────────────────────────────────────
export default function AppShell({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebar] = useState(true)
  const [mobileOpen,  setMobile]  = useState(false)
  const [historyOpen, setHistory] = useState(false)
  const [userMenu,    setUserMenu] = useState(false)

  const { isAuthenticated, user, logout } = useAuthStore()
  const nav = useNavigate()

  const handleLogout = async () => {
    setUserMenu(false)
    await logout()
    nav("/")
  }

  const initials = user?.display_name
    ? user.display_name.split(" ").map((n: string) => n[0]).join("").toUpperCase().slice(0, 2)
    : "?"

  // 280px when open, 0 when collapsed
  const SIDEBAR_W = 280

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden", background: "#0b1120" }}>

      {/* ── Desktop sidebar ─────────────────────────────── */}
      <div style={{
        width: sidebarOpen ? SIDEBAR_W : 0,
        minWidth: sidebarOpen ? SIDEBAR_W : 0,
        flexShrink: 0,
        transition: "width .2s, min-width .2s",
        overflow: "hidden",
        display: "flex",
      }}
        className="hidden md:flex"
      >
        <Sidebar />
      </div>

      {/* ── Mobile overlay ──────────────────────────────── */}
      {mobileOpen && (
        <>
          <div
            style={{ position: "fixed", inset: 0, zIndex: 40, background: "rgba(0,0,0,.6)" }}
            className="md:hidden"
            onClick={() => setMobile(false)}
          />
          <div style={{
            position: "fixed", left: 0, top: 0, height: "100%",
            zIndex: 50, width: SIDEBAR_W,
            boxShadow: "4px 0 24px rgba(0,0,0,.4)",
          }}
            className="md:hidden"
          >
            <Sidebar />
          </div>
        </>
      )}

      {/* ── Main area ───────────────────────────────────── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, overflow: "hidden" }}>

        {/* Header */}
        <header style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          height: 48, padding: "0 16px",
          borderBottom: "1px solid #1e293b",
          background: "rgba(11,17,32,.95)",
          backdropFilter: "blur(8px)",
          flexShrink: 0,
        }}>
          {/* Hamburger */}
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <button
              onClick={() => setSidebar(v => !v)}
              style={{
                background: "none",
                border: "none",
                color: "#64748b",
                cursor: "pointer",
                padding: 6,
                borderRadius: 8,
      // display: "none"  // REMOVED – now always visible
            }}
            title="Toggle sidebar"
            >
            <Menu size={16} />
            </button>
            {/* REMOVED the useless mobile toggle button */}
          </div>

          {/* Auth area */}
          {isAuthenticated && user ? (
            <div style={{ position: "relative" }}>
              <button
                onClick={() => setUserMenu(v => !v)}
                style={{
                  display: "flex", alignItems: "center", gap: 8,
                  padding: "6px 10px", borderRadius: 8, cursor: "pointer",
                  background: "none", border: "none",
                }}
              >
                <div style={{
                  width: 28, height: 28, borderRadius: "50%",
                  background: "rgba(99,102,241,.2)", border: "1px solid rgba(99,102,241,.3)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 11, fontWeight: 700, color: "#818cf8",
                }}>
                  {initials}
                </div>
                <span style={{ fontSize: 13, color: "#e2e8f0", maxWidth: 120,
                               overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {user.display_name}
                </span>
                <ChevronDown size={13} color="#64748b"
                  style={{ transform: userMenu ? "rotate(180deg)" : "none", transition: "transform .15s" }} />
              </button>

              {userMenu && (
                <div style={{
                  position: "absolute", right: 0, top: "calc(100% + 4px)",
                  width: 210, background: "#161b22",
                  border: "1px solid #30363d", borderRadius: 12,
                  boxShadow: "0 8px 32px rgba(0,0,0,.4)",
                  padding: "6px 0", zIndex: 50,
                }}
                  onClick={() => setUserMenu(false)}
                >
                  <div style={{ padding: "8px 12px 10px", borderBottom: "1px solid #30363d", marginBottom: 4 }}>
                    <p style={{ margin: 0, fontSize: 13, fontWeight: 600, color: "#e2e8f0",
                                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {user.display_name}
                    </p>
                    <p style={{ margin: 0, fontSize: 11, color: "#64748b",
                                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {user.email}
                    </p>
                  </div>
                  {HistoryModal && (
                    <button
                      onClick={() => setHistory(true)}
                      style={{ width: "100%", display: "flex", alignItems: "center", gap: 10,
                               padding: "8px 12px", background: "none", border: "none",
                               color: "#c9d1d9", fontSize: 13, cursor: "pointer", textAlign: "left" }}
                    >
                      <History size={14} /> Scan History
                    </button>
                  )}
                  <div style={{ borderTop: "1px solid #30363d", margin: "4px 0" }} />
                  <button
                    onClick={handleLogout}
                    style={{ width: "100%", display: "flex", alignItems: "center", gap: 10,
                             padding: "8px 12px", background: "none", border: "none",
                             color: "#f87171", fontSize: 13, cursor: "pointer", textAlign: "left" }}
                  >
                    <LogOut size={14} /> Sign out
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Link to="/login" style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "6px 12px", borderRadius: 8, fontSize: 12, fontWeight: 500,
                color: "#94a3b8", border: "1px solid #334155", textDecoration: "none",
              }}>
                <LogIn size={13} /> Sign in
              </Link>
              <Link to="/register" style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "6px 12px", borderRadius: 8, fontSize: 12, fontWeight: 600,
                background: "linear-gradient(135deg,#6366f1,#8b5cf6)",
                color: "white", textDecoration: "none",
              }}>
                <UserPlus size={13} /> Register
              </Link>
            </div>
          )}
        </header>

        {/* Page */}
        <main style={{ flex: 1, display: "flex", flexDirection: "column",
                       minHeight: 0, overflow: "hidden" }}>
          {children}
        </main>
      </div>

      {historyOpen && HistoryModal && <HistoryModal onClose={() => setHistory(false)} />}

      <style>{`
        @media (min-width: 768px) {
          .md-hamburger { display: flex !important; }
        }
      `}</style>
    </div>
  )
}
