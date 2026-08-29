import { create } from "zustand"
import { persist } from "zustand/middleware"

// ── Types ─────────────────────────────────────────────────────
interface User {
  id: string; email: string; display_name: string
  email_verified: boolean; created_at: string; last_login: string | null
}
interface AuthStore {
  user:            User | null
  isAuthenticated: boolean
  isRestoring:     boolean
  error:           string | null
  clearError:      () => void
  login:              (email: string, pwd: string) => Promise<void>
  register:           (email: string, pwd: string, name: string) => Promise<{ needsVerification: boolean; message: string }>
  logout:             () => Promise<void>
  loadUser:           () => Promise<void>
  verifyEmail:        (token: string) => Promise<string>
  resendVerification: (email: string) => Promise<void>
  forgotPassword:     (email: string) => Promise<void>
  resetPassword:      (token: string, pwd: string) => Promise<void>
}

// ── Store ─────────────────────────────────────────────────────
export const useAuthStore = create<AuthStore>()(
  persist(
    (set) => ({
      user: null, isAuthenticated: false,
      // isRestoring = true until loadUser() completes
      isRestoring: true,
      error: null,
      clearError: () => set({ error: null }),

      // ── Restore session from stored refresh token ──────────────
      loadUser: async () => {
        console.log("[Auth] loadUser() called")
        // Safety net: isRestoring MUST become false no matter what happens
        try {
          const { default: axios } = await import("axios")
          const stored = localStorage.getItem("aegis_refresh_token")
          console.log("[Auth] refresh token in storage:", stored ? "found" : "none")

          if (!stored) {
            console.log("[Auth] no token → guest mode")
            set({ isRestoring: false, isAuthenticated: false })
            return
          }

          let access_token: string | null = null

          try {
            const res = await axios.post("/api/auth/refresh", { refresh_token: stored })
            access_token = res.data.access_token
            const newRefresh = res.data.refresh_token
            console.log("[Auth] refresh OK")
            sessionStorage.setItem("aegis_access_token", access_token!)
            if (newRefresh) localStorage.setItem("aegis_refresh_token", newRefresh)
            axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`
          } catch (refreshErr: unknown) {
            const status = (refreshErr as {response?: {status?: number}})?.response?.status
            console.warn("[Auth] refresh failed, status:", status)
            if (!status || status === 401 || status === 403) {
              // Token is revoked/expired — clear it and go guest
              console.warn("[Auth] clearing stale refresh token → guest mode")
              localStorage.removeItem("aegis_refresh_token")
              sessionStorage.removeItem("aegis_access_token")
              set({ user: null, isAuthenticated: false, isRestoring: false })
              return
            }
            // 5xx / network — try existing access token instead
            access_token = sessionStorage.getItem("aegis_access_token")
            if (!access_token) {
              console.warn("[Auth] no fallback access token → guest mode")
              set({ user: null, isAuthenticated: false, isRestoring: false })
              return
            }
            console.warn("[Auth] using cached access token as fallback")
            axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`
          }

          // Fetch user profile
          try {
            const meRes = await axios.get("/api/auth/me", {
              headers: { Authorization: `Bearer ${access_token}` }
            })
            const user = meRes.data
            console.log("[Auth] user loaded:", user.display_name)
            set({ user, isAuthenticated: true, isRestoring: false })
          } catch (meErr: unknown) {
            const status = (meErr as {response?: {status?: number}})?.response?.status
            console.warn("[Auth] /me failed, status:", status)
            // /me failed — clear tokens and go guest
            localStorage.removeItem("aegis_refresh_token")
            sessionStorage.removeItem("aegis_access_token")
            set({ user: null, isAuthenticated: false, isRestoring: false })
          }

        } catch (fatalErr) {
          // Absolute last resort — something totally unexpected happened
          console.error("[Auth] loadUser fatal error:", fatalErr)
          set({ user: null, isAuthenticated: false, isRestoring: false })
        }
      },

      // ── Login ───────────────────────────────────────────────────
      login: async (email, pwd) => {
        console.log("[Auth] login:", email)
        const { default: axios } = await import("axios")
        const { default: toast } = await import("react-hot-toast")
        set({ error: null })
        try {
          const res = await axios.post("/api/auth/login", { email, password: pwd })
          const { access_token, refresh_token } = res.data
          localStorage.setItem("aegis_refresh_token", refresh_token)
          sessionStorage.setItem("aegis_access_token", access_token)
          axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`
          const meRes = await axios.get("/api/auth/me")
          const user = meRes.data
          console.log("[Auth] login OK:", user.display_name)
          set({ user, isAuthenticated: true, isRestoring: false })
          toast.success(`Welcome back, ${user.display_name}!`)
        } catch (e: unknown) {
          const msg = getErrMsg(e, "Sign in failed.")
          console.error("[Auth] login failed:", msg)
          set({ error: msg })
          throw new Error(msg)
        }
      },

      // ── Register ────────────────────────────────────────────────
      register: async (email, pwd, name) => {
        console.log("[Auth] register:", email)
        const { default: axios } = await import("axios")
        const { default: toast } = await import("react-hot-toast")
        set({ error: null })
        try {
          const regRes = await axios.post("/api/auth/register", { email, password: pwd, display_name: name })
          if (!regRes.data.email_verified) {
            return { needsVerification: true, message: regRes.data.message || "Check your inbox." }
          }
          const res = await axios.post("/api/auth/login", { email, password: pwd })
          const { access_token, refresh_token } = res.data
          localStorage.setItem("aegis_refresh_token", refresh_token)
          sessionStorage.setItem("aegis_access_token", access_token)
          axios.defaults.headers.common["Authorization"] = `Bearer ${access_token}`
          const meRes = await axios.get("/api/auth/me")
          set({ user: meRes.data, isAuthenticated: true, isRestoring: false })
          toast.success("Account created!")
          return { needsVerification: false, message: "Account created!" }
        } catch (e: unknown) {
          const msg = getErrMsg(e, "Registration failed.")
          set({ error: msg }); throw new Error(msg)
        }
      },

      // ── Logout ──────────────────────────────────────────────────
      logout: async () => {
        console.log("[Auth] logout")
        const { default: axios } = await import("axios")
        const { default: toast } = await import("react-hot-toast")
        const refresh = localStorage.getItem("aegis_refresh_token")
        if (refresh) {
          try { await axios.post("/api/auth/logout", { refresh_token: refresh }) } catch { /* ignore */ }
        }
        localStorage.removeItem("aegis_refresh_token")
        sessionStorage.removeItem("aegis_access_token")
        delete axios.defaults.headers.common["Authorization"]
        set({ user: null, isAuthenticated: false })
        // Clear all chat messages so guest sees a clean slate
        const { useChatStore } = await import("@/stores/chatStore")
        useChatStore.getState().reset()
        toast.success("Signed out")
      },

      verifyEmail: async (token) => {
        const { default: axios } = await import("axios")
        const res = await axios.post("/api/auth/verify-email", { token })
        return res.data.message as string
      },
      resendVerification: async (email) => {
        const { default: axios } = await import("axios")
        try { await axios.post("/api/auth/resend-verification", { email }) } catch { /* ignore */ }
      },
      forgotPassword: async (email) => {
        const { default: axios } = await import("axios")
        try { await axios.post("/api/auth/forgot-password", { email }) } catch { /* ignore */ }
      },
      resetPassword: async (token, pwd) => {
        const { default: axios } = await import("axios")
        await axios.post("/api/auth/reset-password", { token, new_password: pwd })
      },
    }),
    {
      name: "aegis-auth",
      partialize: (s) => ({ user: s.user }),
    }
  )
)

function getErrMsg(e: unknown, fallback: string): string {
  if (e && typeof e === "object" && "response" in e)
    return ((e as { response?: { data?: { detail?: string } } }).response?.data?.detail) || fallback
  if (e instanceof Error) return e.message
  return fallback
}
