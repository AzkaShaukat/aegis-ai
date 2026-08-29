import axios from "axios"

// ── Token store (reads from storage so authStore and client stay in sync) ──────
export const tokenStore = {
  getAccess:    () => sessionStorage.getItem("aegis_access_token") || "",
  setAccess:    (t: string) => { sessionStorage.setItem("aegis_access_token", t); axios.defaults.headers.common["Authorization"] = `Bearer ${t}` },
  getRefresh:   () => localStorage.getItem("aegis_refresh_token") || "",
  setRefresh:   (t: string) => localStorage.setItem("aegis_refresh_token", t),
  clearAll:     () => { sessionStorage.removeItem("aegis_access_token"); localStorage.removeItem("aegis_refresh_token"); delete axios.defaults.headers.common["Authorization"] },
}

// Initialize axios auth header from storage on module load
const storedToken = tokenStore.getAccess()
if (storedToken) axios.defaults.headers.common["Authorization"] = `Bearer ${storedToken}`

// ── API base ──────────────────────────────────────────────────────────────────
const api = axios.create({ baseURL: "/" })

// Attach token to every request
api.interceptors.request.use((config) => {
  const token = tokenStore.getAccess()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ── Auth API ──────────────────────────────────────────────────────────────────
export const authApi = {
  login:              (email: string, password: string) => api.post("/api/auth/login", { email, password }),
  register:           (email: string, password: string, display_name: string) => api.post("/api/auth/register", { email, password, display_name }),
  logout:             (refresh_token: string) => api.post("/api/auth/logout", { refresh_token }),
  refresh:            (refresh_token: string) => api.post("/api/auth/refresh", { refresh_token }),
  me:                 () => api.get("/api/auth/me"),
  verifyEmail:        (token: string) => api.post("/api/auth/verify-email", { token }),
  resendVerification: (email: string) => api.post("/api/auth/resend-verification", { email }),
  forgotPassword:     (email: string) => api.post("/api/auth/forgot-password", { email }),
  resetPassword:      (token: string, new_password: string) => api.post("/api/auth/reset-password", { token, new_password }),
}

// ── Chat API ──────────────────────────────────────────────────────────────────
export const chatApi = {
  listSessions:  () => api.get("/api/chat/sessions"),
  getSession:    (id: string) => api.get(`/api/chat/sessions/${id}`),
  renameSession: (id: string, title: string) => api.patch(`/api/chat/sessions/${id}`, { title }),
  deleteSession: (id: string) => api.delete(`/api/chat/sessions/${id}`),
}

// ── Upload API ────────────────────────────────────────────────────────────────
export const uploadApi = {
  image: (file: File, onProgress?: (pct: number) => void) => {
    const form = new FormData(); form.append("file", file)
    return api.post("/api/upload/image", form, {
      headers: { "Content-Type": "multipart/form-data" },
      onUploadProgress: e => onProgress?.(Math.round((e.loaded * 100) / (e.total || 1))),
    })
  },
  video: (file: File, onProgress?: (pct: number) => void) => {
    const form = new FormData(); form.append("file", file)
    return api.post("/api/upload/video", form, {
      headers: { "Content-Type": "multipart/form-data" },
      onUploadProgress: e => onProgress?.(Math.round((e.loaded * 100) / (e.total || 1))),
    })
  },
}

// ── History API ───────────────────────────────────────────────────────────────
export const historyApi = {
  get30Days: () => api.get("/api/history/30days"),
  getStats:  () => api.get("/api/history/stats"),
}

export default api
