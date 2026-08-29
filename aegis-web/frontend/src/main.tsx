import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import "./index.css"

// Show errors visibly on the page — essential for diagnosing blank screens
function showFatalError(msg: string) {
  const root = document.getElementById("root")!
  root.innerHTML = `
    <div style="
      min-height:100vh; background:#0d1117; display:flex;
      align-items:center; justify-content:center; padding:24px; font-family:monospace;
    ">
      <div style="
        max-width:600px; width:100%; background:#161b22; border:1px solid #f8514966;
        border-radius:16px; padding:32px; color:#e6edf3;
      ">
        <div style="font-size:32px; margin-bottom:12px;">⚠️</div>
        <h1 style="color:#f85149; font-size:16px; margin:0 0 12px;">Aegis AI — Startup Error</h1>
        <pre style="
          background:#0d1117; border:1px solid #21262d; border-radius:8px;
          padding:16px; font-size:12px; color:#f0883e; white-space:pre-wrap;
          word-break:break-all; overflow-x:auto; max-height:300px; overflow-y:auto;
        ">${msg}</pre>
        <p style="color:#8b949e; font-size:12px; margin-top:16px;">
          See browser console (F12) for full stack trace.<br/>
          Common fixes: check that all imports exist, run <code style="color:#58a6ff">python FIX_COMPLETE.py</code>
        </p>
        <button onclick="location.reload()" style="
          margin-top:16px; padding:10px 20px; background:#1f6feb; color:white;
          border:none; border-radius:8px; cursor:pointer; font-size:13px;
        ">Reload</button>
      </div>
    </div>
  `.replace(/\${msg}/g, msg)
}

// Catch synchronous errors before React mounts
window.addEventListener("error", (e) => {
  console.error("Global error:", e)
  showFatalError(`${e.message}\n\nFile: ${e.filename}\nLine: ${e.lineno}`)
})

window.addEventListener("unhandledrejection", (e) => {
  console.error("Unhandled promise rejection:", e.reason)
  showFatalError(`Unhandled Promise: ${e.reason?.message || String(e.reason)}\n\n${e.reason?.stack || ""}`)
})

// Dynamic import so module-level errors in App are caught
import("./App").then(({ default: App }) => {
  const el = document.getElementById("root")
  if (!el) { showFatalError("No #root element in HTML!"); return }
  try {
    createRoot(el).render(<StrictMode><App /></StrictMode>)
  } catch (err: unknown) {
    showFatalError(err instanceof Error ? `${err.message}\n\n${err.stack}` : String(err))
  }
}).catch((err: unknown) => {
  showFatalError(
    `Failed to load App module:\n\n${err instanceof Error ? err.message + "\n\n" + err.stack : String(err)}`
  )
})
