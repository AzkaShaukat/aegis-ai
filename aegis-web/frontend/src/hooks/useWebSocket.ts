import { useEffect, useRef } from "react"
import { useChatStore } from "@/stores/chatStore"
import { useAuthStore  } from "@/stores/authStore"

let _ws:    WebSocket | null = null
let _token  = "__uninit__"
let _beat:  ReturnType<typeof setInterval>  | null = null
let _retry: ReturnType<typeof setTimeout>   | null = null
let _n = 0   // retry count

function tok() { return sessionStorage.getItem("aegis_access_token") || "" }

function status(s: "connecting"|"open"|"closed") {
  useChatStore.setState({ wsStatus: s })
}

function beat() {
  if (_beat) clearInterval(_beat)
  _beat = setInterval(() => {
    if (_ws?.readyState === 1) {
      try { _ws.send(JSON.stringify({ session_id: useChatStore.getState().primarySid, type:"ping" })) } catch {/**/}
    }
  }, 25_000)
}

export function connect() {
  if (_retry) { clearTimeout(_retry); _retry = null }
  const t = tok()
  if (_ws && _token === t && (_ws.readyState===0||_ws.readyState===1)) return
  if (_ws) {
    _ws.onopen=_ws.onmessage=_ws.onerror=_ws.onclose=null
    try{_ws.close(1000)}catch{/**/}
    _ws=null
  }
  _token = t
  const proto = location.protocol==="https:"?"wss:":"ws:"
  const url   = `${proto}//${location.host}${t?`/ws/chat?token=${t}`:"/ws/chat?guest=1"}`
  console.log("[WS] connecting",t?"(auth)":"(guest)")
  status("connecting")
  const ws = new WebSocket(url)
  _ws = ws
  ws.onopen = () => {
    if (_ws!==ws) return
    _n=0; status("open"); beat()
    console.log("[WS] open ✅")
  }
  ws.onmessage = (e) => {
    if (_ws!==ws) return
    try {
      const m = JSON.parse(e.data)
      if (m?.type==="pong") return
      const st = useChatStore.getState()
      const tp = m.type as string
      if (tp==="thinking") {
        st.setThinking(m.content as string||"")
        return
      }
      if (tp==="chunk") {
        st.appendBotChunk(m.message_id as string, m.content as string)
        return
      }
      if (tp==="result") {
        // Pass followups if present, else empty array
        const followups = (m.followups as string[]) || []
        st.appendBotMsg(
          m.message_id as string,
          (m.content as string) || "",
          m.structured as Record<string,unknown>|undefined,
          m.module as string|undefined,
          m.risk_level as string|undefined,
          followups
        )
        st.setStreaming(false)
        if (m.session_id) setTimeout(()=>st.loadStats(),400)
        return
      }
      if (tp==="error") {
        st.setStreamingErr(m.content as string||"Server error")
      }

      // frontend/src/hooks/useWebSocket.ts

      if (tp === "reload") {
  // If user is authenticated, go to login
        if (!tok()) {
          window.location.reload()
        } else {
          sessionStorage.removeItem("aegis_access_token")
          window.location.href = "/login"
        }
    return
  }
    } catch (err) {
      console.warn("[WS] parse error:", err)
    }
  }
  ws.onerror = () => {/*onclose fires*/}
  ws.onclose = (e) => {
    if (_ws!==ws) return
    if (_beat){clearInterval(_beat);_beat=null}
    _ws=null; status("closed")
    console.log("[WS] closed",e.code)
    const d = Math.min(1000*Math.pow(2,_n),30000); _n++
    _retry = setTimeout(connect, d)
  }
}

export function sendWs(payload: Record<string,unknown>) {
  if (_ws?.readyState!==1) return false
  try { _ws.send(JSON.stringify(payload)); return true } catch { return false }
}

export function retryWs() { _n=0; connect() }

export function useWebSocket() {
  const { isRestoring, isAuthenticated } = useAuthStore()
  const wsStatus = useChatStore(s => s.wsStatus)
  const ready = useRef(false)

  useEffect(() => {
    if (isRestoring) return
    if (!ready.current) { ready.current=true; connect() }
  }, [isRestoring])  // eslint-disable-line

  useEffect(() => {
    if (isRestoring) return
    const t = tok()
    if (t !== _token) { _n = 0; connect() }
  }, [isAuthenticated, isRestoring])

  useEffect(() => {
    if (isRestoring) return
    const iv = setInterval(() => {
      if (tok() !== _token) { _n = 0; connect() }
    }, 2000)
    return () => clearInterval(iv)
  }, [isRestoring, isAuthenticated])

  return { status: wsStatus, send: sendWs, retry: retryWs, isGuest: !tok() }
}