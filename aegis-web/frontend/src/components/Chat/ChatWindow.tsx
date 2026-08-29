import { useEffect, useRef } from "react"
import { Message } from "@/types"
import MessageBubble, { ThinkingBubble } from "./MessageBubble"

interface Props {
  messages:          Message[]
  isStreaming:       boolean
  thinkingText:      string
  onSuggestionClick: (text: string) => void
}

const SUGGESTIONS = [
  { label: "🔗 Check a link",          prompt: "https://suspicious-example.tk" },
  { label: "📧 Check email for breach", prompt: "check if test@example.com was breached" },
  { label: "👤 Analyse a social profile", prompt: "@suspicious_handle" },
  { label: "📩 Detect SMS scam",        prompt: "You won! Claim at http://scam.tk now" },
]

export default function ChatWindow({ messages, isStreaming, thinkingText, onSuggestionClick }: Props) {
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages, isStreaming])

  if (messages.length === 0) {
    return (
      <div style={{ flex:1, display:"flex", flexDirection:"column",
                    alignItems:"center", justifyContent:"center",
                    padding:32, textAlign:"center", overflowY:"auto" }}>
        {/* Logo */}
        <div style={{ width:64, height:64, borderRadius:16, marginBottom:20,
                      background:"rgba(31,111,235,0.1)", border:"1px solid rgba(31,111,235,0.2)",
                      display:"flex", alignItems:"center", justifyContent:"center" }}>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#1f6feb" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>

        <h1 style={{ color:"#e6edf3", fontSize:26, fontWeight:700, margin:"0 0 8px" }}>Aegis AI</h1>
        <p style={{ color:"#8b949e", fontSize:14, maxWidth:420, lineHeight:1.7, margin:"0 0 32px" }}>
          Your cybersecurity assistant. Scan links, check credentials,
          analyse social profiles, and detect scam messages — all in one place.
        </p>

        {/* Suggestion cards */}
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12,
                      width:"100%", maxWidth:560 }}>
          {SUGGESTIONS.map(({ label, prompt }) => (
            <button key={label} onClick={() => onSuggestionClick(prompt)}
              style={{ padding:"14px 16px", borderRadius:12, border:"1px solid #30363d",
                       background:"#161b22", color:"#c9d1d9", fontSize:13, cursor:"pointer",
                       textAlign:"left", transition:"all 0.15s" }}
              onMouseOver={e => { const el = e.currentTarget as HTMLButtonElement
                el.style.background = "#21262d"; el.style.borderColor = "#58a6ff44" }}
              onMouseOut={e => { const el = e.currentTarget as HTMLButtonElement
                el.style.background = "#161b22"; el.style.borderColor = "#30363d" }}>
              {label}
            </button>
          ))}
        </div>

        {/* Capability pills */}
        <div style={{ display:"flex", flexWrap:"wrap", gap:8, justifyContent:"center",
                      maxWidth:480, marginTop:24 }}>
          {["🔗 Link Scanning","📷 QR Codes","🔑 Credential Breaches",
            "👤 Social Profiles","📩 SMS Scams","🎭 Deepfake Detection"].map(c => (
            <span key={c} style={{ padding:"5px 12px", borderRadius:20, fontSize:12,
                                    border:"1px solid #30363d", color:"#8b949e",
                                    background:"rgba(22,27,34,0.6)" }}>
              {c}
            </span>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div style={{ flex:1, overflowY:"auto", padding:"24px 16px" }}>
      <div style={{ maxWidth:740, margin:"0 auto", display:"flex",
                    flexDirection:"column", gap:24 }}>
        {messages.map((m, i) => (
          <MessageBubble key={m.id} message={m} isLast={i === messages.length - 1} />
        ))}
        {isStreaming && <ThinkingBubble text={thinkingText} />}
        <div ref={endRef} />
      </div>
    </div>
  )
}
