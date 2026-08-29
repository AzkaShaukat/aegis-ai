import React from "react"
import { useChatStore } from "@/stores/chatStore"

interface Props { isAuthenticated: boolean }

const ACTIONS = [
  { icon: "🔗", label: "Check a link",         placeholder: "Paste a URL to analyse…",          hint: "https://example.com" },
  { icon: "📧", label: "Check email for breach",placeholder: "Enter email to check for breaches…", hint: "you@example.com" },
  { icon: "👤", label: "Analyse social profile", placeholder: "Enter @handle or profile URL…",     hint: "@username" },
  { icon: "💬", label: "Detect SMS scam",        placeholder: "Paste a suspicious message…",       hint: "You've won a prize! Click here…" },
]

const CHIPS = [
  { icon: "🔗", label: "Link Scanning" },
  { icon: "📷", label: "QR Codes" },
  { icon: "🔑", label: "Credential Breaches" },
  { icon: "👤", label: "Social Profiles" },
  { icon: "💬", label: "SMS Scams" },
  { icon: "🎭", label: "Deepfake Detection" },
]

export function WelcomeScreen({ isAuthenticated }: Props) {
  const handleAction = (placeholder: string, hint: string) => {
    const input = document.querySelector<HTMLTextAreaElement>(".chat-input")
    if (input) {
      input.placeholder = placeholder
      input.focus()
      // Show hint briefly
      input.setAttribute("data-hint", hint)
    }
  }

  return (
    <div className="welcome-screen">
      <div className="welcome-icon">🛡️</div>
      <h1 className="welcome-title">Aegis AI</h1>
      <p className="welcome-sub">
        Your cybersecurity assistant. Scan links, check credentials,<br/>
        analyse social profiles, and detect scam messages — all in one place.
      </p>

      <div className="action-grid">
        {ACTIONS.map(a => (
          <button key={a.label} className="action-card"
            onClick={() => handleAction(a.placeholder, a.hint)}
          >
            <span className="action-icon">{a.icon}</span>
            <span className="action-label">{a.label}</span>
          </button>
        ))}
      </div>

      <div className="capability-chips">
        {CHIPS.map(c => (
          <span key={c.label} className="cap-chip">
            {c.icon} {c.label}
          </span>
        ))}
      </div>
    </div>
  )
}
