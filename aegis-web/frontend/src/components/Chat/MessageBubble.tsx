import React, { useMemo } from "react"
import { Message } from "@/stores/chatStore"

// ── helpers ────────────────────────────────────────────────────

// Bold specific patterns
function boldPatterns(text: string): React.ReactNode {
  const patterns = [
    /✅\s*SAFE\s*[—\-]\s*Link\s*Analysis/gi,
    /⚠️?\s*MEDIUM\s*[—\-]\s*Link\s*Analysis/gi,
    /🚨?\s*HIGH\s*[—\-]\s*Link\s*Analysis/gi,
    /Verdict:/gi,
    /Action:/gi,
    /Technical Details:/gi,
    /Risk\s*Level:/gi,
    /Confidence:/gi,
    /Flags:/gi,
    /Antivirus:/gi,
    /Domain\s*Age:/gi,
    /Final\s*URL:/gi,
    /URL:/gi,
    /Type:/gi,
    /Payload/gi,
  ]
  const combined = new RegExp(patterns.map(p => p.source).join('|'), 'gi')
  const parts = text.split(combined)
  const matches = text.match(combined)
  const result: React.ReactNode[] = []
  let idx = 0
  for (let i = 0; i < parts.length; i++) {
    if (parts[i]) {
      result.push(parts[i])
    }
    if (matches && i < matches.length) {
      result.push(<strong key={`bold-${idx}`} className="font-bold">{matches[i]}</strong>)
      idx++
    }
  }
  return result.length ? result : text
}

// Detect URLs and render as clickable links
function renderTextWithLinks(text: string): React.ReactNode {
  const parts = text.split(/(https?:\/\/[^\s]+)/g)
  return parts.map((part, i) => {
    if (part.match(/^https?:\/\//)) {
      return (
        <a
          key={i}
          href={part}
          target="_blank"
          rel="noopener noreferrer"
          className="text-blue-600 underline hover:text-blue-800 break-all"
        >
          {part}
        </a>
      )
    }
    return part
  })
}

function inlineRender(text: string): React.ReactNode {
  const withBold = boldPatterns(text)
  if (Array.isArray(withBold)) {
    return withBold.map((part, idx) => {
      if (typeof part === 'string') {
        const mdParts = part.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g)
        return mdParts.map((subpart, j) => {
          if (subpart.startsWith("**") && subpart.endsWith("**")) {
            const content = subpart.slice(2, -2)
            return <strong key={`${idx}-${j}`} className="font-bold">{content}</strong>
          }
          if (subpart.startsWith("*") && subpart.endsWith("*")) {
            return <em key={`${idx}-${j}`} className="italic">{subpart.slice(1, -1)}</em>
          }
          if (subpart.startsWith("`") && subpart.endsWith("`")) {
            return <code key={`code-${idx}-${j}`} className="bg-slate-800 text-slate-200 px-2 py-1 rounded-md text-sm font-mono border border-slate-700">{subpart.slice(1, -1)}</code>
          }
          return renderTextWithLinks(subpart)
        })
      }
      return part
    })
  }
  return renderTextWithLinks(text)
}

// Pre-process text to properly format technical details and bullets
function preprocessText(text: string): string {
  let res = text

  // 1. Convert ⚙️ Technical Details: to a heading ## on its own line
  //    Also ensure it has a newline before and after
  res = res.replace(/(⚙️\s*Technical\s*Details:)/gi, '\n\n## $1\n\n')
  res = res.replace(/(I can analyse:)\s*/gi, '$1\n\n')

  // 2. Add bullets to specific items and ensure they are on their own lines
  const bulletPatterns = [
    /(🛡️\s*Risk\s*Level:)/gi,
    /(🤖\s*Confidence:)/gi,
    /(🚩\s*Flags:)/gi,
    /(🦠\s*Antivirus:)/gi,
    /(📅\s*Domain\s*Age:)/gi,
    /(↪️\s*Final\s*URL:)/gi,
    /(Verdict:)/gi,
    /(Action:)/gi,
    /(🔗\s*Links\b)/gi,
    /(📷\s*QR\s*Codes\b)/gi,
    /(🎭\s*Deepfake\s*Detection\b)/gi,
    /(🔑\s*Credentials\b)/gi,
    /(👤\s*Social\s*Profiles\b)/gi,
  ]

  bulletPatterns.forEach(pattern => {
    // Replace with newline + bullet + the pattern
    res = res.replace(pattern, (match) => {
      // Check if it's already on a new line with bullet
      // We'll just replace and ensure newline before
      return `\n• ${match}`
    })
  })

  // 3. Clean up duplicate newlines
  res = res.replace(/\n{3,}/g, '\n\n')
  res = res.replace(/\n\s*\n\s*\n/g, '\n\n')

  // 4. Ensure "Safe to visit." and "Report:" are on their own lines (not bullets)
  res = res.replace(/(✅\s*Safe\s*to\s*visit\.)/gi, '\n$1')
  res = res.replace(/(📋\s*Report:)/gi, '\n$1')

  // 5. Remove any duplicate bullets (e.g., "• •")
  res = res.replace(/•\s*•/g, '•')

  return res
}

function renderMarkdown(text: string): React.ReactNode[] {
  const processed = preprocessText(text)
  const lines = processed.split("\n")
  const out: React.ReactNode[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    // Empty line
    if (line.trim() === "") { 
      out.push(<br key={i} />); 
      i++; 
      continue 
    }

    // Heading  ## or ###
    if (/^#{2,3}\s/.test(line)) {
      const level = line.match(/^#+/)?.[0]?.length || 2
      const content = line.replace(/^#+\s/, "")
      const size = level === 2 ? "text-2xl" : "text-xl"
      out.push(
        <h2 key={i} className={`${size} font-bold mt-6 mb-3 text-gray-800`}>
          {inlineRender(content)}
        </h2>
      )
      i++; continue
    }

    // Bullet list (Groups consecutive bullets and ignores empty lines between them)
    if (/^[•\-\*]\s/.test(line)) {
      const items: string[] = []
      while (i < lines.length) {
        if (lines[i].trim() === "") {
          // Look ahead to see if the next non-empty line is still a bullet
          let nextI = i + 1;
          while(nextI < lines.length && lines[nextI].trim() === "") nextI++;
          if (nextI < lines.length && /^[•\-\*]\s/.test(lines[nextI])) {
            i = nextI; // Skip empty gaps between bullets
            continue;
          } else {
            break; // End of list
          }
        } else if (/^[•\-\*]\s/.test(lines[i])) {
          items.push(lines[i].replace(/^[•\-\*]\s/, ""))
          i++
        } else {
          break;
        }
      }
      out.push(
        <ul key={`ul-${i}`} className="list-disc pl-6 my-2 space-y-1">
          {items.map((it, j) => (
            <li key={j} className="text-lg leading-relaxed">{inlineRender(it)}</li>
          ))}
        </ul>
      )
      continue
    }

    // Numbered list
    if (/^\d+\.\s/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\.\s/, ""))
        i++
      }
      out.push(
        <ol key={`ol-${i}`} className="list-decimal pl-6 my-2 space-y-1">
          {items.map((it, j) => (
            <li key={j} className="text-lg leading-relaxed">{inlineRender(it)}</li>
          ))}
        </ol>
      )
      continue
    }

    // Normal paragraph – join consecutive lines
    const paraLines: string[] = []
    while (i < lines.length && lines[i].trim() !== "" && !/^[#•\-\*\d]/.test(lines[i])) {
      paraLines.push(lines[i])
      i++
    }
    if (paraLines.length === 0 && i < lines.length) {
      paraLines.push(lines[i])
      i++
    }
    const paraText = paraLines.join(" ")
    out.push(
      <p key={`p-${i}`} className="text-lg leading-relaxed my-1">
        {inlineRender(paraText)}
      </p>
    )
  }
  return out
}

// ── Risk badge (colored with larger size) ────────────────────────
function RiskBadge({ risk }: { risk: string }) {
  const r = (risk || "").toUpperCase()
  let cls = "risk-badge risk-unknown"
  if (r === "CRITICAL" || r === "HIGH" || r === "FAKE" || r === "DEEPFAKE") cls = "risk-badge risk-danger"
  else if (r === "MEDIUM" || r === "WARNING" || r === "LIKELY_FAKE") cls = "risk-badge risk-warning"
  else if (r === "LOW" || r === "SAFE" || r === "CLEAN") cls = "risk-badge risk-safe"
  
  const emoji = r === "CRITICAL" || r === "HIGH" ? "🔴"
    : r === "MEDIUM" || r === "WARNING" ? "🟡"
    : r === "LOW" || r === "SAFE" || r === "CLEAN" ? "🟢" : "⚪"
  return (
    <span className={`${cls} text-2xl font-extrabold px-6 py-2 rounded-full inline-block shadow-sm mb-4`}>
      {emoji} {risk}
    </span>
  )
}

// ── Extract screenshot ─────────────────────────────────────────
function extractScreenshot(content: string): { text: string; screenshotUrl: string | null } {
  const match = content.match(/__SCREENSHOT__\s*(https?:\/\/[^\s]+)\s*__SCREENSHOT__/)
  if (match) {
    const url = match[1].trim()
    const text = content.replace(/__SCREENSHOT__\s*https?:\/\/[^\s]+\s*__SCREENSHOT__/, "").trim()
    return { text, screenshotUrl: url }
  }
  return { text: content, screenshotUrl: null }
}

// ── Main MessageBubble ──────────────────────────────────────────
interface Props { message: Message }

export function MessageBubble({ message }: Props) {
  const isUser = message.role === "user"
  const hasMedia = !!message.media_url

  const { text: cleanContent, screenshotUrl } = useMemo(() => {
    if (!message.content) return { text: "", screenshotUrl: null }
    return extractScreenshot(message.content)
  }, [message.content])

  const rendered = useMemo(() => {
    if (isUser || !cleanContent) return null
    return renderMarkdown(cleanContent)
  }, [cleanContent, isUser])

  const time = useMemo(() => {
    if (!message.created_at) return ""
    return new Date(message.created_at).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})
  }, [message.created_at])

  // Determine bubble color based on risk
  const getBubbleClass = (risk: string) => {
    if (!risk || risk === "null") return "bg-white border border-gray-200"
    const r = risk.toUpperCase()
    if (r === "CRITICAL" || r === "HIGH" || r === "FAKE" || r === "DEEPFAKE") {
      return "bg-red-50 border-red-300 border-2"
    } else if (r === "MEDIUM" || r === "WARNING" || r === "LIKELY_FAKE") {
      return "bg-yellow-50 border-yellow-300 border-2"
    } else if (r === "LOW" || r === "SAFE" || r === "CLEAN") {
      return "bg-green-50 border-green-300 border-2"
    }
    return "bg-white border border-gray-200"
  }

  if (isUser) {
    return (
      <div className="msg-row msg-row-user flex flex-col items-end mb-4 w-full">
        <div className="flex flex-row justify-end items-end w-full">
          <div className="msg-user-bubble">
            {hasMedia && (
              <div className="msg-media">
                {message.media_type?.startsWith("video") ? (
                  <video src={message.media_url!} controls className="msg-video-preview" />
                ) : (
                  <img src={message.media_url!} alt="upload" className="msg-img-preview" />
                )}
              </div>
            )}
            {message.content && <span className="msg-user-text text-lg">{message.content}</span>}
          </div>
          <div className="msg-avatar msg-avatar-user ml-2">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 12c2.7 0 4.8-2.1 4.8-4.8S14.7 2.4 12 2.4 7.2 4.5 7.2 7.2 9.3 12 12 12zm0 2.4c-3.2 0-9.6 1.6-9.6 4.8v2.4h19.2v-2.4c0-3.2-6.4-4.8-9.6-4.8z"/>
            </svg>
          </div>
        </div>
        {/* User message time shifted to the very right and size increased */}
      {/*time && <div className="w-full text-right mt-1"><span className="text-sm text-gray-400 opacity-80">{time}</span></div>}*/}
      </div>
    )
  }

  // Bot message - with dynamic bubble color based on risk
  return (
    <div className="msg-row msg-row-bot flex flex-col items-start mb-4 w-full">
      <div className="flex flex-row items-end w-full">
        <div className="msg-bot-avatar mr-2 mb-1">🛡️</div>
        <div className="msg-bot-content w-full flex-1 max-w-full">
          <div className={`msg-bot-bubble w-full ${getBubbleClass(message.risk_level || '')}`}>
            {/* Risk badge at top if applicable */}
            {message.risk_level && message.risk_level !== "null" && (
              <div className="msg-risk-header">
                <RiskBadge risk={message.risk_level} />
              </div>
            )}

            {/* Rendered markdown content */}
            <div className="msg-body text-lg w-full">{rendered}</div>

            {/* Screenshot */}
            {screenshotUrl && (
              <div className="mt-3">
                <img src={screenshotUrl} alt="Screenshot" className="rounded-lg border max-h-96 w-auto" />
              </div>
            )}
          </div>
        </div>
      </div>
      {/* Bot message time shifted to the very left and size increased */}
      {time && <div className="w-full text-left mt-1"><span className="text-sm text-gray-400 opacity-80">{time}</span></div>}
    </div>
  )
}