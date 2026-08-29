import React, { useEffect, useRef, useState, useCallback } from "react"
import { useAuthStore }  from "@/stores/authStore"
import { useChatStore }  from "@/stores/chatStore"
import InputBar          from "@/components/Chat/InputBar"
import { MessageBubble } from "@/components/Chat/MessageBubble"
import { WelcomeScreen } from "@/components/Chat/WelcomeScreen"
import { useWebSocket, sendWs, retryWs } from "@/hooks/useWebSocket"

export default function ChatPage() {
  const { user }    = useAuthStore()
  const {
    messages, isStreaming, thinkingText, hasMore,
    primarySid, initSession, loadHistory, wsStatus,
    pendingMediaPreview, pendingMediaName, pendingMediaId,
    setPendingMedia, appendUserMsg,
  } = useChatStore()

  // useWebSocket just manages connection lifecycle — send/retry use module-level fns
  useWebSocket()

  const bottomRef              = useRef<HTMLDivElement>(null)
  const [input, setInput]      = useState("")
  const [autoScroll, setAutoScroll] = useState(true)

  // ── Init session on mount / auth change ──────────────────
  useEffect(() => {
    if (user) initSession().catch(console.warn)
  }, [user?.id])

  // ── Auto-scroll ───────────────────────────────────────────
  useEffect(() => {
    if (autoScroll) bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages, thinkingText, autoScroll])

  // ── Scroll handler ────────────────────────────────────────
  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 80
    setAutoScroll(atBottom)
    if (el.scrollTop < 100 && hasMore) {
      const oldest = messages[0]?.id
      if (oldest) loadHistory(oldest)
    }
  }, [messages, hasMore])

  // ── Send ──────────────────────────────────────────────────
  const handleSend = useCallback(() => {
    const text = input.trim()
    if (!text && !pendingMediaId) return

    // Add user message to UI immediately
    appendUserMsg(text, pendingMediaPreview ?? undefined, pendingMediaName ?? undefined)
    setInput("")

    // Build payload for WebSocket
    const payload: Record<string, unknown> = {
      type:       "message",
      session_id: primarySid,
      content:    text,
    }
    if (pendingMediaId) {
      payload.media_id = pendingMediaId
    }

    const sent = sendWs(payload)
    if (!sent) {
      // WS not open yet — store will show error after timeout
      useChatStore.getState().setStreamingErr("Not connected. Please wait and retry.")
    }

    // Clear pending media
    setPendingMedia(null, null, null)
  }, [input, pendingMediaId, pendingMediaPreview, pendingMediaName, primarySid, appendUserMsg, setPendingMedia])

  const handleClearMedia = () => setPendingMedia(null, null, null)

  const isEmpty = messages.length === 0 && !isStreaming

  return (
    <div className="chat-page">
      {/* Connection status banner */}
      {wsStatus === "closed" && (
        <div className="ws-banner">
          ⚠️ Disconnected from server
          <button onClick={() => retryWs()}>Retry</button>
        </div>
      )}

      {/* Messages area */}
      <div className="chat-messages" onScroll={handleScroll}>
        {hasMore && (
          <button className="load-more-btn" onClick={() => {
            const oldest = messages[0]?.id
            if (oldest) loadHistory(oldest)
          }}>
            ↑ Load older messages
          </button>
        )}

        {isEmpty
          ? <WelcomeScreen isAuthenticated={!!user} />
          : messages.map(m => <MessageBubble key={m.id} message={m} />)
        }

        {/* Thinking indicator */}
        {isStreaming && thinkingText && (
          <div className="thinking-bubble">
            <div className="thinking-dots"><span/><span/><span/></div>
            <span className="thinking-text">{thinkingText}</span>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      <InputBar
        value={input}
        onChange={setInput}
        onSend={handleSend}
        disabled={isStreaming || wsStatus !== "open"}
        wsStatus={wsStatus}
        onRetry={() => retryWs()}
        pendingMediaPreview={pendingMediaPreview}
        pendingMediaName={pendingMediaName}
        onClearMedia={handleClearMedia}
      />
    </div>
  )
}
