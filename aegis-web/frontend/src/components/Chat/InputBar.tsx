import { useRef, ChangeEvent } from "react"
import { Paperclip, Send, X, RotateCcw } from "lucide-react"
import { useChatStore } from "@/stores/chatStore"
import { uploadApi }   from "@/api/client"

interface Props {
  value:               string
  onChange:            (v: string) => void
  onSend:              () => void
  disabled?:           boolean
  wsStatus?:           string
  onRetry?:            () => void
  pendingMediaPreview: string | null
  pendingMediaName:    string | null
  onClearMedia:        () => void
}

export default function InputBar({
  value, onChange, onSend, disabled, wsStatus,
  onRetry, pendingMediaPreview, pendingMediaName, onClearMedia
}: Props) {
  const fileRef = useRef<HTMLInputElement>(null)
  const { setPendingMedia } = useChatStore()

  const handleFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    e.target.value = ""
    try {
      const preview = URL.createObjectURL(file)
      const isVideo = file.type.startsWith("video/")
      const res = await (isVideo ? uploadApi.video(file) : uploadApi.image(file))
      setPendingMedia(res.data.media_id, preview, file.name)
    } catch (err) {
      console.error("Upload failed:", err)
    }
  }

  const handleKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      if (!disabled) onSend()
    }
  }

  const notConn = wsStatus && wsStatus !== "open"

  return (
    <div style={{
      borderTop: "1px solid #21262d", padding: "12px 16px",
      background: "#0d1117", flexShrink: 0,
    }}>
      {/* Media preview */}
      {pendingMediaPreview && (
        <div style={{ marginBottom: 8, position: "relative", display: "inline-block" }}>
          <img src={pendingMediaPreview} alt="preview"
            style={{ maxHeight: 80, maxWidth: 120, borderRadius: 8,
                     border: "1px solid #30363d", objectFit: "cover" }}/>
          <button onClick={onClearMedia} style={{
            position:"absolute", top:-6, right:-6, width:18, height:18,
            borderRadius:"50%", background:"#f85149", border:"none",
            color:"white", cursor:"pointer", fontSize:10, lineHeight:"18px",
            display:"flex", alignItems:"center", justifyContent:"center",
          }}><X size={10}/></button>
          {pendingMediaName && (
            <span style={{ display:"block", fontSize:11, color:"#8b949e", marginTop:3 }}>
              {pendingMediaName}
            </span>
          )}
        </div>
      )}

      {/* Input row */}
      <div style={{
        display:"flex", alignItems:"flex-end", gap:8,
        background:"#161b22", borderRadius:12,
        border:`1px solid ${notConn?"#f8514944":"#30363d"}`,
        padding:"8px 12px",
      }}>
        {/* Attach */}
        <button onClick={() => fileRef.current?.click()}
          title="Attach image or video"
          style={{ background:"none", border:"none", color:"#8b949e",
                   cursor:"pointer", padding:4, flexShrink:0 }}>
          <Paperclip size={16}/>
        </button>
        <input ref={fileRef} type="file" accept="image/*,video/*"
          style={{ display:"none" }} className="chat-input" onChange={handleFile}/>

        {/* Textarea */}
        <textarea
          value={value}
          className="chat-input" onChange={e => onChange(e.target.value)}
          onKeyDown={handleKey}
          disabled={!!disabled}
          placeholder={notConn ? "Not connected — click Retry" : "Paste a URL, email, @handle, CNIC, or suspicious SMS…"}
          rows={1}
          style={{
            flex:1, background:"none", border:"none", outline:"none", resize:"none",
            color: disabled ? "#8b949e" : "#e6edf3",
            fontSize:14, lineHeight:1.5, fontFamily:"inherit",
            minHeight:22, maxHeight:120, overflowY:"auto",
          }}
          onInput={e => {
            const el = e.currentTarget
            el.style.height = "auto"
            el.style.height = Math.min(el.scrollHeight, 120) + "px"
          }}
        />

        {/* Retry when disconnected */}
        {notConn && onRetry && (
          <button onClick={onRetry} title="Reconnect"
            style={{ background:"#1f6feb", border:"none", color:"white",
                     borderRadius:8, padding:"6px 10px", cursor:"pointer",
                     display:"flex", alignItems:"center", gap:4, fontSize:12 }}>
            <RotateCcw size={13}/> Retry
          </button>
        )}

        {/* Send */}
        {wsStatus === "open" && (
          <button onClick={onSend}
            disabled={!!disabled || (!value.trim() && !pendingMediaPreview)}
            style={{
              background: (!disabled && (value.trim()||pendingMediaPreview)) ? "#1f6feb" : "#21262d",
              border:"none", color:"white", borderRadius:8, padding:"6px 10px",
              cursor: disabled ? "not-allowed" : "pointer",
              display:"flex", alignItems:"center",
            }}>
            <Send size={14}/>
          </button>
        )}
      </div>
    </div>
  )
}
