import { create } from "zustand";
import axios from "axios";

export interface Message {
  id: string;
  role: "user" | "bot";
  content: string;
  structured?: Record<string, unknown> | null;
  module_used?: string | null;
  risk_level?: string | null;
  media_url?: string | null;
  media_type?: string | null;
  created_at: string;
  followups?: string[];              // <-- added
}

export interface ScanStat {
  module: string;
  risk: string;
  excerpt: string;
  time: string | null;
}

export interface SidebarStats {
  total: number;
  safe: number;
  warning: number;
  danger: number;
  recent: ScanStat[];
}

interface ChatStore {
  primarySid: string | null;
  messages: Message[];
  hasMore: boolean;
  isStreaming: boolean;
  thinkingText: string;
  streamingMsgId: string | null;
  wsStatus: "connecting" | "open" | "closed";
  pendingMediaId: string | null;
  pendingMediaPreview: string | null;
  pendingMediaName: string | null;
  sidebarStats: SidebarStats | null;

  setWsStatus: (s: "connecting" | "open" | "closed") => void;
  setPrimarySession: (sid: string) => void;
  initSession: () => Promise<void>;
  loadHistory: (before?: string) => Promise<void>;
  loadStats: () => Promise<void>;
  appendUserMsg: (content: string, preview?: string, name?: string) => string;
  appendBotChunk: (id: string, chunk: string) => void;
  appendBotMsg: (
    id: string,
    content: string,
    structured?: unknown,
    module_used?: string,
    risk?: string,
    followups?: string[]           // <-- added
  ) => void;
  setThinking: (t: string) => void;
  setStreaming: (v: boolean) => void;
  setStreamingErr: (msg: string) => void;
  setPendingMedia: (
    id: string | null,
    preview: string | null,
    name: string | null
  ) => void;
  reset: () => void;
}

const BLANK = {
  primarySid: null,
  messages: [] as Message[],
  hasMore: false,
  isStreaming: false,
  thinkingText: "",
  streamingMsgId: null,
  wsStatus: "connecting" as const,
  pendingMediaId: null,
  pendingMediaPreview: null,
  pendingMediaName: null,
  sidebarStats: null,
};

const token = () => sessionStorage.getItem("aegis_access_token");
const ax = () =>
  axios.create({ headers: { Authorization: `Bearer ${token()}` } });

export const useChatStore = create<ChatStore>((set, get) => ({
  ...BLANK,

  setWsStatus: (s) => set({ wsStatus: s }),

  setPrimarySession: (sid) => {
    if (sid !== get().primarySid) {
      set({ primarySid: sid, messages: [], hasMore: false });
      get().loadHistory();
    }
  },

  // Implementation of initSession — dedup guard prevents concurrent calls
  // which caused duplicate /api/auth/refresh requests → DB UniqueViolation
  _initSessionInFlight: false as unknown as boolean,

  initSession: async () => {
    if (!token()) return;
    const store = get() as ChatStore & { _initSessionInFlight: boolean };
    if (store._initSessionInFlight) return;          // already running
    (store as any)._initSessionInFlight = true;
    try {
      // Get or create primary session
      const res = await ax().get("/api/chat/primary-session");
      const sid = res.data?.session_id;
      if (sid && sid !== get().primarySid) {
        set({ primarySid: sid, messages: [], hasMore: false });
        // Load last 100 messages
        const h = await ax().get("/api/chat/history", { params: { limit: "100" } });
        const msgs = (h.data?.messages || []).map(
          (m: {
            id: string;
            role: string;
            content: string;
            structured?: unknown;
            module_used?: string;
            risk_level?: string;
            created_at: string;
          }) => ({
            id: m.id,
            role: (m.role || "").toLowerCase() === "user" ? "user" : "bot",
            content: m.content || "",
            structured: (m.structured as Record<string, unknown> | null) || null,
            module_used: m.module_used || null,
            risk_level: m.risk_level || null,
            media_url: null,
            media_type: null,
            created_at: m.created_at,
            followups: undefined,         // not stored
          })
        );
        set({ messages: msgs, hasMore: msgs.length >= 100, primarySid: sid });
      }
    } catch (e) {
      console.warn("[Chat] initSession:", e);
    } finally {
      (get() as any)._initSessionInFlight = false;   // always release lock
    }
  },

  loadHistory: async (before?: string) => {
    if (!token()) return;
    try {
      const params: Record<string, string> = { limit: "100" };
      if (before) params.before_id = before;
      const res = await ax().get("/api/chat/history", { params });
      const msgs: Message[] = (res.data.messages || []).map(
        (m: {
          id: string;
          role: string;
          content: string;
          structured?: unknown;
          module_used?: string;
          risk_level?: string;
          created_at: string;
        }) => ({
          id: m.id,
          role: (m.role || "").toLowerCase() === "user" ? "user" : "bot",
          content: m.content || "",
          structured: (m.structured as Record<string, unknown> | null) || null,
          module_used: m.module_used || null,
          risk_level: m.risk_level || null,
          media_url: null,
          media_type: null,
          created_at: m.created_at,
          followups: undefined,
        })
      );
      if (before) {
        // prepend older messages
        set((s) => ({
          messages: [...msgs, ...s.messages],
          hasMore: msgs.length === 100,
        }));
      } else {
        set({ messages: msgs, hasMore: msgs.length === 100 });
      }
      // Also save session id if not set
      if (!get().primarySid && res.data.session_id) {
        set({ primarySid: res.data.session_id });
      }
    } catch (e) {
      console.warn("[Chat] loadHistory:", e);
    }
  },

  loadStats: async () => {
    if (!token()) return;
    try {
      const res = await ax().get("/api/chat/sidebar-stats");
      set({ sidebarStats: res.data });
    } catch (e) {
      console.warn("[Chat] loadStats:", e);
    }
  },

  appendUserMsg: (content, preview, name) => {
    const id = `user-${Date.now()}`;
    set((s) => ({
      messages: [
        ...s.messages,
        {
          id,
          role: "user" as const,
          content: content || (name ? `📎 ${name}` : ""),
          media_url: preview || null,
          media_type: preview ? "image" : null,
          structured: null,
          module_used: null,
          risk_level: null,
          created_at: new Date().toISOString(),
          followups: undefined,
        },
      ],
      isStreaming: true,
      thinkingText: "",
    }));
    return id;
  },

  appendBotChunk: (msgId, chunk) =>
    set((s) => {
      if (s.messages.find((m) => m.id === msgId))
        return {
          messages: s.messages.map((m) =>
            m.id === msgId ? { ...m, content: m.content + chunk } : m
          ),
        };
      return {
        streamingMsgId: msgId,
        messages: [
          ...s.messages,
          {
            id: msgId,
            role: "bot" as const,
            content: chunk,
            structured: null,
            module_used: null,
            risk_level: null,
            media_url: null,
            media_type: null,
            created_at: new Date().toISOString(),
            followups: undefined,
          },
        ],
      };
    }),

  appendBotMsg: (msgId, content, structured, module_used, risk_level, followups) =>
    set((s) => {
      const bot: Message = {
        id: msgId,
        role: "bot",
        content,
        structured: (structured as Record<string, unknown> | null) || null,
        module_used: module_used || null,
        risk_level: risk_level || null,
        media_url: null,
        media_type: null,
        created_at: new Date().toISOString(),
        followups: followups || [],
      };
      return {
        messages: s.messages.find((m) => m.id === msgId)
          ? s.messages.map((m) => (m.id === msgId ? bot : m))
          : [...s.messages, bot],
        isStreaming: false,
        streamingMsgId: null,
        thinkingText: "",
      };
    }),

  setThinking: (t) => set({ thinkingText: t }),

  setStreaming: (v) => set({ isStreaming: v, ...(!v ? { thinkingText: "" } : {}) }),

  setStreamingErr: (msg) =>
    set((s) => ({
      isStreaming: false,
      thinkingText: "",
      messages: [
        ...s.messages,
        {
          id: `err-${Date.now()}`,
          role: "bot" as const,
          content: `⚠️ ${msg}`,
          structured: null,
          module_used: null,
          risk_level: null,
          media_url: null,
          media_type: null,
          created_at: new Date().toISOString(),
          followups: [],
        },
      ],
    })),

  setPendingMedia: (id, preview, name) =>
    set({
      pendingMediaId: id,
      pendingMediaPreview: preview,
      pendingMediaName: name,
    }),

  reset: () => set({ ...BLANK }),
}));