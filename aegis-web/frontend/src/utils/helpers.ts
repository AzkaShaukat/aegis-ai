import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { formatDistanceToNow, format } from 'date-fns'

// ── Class merging ─────────────────────────────────────────────────────────────
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// ── Risk level colours ────────────────────────────────────────────────────────
export const RISK_CONFIG: Record<string, { label: string; color: string; bg: string; border: string; emoji: string }> = {
  SAFE:     { label: 'Safe',     color: 'text-green-400',  bg: 'bg-green-900/20',  border: 'border-green-800',  emoji: '✅' },
  LOW:      { label: 'Low',      color: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-800', emoji: '🟡' },
  MEDIUM:   { label: 'Medium',   color: 'text-orange-400', bg: 'bg-orange-900/20', border: 'border-orange-800', emoji: '⚠️' },
  HIGH:     { label: 'High',     color: 'text-red-400',    bg: 'bg-red-900/20',    border: 'border-red-900',    emoji: '🚨' },
  CRITICAL: { label: 'Critical', color: 'text-red-300',    bg: 'bg-red-950/40',    border: 'border-red-700',    emoji: '🆘' },
}

export function getRiskConfig(risk?: string | null) {
  const key = (risk || 'SAFE').toUpperCase()
  return RISK_CONFIG[key] ?? RISK_CONFIG.SAFE
}

// ── Module icons / labels ─────────────────────────────────────────────────────
export const MODULE_META: Record<string, { icon: string; label: string }> = {
  link:       { icon: '🔗', label: 'Link Analysis' },
  qr:         { icon: '📷', label: 'QR Scan' },
  credential: { icon: '🔑', label: 'Credential Check' },
  profile:    { icon: '👤', label: 'Profile Analysis' },
  smishing:   { icon: '📩', label: 'SMS Analysis' },
  deepfake:   { icon: '🎭', label: 'Deepfake Detection' },
  cyber_qa:   { icon: '🎓', label: 'Cyber Q&A' },
  help:       { icon: '🛡️', label: 'Help' },
  history:    { icon: '📋', label: 'History' },
  system:     { icon: '⚙️', label: 'System' },
}

export function getModuleMeta(module?: string | null) {
  return MODULE_META[module || ''] ?? { icon: '🔍', label: 'Analysis' }
}

// ── Date formatting ───────────────────────────────────────────────────────────
export function timeAgo(dateStr: string): string {
  try {
    return formatDistanceToNow(new Date(dateStr), { addSuffix: true })
  } catch {
    return ''
  }
}

export function formatDate(dateStr: string): string {
  try {
    return format(new Date(dateStr), 'MMM d, yyyy HH:mm')
  } catch {
    return ''
  }
}

// ── Group sessions by date ────────────────────────────────────────────────────
export function groupByDate<T extends { updated_at: string }>(
  items: T[]
): Array<{ label: string; items: T[] }> {
  const now   = new Date()
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const yday  = new Date(today.getTime() - 86_400_000)
  const week  = new Date(today.getTime() - 7 * 86_400_000)

  const groups: Record<string, T[]> = {}

  for (const item of items) {
    const d = new Date(item.updated_at)
    let label: string
    if (d >= today)      label = 'Today'
    else if (d >= yday)  label = 'Yesterday'
    else if (d >= week)  label = 'Last 7 Days'
    else                 label = format(d, 'MMMM yyyy')

    if (!groups[label]) groups[label] = []
    groups[label].push(item)
  }

  const order = ['Today', 'Yesterday', 'Last 7 Days']
  return Object.entries(groups)
    .sort(([a], [b]) => {
      const ai = order.indexOf(a)
      const bi = order.indexOf(b)
      if (ai !== -1 && bi !== -1) return ai - bi
      if (ai !== -1) return -1
      if (bi !== -1) return 1
      return b.localeCompare(a)
    })
    .map(([label, items]) => ({ label, items }))
}

// ── Truncate text ─────────────────────────────────────────────────────────────
export function truncate(str: string, n: number): string {
  return str.length > n ? str.slice(0, n - 1) + '…' : str
}
