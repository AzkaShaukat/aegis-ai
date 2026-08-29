import { useEffect, useState } from 'react'
import { X, Shield, TrendingUp, Link, KeyRound, User, MessageSquare } from 'lucide-react'
import { historyApi } from '@/api/client'
import { ScanHistoryEntry, ScanStats } from '@/types'
import { getRiskConfig, formatDate, cn } from '@/utils/helpers'

interface Props {
  onClose: () => void
}

export default function HistoryModal({ onClose }: Props) {
  const [entries, setEntries] = useState<ScanHistoryEntry[]>([])
  const [stats,   setStats]   = useState<ScanStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [hRes, sRes] = await Promise.all([
          historyApi.get30Days(),
          historyApi.getStats(),
        ])
        setEntries(hRes.data.entries || [])
        setStats(sRes.data)
      } catch { /* silent */ }
      finally { setLoading(false) }
    }
    load()
  }, [])

  return (
    // Backdrop
    <div
      className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center px-4 animate-fade-in"
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="bg-aegis-surface border border-aegis-border rounded-2xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col animate-slide-up">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-aegis-border">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-aegis-accent" />
            <h2 className="text-base font-semibold text-white">30-Day Scan History</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-aegis-muted hover:text-white hover:bg-white/5 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16">
            <div className="w-6 h-6 border-2 border-aegis-border border-t-aegis-accent rounded-full animate-spin" />
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto">
            {/* Stats bar */}
            {stats && <StatsBar stats={stats} />}

            {/* Entry list */}
            {entries.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-aegis-muted">
                <Shield className="w-10 h-10 mb-3 opacity-30" />
                <p className="text-sm">No scans recorded yet.</p>
                <p className="text-xs mt-1">Start chatting to see your history here.</p>
              </div>
            ) : (
              <div className="divide-y divide-aegis-border">
                {entries.map(e => (
                  <HistoryRow key={e.id} entry={e} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Footer */}
        <div className="px-6 py-3 border-t border-aegis-border">
          <p className="text-xs text-aegis-muted text-center">
            🔒 Scan values are anonymised with SHA-256 hashing. Raw data is never stored.
          </p>
        </div>
      </div>
    </div>
  )
}

// ── Stats bar ─────────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: ScanStats }) {
  const items = [
    { icon: TrendingUp,   label: 'Total',       value: stats.total_scans,         danger: false },
    { icon: Shield,       label: 'Threats',     value: stats.threats_found,       danger: stats.threats_found > 0 },
    { icon: Link,         label: 'Links',       value: stats.links_scanned,       danger: false },
    { icon: KeyRound,     label: 'Credentials', value: stats.credentials_checked, danger: false },
    { icon: User,         label: 'Profiles',    value: stats.profiles_analysed,   danger: false },
    { icon: MessageSquare, label: 'Smishing',   value: stats.smishing_detected,   danger: stats.smishing_detected > 0 },
  ]
  return (
    <div className="grid grid-cols-3 sm:grid-cols-6 gap-px bg-aegis-border/50 border-b border-aegis-border">
      {items.map(({ icon: Icon, label, value, danger }) => (
        <div key={label} className="bg-aegis-surface flex flex-col items-center py-4 gap-1">
          <Icon className={cn('w-4 h-4', danger && value > 0 ? 'text-red-400' : 'text-aegis-muted')} />
          <span className={cn('text-lg font-bold', danger && value > 0 ? 'text-red-400' : 'text-white')}>
            {value}
          </span>
          <span className="text-xs text-aegis-muted">{label}</span>
        </div>
      ))}
    </div>
  )
}

// ── History row ───────────────────────────────────────────────────────────────

const TYPE_ICONS: Record<string, string> = {
  link: '🔗', qr: '📷', credential: '🔑', profile: '👤', smishing: '📩', deepfake: '🎭',
}

function HistoryRow({ entry }: { entry: ScanHistoryEntry }) {
  const risk = getRiskConfig(entry.risk_level)
  return (
    <div className="flex items-center gap-3 px-6 py-3 hover:bg-white/3 transition-colors">
      <span className="text-lg">{TYPE_ICONS[entry.entry_type] || '🔍'}</span>
      <div className="flex-1 min-w-0">
        <p className="text-sm text-[#e6edf3] capitalize">{entry.entry_type.replace('_', ' ')}</p>
        <p className="text-xs text-aegis-muted">{formatDate(entry.scanned_at)}</p>
      </div>
      <span className={cn(
        'shrink-0 px-2.5 py-1 rounded-full text-xs font-semibold border',
        risk.color, risk.bg, risk.border
      )}>
        {risk.emoji} {risk.label}
      </span>
    </div>
  )
}
