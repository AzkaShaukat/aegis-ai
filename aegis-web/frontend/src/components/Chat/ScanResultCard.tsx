import { useState } from 'react'
import { ChevronDown, ChevronUp, ExternalLink, AlertTriangle, Shield } from 'lucide-react'
import { ScanResult } from '@/types'
import { getRiskConfig, getModuleMeta, cn } from '@/utils/helpers'

interface Props {
  module?: string | null
  riskLevel?: string | null
  structured?: ScanResult | null
  flags?: string[]
  action?: string
}

export default function ScanResultCard({ module, riskLevel, structured, flags, action }: Props) {
  const [expanded, setExpanded] = useState(false)
  if (!structured || !module || module === 'help' || module === 'cyber_qa') return null

  const risk   = getRiskConfig(riskLevel)
  const meta   = getModuleMeta(module)

  return (
    <div className={cn(
      'rounded-xl border overflow-hidden mt-3 text-sm',
      risk.border, risk.bg
    )}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="text-base">{meta.icon}</span>
          <span className="font-medium text-[#e6edf3]">{meta.label}</span>
          <span className={cn('px-2 py-0.5 rounded-full text-xs font-semibold border', risk.color, risk.border, risk.bg)}>
            {risk.emoji} {risk.label}
          </span>
        </div>
        <button
          onClick={() => setExpanded(v => !v)}
          className="text-aegis-muted hover:text-[#e6edf3] transition-colors p-1 rounded"
          aria-label={expanded ? 'Collapse details' : 'Expand details'}
        >
          {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
      </div>

      {/* Always-visible quick stats */}
      <QuickStats module={module} structured={structured} riskLevel={riskLevel} />

      {/* Expandable full details */}
      {expanded && (
        <div className="border-t border-aegis-border/50 px-4 py-3 space-y-3 animate-fade-in">
          <FullDetails module={module} structured={structured} />

          {/* Flags */}
          {flags && flags.length > 0 && (
            <div>
              <p className="text-xs font-medium text-aegis-muted uppercase tracking-wider mb-2">Signals Detected</p>
              <div className="space-y-1">
                {flags.slice(0, 6).map((f, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-[#e6edf3]">
                    <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0 mt-0.5" />
                    <span>{f}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Action */}
          {action && (
            <div className={cn('rounded-lg px-3 py-2.5 text-xs font-medium', risk.bg, risk.color, 'border', risk.border)}>
              <Shield className="w-3.5 h-3.5 inline mr-1.5 mb-0.5" />
              {action}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Quick Stats (always visible) ──────────────────────────────────────────────

function QuickStats({ module, structured, riskLevel }: { module: string; structured: ScanResult; riskLevel?: string | null }) {
  const items: { label: string; value: string | number; highlight?: boolean }[] = []

  if (module === 'link') {
    const score = structured.confidence_score ?? structured.overall_risk_score
    const mal   = structured.detection_counts?.malicious ?? 0
    const total = structured.scanners_count ?? 94
    if (score !== undefined) items.push({ label: 'Confidence', value: `${score}%` })
    items.push({ label: 'Antivirus', value: mal > 0 ? `${mal}/${total} flagged` : `Clean (${total} engines)`, highlight: mal > 0 })
    const age = structured.whois?.domain_age_days
    if (age) items.push({ label: 'Domain Age', value: age > 365 ? `${Math.floor(age/365)}y` : `${age}d` })
  }

  if (module === 'credential') {
    const breach = structured.hibp_count ?? structured.pwned_count ?? 0
    const score  = structured.overall_risk_score
    if (breach > 0) items.push({ label: 'Breach Records', value: breach.toLocaleString(), highlight: true })
    else items.push({ label: 'Breach Status', value: 'Not found ✅' })
    if (score !== undefined) items.push({ label: 'Risk Score', value: `${score}/100` })
  }

  if (module === 'profile') {
    const score   = structured.combined_score ?? structured.verdict?.final_score
    const verdict = structured.verdict as string | undefined
    if (verdict) items.push({ label: 'Verdict', value: String(verdict), highlight: ['SCAMMER','FAKE','IMPERSONATOR'].includes(String(verdict)) })
    if (score !== undefined) items.push({ label: 'Combined Score', value: `${score}/100` })
  }

  if (module === 'smishing') {
    const conf = structured.confidence
    const cat  = structured.category
    if (conf !== undefined) items.push({ label: 'AI Confidence', value: `${conf}%`, highlight: Number(conf) > 60 })
    if (cat) items.push({ label: 'Category', value: String(cat).replace(/_/g,' ') })
  }

  if (module === 'deepfake') {
    const prob  = structured.ensemble_probability
    const faces = structured.face_info?.faces_detected
    if (prob !== undefined) items.push({ label: 'Fake Probability', value: `${Math.round(Number(prob)*100)}%`, highlight: Number(prob) > 0.6 })
    if (faces !== undefined) items.push({ label: 'Faces Detected', value: String(faces) })
  }

  if (items.length === 0) return null

  return (
    <div className="px-4 pb-3 flex flex-wrap gap-x-5 gap-y-1">
      {items.map(item => (
        <div key={item.label} className="flex items-baseline gap-1.5">
          <span className="text-xs text-aegis-muted">{item.label}:</span>
          <span className={cn('text-xs font-medium', item.highlight ? 'text-red-400' : 'text-[#e6edf3]')}>
            {item.value}
          </span>
        </div>
      ))}
    </div>
  )
}

// ── Full Details ──────────────────────────────────────────────────────────────

function FullDetails({ module, structured }: { module: string; structured: ScanResult }) {
  if (module === 'link') {
    const redir = structured.redirects
    const vtRep = structured.virustotal_report as string | undefined
    return (
      <div className="space-y-2">
        {redir?.hop_count && redir.hop_count > 1 && (
          <div className="text-xs text-aegis-muted">
            Redirects: <span className="text-[#e6edf3]">{redir.hop_count} hops</span>
            {redir.final_url && <span> → <span className="font-mono text-aegis-accent truncate">{redir.final_url.slice(0,50)}</span></span>}
          </div>
        )}
        {vtRep && (
          <a href={vtRep} target="_blank" rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-aegis-accent hover:underline">
            <ExternalLink className="w-3 h-3" /> View VirusTotal Report
          </a>
        )}
      </div>
    )
  }

  if (module === 'credential') {
    const isDisposable = structured.is_disposable
    return (
      <div className="space-y-1 text-xs text-aegis-muted">
        {isDisposable && <p className="text-orange-400">⚠️ Disposable email address detected</p>}
      </div>
    )
  }

  if (module === 'profile') {
    const signals = structured.signals as string[] | undefined
    return signals && signals.length > 0 ? (
      <div>
        <p className="text-xs font-medium text-aegis-muted uppercase tracking-wider mb-1.5">Top Signals</p>
        {signals.slice(0,5).map((s,i) => (
          <div key={i} className="text-xs text-[#e6edf3] py-0.5">{s}</div>
        ))}
      </div>
    ) : null
  }

  return null
}
