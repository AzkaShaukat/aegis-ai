import { useState, useRef, useEffect } from 'react'
import { LogOut, History, User, ChevronDown } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/stores/authStore'
import { cn } from '@/utils/helpers'

interface Props {
  onHistoryClick: () => void
}

export default function UserMenu({ onHistoryClick }: Props) {
  const [open, setOpen]   = useState(false)
  const ref               = useRef<HTMLDivElement>(null)
  const navigate          = useNavigate()
  const { user, logout }  = useAuthStore()

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const initials = user?.display_name
    ? user.display_name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2)
    : '?'

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-white/5 transition-colors"
      >
        {/* Avatar */}
        <div className="w-7 h-7 rounded-full bg-aegis-accent/20 border border-aegis-accent/30 flex items-center justify-center text-xs font-semibold text-aegis-accent">
          {initials}
        </div>
        <span className="text-sm text-[#e6edf3] hidden sm:block max-w-[120px] truncate">
          {user?.display_name}
        </span>
        <ChevronDown className={cn('w-3.5 h-3.5 text-aegis-muted transition-transform', open && 'rotate-180')} />
      </button>

      {/* Dropdown */}
      {open && (
        <div className="absolute right-0 top-full mt-1 w-52 bg-aegis-surface border border-aegis-border rounded-xl shadow-2xl py-1.5 z-50 animate-slide-up">
          {/* User info */}
          <div className="px-3 py-2 border-b border-aegis-border mb-1">
            <p className="text-sm font-medium text-white truncate">{user?.display_name}</p>
            <p className="text-xs text-aegis-muted truncate">{user?.email}</p>
          </div>

          <MenuItem
            icon={User}
            label="Account"
            onClick={() => { setOpen(false) }}
          />
          <MenuItem
            icon={History}
            label="Scan History"
            onClick={() => { setOpen(false); onHistoryClick() }}
          />

          <div className="border-t border-aegis-border my-1" />

          <MenuItem
            icon={LogOut}
            label="Sign out"
            onClick={handleLogout}
            danger
          />
        </div>
      )}
    </div>
  )
}

function MenuItem({
  icon: Icon, label, onClick, danger,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  onClick: () => void
  danger?: boolean
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full flex items-center gap-2.5 px-3 py-2 text-sm transition-colors',
        danger
          ? 'text-red-400 hover:bg-red-900/20 hover:text-red-300'
          : 'text-[#c9d1d9] hover:bg-white/5 hover:text-white'
      )}
    >
      <Icon className="w-4 h-4 shrink-0" />
      {label}
    </button>
  )
}
