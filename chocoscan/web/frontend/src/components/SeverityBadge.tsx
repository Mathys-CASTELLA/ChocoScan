const CONFIG = {
  CRITICAL: { bg: 'bg-red-500/10',    border: 'border-red-500/20',    text: 'text-red-400'    },
  HIGH:     { bg: 'bg-orange-500/10', border: 'border-orange-500/20', text: 'text-orange-400' },
  MEDIUM:   { bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', text: 'text-yellow-400' },
  LOW:      { bg: 'bg-blue-500/10',   border: 'border-blue-500/20',   text: 'text-blue-400'   },
  UNKNOWN:  { bg: 'bg-zinc-500/10',   border: 'border-zinc-500/20',   text: 'text-zinc-400'   },
}

interface Props {
  severity: string
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'sm' }: Props) {
  const cfg = CONFIG[severity as keyof typeof CONFIG] ?? CONFIG.UNKNOWN
  const padding = size === 'md' ? 'px-2.5 py-0.5 text-xs' : 'px-2 py-0.5 text-[11px]'
  return (
    <span className={`inline-flex items-center font-medium rounded-md border ${cfg.bg} ${cfg.border} ${cfg.text} ${padding} tracking-wide`}>
      {severity}
    </span>
  )
}

export function severityColor(severity: string): string {
  return { CRITICAL: '#f87171', HIGH: '#fb923c', MEDIUM: '#facc15', LOW: '#60a5fa' }[severity] ?? '#71717a'
}
