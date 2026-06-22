import { useState } from 'react'
import { SeverityBadge } from './SeverityBadge'
import type { CVE } from '../types'

interface Props { cve: CVE }

export function CVECard({ cve }: Props) {
  const [expanded, setExpanded] = useState(false)
  const cvss = typeof cve.cvss === 'number' ? cve.cvss.toFixed(1) : cve.cvss

  return (
    <div
      onClick={() => setExpanded(e => !e)}
      className="border border-choco-border rounded-lg bg-choco-surface2
                 hover:border-zinc-500 transition-colors duration-150 cursor-pointer"
    >
      {/* Ligne principale */}
      <div className="flex items-center gap-3 px-3 py-2.5">
        <SeverityBadge severity={cve.severity} />

        <span className="font-mono text-sm text-choco-text font-medium tracking-tight">{cve.id}</span>

        <span className="text-choco-muted text-xs tabular-nums">
          {cvss !== 'N/A' ? `CVSS ${cvss}` : 'N/A'}
        </span>

        <div className="flex items-center gap-1.5 ml-1">
          {cve.cisa_kev && (
            <span className="px-1.5 py-px text-[10px] font-medium rounded-md
                             bg-red-500/10 border border-red-500/20 text-red-400 tracking-wide">
              KEV
            </span>
          )}
          {cve.exploit_available && (
            <span className="px-1.5 py-px text-[10px] font-medium rounded-md
                             bg-orange-500/10 border border-orange-500/20 text-orange-400 tracking-wide">
              PoC
            </span>
          )}
          {cve.contextual_score != null && (
            <span className="px-1.5 py-px text-[10px] rounded-md
                             bg-choco-surface border border-choco-border text-choco-muted tabular-nums">
              {cve.contextual_score.toFixed(1)}
            </span>
          )}
        </div>

        <p className="flex-1 text-choco-text-dim text-xs truncate ml-1">
          {cve.description_fr || cve.description || '—'}
        </p>

        <span className="text-choco-muted text-xs ml-2 flex-shrink-0">
          {expanded ? '↑' : '↓'}
        </span>
      </div>

      {/* Détails */}
      {expanded && (
        <div className="border-t border-choco-border px-3 py-3 space-y-2.5 animate-slide-up">
          {cve.description && (
            <p className="text-choco-text-dim text-xs leading-relaxed">
              {cve.description}
            </p>
          )}

          <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-choco-muted">
            {cve.affected_versions && (
              <span>
                Versions&nbsp;:&nbsp;
                <span className="text-choco-text-dim font-mono">
                  {Array.isArray(cve.affected_versions)
                    ? cve.affected_versions.join(', ')
                    : cve.affected_versions}
                </span>
              </span>
            )}
            {cve.source && <span>Source&nbsp;: <span className="text-choco-text-dim">{cve.source}</span></span>}
          </div>

          {cve.tags.length > 0 && (
            <div className="flex gap-1.5 flex-wrap">
              {cve.tags.map(tag => <span key={tag} className="tag">{tag}</span>)}
            </div>
          )}

          {cve.exploits.length > 0 && (
            <div className="space-y-1">
              <p className="text-choco-muted text-xs font-medium">PoC publics</p>
              {cve.exploits.map((e, i) => (
                <a key={i} href={e.url} target="_blank" rel="noopener noreferrer"
                   onClick={ev => ev.stopPropagation()}
                   className="block text-xs text-choco-accent hover:underline truncate">
                  {e.title || e.url}
                </a>
              ))}
            </div>
          )}

          <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
             target="_blank" rel="noopener noreferrer"
             onClick={ev => ev.stopPropagation()}
             className="inline-flex items-center gap-1 text-xs text-choco-text-dim hover:text-choco-accent transition-colors">
            Voir sur NVD →
          </a>
        </div>
      )}
    </div>
  )
}
