import { useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { getScan, exportJsonUrl, exportHtmlUrl } from '../api/client'
import { CVECard } from '../components/CVECard'
// SeverityBadge used in CVECard
import type { ScanDetail as ScanDetailType, ServiceResult } from '../types'

function ServiceCard({ svc, filters }: {
  svc: ServiceResult
  filters: { text: string; minCvss: number; severity: string; onlyExploit: boolean; onlyKev: boolean }
}) {
  const filtered = svc.cves.filter(c => {
    const cvss = typeof c.cvss === 'number' ? c.cvss : parseFloat(String(c.cvss)) || 0
    if (filters.minCvss > 0 && cvss < filters.minCvss) return false
    if (filters.severity && c.severity !== filters.severity) return false
    if (filters.onlyExploit && !c.exploit_available) return false
    if (filters.onlyKev && !c.cisa_kev) return false
    if (filters.text) {
      const q = filters.text.toLowerCase()
      return c.id.toLowerCase().includes(q) || c.description.toLowerCase().includes(q)
    }
    return true
  })

  if (filtered.length === 0) return null

  const maxSev = ['CRITICAL','HIGH','MEDIUM','LOW'].find(s => filtered.some(c => c.severity === s)) ?? 'UNKNOWN'

  return (
    <div className="card space-y-3 animate-slide-up">
      {/* Header service */}
      <div className="flex items-start gap-3">
        <div className={`w-1.5 h-full min-h-[2.5rem] rounded-full flex-shrink-0 mt-0.5 ${
          { CRITICAL: 'bg-red-500', HIGH: 'bg-orange-500', MEDIUM: 'bg-yellow-500', LOW: 'bg-blue-500' }[maxSev] ?? 'bg-gray-500'
        }`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm font-semibold text-choco-text">
              {svc.host}:{svc.port}/{svc.protocol}
            </span>
            {svc.service_name && (
              <span className="tag">{svc.service_name}</span>
            )}
            {svc.product && (
              <span className="text-choco-text-dim text-xs font-mono">
                {svc.product} {svc.version}
              </span>
            )}
            <span className="ml-auto text-choco-muted text-xs">{filtered.length} CVE</span>
          </div>
          {svc.banner && svc.banner !== `${svc.product} ${svc.version}`.trim() && (
            <p className="text-choco-muted text-xs font-mono mt-0.5 truncate">{svc.banner}</p>
          )}
        </div>
      </div>

      {/* CVE list */}
      <div className="space-y-2 pl-4">
        {filtered.map(cve => <CVECard key={cve.id} cve={cve} />)}
      </div>
    </div>
  )
}

export function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [scan, setScan] = useState<ScanDetailType | null>(null)
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({
    text: '', minCvss: 0, severity: '', onlyExploit: false, onlyKev: false,
  })

  useEffect(() => {
    if (!id) return
    getScan(parseInt(id)).then(setScan).finally(() => setLoading(false))
  }, [id])

  const totalVisible = useMemo(() => {
    if (!scan) return 0
    return scan.results.reduce((acc, svc) => {
      return acc + svc.cves.filter(c => {
        const cvss = typeof c.cvss === 'number' ? c.cvss : parseFloat(String(c.cvss)) || 0
        if (filters.minCvss > 0 && cvss < filters.minCvss) return false
        if (filters.severity && c.severity !== filters.severity) return false
        if (filters.onlyExploit && !c.exploit_available) return false
        if (filters.onlyKev && !c.cisa_kev) return false
        if (filters.text) {
          const q = filters.text.toLowerCase()
          return c.id.toLowerCase().includes(q) || c.description.toLowerCase().includes(q)
        }
        return true
      }).length
    }, 0)
  }, [scan, filters])

  if (loading) return (
    <div className="flex items-center justify-center h-full text-choco-muted font-mono text-sm">
      Chargement du scan…
    </div>
  )

  if (!scan) return (
    <div className="flex flex-col items-center justify-center h-full gap-4">
      <p className="text-choco-muted text-sm">Scan introuvable.</p>
      <button className="btn-ghost" onClick={() => navigate('/')}>← Retour</button>
    </div>
  )

  const st = scan.stats

  return (
    <div className="p-7 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <button onClick={() => navigate('/')} className="text-choco-muted text-xs hover:text-choco-text mb-2 flex items-center gap-1">
            ← Dashboard
          </button>
          <h1 className="text-xl font-semibold text-choco-text font-mono">{scan.target}</h1>
          <p className="text-choco-text-dim text-xs mt-0.5">
            {new Date(scan.created_at).toLocaleString('fr-FR')} · {scan.input_type}
          </p>
        </div>

        {/* Export */}
        <div className="flex gap-2">
          <a href={exportJsonUrl(scan.id)} download className="btn-ghost">↓ JSON</a>
          <a href={exportHtmlUrl(scan.id)} download className="btn-ghost">↓ HTML</a>
        </div>
      </div>

      {/* Stats bar */}
      {st && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
          {[
            { label: 'Total',    value: st.total_cves, cls: 'text-choco-text' },
            { label: 'Critical', value: st.critical,   cls: 'text-red-400'    },
            { label: 'High',     value: st.high,       cls: 'text-orange-400' },
            { label: 'Medium',   value: st.medium,     cls: 'text-yellow-400' },
            { label: 'Low',      value: st.low,        cls: 'text-blue-400'   },
            { label: 'Services', value: st.services,   cls: 'text-choco-text' },
            { label: 'Exploits', value: st.with_exploit, cls: 'text-orange-300' },
            { label: 'KEV',      value: st.cisa_kev,   cls: 'text-red-300'    },
          ].map(({ label, value, cls }) => (
            <div key={label} className="card py-3 text-center">
              <p className={`text-xl font-bold font-mono ${cls}`}>{value}</p>
              <p className="text-choco-muted text-[11px] mt-0.5">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Filtres temps réel */}
      <div className="card">
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex-1 min-w-[160px]">
            <label className="text-choco-muted text-xs mb-1 block">Recherche</label>
            <input value={filters.text} onChange={e => setFilters(f => ({ ...f, text: e.target.value }))}
              className="input w-full" placeholder="CVE-ID ou mot-clé…" />
          </div>
          <div>
            <label className="text-choco-muted text-xs mb-1 block">CVSS min</label>
            <input type="number" min="0" max="10" step="0.5" value={filters.minCvss}
              onChange={e => setFilters(f => ({ ...f, minCvss: parseFloat(e.target.value) || 0 }))}
              className="input w-24" />
          </div>
          <div>
            <label className="text-choco-muted text-xs mb-1 block">Sévérité</label>
            <select value={filters.severity}
              onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}
              className="input">
              <option value="">Toutes</option>
              {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          <label className="flex items-center gap-1.5 cursor-pointer pb-2">
            <input type="checkbox" checked={filters.onlyExploit}
              onChange={e => setFilters(f => ({ ...f, onlyExploit: e.target.checked }))}
              className="accent-choco-accent" />
            <span className="text-choco-text-dim text-xs">Exploit dispo</span>
          </label>
          <label className="flex items-center gap-1.5 cursor-pointer pb-2">
            <input type="checkbox" checked={filters.onlyKev}
              onChange={e => setFilters(f => ({ ...f, onlyKev: e.target.checked }))}
              className="accent-choco-accent" />
            <span className="text-choco-text-dim text-xs">CISA KEV</span>
          </label>
          <span className="text-choco-muted text-xs pb-2">{totalVisible} résultat(s)</span>
        </div>
      </div>

      {/* Résultats */}
      <div className="space-y-4">
        {scan.results
          .slice()
          .sort((a, b) => {
            const maxCvss = (svc: ServiceResult) =>
              Math.max(0, ...svc.cves.map(c => typeof c.cvss === 'number' ? c.cvss : 0))
            return maxCvss(b) - maxCvss(a)
          })
          .map(svc => (
            <ServiceCard key={`${svc.host}:${svc.port}`} svc={svc} filters={filters} />
          ))}
      </div>
    </div>
  )
}
