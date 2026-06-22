import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { listScans, deleteScan } from '../api/client'
import { severityColor } from '../components/SeverityBadge'
import type { ScanSummary, ScanStats } from '../types'

function StatCard({ label, value, note }: { label: string; value: number; note?: string }) {
  return (
    <div className="card">
      <p className="text-choco-muted text-xs font-medium mb-1">{label}</p>
      <p className="text-2xl font-semibold text-choco-text tabular-nums">{value}</p>
      {note && <p className="text-choco-muted text-xs mt-1">{note}</p>}
    </div>
  )
}

function TypeBadge({ type }: { type: string }) {
  const cfg: Record<string, string> = {
    file:   'bg-blue-500/10 text-blue-400 border-blue-500/20',
    direct: 'bg-choco-accent/10 text-choco-accent border-choco-accent/20',
    ssh:    'bg-violet-500/10 text-violet-400 border-violet-500/20',
  }
  const label: Record<string, string> = { file: 'Fichier', direct: 'Scan IP', ssh: 'SSH' }
  return (
    <span className={`inline-flex items-center px-2 py-px text-[11px] font-medium rounded-md border ${cfg[type] ?? 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'}`}>
      {label[type] ?? type}
    </span>
  )
}

function globalStats(scans: ScanSummary[]): ScanStats {
  const zero: ScanStats = { total_cves: 0, critical: 0, high: 0, medium: 0, low: 0, services: 0, hosts: 0, with_exploit: 0, cisa_kev: 0 }
  return scans.filter(s => s.stats).reduce((acc, s) => {
    const st = s.stats!
    return { total_cves: acc.total_cves + st.total_cves, critical: acc.critical + st.critical,
             high: acc.high + st.high, medium: acc.medium + st.medium, low: acc.low + st.low,
             services: acc.services + st.services, hosts: acc.hosts + st.hosts,
             with_exploit: acc.with_exploit + st.with_exploit, cisa_kev: acc.cisa_kev + st.cisa_kev }
  }, zero)
}

export function Dashboard() {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = () => { setLoading(true); listScans().then(setScans).finally(() => setLoading(false)) }
  useEffect(() => { load() }, [])

  const done = scans.filter(s => s.status === 'done')
  const global = globalStats(done)

  const pieData = [
    { name: 'CRITICAL', value: global.critical },
    { name: 'HIGH',     value: global.high },
    { name: 'MEDIUM',   value: global.medium },
    { name: 'LOW',      value: global.low },
  ].filter(d => d.value > 0)

  const handleDelete = async (e: React.MouseEvent, id: number) => {
    e.stopPropagation()
    await deleteScan(id)
    load()
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in max-w-6xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-choco-text">Dashboard</h1>
          <p className="text-choco-muted text-sm mt-0.5">{done.length} scan{done.length !== 1 ? 's' : ''} terminé{done.length !== 1 ? 's' : ''}</p>
        </div>
        <button className="btn-primary" onClick={() => navigate('/scan')}>Nouveau scan</button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-40 text-choco-muted text-sm">Chargement…</div>
      ) : (
        <>
          {/* Stats */}
          <div className="grid grid-cols-4 gap-3">
            <StatCard label="CVE totales" value={global.total_cves} />
            <StatCard label="Critical" value={global.critical} />
            <StatCard label="High" value={global.high} />
            <StatCard label="Avec exploit" value={global.with_exploit} note={`${global.cisa_kev} CISA KEV`} />
          </div>

          <div className="grid grid-cols-3 gap-5">
            {/* Graphique */}
            <div className="card">
              <p className="text-choco-muted text-xs font-medium mb-4">Répartition des sévérités</p>
              {pieData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={150}>
                    <PieChart>
                      <Pie data={pieData} dataKey="value" cx="50%" cy="50%"
                           innerRadius={42} outerRadius={64} paddingAngle={2} strokeWidth={0}>
                        {pieData.map(e => <Cell key={e.name} fill={severityColor(e.name)} />)}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: '#18181b', border: '1px solid #3f3f46', borderRadius: 8, fontSize: 12 }}
                        itemStyle={{ color: '#a1a1aa' }}
                        labelStyle={{ color: '#f4f4f5' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="flex flex-wrap justify-center gap-3 mt-3">
                    {['CRITICAL','HIGH','MEDIUM','LOW'].map(sev => (
                      <div key={sev} className="flex items-center gap-1.5">
                        <div className="w-2 h-2 rounded-full" style={{ background: severityColor(sev) }} />
                        <span className="text-[11px] text-choco-muted">{sev}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="flex items-center justify-center h-32 text-choco-muted text-sm">
                  Aucune donnée
                </div>
              )}
            </div>

            {/* Scans récents */}
            <div className="card col-span-2">
              <div className="flex items-center justify-between mb-4">
                <p className="text-choco-muted text-xs font-medium">Scans récents</p>
                <button onClick={() => navigate('/history')}
                  className="text-xs text-choco-text-dim hover:text-choco-accent transition-colors">
                  Voir tout →
                </button>
              </div>

              {scans.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-28 gap-3">
                  <p className="text-choco-muted text-sm">Aucun scan pour l'instant.</p>
                  <button className="btn-primary" onClick={() => navigate('/scan')}>Lancer un scan</button>
                </div>
              ) : (
                <div className="space-y-1.5">
                  {scans.slice(0, 7).map(scan => (
                    <div key={scan.id}
                      onClick={() => scan.status === 'done' && navigate(`/scan/${scan.id}`)}
                      className={`flex items-center gap-3 px-3 py-2 rounded-lg
                        border border-transparent hover:border-choco-border hover:bg-choco-surface2
                        transition-colors duration-150
                        ${scan.status === 'done' ? 'cursor-pointer' : 'opacity-60'}`}>
                      <TypeBadge type={scan.input_type} />

                      <span className="flex-1 text-sm text-choco-text truncate font-mono text-[13px]">
                        {scan.target}
                      </span>

                      {scan.status === 'done' && scan.stats && (
                        <div className="flex items-center gap-3 text-xs tabular-nums flex-shrink-0">
                          <span className="text-red-400">{scan.stats.critical}C</span>
                          <span className="text-orange-400">{scan.stats.high}H</span>
                          <span className="text-choco-muted">{scan.stats.total_cves} CVE</span>
                        </div>
                      )}

                      <span className="text-choco-muted text-[11px] flex-shrink-0">
                        {new Date(scan.created_at).toLocaleDateString('fr-FR')}
                      </span>

                      <button onClick={e => handleDelete(e, scan.id)}
                        className="text-choco-muted hover:text-red-400 transition-colors text-xs ml-1 opacity-0 group-hover:opacity-100">
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
