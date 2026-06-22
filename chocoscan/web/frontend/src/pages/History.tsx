import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { listScans, deleteScan } from '../api/client'
import type { ScanSummary } from '../types'

export function History() {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = () => { setLoading(true); listScans(100).then(setScans).finally(() => setLoading(false)) }
  useEffect(() => { load() }, [])

  const handleDelete = async (e: React.MouseEvent, id: number) => {
    e.stopPropagation()
    if (!confirm('Supprimer ce scan ?')) return
    await deleteScan(id)
    load()
  }

  const TYPE_LABEL = { file: 'Fichier', direct: 'Scan IP', ssh: 'SSH' }
  const STATUS_CONFIG = {
    done:    { cls: 'text-choco-accent',  label: '● Terminé'  },
    running: { cls: 'text-yellow-400',    label: '◌ En cours' },
    error:   { cls: 'text-red-400',       label: '✕ Erreur'   },
    pending: { cls: 'text-choco-muted',   label: '○ En attente' },
  }

  return (
    <div className="p-7 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-choco-text">Historique</h1>
          <p className="text-choco-text-dim text-sm mt-0.5">{scans.length} scan(s) enregistré(s)</p>
        </div>
        <button className="btn-primary" onClick={() => navigate('/scan')}>+ Nouveau scan</button>
      </div>

      {loading ? (
        <div className="text-center py-20 text-choco-muted font-mono text-sm">Chargement…</div>
      ) : scans.length === 0 ? (
        <div className="card text-center py-16">
          <p className="text-choco-muted text-2xl mb-4">◈</p>
          <p className="text-choco-text-dim text-sm">Aucun scan pour l'instant.</p>
          <button className="btn-primary mt-4" onClick={() => navigate('/scan')}>Lancer un scan</button>
        </div>
      ) : (
        <div className="card overflow-hidden p-0">
          <table className="w-full text-sm">
            <thead className="border-b border-choco-border">
              <tr>
                {['#', 'Cible', 'Type', 'Date', 'Total', 'Critical', 'High', 'Exploit', 'Statut', ''].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-choco-muted text-xs font-mono uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-choco-border">
              {scans.map(scan => {
                const st = scan.stats
                const sc = STATUS_CONFIG[scan.status as keyof typeof STATUS_CONFIG] ?? STATUS_CONFIG.pending
                return (
                  <tr key={scan.id}
                    onClick={() => scan.status === 'done' && navigate(`/scan/${scan.id}`)}
                    className={`transition-colors ${scan.status === 'done'
                      ? 'hover:bg-choco-surface2 cursor-pointer'
                      : ''}`}>
                    <td className="px-4 py-3 font-mono text-choco-muted text-xs">{scan.id}</td>
                    <td className="px-4 py-3 font-mono text-choco-text max-w-[200px] truncate">
                      {scan.target}
                    </td>
                    <td className="px-4 py-3 text-choco-text-dim text-xs">
                      {TYPE_LABEL[scan.input_type as keyof typeof TYPE_LABEL] ?? scan.input_type}
                    </td>
                    <td className="px-4 py-3 text-choco-muted text-xs whitespace-nowrap">
                      {new Date(scan.created_at).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="px-4 py-3 font-mono text-choco-text text-center">
                      {st?.total_cves ?? '—'}
                    </td>
                    <td className="px-4 py-3 font-mono text-red-400 text-center font-semibold">
                      {st?.critical ?? '—'}
                    </td>
                    <td className="px-4 py-3 font-mono text-orange-400 text-center">
                      {st?.high ?? '—'}
                    </td>
                    <td className="px-4 py-3 font-mono text-yellow-400 text-center">
                      {st?.with_exploit ?? '—'}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-mono ${sc.cls}`}>{sc.label}</span>
                      {scan.error_msg && (
                        <p className="text-red-400 text-[11px] truncate max-w-[180px]" title={scan.error_msg}>
                          {scan.error_msg}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={e => handleDelete(e, scan.id)}
                        className="text-choco-muted hover:text-red-400 transition-colors text-xs">
                        ✕
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
