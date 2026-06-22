import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { uploadScan, directScan, sshScan } from '../api/client'

type Tab = 'upload' | 'direct' | 'ssh'

interface Filters { min_cvss: number; severity: string; after_year: string; no_api: boolean }

function FilterSection({ filters, onChange }: { filters: Filters; onChange: (k: string, v: unknown) => void }) {
  return (
    <div>
      <p className="text-choco-muted text-xs font-medium mb-3">Filtres</p>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-choco-text-dim text-xs block mb-1">CVSS minimum</label>
          <input type="number" min="0" max="10" step="0.5" value={filters.min_cvss}
            onChange={e => onChange('min_cvss', parseFloat(e.target.value) || 0)}
            className="input w-full" placeholder="0.0" />
        </div>
        <div>
          <label className="text-choco-text-dim text-xs block mb-1">Sévérités</label>
          <input value={filters.severity} onChange={e => onChange('severity', e.target.value)}
            className="input w-full" placeholder="CRITICAL,HIGH" />
        </div>
        <div>
          <label className="text-choco-text-dim text-xs block mb-1">CVE depuis l'année</label>
          <input type="number" min="2000" value={filters.after_year}
            onChange={e => onChange('after_year', e.target.value)}
            className="input w-full" placeholder="2020" />
        </div>
        <div className="flex items-end pb-0.5">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={filters.no_api}
              onChange={e => onChange('no_api', e.target.checked)}
              className="w-3.5 h-3.5 rounded accent-choco-accent" />
            <span className="text-choco-text-dim text-xs">Base locale uniquement</span>
          </label>
        </div>
      </div>
    </div>
  )
}

export function NewScan() {
  const navigate = useNavigate()
  const [tab, setTab] = useState<Tab>('upload')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [filters, setFilters] = useState<Filters>({ min_cvss: 0, severity: '', after_year: '', no_api: false })
  const [target, setTarget] = useState('')
  const [nmapArgs, setNmapArgs] = useState('-sV -T4 --open')
  const [ssh, setSsh] = useState({ host: '', port: 22, username: '', password: '', key_path: '' })

  const updateFilter = (k: string, v: unknown) => setFilters(f => ({ ...f, [k]: v }))
  const updateSsh    = (k: string, v: unknown) => setSsh(s => ({ ...s, [k]: v }))

  const submit = async () => {
    setError(null)
    setLoading(true)
    try {
      const opts = {
        min_cvss: filters.min_cvss,
        severity: filters.severity,
        after_year: filters.after_year ? parseInt(filters.after_year) : undefined,
        no_api: filters.no_api,
      }
      let result
      if (tab === 'upload') {
        if (!selectedFile) { setError('Sélectionne un fichier.'); setLoading(false); return }
        result = await uploadScan(selectedFile, opts)
      } else if (tab === 'direct') {
        if (!target) { setError('Saisis une cible.'); setLoading(false); return }
        result = await directScan(target, { ...opts, nmap_args: nmapArgs })
      } else {
        if (!ssh.host || !ssh.username) { setError('Hôte et utilisateur requis.'); setLoading(false); return }
        result = await sshScan({
          host: ssh.host, port: ssh.port, username: ssh.username,
          password: ssh.password || undefined, key_path: ssh.key_path || undefined,
          filters: { min_cvss: filters.min_cvss, severity: filters.severity ? filters.severity.split(',') : [], no_api: filters.no_api },
        })
      }
      navigate(`/scan/${result.id}`)
    } catch (e: unknown) {
      setError((e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Erreur inattendue.')
    } finally {
      setLoading(false)
    }
  }

  const TABS: { id: Tab; label: string; desc: string }[] = [
    { id: 'upload', label: 'Fichier de scan', desc: 'Nmap, Masscan, Nessus…' },
    { id: 'direct', label: 'Scanner une IP',  desc: 'Via nmap intégré'       },
    { id: 'ssh',    label: 'Scan SSH',         desc: 'Paquets installés'      },
  ]

  return (
    <div className="p-6 max-w-xl space-y-5 animate-fade-in">
      <div>
        <h1 className="text-lg font-semibold text-choco-text">Nouveau scan</h1>
        <p className="text-choco-muted text-sm mt-0.5">Analyse un fichier de scan ou lance une analyse directe.</p>
      </div>

      {/* Onglets */}
      <div className="flex gap-px bg-choco-surface border border-choco-border rounded-xl overflow-hidden">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex-1 px-3 py-3 text-left transition-colors duration-150
              ${tab === t.id ? 'bg-choco-surface2' : 'hover:bg-choco-surface2/50'}`}>
            <p className={`text-sm font-medium ${tab === t.id ? 'text-choco-text' : 'text-choco-text-dim'}`}>
              {t.label}
            </p>
            <p className="text-[11px] text-choco-muted mt-0.5">{t.desc}</p>
          </button>
        ))}
      </div>

      <div className="card space-y-4">
        {/* Upload */}
        {tab === 'upload' && (
          <div
            onDragOver={e => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={e => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) setSelectedFile(f) }}
            onClick={() => fileRef.current?.click()}
            className={`border-2 border-dashed rounded-lg py-10 text-center cursor-pointer transition-colors
              ${dragging ? 'border-choco-accent/60 bg-choco-accent/5' : 'border-choco-border hover:border-zinc-500'}`}
          >
            <input ref={fileRef} type="file" className="hidden"
              accept=".xml,.nmap,.txt,.csv,.json,.nessus"
              onChange={e => e.target.files?.[0] && setSelectedFile(e.target.files[0])} />
            {selectedFile ? (
              <>
                <p className="text-sm font-medium text-choco-text">{selectedFile.name}</p>
                <p className="text-choco-muted text-xs mt-1">{(selectedFile.size / 1024).toFixed(1)} Ko · Clic pour changer</p>
              </>
            ) : (
              <>
                <p className="text-sm text-choco-text-dim">Glisse un fichier ici</p>
                <p className="text-choco-muted text-xs mt-1">ou clique pour parcourir</p>
              </>
            )}
          </div>
        )}

        {/* Direct */}
        {tab === 'direct' && (
          <div className="space-y-3">
            <div>
              <label className="text-choco-text-dim text-xs block mb-1">Cible</label>
              <input value={target} onChange={e => setTarget(e.target.value)}
                className="input w-full font-mono" placeholder="10.10.10.50" />
            </div>
            <div>
              <label className="text-choco-text-dim text-xs block mb-1">Arguments nmap</label>
              <input value={nmapArgs} onChange={e => setNmapArgs(e.target.value)}
                className="input w-full font-mono text-xs" />
            </div>
          </div>
        )}

        {/* SSH */}
        {tab === 'ssh' && (
          <div className="space-y-3">
            <div className="grid grid-cols-4 gap-2">
              <div className="col-span-3">
                <label className="text-choco-text-dim text-xs block mb-1">Hôte</label>
                <input value={ssh.host} onChange={e => updateSsh('host', e.target.value)}
                  className="input w-full font-mono" placeholder="10.10.10.50" />
              </div>
              <div>
                <label className="text-choco-text-dim text-xs block mb-1">Port</label>
                <input type="number" value={ssh.port} onChange={e => updateSsh('port', parseInt(e.target.value))}
                  className="input w-full font-mono" />
              </div>
            </div>
            <div>
              <label className="text-choco-text-dim text-xs block mb-1">Utilisateur</label>
              <input value={ssh.username} onChange={e => updateSsh('username', e.target.value)}
                className="input w-full" placeholder="admin" />
            </div>
            <div>
              <label className="text-choco-text-dim text-xs block mb-1">Mot de passe</label>
              <input type="password" value={ssh.password} onChange={e => updateSsh('password', e.target.value)}
                className="input w-full" placeholder="Laisser vide pour utiliser une clé SSH" />
            </div>
            <div>
              <label className="text-choco-text-dim text-xs block mb-1">Clé SSH</label>
              <input value={ssh.key_path} onChange={e => updateSsh('key_path', e.target.value)}
                className="input w-full font-mono text-xs" placeholder="~/.ssh/id_rsa" />
            </div>
          </div>
        )}

        <div className="border-t border-choco-border pt-4">
          <FilterSection filters={filters} onChange={updateFilter} />
        </div>
      </div>

      {error && (
        <p className="text-red-400 text-sm">{error}</p>
      )}

      <button onClick={submit} disabled={loading}
        className="btn-primary w-full py-2.5 justify-center disabled:opacity-50">
        {loading
          ? <><span className="inline-block w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Analyse en cours…</>
          : 'Lancer le scan'}
      </button>
    </div>
  )
}
