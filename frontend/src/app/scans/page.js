'use client'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { List, RefreshCw, Trash2 } from 'lucide-react'

function loadLocalScans() {
  if (typeof window === 'undefined') return []
  const out = []
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i)
    if (!key || !key.startsWith('scan-')) continue
    try {
      const data = JSON.parse(localStorage.getItem(key))
      if (data?.scan_id) out.push(data)
    } catch {}
  }
  return out.sort((a, b) => (b.started_at || '').localeCompare(a.started_at || ''))
}

export default function ScansListPage() {
  const [scans, setScans] = useState([])

  const load = () => setScans(loadLocalScans())

  useEffect(() => { load() }, [])

  const remove = (id) => {
    if (!confirm('¿Eliminar este escaneo del historial local?')) return
    localStorage.removeItem(`scan-${id}`)
    load()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <List className="w-8 h-8 text-carlos-accent" /> Mis escaneos
        </h1>
        <button onClick={load} className="btn-secondary flex items-center gap-2">
          <RefreshCw className="w-4 h-4" /> Recargar
        </button>
      </div>

      <p className="text-sm text-carlos-muted">
        Los escaneos se guardan localmente en tu navegador (este dispositivo). No hay persistencia en servidor.
      </p>

      {scans.length === 0 && (
        <div className="card p-12 text-center text-carlos-muted">
          Sin escaneos. <Link href="/" className="text-carlos-accent">Comenzar uno →</Link>
        </div>
      )}

      {scans.length > 0 && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-carlos-bg">
              <tr>
                <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Scan ID</th>
                <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Target</th>
                <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Estado</th>
                <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Score</th>
                <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Iniciado</th>
                <th className="text-right px-4 py-2 text-carlos-muted text-xs uppercase">Acciones</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-carlos-border">
              {scans.map(s => (
                <tr key={s.scan_id} className="hover:bg-carlos-bg/50">
                  <td className="px-4 py-2 font-mono text-xs text-carlos-text">{s.scan_id.slice(0, 8)}...</td>
                  <td className="px-4 py-2 text-white truncate max-w-md">{s.target}</td>
                  <td className="px-4 py-2">
                    <span className={`badge-${s.status === 'completed' ? 'low' : s.status === 'running' ? 'medium' : 'high'}`}>
                      {s.status}
                    </span>
                  </td>
                  <td className="px-4 py-2 tabular-nums text-carlos-text">{s.security_score ?? '—'}</td>
                  <td className="px-4 py-2 text-xs text-carlos-muted">
                    {s.started_at ? new Date(s.started_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-2 text-right space-x-3">
                    <Link href={`/results/${s.scan_id}`} className="text-carlos-accent text-xs">Ver →</Link>
                    <button onClick={() => remove(s.scan_id)} className="text-carlos-danger text-xs">
                      <Trash2 className="w-3 h-3 inline" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
