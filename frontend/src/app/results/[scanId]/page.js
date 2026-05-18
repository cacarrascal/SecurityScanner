'use client'
import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { ArrowLeft, FileJson } from 'lucide-react'
import Dashboard from '../../../components/Dashboard'
import VulnTable from '../../../components/VulnTable'
import { loadResult, downloadJSON } from '../../../lib/api'

const tabs = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'vulnerabilities', label: 'Vulnerabilidades' },
  { id: 'dependencies', label: 'Dependencias' },
  { id: 'url', label: 'URL Scan' },
  { id: 'metrics', label: 'Métricas' },
]

export default function ResultsPage() {
  const { scanId } = useParams()
  const router = useRouter()
  const [result, setResult] = useState(null)
  const [tab, setTab] = useState('dashboard')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const data = loadResult(scanId)
    if (!data) {
      router.push('/')
      return
    }
    setResult(data)
    setLoading(false)
  }, [scanId, router])

  if (loading) return <div className="text-center text-carlos-muted py-12">Cargando...</div>
  if (!result) return null

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <button onClick={() => router.push('/')}
            className="text-sm text-carlos-muted hover:text-white flex items-center gap-1 mb-2">
            <ArrowLeft className="w-4 h-4" /> Volver
          </button>
          <h1 className="text-2xl font-bold text-white">Resultados del análisis</h1>
          <p className="text-xs text-carlos-muted mt-1 font-mono">{scanId}</p>
          <p className="text-sm text-carlos-muted mt-1">
            Target: <span className="text-carlos-accent">{result.target}</span>
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => downloadJSON(scanId, result)} className="btn-secondary flex items-center gap-2">
            <FileJson className="w-4 h-4" /> Descargar JSON
          </button>
        </div>
      </div>

      <div className="border-b border-carlos-border flex gap-1 overflow-x-auto">
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
              tab === t.id ? 'border-carlos-accent text-white' : 'border-transparent text-carlos-muted hover:text-white'
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      <div>
        {tab === 'dashboard' && <Dashboard result={result} />}
        {tab === 'vulnerabilities' && <VulnTable vulnerabilities={result.vulnerabilities || []} />}
        {tab === 'dependencies' && <DepsView deps={result.dependencies || []} />}
        {tab === 'url' && <URLView url={result.url_result} />}
        {tab === 'metrics' && <MetricsView metrics={result.code_metrics || []} />}
      </div>
    </div>
  )
}

function DepsView({ deps }) {
  if (!deps.length) return <div className="card p-8 text-center text-carlos-success">✓ Sin dependencias vulnerables.</div>
  return (
    <div className="card overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-carlos-bg">
          <tr>
            <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Paquete</th>
            <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Versión</th>
            <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">CVE</th>
            <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Severidad</th>
            <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Fix</th>
            <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Descripción</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-carlos-border">
          {deps.map((d, i) => (
            <tr key={i} className="hover:bg-carlos-bg/50">
              <td className="px-4 py-2 font-mono text-white">{d.package}</td>
              <td className="px-4 py-2 text-carlos-muted">{d.version}</td>
              <td className="px-4 py-2 font-mono text-xs text-carlos-accent">{d.vulnerability_id}</td>
              <td className="px-4 py-2"><span className={`badge-${d.severity}`}>{d.severity}</span></td>
              <td className="px-4 py-2 text-carlos-success">{d.fix_version || '—'}</td>
              <td className="px-4 py-2 text-xs text-carlos-text">{d.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function MetricsView({ metrics }) {
  if (!metrics.length) return <div className="card p-8 text-center text-carlos-muted">Sin métricas.</div>
  return (
    <div className="card overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-carlos-bg">
          <tr>
            <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Archivo</th>
            <th className="text-left px-4 py-2 text-carlos-muted text-xs uppercase">Lenguaje</th>
            <th className="text-right px-4 py-2 text-carlos-muted text-xs uppercase">LOC</th>
            <th className="text-right px-4 py-2 text-carlos-muted text-xs uppercase">Complejidad</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-carlos-border">
          {metrics.slice(0, 200).map((m, i) => (
            <tr key={i} className="hover:bg-carlos-bg/50">
              <td className="px-4 py-2 font-mono text-xs text-white truncate max-w-md">{m.file_path}</td>
              <td className="px-4 py-2 text-carlos-muted text-xs">{m.language}</td>
              <td className="px-4 py-2 text-right text-carlos-text tabular-nums">{m.lines_of_code}</td>
              <td className="px-4 py-2 text-right text-carlos-text tabular-nums">{m.complexity?.toFixed(2)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function URLView({ url }) {
  if (!url) return <div className="card p-8 text-center text-carlos-muted">Sin escaneo de URL.</div>
  return (
    <div className="space-y-4">
      <div className="card p-5">
        <h3 className="font-medium text-white mb-3">HTTP</h3>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div><span className="text-carlos-muted">URL:</span> <span className="text-carlos-accent">{url.url}</span></div>
          <div><span className="text-carlos-muted">Final URL:</span> <span className="text-carlos-text">{url.final_url}</span></div>
          <div><span className="text-carlos-muted">Status:</span> <span className="text-white">{url.status_code}</span></div>
          <div><span className="text-carlos-muted">Formularios:</span> <span className="text-white">{url.forms?.length || 0}</span></div>
        </div>
      </div>

      {url.technologies?.length > 0 && (
        <div className="card p-5">
          <h3 className="font-medium text-white mb-3">Tecnologías</h3>
          <div className="flex gap-2 flex-wrap">
            {url.technologies.map((t, i) => (
              <span key={i} className="px-2 py-1 bg-carlos-bg border border-carlos-border rounded text-xs">{t}</span>
            ))}
          </div>
        </div>
      )}

      {url.exposed_paths?.length > 0 && (
        <div className="card p-5 border-carlos-warning/40">
          <h3 className="font-medium text-carlos-warning mb-3">Paths expuestos ({url.exposed_paths.length})</h3>
          <ul className="space-y-1 text-sm font-mono">
            {url.exposed_paths.map((p, i) => (
              <li key={i} className="flex items-center gap-2">
                <span className="badge-medium">{p.status}</span>
                <span className="text-carlos-text">{p.path}</span>
                <span className="text-carlos-muted text-xs">{p.size} bytes</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {url.missing_security_headers?.length > 0 && (
        <div className="card p-5">
          <h3 className="font-medium text-white mb-3">Headers de seguridad faltantes</h3>
          <ul className="space-y-1 text-sm">
            {url.missing_security_headers.map((h, i) => (
              <li key={i} className="text-carlos-warning">• {h}</li>
            ))}
          </ul>
        </div>
      )}

      {url.insecure_cookies?.length > 0 && (
        <div className="card p-5">
          <h3 className="font-medium text-white mb-3">Cookies inseguras</h3>
          <table className="w-full text-sm">
            <thead><tr className="text-carlos-muted text-xs uppercase">
              <th className="text-left py-2">Nombre</th>
              <th className="text-left py-2">Issues</th>
            </tr></thead>
            <tbody>
              {url.insecure_cookies.map((c, i) => (
                <tr key={i}>
                  <td className="py-2 font-mono text-white">{c.name}</td>
                  <td className="py-2 text-carlos-warning">{(c.issues || []).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {url.reflected_xss?.length > 0 && (
        <div className="card p-5 border-carlos-danger/40">
          <h3 className="font-medium text-carlos-danger mb-3">XSS reflejado detectado</h3>
          <ul className="text-sm space-y-1">
            {url.reflected_xss.map((r, i) => <li key={i} className="text-carlos-text">• {r}</li>)}
          </ul>
        </div>
      )}

      {url.open_redirects?.length > 0 && (
        <div className="card p-5 border-carlos-warning/40">
          <h3 className="font-medium text-carlos-warning mb-3">Open redirects</h3>
          <ul className="text-sm space-y-1">
            {url.open_redirects.map((r, i) => <li key={i} className="text-carlos-text">• {r}</li>)}
          </ul>
        </div>
      )}
    </div>
  )
}
