'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Globe, AlertCircle } from 'lucide-react'
import ProgressBar from '../../components/ProgressBar'
import Console from '../../components/Console'
import { streamScan, saveResult } from '../../lib/api'

export default function URLPage() {
  const router = useRouter()
  const [url, setUrl] = useState('')
  const [deepScan, setDeepScan] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState(0)
  const [step, setStep] = useState('')
  const [status, setStatus] = useState('')
  const [messages, setMessages] = useState([])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    if (!/^https?:\/\//.test(url)) {
      setError('La URL debe empezar con http:// o https://')
      return
    }
    setMessages([])
    setProgress(0)
    setStep('')
    setStatus('running')
    setLoading(true)

    try {
      const result = await streamScan('/scans/url', { url, deep_scan: deepScan }, {
        onProgress: (e) => { setProgress(e.progress || 0); setStep(e.step || '') },
        onLog: (e) => setMessages(prev => [...prev.slice(-500), e]),
        onStatus: (e) => setStatus(e.status),
        onError: (e) => setError(e.message),
      })

      if (result) {
        saveResult(result.scan_id, result)
        router.push(`/results/${result.scan_id}`)
      } else {
        setLoading(false)
      }
    } catch (err) {
      setError(err.message)
      setLoading(false)
    }
  }

  return (
    <div className="space-y-8 max-w-3xl">
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Globe className="w-8 h-8 text-carlos-accent" /> Escanear URL
        </h1>
        <p className="text-carlos-muted mt-2">
          Detecta headers inseguros, cookies vulnerables, formularios sin CSRF, XSS reflejado, open redirects, paths expuestos y más.
        </p>
      </div>

      {!loading && (
        <>
          <form onSubmit={handleSubmit} className="card p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-white mb-2">URL objetivo</label>
              <input
                type="url"
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full bg-carlos-bg border border-carlos-border rounded px-4 py-2 text-white placeholder:text-carlos-muted focus:border-carlos-accent outline-none"
                required
              />
            </div>

            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={deepScan}
                onChange={e => setDeepScan(e.target.checked)}
                className="w-4 h-4 accent-carlos-accent"
              />
              <div>
                <div className="text-sm text-white">Deep scan</div>
                <div className="text-xs text-carlos-muted">Prueba paths comunes (.env, /admin, .git, backups...) — más lento</div>
              </div>
            </label>

            <button type="submit" disabled={!url}
              className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed">
              Escanear ahora
            </button>

            {error && (
              <div className="flex items-start gap-2 text-sm text-carlos-danger">
                <AlertCircle className="w-4 h-4 mt-0.5" />{error}
              </div>
            )}
          </form>

          <div className="card p-5 border-carlos-warning/40 bg-carlos-warning/5">
            <div className="text-sm text-carlos-warning font-medium">⚠ Solo escaneá sitios con autorización.</div>
            <div className="text-xs text-carlos-muted mt-1">El deep scan envía requests activos (paths, XSS payloads). WAFs pueden detectarlo.</div>
          </div>
        </>
      )}

      {loading && (
        <div className="space-y-6">
          <ProgressBar progress={progress} label={`Estado: ${status}`} step={step} />
          <Console messages={messages} />
          {error && (
            <div className="card p-4 border-carlos-danger/40 bg-carlos-danger/5 text-sm text-carlos-danger">
              {error}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
