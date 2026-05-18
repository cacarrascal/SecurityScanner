'use client'
import { useCallback, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useDropzone } from 'react-dropzone'
import { Upload, FileArchive, AlertCircle, Shield, Zap, Eye, FileSearch } from 'lucide-react'
import ProgressBar from '../components/ProgressBar'
import Console from '../components/Console'
import { streamScan, saveResult } from '../lib/api'

const features = [
  { Icon: Shield, title: 'Multi-scanner', desc: 'Pattern matching + Bandit + deps + complexity.' },
  { Icon: Zap, title: 'Multi-lenguaje', desc: 'Python, JS/TS, Java, PHP, Go, Ruby y más.' },
  { Icon: Eye, title: 'Sin persistencia', desc: 'Workspaces efímeros (serverless).' },
  { Icon: FileSearch, title: 'Reportes', desc: 'JSON descargable con scoring.' },
]

export default function HomePage() {
  const router = useRouter()
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState(0)
  const [step, setStep] = useState('')
  const [status, setStatus] = useState('')
  const [messages, setMessages] = useState([])

  const onDrop = useCallback(async (files) => {
    if (!files.length) return
    setError(null)
    setMessages([])
    setProgress(0)
    setStep('')
    setStatus('running')
    setScanning(true)

    const form = new FormData()
    form.append('file', files[0])

    try {
      const result = await streamScan('/scans/upload', form, {
        onProgress: (e) => { setProgress(e.progress || 0); setStep(e.step || '') },
        onLog: (e) => setMessages(prev => [...prev.slice(-500), e]),
        onStatus: (e) => setStatus(e.status),
        onError: (e) => setError(e.message),
      })
      if (result) {
        saveResult(result.scan_id, result)
        router.push(`/results/${result.scan_id}`)
      } else {
        setScanning(false)
      }
    } catch (err) {
      setError(err.message)
      setScanning(false)
    }
  }, [router])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    disabled: scanning,
  })

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white">Análisis de Seguridad</h1>
        <p className="text-carlos-muted mt-2">
          Subí un proyecto y descubrí vulnerabilidades, debilidades y problemas de calidad del código.
        </p>
      </div>

      {!scanning && (
        <div className="space-y-4">
          <div {...getRootProps()}
            className={`card p-12 border-2 border-dashed transition-all cursor-pointer text-center ${
              isDragActive ? 'border-carlos-accent bg-carlos-accent/5' : 'border-carlos-border hover:border-carlos-accent'
            }`}>
            <input {...getInputProps()} />
            <div className="flex flex-col items-center gap-4">
              <Upload className="w-16 h-16 text-carlos-muted" />
              <div>
                <div className="text-lg font-medium text-white">
                  {isDragActive ? 'Soltá el archivo' : 'Arrastrá ZIP, TAR o archivo de código'}
                </div>
                <div className="text-sm text-carlos-muted mt-1">o hacé click — máx ~50MB</div>
              </div>
              <div className="flex gap-2 flex-wrap justify-center mt-2">
                {['ZIP', 'TAR', 'PY', 'JS', 'TS', 'JAVA', 'PHP', 'GO'].map(ext => (
                  <span key={ext} className="text-xs px-2 py-1 bg-carlos-bg border border-carlos-border rounded">{ext}</span>
                ))}
              </div>
            </div>
          </div>

          {error && (
            <div className="card p-4 border-carlos-danger/40 bg-carlos-danger/5 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-carlos-danger shrink-0 mt-0.5" />
              <div>
                <div className="font-medium text-carlos-danger">Error</div>
                <div className="text-sm text-carlos-text mt-1">{error}</div>
              </div>
            </div>
          )}
        </div>
      )}

      {scanning && (
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

      {!scanning && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {features.map(({ Icon, title, desc }) => (
            <div key={title} className="card p-5">
              <Icon className="w-6 h-6 text-carlos-accent mb-3" />
              <h3 className="text-sm font-semibold text-white">{title}</h3>
              <p className="text-xs text-carlos-muted mt-1">{desc}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
