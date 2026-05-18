'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { GitBranch, AlertCircle } from 'lucide-react'
import ProgressBar from '../../components/ProgressBar'
import Console from '../../components/Console'
import { streamScan, saveResult } from '../../lib/api'

export default function GitPage() {
  const router = useRouter()
  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('main')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState(0)
  const [step, setStep] = useState('')
  const [status, setStatus] = useState('')
  const [messages, setMessages] = useState([])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    setMessages([])
    setProgress(0)
    setStep('')
    setStatus('running')
    setLoading(true)

    try {
      const result = await streamScan('/scans/git', { repo_url: repoUrl, branch }, {
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
          <GitBranch className="w-8 h-8 text-carlos-accent" /> Repositorio Git
        </h1>
        <p className="text-carlos-muted mt-2">Cloná un repo público y analizalo automáticamente.</p>
      </div>

      {!loading && (
        <form onSubmit={handleSubmit} className="card p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-white mb-2">URL del repo</label>
            <input
              type="url"
              value={repoUrl}
              onChange={e => setRepoUrl(e.target.value)}
              placeholder="https://github.com/usuario/repo.git"
              className="w-full bg-carlos-bg border border-carlos-border rounded px-4 py-2 text-white placeholder:text-carlos-muted focus:border-carlos-accent outline-none"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-white mb-2">Branch</label>
            <input
              type="text"
              value={branch}
              onChange={e => setBranch(e.target.value)}
              placeholder="main"
              className="w-full bg-carlos-bg border border-carlos-border rounded px-4 py-2 text-white placeholder:text-carlos-muted focus:border-carlos-accent outline-none"
            />
          </div>
          <button type="submit" disabled={!repoUrl}
            className="btn-primary w-full disabled:opacity-50">
            Clonar y analizar
          </button>
          {error && (
            <div className="flex items-start gap-2 text-sm text-carlos-danger">
              <AlertCircle className="w-4 h-4 mt-0.5" />{error}
            </div>
          )}
        </form>
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
