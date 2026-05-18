'use client'
import { useState, useMemo } from 'react'
import { ChevronRight, ChevronDown, Filter } from 'lucide-react'

const order = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

export default function VulnTable({ vulnerabilities = [] }) {
  const [expanded, setExpanded] = useState(null)
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')

  const filtered = useMemo(() => {
    let r = [...vulnerabilities]
    if (filter !== 'all') r = r.filter(v => v.severity === filter)
    if (search) {
      const q = search.toLowerCase()
      r = r.filter(v =>
        (v.title || '').toLowerCase().includes(q) ||
        (v.rule_id || '').toLowerCase().includes(q) ||
        (v.file_path || '').toLowerCase().includes(q)
      )
    }
    return r.sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0))
  }, [vulnerabilities, filter, search])

  if (!vulnerabilities.length) {
    return <div className="card p-8 text-center text-carlos-success">✓ Sin vulnerabilidades detectadas.</div>
  }

  return (
    <div className="card overflow-hidden">
      <div className="p-4 border-b border-carlos-border flex flex-wrap gap-3 items-center">
        <Filter className="w-4 h-4 text-carlos-muted" />
        <select value={filter} onChange={e => setFilter(e.target.value)}
          className="bg-carlos-bg border border-carlos-border rounded px-3 py-1.5 text-sm text-white">
          <option value="all">Todas</option>
          <option value="critical">Críticas</option>
          <option value="high">Altas</option>
          <option value="medium">Medias</option>
          <option value="low">Bajas</option>
          <option value="info">Info</option>
        </select>
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Buscar..."
          className="flex-1 min-w-[200px] bg-carlos-bg border border-carlos-border rounded px-3 py-1.5 text-sm text-white placeholder:text-carlos-muted focus:border-carlos-accent outline-none" />
        <span className="text-sm text-carlos-muted">{filtered.length} de {vulnerabilities.length}</span>
      </div>

      <div className="divide-y divide-carlos-border max-h-[600px] overflow-y-auto">
        {filtered.map(v => (
          <div key={v.id}>
            <button onClick={() => setExpanded(expanded === v.id ? null : v.id)}
              className="w-full px-4 py-3 flex items-start gap-3 hover:bg-carlos-bg/50 text-left">
              {expanded === v.id ? (
                <ChevronDown className="w-4 h-4 mt-1 text-carlos-muted shrink-0" />
              ) : (
                <ChevronRight className="w-4 h-4 mt-1 text-carlos-muted shrink-0" />
              )}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`badge-${v.severity}`}>{v.severity}</span>
                  <span className="font-medium text-white truncate">{v.title}</span>
                </div>
                <div className="text-xs text-carlos-muted mt-1 truncate">
                  <code className="font-mono">{v.rule_id}</code>
                  {v.file_path && (
                    <>
                      <span className="mx-2">·</span>
                      <span className="text-carlos-accent">{v.file_path}</span>
                      {v.line_number ? <span>:{v.line_number}</span> : null}
                    </>
                  )}
                </div>
              </div>
              <span className="text-xs text-carlos-muted shrink-0">{v.scanner}</span>
            </button>

            {expanded === v.id && (
              <div className="px-12 pb-4 space-y-3">
                <p className="text-sm text-carlos-text">{v.description}</p>
                {v.code_snippet && (
                  <pre className="bg-carlos-bg p-3 rounded text-xs overflow-x-auto font-mono">{v.code_snippet}</pre>
                )}
                {v.recommendation && (
                  <div className="text-sm">
                    <span className="text-carlos-success font-medium">💡 Recomendación: </span>
                    <span className="text-carlos-text">{v.recommendation}</span>
                  </div>
                )}
                {(v.cwe || v.owasp) && (
                  <div className="flex gap-2 flex-wrap text-xs">
                    {v.cwe && <span className="px-2 py-1 bg-carlos-bg rounded text-carlos-muted">CWE: {v.cwe}</span>}
                    {v.owasp && <span className="px-2 py-1 bg-carlos-bg rounded text-carlos-muted">OWASP: {v.owasp}</span>}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
