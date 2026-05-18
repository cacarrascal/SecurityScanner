'use client'
import { useEffect, useRef } from 'react'
import { Terminal } from 'lucide-react'

const levelColor = {
  info: 'text-carlos-accent',
  success: 'text-carlos-success',
  warning: 'text-carlos-warning',
  error: 'text-carlos-danger',
}

export default function Console({ messages = [] }) {
  const ref = useRef(null)
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight }, [messages])

  return (
    <div className="card overflow-hidden">
      <div className="px-4 py-2 border-b border-carlos-border bg-carlos-bg flex items-center gap-2">
        <Terminal className="w-4 h-4 text-carlos-accent" />
        <span className="text-sm font-medium text-white">Consola en vivo</span>
        <span className="ml-auto text-xs text-carlos-muted">{messages.length} líneas</span>
      </div>
      <div ref={ref} className="h-80 overflow-y-auto p-4 font-mono text-xs leading-relaxed bg-black/40">
        {messages.length === 0 ? (
          <div className="text-carlos-muted italic">Esperando salida del backend...</div>
        ) : (
          messages.map((m, i) => (
            <div key={i} className="flex gap-3">
              <span className="text-carlos-muted shrink-0">
                {m.timestamp ? new Date(m.timestamp).toLocaleTimeString() : ''}
              </span>
              <span className={clsx('uppercase text-[10px] w-12 shrink-0', levelColor[m.level] || 'text-carlos-text')}>
                {m.level || m.type}
              </span>
              <span className="whitespace-pre-wrap break-all flex-1">
                {m.message || m.step || ''}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function clsx(...args) {
  return args.filter(Boolean).join(' ')
}
