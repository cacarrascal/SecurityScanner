export default function ProgressBar({ progress = 0, label = '', step = '' }) {
  const pct = Math.min(100, Math.max(0, progress))
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-2">
        <div>
          <div className="text-sm font-medium text-white">{label || 'Progreso'}</div>
          {step && <div className="text-xs text-carlos-muted mt-0.5">{step}</div>}
        </div>
        <div className="text-2xl font-bold text-carlos-accent tabular-nums">{pct.toFixed(1)}%</div>
      </div>
      <div className="w-full h-3 bg-carlos-bg rounded-full overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-carlos-accent to-blue-400 transition-all duration-300"
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}
