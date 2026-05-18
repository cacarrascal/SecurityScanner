'use client'
import { Shield, AlertTriangle, FileWarning, Code2 } from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts'

const SEV_COLOR = {
  critical: '#f85149', high: '#ff7b72', medium: '#d29922', low: '#58a6ff', info: '#8b949e',
}

function Score({ label, value, Icon }) {
  const cls = value >= 80 ? 'text-carlos-success' : value >= 50 ? 'text-carlos-warning' : 'text-carlos-danger'
  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-carlos-muted uppercase tracking-wide">{label}</span>
        <Icon className={`w-5 h-5 ${cls}`} />
      </div>
      <div className={`text-4xl font-bold tabular-nums ${cls}`}>{value}</div>
      <div className="text-xs text-carlos-muted mt-1">/ 100</div>
    </div>
  )
}

function Stat({ label, value, Icon }) {
  return (
    <div className="card p-5">
      <div className="flex items-center gap-3">
        <Icon className="w-8 h-8 text-carlos-accent" />
        <div>
          <div className="text-2xl font-bold text-white tabular-nums">{value}</div>
          <div className="text-xs text-carlos-muted">{label}</div>
        </div>
      </div>
    </div>
  )
}

export default function Dashboard({ result }) {
  if (!result) return null
  const sev = result.metrics?.severity_breakdown || {}
  const pieData = ['critical', 'high', 'medium', 'low', 'info'].map(k => ({
    name: k.charAt(0).toUpperCase() + k.slice(1),
    value: sev[k] || 0,
    color: SEV_COLOR[k],
  })).filter(d => d.value > 0)

  const scannerCounts = (result.vulnerabilities || []).reduce((acc, v) => {
    acc[v.scanner] = (acc[v.scanner] || 0) + 1
    return acc
  }, {})
  const barData = Object.entries(scannerCounts).map(([name, count]) => ({ name, count }))

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Score label="Security Score" value={result.security_score || 0} Icon={Shield} />
        <Score label="Quality Score" value={result.quality_score || 0} Icon={Code2} />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Stat label="Vulnerabilidades" value={(result.vulnerabilities || []).length} Icon={AlertTriangle} />
        <Stat label="Deps vulnerables" value={(result.dependencies || []).length} Icon={FileWarning} />
        <Stat label="Archivos analizados" value={result.metrics?.total_files || 0} Icon={Code2} />
        <Stat label="Líneas de código" value={result.metrics?.lines_of_code || 0} Icon={Code2} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card p-5">
          <h3 className="text-sm font-medium text-white mb-3">Severidad</h3>
          <div className="h-64">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" cx="50%" cy="50%" innerRadius={50} outerRadius={90} label>
                    {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-carlos-muted">Sin vulnerabilidades</div>
            )}
          </div>
        </div>
        <div className="card p-5">
          <h3 className="text-sm font-medium text-white mb-3">Por scanner</h3>
          <div className="h-64">
            {barData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData}>
                  <CartesianGrid stroke="#30363d" />
                  <XAxis dataKey="name" stroke="#8b949e" fontSize={11} />
                  <YAxis stroke="#8b949e" />
                  <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d' }} />
                  <Bar dataKey="count" fill="#58a6ff" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-carlos-muted">Sin datos</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
