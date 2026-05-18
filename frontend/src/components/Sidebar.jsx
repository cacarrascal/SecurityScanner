'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Shield, Upload, Globe, GitBranch, Info, Activity, List } from 'lucide-react'
import clsx from 'clsx'

const items = [
  { href: '/', icon: Upload, label: 'Subir proyecto' },
  { href: '/url', icon: Globe, label: 'Escanear URL' },
  { href: '/git', icon: GitBranch, label: 'Repo Git' },
  { href: '/scans', icon: List, label: 'Mis escaneos' },
  { href: '/about', icon: Info, label: 'Acerca de' },
]

export default function Sidebar() {
  const pathname = usePathname()
  return (
    <aside className="w-64 bg-carlos-surface border-r border-carlos-border flex flex-col">
      <div className="px-6 py-6 border-b border-carlos-border">
        <Link href="/" className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-carlos-accent" />
          <div>
            <div className="text-xl font-bold text-white tracking-tight">SecurityScanner</div>
            <div className="text-xs text-carlos-muted">Security Analyzer</div>
          </div>
        </Link>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {items.map(({ href, icon: Icon, label }) => {
          const active = pathname === href || (href !== '/' && pathname.startsWith(href))
          return (
            <Link
              key={href}
              href={href}
              className={clsx(
                'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                active
                  ? 'bg-carlos-accent/10 text-carlos-accent border-l-2 border-carlos-accent'
                  : 'text-carlos-text hover:bg-carlos-bg hover:text-white'
              )}
            >
              <Icon className="w-4 h-4" />
              {label}
            </Link>
          )
        })}
      </nav>

      <div className="px-4 py-3 border-t border-carlos-border text-xs text-carlos-muted">
        <div className="flex items-center gap-2">
          <Activity className="w-3 h-3 text-carlos-success animate-pulse" />
          <span>Sin persistencia</span>
        </div>
        <div className="mt-1 text-[10px] opacity-60">Workspace efímero · TTL 1h</div>
      </div>
    </aside>
  )
}
