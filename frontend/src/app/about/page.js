import { Shield, Code2, GitBranch, Globe, Lock } from 'lucide-react'

export default function AboutPage() {
  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Shield className="w-8 h-8 text-carlos-accent" /> Acerca de SecurityScanner
        </h1>
        <p className="text-carlos-muted mt-2">Security analyzer sin DB, sin auth, sin persistencia.</p>
      </div>

      <div className="card p-6 space-y-3">
        <h2 className="text-xl font-semibold text-white">Cómo funciona</h2>
        <ol className="space-y-2 text-sm text-carlos-text list-decimal list-inside">
          <li>Subís ZIP, repo Git o URL.</li>
          <li>Backend crea workspace temporal y ejecuta scanners reales.</li>
          <li>WebSocket transmite progreso en vivo.</li>
          <li>Se generan reportes HTML, PDF y JSON.</li>
          <li>Workspace se elimina automáticamente tras 1h.</li>
        </ol>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Section Icon={Code2} title="Scanners embebidos (sin deps)">
          <ul className="text-sm space-y-1 text-carlos-text">
            <li>• Pattern scanner: secretos, eval, exec, SQL injection, XSS</li>
            <li>• Dependency scanner: requirements.txt, package.json, composer.json</li>
            <li>• Complexity scanner: LOC, ciclomática por archivo</li>
            <li>• URL scanner: headers, cookies, XSS, paths, redirects, info disclosure</li>
          </ul>
        </Section>
        <Section Icon={Globe} title="Scanners externos (opcionales)">
          <ul className="text-sm space-y-1 text-carlos-text">
            <li>• Semgrep (si está instalado)</li>
            <li>• Bandit (Python)</li>
            <li>• pip-audit (CVE deps Python)</li>
          </ul>
        </Section>
        <Section Icon={Lock} title="Seguridad del propio SecurityScanner">
          <ul className="text-sm space-y-1 text-carlos-text">
            <li>• SSRF: bloquea IPs privadas en URL scans</li>
            <li>• Path traversal: validación en ZIP extract</li>
            <li>• Zip bomb: límite de descompresión</li>
            <li>• File size: 500MB máx por upload</li>
            <li>• Workspaces TTL: 1h auto-cleanup</li>
          </ul>
        </Section>
        <Section Icon={GitBranch} title="Lenguajes soportados">
          <ul className="text-sm space-y-1 text-carlos-text">
            <li>• Python, JS/TS, Java, PHP, Go, Rust, Ruby</li>
            <li>• React, Vue, Angular, Svelte, Next.js</li>
            <li>• Django, Flask, FastAPI, Express, Laravel</li>
          </ul>
        </Section>
      </div>

      <div className="card p-5 border-carlos-warning/40 bg-carlos-warning/5">
        <div className="text-sm text-carlos-warning font-medium">⚠ Para análisis defensivo y pruebas autorizadas.</div>
      </div>
    </div>
  )
}

function Section({ Icon, title, children }) {
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-5 h-5 text-carlos-accent" />
        <h3 className="font-semibold text-white">{title}</h3>
      </div>
      {children}
    </div>
  )
}
