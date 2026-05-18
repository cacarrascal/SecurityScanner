'use client'
import { useEffect } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { loadResult } from '../../../lib/api'

// Página obsoleta: en la arquitectura serverless el progreso es inline en la
// página de origen (/, /git, /url) y al terminar se navega a /results/[id].
// Si alguien llega aquí (link antiguo), redirigimos según corresponda.
export default function ScanPage() {
  const { scanId } = useParams()
  const router = useRouter()

  useEffect(() => {
    if (!scanId) return
    if (loadResult(scanId)) {
      router.replace(`/results/${scanId}`)
    } else {
      router.replace('/')
    }
  }, [scanId, router])

  return <div className="text-center text-carlos-muted py-12">Redirigiendo...</div>
}
