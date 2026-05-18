import axios from 'axios'

export const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
})

export const scansAPI = {
  status: () => api.get('/status'),
  health: () => api.get('/health'),
}

/**
 * streamScan — abre un POST contra el backend y procesa los SSE que va emitiendo.
 *
 * @param {string} path       endpoint relativo bajo /api (ej. "/scans/git")
 * @param {object|FormData} body    body del POST (JSON o FormData)
 * @param {object} handlers   { onProgress, onLog, onStatus, onResult, onError }
 * @returns {Promise<object|null>}  el ScanResult final o null si falló
 */
export async function streamScan(path, body, handlers = {}) {
  const isForm = typeof FormData !== 'undefined' && body instanceof FormData
  const init = {
    method: 'POST',
    headers: isForm ? {} : { 'Content-Type': 'application/json' },
    body: isForm ? body : JSON.stringify(body),
  }

  const res = await fetch(`/api${path}`, init)
  if (!res.ok) {
    let detail = ''
    try { detail = (await res.json())?.detail || '' } catch {}
    throw new Error(detail || `HTTP ${res.status}`)
  }
  if (!res.body) throw new Error('Sin stream de respuesta')

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let finalResult = null

  while (true) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })

    // SSE frames separados por línea en blanco
    let idx
    while ((idx = buffer.indexOf('\n\n')) !== -1) {
      const frame = buffer.slice(0, idx)
      buffer = buffer.slice(idx + 2)

      for (const line of frame.split('\n')) {
        if (!line.startsWith('data:')) continue
        const json = line.slice(5).trim()
        if (!json) continue
        let evt
        try { evt = JSON.parse(json) } catch { continue }

        switch (evt.type) {
          case 'progress': handlers.onProgress?.(evt); break
          case 'log':      handlers.onLog?.(evt);      break
          case 'status':   handlers.onStatus?.(evt);   break
          case 'result':   finalResult = evt.result; handlers.onResult?.(evt.result); break
          case 'error':    handlers.onError?.(evt);   break
        }
      }
    }
  }

  return finalResult
}

/** Guarda el resultado en localStorage para que /results/[scanId] lo lea. */
export function saveResult(scanId, result) {
  try {
    localStorage.setItem(`scan-${scanId}`, JSON.stringify(result))
  } catch (e) {
    console.warn('No se pudo guardar el resultado en localStorage:', e)
  }
}

export function loadResult(scanId) {
  try {
    const raw = localStorage.getItem(`scan-${scanId}`)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

/** Construye un Blob con el JSON del resultado y devuelve una URL descargable. */
export function downloadJSON(scanId, result) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  triggerDownload(url, `scan-${scanId.slice(0, 8)}.json`)
}

function triggerDownload(url, filename) {
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  setTimeout(() => {
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, 100)
}
