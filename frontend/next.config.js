/** @type {import('next').NextConfig} */
const nextConfig = {
  // En Vercel, /api/* lo enruta vercel.json directamente al Python function.
  // En local (sin Vercel), reenviamos a uvicorn en localhost:8000.
  async rewrites() {
    if (process.env.NODE_ENV === 'production') return []
    const backendUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
    return [
      { source: '/api/:path*', destination: `${backendUrl}/api/:path*` },
    ]
  },
}

module.exports = nextConfig
