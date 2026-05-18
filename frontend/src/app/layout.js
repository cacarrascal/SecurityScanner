import './globals.css'
import Sidebar from '../components/Sidebar'
import Footer from '../components/Footer'

export const metadata = {
  title: 'SecurityScanner',
  description: 'Análisis automático de seguridad y testing E2E.',
  icons: {
    icon: '/hacker.png',
  },
}

export default function RootLayout({ children }) {
  return (
    <html lang="es" className="dark">
      <body className="bg-carlos-bg text-carlos-text">
        <div className="flex h-screen">
          <Sidebar />
          <main className="flex-1 overflow-y-auto">
            <div className="max-w-7xl mx-auto px-6 py-8 pb-20">{children}</div>
          </main>
        </div>
        <Footer />
      </body>
    </html>
  )
}
