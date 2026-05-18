export default function Footer() {
  return (
    <footer className="fixed bottom-0 left-0 right-0 bg-carlos-surface border-t border-carlos-border py-3 px-4">
      <div className="flex items-center justify-center gap-4 md:gap-8">
        <img 
          src="/logo.png" 
          alt="Logo" 
          className="w-6 h-6 md:w-8 md:h-8" 
        />
        <div className="flex items-center gap-2 md:gap-4 text-xs md:text-sm text-carlos-muted">
          <span className="text-carlos-text">Realizado por Carlos Carrascal</span>
          <span className="hidden md:inline">•</span>
          <span>© {new Date().getFullYear()} SecurityScanner</span>
        </div>
      </div>
    </footer>
  )
}