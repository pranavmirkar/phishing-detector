import { useState, useEffect } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import Analyzer from './pages/Analyzer'
import History from './pages/History'
import Patterns from './pages/Patterns'
import { api } from './api/client'
import { useTheme } from './theme'

export default function App() {
  const [page, setPage] = useState('dashboard')
  const [apiOnline, setApiOnline] = useState(null)
  const [theme, toggleTheme] = useTheme()

  useEffect(() => {
    api.health()
      .then(() => setApiOnline(true))
      .catch(() => setApiOnline(false))
  }, [])

  return (
    <div className="shell">
      <Sidebar current={page} onNavigate={setPage} apiOnline={apiOnline} theme={theme} onToggleTheme={toggleTheme} />
      <main className="main">
        {page === 'dashboard' && <Dashboard onNavigate={setPage} theme={theme} />}
        {page === 'analyze'   && <Analyzer />}
        {page === 'history'   && <History />}
        {page === 'patterns'  && <Patterns />}
      </main>
    </div>
  )
}
