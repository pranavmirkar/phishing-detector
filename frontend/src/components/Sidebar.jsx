const NAV = [
  {
    id: 'dashboard', label: 'Dashboard',
    icon: (
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
        <rect x="2" y="2" width="7" height="7" rx="1.5"/>
        <rect x="11" y="2" width="7" height="7" rx="1.5"/>
        <rect x="2" y="11" width="7" height="7" rx="1.5"/>
        <rect x="11" y="11" width="7" height="7" rx="1.5"/>
      </svg>
    ),
  },
  {
    id: 'analyze', label: 'Analyze',
    icon: (
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
        <circle cx="9" cy="9" r="6"/>
        <path d="m17 17-3.5-3.5" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    id: 'history', label: 'History',
    icon: (
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
        <circle cx="10" cy="10" r="7.5"/>
        <path d="M10 6v4l2.5 2.5" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    id: 'patterns', label: 'Attack Patterns',
    icon: (
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
        <path d="M10 2 2 6l8 4 8-4-8-4z" strokeLinejoin="round"/>
        <path d="M2 14l8 4 8-4M2 10l8 4 8-4" strokeLinecap="round"/>
      </svg>
    ),
  },
]

const SUN = (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
    <circle cx="8" cy="8" r="3"/>
    <path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M3.4 12.6l1-1M11.6 4.4l1-1"/>
  </svg>
)
const MOON = (
  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round">
    <path d="M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7z"/>
  </svg>
)

export default function Sidebar({ current, onNavigate, apiOnline, theme, onToggleTheme }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-top">
        <div className="brand">
          <svg className="brand-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round">
            <path d="M10 2 3.5 4.5V9.5c0 4 2.8 7.2 6.5 8.5 3.7-1.3 6.5-4.5 6.5-8.5V4.5L10 2z"/>
          </svg>
          <span className="brand-name">PhishGuard</span>
        </div>

        <nav className="nav">
          {NAV.map(n => (
            <button
              key={n.id}
              className={`nav-item${current === n.id ? ' active' : ''}`}
              onClick={() => onNavigate(n.id)}
              aria-current={current === n.id ? 'page' : undefined}
            >
              {n.icon}
              {n.label}
            </button>
          ))}
        </nav>
      </div>

      <div className="sidebar-bottom">
        <div className="api-status-row" title="Backend API status">
          <span className={`api-dot${apiOnline === true ? ' online' : apiOnline === false ? ' offline' : ''}`} />
          <span>
            {apiOnline === null ? 'Connecting' : apiOnline ? 'API online' : 'API offline'}
          </span>
        </div>
        <button
          className="theme-toggle"
          onClick={onToggleTheme}
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          title={theme === 'dark' ? 'Light mode' : 'Dark mode'}
        >
          {theme === 'dark' ? SUN : MOON}
        </button>
      </div>
    </aside>
  )
}
