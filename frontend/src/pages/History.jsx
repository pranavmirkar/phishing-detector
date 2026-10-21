import { useEffect, useState } from 'react'
import RiskBadge from '../components/RiskBadge'
import { api } from '../api/client'

function timeAgo(iso) {
  const diff = Date.now() - new Date(iso + 'Z').getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return new Date(iso).toLocaleDateString('en', { month: 'short', day: 'numeric' })
}

export default function History() {
  const [emails,  setEmails]  = useState([])
  const [loading, setLoading] = useState(true)
  const [filter,  setFilter]  = useState('ALL')

  useEffect(() => {
    api.emails()
      .then(setEmails)
      .catch(() => setEmails([]))
      .finally(() => setLoading(false))
  }, [])

  const visible = filter === 'ALL' ? emails : emails.filter(e => e.risk_score === filter)

  return (
    <>
      <header className="page-hd">
        <div>
          <h1 className="page-title">History</h1>
          <p className="page-sub">{emails.length} email{emails.length !== 1 ? 's' : ''} analyzed</p>
        </div>
        <div className="filter-row">
          {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
            <button key={f} className={`filter-btn${filter === f ? ' active' : ''}`} onClick={() => setFilter(f)}>
              {f === 'ALL' ? 'All' : f.charAt(0) + f.slice(1).toLowerCase()}
            </button>
          ))}
        </div>
      </header>

      <div className="card">
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>#</th>
                <th>Sender</th>
                <th>Domain</th>
                <th>Subject</th>
                <th>Risk</th>
                <th>Flags</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="7"><div className="loading-row"><span className="spinner" /> Loading…</div></td></tr>
              ) : visible.length === 0 ? (
                <tr><td colSpan="7" className="tbl-empty">
                  {emails.length === 0 ? 'No emails analyzed yet. Go to Analyze Email to get started.' : 'No emails match this filter.'}
                </td></tr>
              ) : visible.map((e, idx) => (
                <tr key={e.id}>
                  <td style={{ color: 'var(--text-3)', fontSize: '.75rem' }}>{idx + 1}</td>
                  <td className="mono truncate">{e.sender}</td>
                  <td className="mono" style={{ color: 'var(--text)' }}>{e.domain}</td>
                  <td style={{ maxWidth: 220 }} className="truncate">
                    {e.subject || <span style={{ color: 'var(--text-3)' }}>—</span>}
                  </td>
                  <td><RiskBadge level={e.risk_score} /></td>
                  <td>
                    <span style={{ fontSize: '.78rem', color: 'var(--text-3)' }}>
                      {e.warnings?.length ?? 0} flag{e.warnings?.length !== 1 ? 's' : ''}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-3)', fontSize: '.78rem', whiteSpace: 'nowrap' }}>
                    {timeAgo(e.timestamp)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
