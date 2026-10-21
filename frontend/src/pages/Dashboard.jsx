import { useEffect, useState } from 'react'
import { Bar } from 'react-chartjs-2'
import RiskBadge from '../components/RiskBadge'
import { api } from '../api/client'
import { cssVar } from '../theme'

function timeAgo(iso) {
  const diff = Date.now() - new Date(iso + 'Z').getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

const ATTACK_LABELS = {
  LOOKALIKE_DOMAIN: 'Lookalike domain',
  SUSPICIOUS_KEYWORDS: 'Suspicious keywords',
  LINK_MISMATCH: 'Link mismatch',
  SUBDOMAIN_ABUSE: 'Subdomain abuse',
  HOMOGLYPH_ATTACK: 'Homoglyph attack',
  REPLY_TO_MISMATCH: 'Reply-To mismatch',
  VERY_NEW_DOMAIN: 'Very new domain',
  NEW_DOMAIN: 'New domain',
  BRAND_IMPERSONATION: 'Brand impersonation',
  BRAND_IN_DOMAIN: 'Brand name in domain',
  BRAND_MISMATCH: 'Brand / sender mismatch',
  ACCOUNT_ACTION_LURE: 'Account-action lure',
  ADMIN_IMPERSONATION: 'Admin impersonation',
  BEC_SCAM_PATTERN: 'Payment / advance-fee scam',
  SUSPICIOUS_LINK: 'Suspicious link',
  PUNYCODE_DOMAIN: 'Punycode domain',
  AUTH_FAILURE: 'Authentication failure',
}

export default function Dashboard({ onNavigate, theme }) {
  const [stats, setStats]   = useState(null)
  const [emails, setEmails] = useState([])
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      const [s, e] = await Promise.all([api.stats(), api.emails()])
      setStats(s)
      setEmails(e.slice(0, 5))
    } catch {
      // API offline — show zeros
      setStats({ total:0, high:0, medium:0, low:0, trend:[], attack_types:{} })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Colours come from CSS tokens so the canvas follows light/dark mode.
  const c = {
    danger: cssVar('--danger'), warn: cssVar('--warn'), safe: cssVar('--safe'),
    grid: cssVar('--border'), tick: cssVar('--text-3'), text: cssVar('--text'),
    card: cssVar('--card'), border: cssVar('--border-2'),
  }

  // ── Trend chart ─────────────────────────────────────────────────
  const SERIES = [
    { key: 'HIGH',   label: 'High',   color: c.danger },
    { key: 'MEDIUM', label: 'Medium', color: c.warn },
    { key: 'LOW',    label: 'Low',    color: c.safe },
  ]
  const trendData = (() => {
    if (!stats?.trend?.length) return null
    const days = [...new Set(stats.trend.map(r => r.day))].sort()
    const get  = (day, score) => stats.trend.find(r => r.day === day && r.risk_score === score)?.cnt ?? 0
    return {
      labels: days.map(d => new Date(d).toLocaleDateString('en', { month: 'short', day: 'numeric' })),
      datasets: SERIES.map(s => ({
        label: s.label,
        data: days.map(d => get(d, s.key)),
        backgroundColor: s.color,
        borderRadius: 2,
        maxBarThickness: 28,
      })),
    }
  })()

  const trendOptions = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: c.card, titleColor: c.text, bodyColor: c.text,
        borderColor: c.border, borderWidth: 1, padding: 10, boxPadding: 4,
        usePointStyle: true, pointStyle: 'rectRounded',
      },
    },
    scales: {
      x: { stacked: true, grid: { display: false }, border: { color: c.grid }, ticks: { color: c.tick, font: { size: 11 } } },
      y: { stacked: true, beginAtZero: true, grid: { color: c.grid }, border: { display: false },
           ticks: { color: c.tick, font: { size: 11 }, precision: 0 } },
    },
  }

  // ── Attack types ────────────────────────────────────────────────
  const attackEntries = Object.entries(stats?.attack_types ?? {})
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
  const attackMax = Math.max(1, ...attackEntries.map(([, v]) => v))

  const intel = stats?.intel ?? {}
  const intelStatus = (() => {
    if (['downloading', 'processing', 'storing'].includes(intel.state))
      return { text: `Updating Tranco domain list (${intel.state})`, cls: 'busy' }
    if (intel.state === 'error')
      return { text: `Tranco update failed: ${intel.error}`, cls: 'error' }
    if (intel.domain_count > 0)
      return { text: `${intel.domain_count.toLocaleString()} trusted domains loaded from Tranco`, cls: 'ok' }
    return { text: 'Tranco domain list not downloaded', cls: '' }
  })()

  return (
    <>
      <header className="page-hd">
        <h1 className="page-title">Dashboard</h1>
        <button className="btn btn-ghost" onClick={load} disabled={loading}>
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
            <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/><path d="M13.5 2.5v3h-3"/>
          </svg>
          Refresh
        </button>
      </header>

      {!loading && (
        <div className="notice">
          <span className={`notice-dot ${intelStatus.cls}`} />
          <span>{intelStatus.text}</span>
          {(!intel.domain_count || intel.state === 'error') ? (
            <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto' }}
              onClick={async () => { await api.intelUpdate?.(); load() }}>
              Download now
            </button>
          ) : intel.updated_at && (
            <span className="notice-meta">Updated {timeAgo(intel.updated_at)}</span>
          )}
        </div>
      )}

      <div className="stat-grid">
        {[
          { label: 'Analyzed',    value: stats?.total,  note: 'All time',        mod: '' },
          { label: 'High risk',   value: stats?.high,   note: 'Likely phishing', mod: 'danger' },
          { label: 'Medium risk', value: stats?.medium, note: 'Suspicious',      mod: 'warn' },
          { label: 'Low risk',    value: stats?.low,    note: 'No issues found', mod: 'safe' },
        ].map(s => (
          <div key={s.label} className={`stat-card ${s.mod}`}>
            <p className="stat-label">{s.mod && <span className="sw" />}{s.label}</p>
            <p className="stat-value">{loading || s.value == null ? '–' : s.value}</p>
            <p className="stat-note">{s.note}</p>
          </div>
        ))}
      </div>

      <div className="charts-row">
        <div className="card">
          <div className="card-hd">
            <h3 className="card-title">Last 7 days</h3>
            {trendData && (
              <div className="chart-legend-inline">
                {SERIES.map(s => <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>)}
              </div>
            )}
          </div>
          <div className="chart-body">
            {trendData ? (
              <div className="chart-canvas-wrap">
                <Bar key={theme} data={trendData} options={trendOptions} />
              </div>
            ) : (
              <div className="empty-state">No emails analyzed in the last 7 days.</div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-hd">
            <h3 className="card-title">Detections by type</h3>
          </div>
          <div className="chart-body">
            {attackEntries.length ? (
              <div className="bar-list">
                {attackEntries.map(([k, v]) => (
                  <div key={k}>
                    <div className="bar-row-hd">
                      <span>{ATTACK_LABELS[k] ?? k}</span>
                      <span>{v}</span>
                    </div>
                    <div className="bar-track">
                      <div className="bar-fill" style={{ width: `${(v / attackMax) * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">No detections yet.</div>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-hd">
          <h3 className="card-title">Recent</h3>
          <button className="btn btn-ghost btn-sm" onClick={() => onNavigate('history')}>View all</button>
        </div>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Sender</th>
                <th>Domain</th>
                <th>Risk</th>
                <th>Findings</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="5"><div className="loading-row"><span className="spinner" /> Loading</div></td></tr>
              ) : emails.length === 0 ? (
                <tr><td colSpan="5" className="tbl-empty">No emails analyzed yet.</td></tr>
              ) : emails.map(e => (
                <tr key={e.id}>
                  <td className="mono truncate">{e.sender}</td>
                  <td className="mono">{e.domain}</td>
                  <td><RiskBadge level={e.risk_score} /></td>
                  <td className="muted">{e.warnings?.length ?? 0}</td>
                  <td className="muted">{timeAgo(e.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
