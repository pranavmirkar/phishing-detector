const ICONS = {
  LOOKALIKE_DOMAIN: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="10" cy="10" r="8"/>
      <path d="M10 6v4M10 14h.01" strokeLinecap="round"/>
    </svg>
  ),
  HOMOGLYPH_ATTACK: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M4 4l12 12M4 16L16 4" strokeLinecap="round"/>
    </svg>
  ),
  SUBDOMAIN_ABUSE: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8">
      <rect x="2" y="5" width="16" height="12" rx="2"/>
      <path d="M6 5V4a4 4 0 0 1 8 0v1" strokeLinecap="round"/>
    </svg>
  ),
  SUSPICIOUS_KEYWORDS: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M3 6h14M3 10h10M3 14h7" strokeLinecap="round"/>
    </svg>
  ),
  LINK_MISMATCH: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M8 11a4 4 0 0 0 6 0l2-2a4 4 0 0 0-6-5.66L8.5 5" strokeLinecap="round"/>
      <path d="M12 9a4 4 0 0 0-6 0L4 11a4 4 0 0 0 6 5.66L11.5 15" strokeLinecap="round"/>
      <path d="M4 4l12 12" strokeLinecap="round"/>
    </svg>
  ),
  REPLY_TO_MISMATCH: (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8">
      <path d="M3 10l7-7 7 7M5 8v7a1 1 0 0 0 1 1h3v-4h4v4h3a1 1 0 0 0 1-1V8" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
}

export default function FindingCard({ warning }) {
  const { type, severity, message, detail } = warning
  return (
    <div className={`finding-card ${severity}`}>
      <div className={`finding-icon ${severity}`}>
        {ICONS[type] ?? ICONS.LOOKALIKE_DOMAIN}
      </div>
      <div className="finding-body">
        <div className="finding-meta">
          <span className={`sev-badge ${severity}`}>{severity.toLowerCase()}</span>
          <span className="finding-type">{type.replace(/_/g, ' ').toLowerCase()}</span>
        </div>
        <p className="finding-msg">{message}</p>
        {detail && <p className="finding-detail">{detail}</p>}
      </div>
    </div>
  )
}
