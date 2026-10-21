export default function RiskBadge({ level }) {
  return (
    <span className={`risk-badge ${level}`}>
      <span className="risk-dot" />
      {String(level ?? '').toLowerCase()}
    </span>
  )
}
