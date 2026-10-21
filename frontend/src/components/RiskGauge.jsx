// SVG semi-circle gauge, 0–100 score
const COLOR = { HIGH: 'var(--danger)', MEDIUM: 'var(--warn)', LOW: 'var(--safe)' }

function arcPath(cx, cy, r, score) {
  if (score <= 0) return ''
  // Map score 0→100 to angle π→0 (left to right, bottom half)
  const angle = Math.PI - (score / 100) * Math.PI
  const x = cx + r * Math.cos(angle)
  const y = cy - r * Math.sin(angle)
  // The arc never exceeds 180°, so it's always the small arc.
  return `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)}`
}

export default function RiskGauge({ score = 0, riskScore = 'LOW' }) {
  const cx = 100, cy = 100, r = 80
  const color = COLOR[riskScore] ?? 'var(--text)'

  return (
    <div className="gauge-wrap">
      <svg className="gauge-svg" viewBox="0 0 200 112">
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 1 1 ${cx + r} ${cy}`}
          fill="none" stroke="var(--surface)" strokeWidth="8" strokeLinecap="round"
        />
        {score > 0 && (
          <path
            d={arcPath(cx, cy, r, Math.min(score, 99.99))}
            fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
          />
        )}
      </svg>
      <div className="gauge-center">
        <div className="gauge-score-val">{score}</div>
        <div className="gauge-score-lbl" style={{ color }}>{String(riskScore).toLowerCase()} risk</div>
      </div>
    </div>
  )
}
