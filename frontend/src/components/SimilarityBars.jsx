// Renders top-5 similarity bars against trusted domains
function barColor(similarity) {
  if (similarity >= 85) return 'var(--danger)'
  if (similarity >= 65) return 'var(--warn)'
  return 'var(--text-3)'
}

export default function SimilarityBars({ matches = [] }) {
  if (!matches.length) return null

  return (
    <div className="sim-list">
      {matches.map((m, i) => (
        <div className="sim-row" key={i}>
          <div className="sim-row-hd">
            <span className="sim-domain">{m.trusted_domain ?? m.trusted}</span>
            <span className="sim-meta">
              dist&nbsp;<strong>{m.distance}</strong>&nbsp;·&nbsp;{m.similarity}%
            </span>
          </div>
          <div className="sim-bar-track">
            <div
              className="sim-bar-fill"
              style={{
                width: `${m.similarity}%`,
                background: barColor(m.similarity),
              }}
            />
          </div>
        </div>
      ))}
    </div>
  )
}
