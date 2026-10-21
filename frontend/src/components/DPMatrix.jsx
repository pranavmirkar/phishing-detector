// Visual Levenshtein DP table with highlighted traceback path

function cellColor(val, maxVal) {
  // Neutral heat: higher edit counts get a stronger tint of the text colour
  const t = maxVal > 0 ? Math.min(val / maxVal, 1) : 0
  return `color-mix(in srgb, var(--text) ${Math.round(t * 14)}%, transparent)`
}

export default function DPMatrix({ matrixData }) {
  if (!matrixData) return null

  const { matrix, path, s1, s2 } = matrixData
  const pathSet = new Set(Array.isArray(path) ? path.map(p => `${p[0]},${p[1]}`) : [...path])
  const maxVal = Math.max(...matrix.flat())

  return (
    <div className="matrix-scroll">
      <table className="matrix-table">
        <thead>
          <tr>
            <th />
            <th />
            {s2.split('').map((c, j) => (
              <th key={j} className="char-header">{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row, i) => (
            <tr key={i}>
              <th className={i > 0 ? 'char-header' : ''}>{i > 0 ? s1[i - 1] : ''}</th>
              <th>{i}</th>
              {row.map((val, j) => {
                const isPath = pathSet.has(`${i},${j}`)
                return (
                  <td
                    key={j}
                    className={`matrix-cell${isPath ? ' path' : ''}`}
                    style={{ background: cellColor(val, maxVal) }}
                  >
                    {val}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
