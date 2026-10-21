// Character-by-character diff with colour-coded boxes

const TYPE_ICONS = {
  substitute: '⇄',
  insert: '+',
  delete: '−',
  match: '',
}

export default function CharDiff({ ops = [], s1 = '', s2 = '' }) {
  if (!ops.length) return null

  const edits = ops.filter(o => o.type !== 'match')

  return (
    <>
      <div className="char-diff-wrap">
        {/* Original (suspicious) domain */}
        <p className="char-row-label">Suspicious domain</p>
        <div className="char-row">
          {ops.map((op, i) => {
            if (op.type === 'insert') return null // not in s1
            return (
              <span
                key={i}
                className={`char-box ${op.type === 'substitute' ? 'sub-from' : op.type === 'delete' ? 'delete' : 'match'}`}
                title={op.description}
              >
                {op.type === 'substitute' ? op.from : op.char ?? op.from ?? op.to}
              </span>
            )
          })}
        </div>

        {/* Trusted domain */}
        <p className="char-row-label" style={{ marginTop: 12 }}>Closest trusted domain</p>
        <div className="char-row">
          {ops.map((op, i) => {
            if (op.type === 'delete') return null // not in s2
            return (
              <span
                key={i}
                className={`char-box ${op.type === 'substitute' ? 'sub-to' : op.type === 'insert' ? 'insert' : 'match'}`}
                title={op.description}
              >
                {op.type === 'substitute' ? op.to : op.char ?? op.to ?? op.from}
              </span>
            )
          })}
        </div>
      </div>

      {edits.length > 0 && (
        <div className="ops-list">
          {edits.map((op, i) => (
            <div className="op-item" key={i}>
              <span className={`op-type ${op.type}`}>{op.type}</span>
              <span className="op-desc">{op.description}</span>
            </div>
          ))}
        </div>
      )}
    </>
  )
}
