import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Line } from 'react-chartjs-2'
import RiskBadge from '../components/RiskBadge'
import { api } from '../api/client'
import { cssVar } from '../theme'

const pct = x => (x == null ? '–' : `${(x * 100).toFixed(1)}%`)
const mb = b => `${(b / 1e6).toFixed(1)} MB`
const when = iso => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '')

// ── Custom file parsing (JSONL, JSON array or CSV) ──────────────────────────
function parseCsv(text) {
  const rows = []
  let row = [], cell = '', q = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (q) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++ }
      else if (c === '"') q = false
      else cell += c
    } else if (c === '"') q = true
    else if (c === ',') { row.push(cell); cell = '' }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++
      row.push(cell); cell = ''
      if (row.some(v => v !== '')) rows.push(row)
      row = []
    } else cell += c
  }
  row.push(cell)
  if (row.some(v => v !== '')) rows.push(row)
  const [head, ...body] = rows
  if (!head) return []
  const keys = head.map(h => h.trim().toLowerCase().replace(/[\s-]+/g, '_'))
  return body.map(r => Object.fromEntries(keys.map((k, i) => [k, r[i] ?? ''])))
}

function parseUpload(name, text) {
  const t = text.trim()
  if (!t) return []
  if (name.toLowerCase().endsWith('.csv')) return parseCsv(text)
  if (t.startsWith('[')) return JSON.parse(t)
  return t.split(/\r?\n/).filter(Boolean).map(l => JSON.parse(l))
}

const normLabel = v => {
  const l = String(v ?? '').trim().toLowerCase()
  return { ham: 'legit', legitimate: 'legit', benign: 'legit', safe: 'legit', phish: 'phishing', malicious: 'phishing' }[l] ?? l
}

// ── Small presentational pieces ─────────────────────────────────────────────
function Seg({ value, options, onChange, label }) {
  return (
    <div className="filter-row" role="group" aria-label={label}>
      {options.map(o => (
        <button key={o.value} type="button" className={`filter-btn${value === o.value ? ' active' : ''}`}
          onClick={() => onChange(o.value)}>{o.label}</button>
      ))}
    </div>
  )
}

function Metric({ label, value, note }) {
  return (
    <div className="stat-card">
      <p className="stat-label">{label}</p>
      <p className="stat-value">{value}</p>
      {note && <p className="stat-note">{note}</p>}
    </div>
  )
}

function ThresholdChart({ sweep, theme }) {
  const c = {
    text: cssVar('--text'), grid: cssVar('--border'), tick: cssVar('--text-3'),
    a: cssVar('--safe'), b: cssVar('--warn'), d: cssVar('--text-2'), card: cssVar('--card'), border: cssVar('--border-2'),
  }
  const series = [
    { key: 'precision', label: 'Precision', color: c.a },
    { key: 'recall', label: 'Recall', color: c.b },
    { key: 'f1', label: 'F1', color: c.d },
  ]
  const data = {
    labels: sweep.map(m => m.threshold),
    datasets: series.map(s => ({
      label: s.label, data: sweep.map(m => +(m[s.key] * 100).toFixed(1)),
      borderColor: s.color, backgroundColor: s.color, borderWidth: 1.5, pointRadius: 0, pointHoverRadius: 3, tension: 0,
    })),
  }
  const options = {
    responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: { backgroundColor: c.card, titleColor: c.text, bodyColor: c.text, borderColor: c.border, borderWidth: 1,
                 callbacks: { title: i => `Score cut-off ${i[0].label}`, label: i => ` ${i.dataset.label}: ${i.raw}%` } },
    },
    scales: {
      x: { grid: { display: false }, border: { color: c.grid }, ticks: { color: c.tick, font: { size: 11 } }, title: { display: true, text: 'Score cut-off', color: c.tick, font: { size: 11 } } },
      y: { min: 0, max: 100, grid: { color: c.grid }, border: { display: false }, ticks: { color: c.tick, font: { size: 11 }, callback: v => `${v}%` } },
    },
  }
  return (
    <>
      <div className="chart-legend-inline" style={{ marginBottom: 10 }}>
        {series.map(s => <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>)}
      </div>
      <div className="chart-canvas-wrap"><Line key={theme} data={data} options={options} /></div>
    </>
  )
}

const TIERS = [
  { name: 'Warning assistant', rule: '≥ 70% of phishing caught and ≤ 20 false alarms per 1,000 legitimate emails', recall: 0.70, fp: 20,
    note: 'Fine as a "take a second look" banner that a person reviews.' },
  { name: 'Inbox filter', rule: '≥ 90% caught and ≤ 1 false alarm per 1,000', recall: 0.90, fp: 1,
    note: 'Needed before mail could be moved or hidden automatically.' },
  { name: 'Production gateway', rule: '≥ 99% caught and ≤ 0.1 false alarms per 1,000', recall: 0.99, fp: 0.1,
    note: 'Roughly where commercial email security products operate. Not claimed here.' },
]

function RealWorld({ shown, op }) {
  const [rlo, rhi] = op.recall_ci
  const [flo, fhi] = op.fp_per_1000_ci
  return (
    <div className="card">
      <div className="card-hd">
        <div><h3 className="card-title">Real-world view</h3>
          <p className="card-sub">What this would feel like in an inbox, at the Medium + cut-off</p></div>
      </div>
      <div className="rw-grid">
        <div><p className="meta-label">False alarms per 1,000 legitimate emails</p>
          <p className="rw-big">{op.fp_per_1000.toFixed(1)}</p>
          <p className="hint">95% interval {flo.toFixed(1)}–{fhi.toFixed(1)} · from {op.negatives} legitimate emails</p></div>
        <div><p className="meta-label">Phishing caught</p>
          <p className="rw-big">{pct(op.recall)}</p>
          <p className="hint">95% interval {pct(rlo)}–{pct(rhi)} · from {op.positives} phishing emails</p></div>
        <div><p className="meta-label">Precision if 1 email in 100 is phishing</p>
          <p className="rw-big">{pct(op.precision_at_prevalence['0.01'])}</p>
          <p className="hint">{pct(op.precision_at_prevalence['0.05'])} at 1 in 20. The balanced test set overstates precision ({pct(op.precision)}).</p></div>
      </div>
      <div className="card-body" style={{ borderTop: '1px solid var(--border)' }}>
        <p className="meta-label">Best recall at a false-alarm budget <span className="muted">(cut-off chosen on this same set, so optimistic)</span></p>
        <div className="budget">
          {shown.fixed_fpr.map(f => (
            <div key={f.target}><span>≤ {pct(f.target)} false alarms</span>
              <strong>{pct(f.recall)}</strong><span className="muted">{f.threshold == null ? 'not reachable' : `cut-off ${f.threshold}`}</span></div>
          ))}
        </div>
      </div>
      <div className="card-body" style={{ borderTop: '1px solid var(--border)' }}>
        <p className="meta-label">Readiness against project targets</p>
        <table className="tbl tiers"><tbody>
          {TIERS.map(t => {
            const met = op.recall >= t.recall && op.fp_per_1000 <= t.fp
            const sure = met && fhi <= t.fp
            return (
              <tr key={t.name}>
                <td><strong>{t.name}</strong><br /><span className="muted">{t.rule}. {t.note}</span></td>
                <td style={{ textAlign: 'right' }}><span className={`tag ${met ? 'ok' : 'no'}`}>{met ? (sure ? 'Met' : 'Met (interval overlaps)') : 'Not met'}</span></td>
              </tr>
            )
          })}
        </tbody></table>
        <p className="hint">Targets are this project's own, not an industry standard. Public data has no marketing mail, receipts or corporate mail,
          so false alarms on those are unmeasured; treat "Met" as "not disproved by this data".</p>
      </div>
    </div>
  )
}

// ── Page ────────────────────────────────────────────────────────────────────
export default function Benchmarks({ theme }) {
  const [info, setInfo] = useState(null)
  const [saved, setSaved] = useState({})
  const [source, setSource] = useState('private_dev')
  const [split, setSplit] = useState('test')
  const [n, setN] = useState(1500)
  const [spam, setSpam] = useState(false)
  const [custom, setCustom] = useState(null)         // { name, rows, summary } | { error }
  const [job, setJob] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [cutoff, setCutoff] = useState('medium_or_above')
  const poll = useRef(null)
  const dlPoll = useRef(null)

  const loadInfo = useCallback(() => api.benchDatasets().then(setInfo).catch(() => setError('Could not reach the API.')), [])
  const loadSaved = useCallback(() => api.benchResults()
    .then(r => setSaved(Object.fromEntries(Object.entries(r).filter(([, v]) => v?.schema >= 2))))
    .catch(() => {}), [])

  useEffect(() => { loadInfo(); loadSaved(); return () => { clearTimeout(poll.current); clearTimeout(dlPoll.current) } }, [loadInfo, loadSaved])

  const real = info?.real
  const downloading = real?.download?.state === 'running'
  const running = job && (job.state === 'queued' || job.state === 'running')

  // keep polling while a download is in progress
  useEffect(() => {
    if (!downloading) return
    dlPoll.current = setTimeout(loadInfo, 900)
    return () => clearTimeout(dlPoll.current)
  }, [downloading, info, loadInfo])

  // show the last saved run for the current selection until a new one finishes
  const savedKey = source === 'real' ? `real_${split}` : source
  const resultKey = r => (r ? (r.dataset === 'real' ? `real_${r.options?.split}` : r.dataset) : null)
  const fresh = result && resultKey(result) === savedKey ? result : null
  const shown = fresh || saved[savedKey] || null
  const isSaved = !!shown && !fresh

  const op = shown?.operating_points?.[cutoff]
  const realReady = !!real?.ready?.[split] && (!spam || real.files.find(f => f.id === 'spam')?.present)

  const canRun = !running && !downloading && (
    source.startsWith('private') || (source === 'real' && realReady) || (source === 'custom' && custom?.rows))

  const pollJob = useCallback(id => {
    api.benchJob(id).then(j => {
      setJob(j)
      if (j.state === 'done') { setResult(j.result); loadSaved(); return }
      if (j.state === 'error') { setError(j.error || 'The run failed.'); return }
      poll.current = setTimeout(() => pollJob(id), 600)
    }).catch(() => setError('Lost contact with the API.'))
  }, [loadSaved])

  const run = async () => {
    setError(''); setResult(null)
    const spec = source === 'real' ? { dataset: 'real', split, n, include_spam: spam }
      : source === 'custom' ? { dataset: 'custom', rows: custom.rows } : { dataset: source }
    try {
      const { job_id } = await api.benchRun(spec)
      setJob({ id: job_id, state: 'queued', done: 0, total: 0, phase: 'queued' })
      pollJob(job_id)
    } catch (e) { setError(e.message) }
  }

  const startDownload = async group => {
    setError('')
    try { await api.benchDownload(group); loadInfo() } catch (e) { setError(e.message) }
  }
  const removeReal = async () => {
    setError('')
    try { await api.benchDeleteReal(); loadInfo() } catch (e) { setError(e.message) }
  }

  const onFile = async e => {
    const f = e.target.files?.[0]
    if (!f) return
    try {
      if (f.size > 6_000_000) throw new Error('File is larger than 6 MB.')
      const raw = parseUpload(f.name, await f.text())
      if (!Array.isArray(raw)) throw new Error('Expected a list of emails.')
      const rows = raw.map(r => ({ ...r, label: normLabel(r.label) }))
        .filter(r => (r.label === 'phishing' || r.label === 'legit') && String(r.sender ?? '').includes('@'))
      const ph = rows.filter(r => r.label === 'phishing').length
      if (!ph || ph === rows.length) throw new Error('Needs at least one phishing and one legit row with a sender address.')
      if (rows.length > (info?.limits?.custom_max_rows ?? 2000)) throw new Error(`At most ${info?.limits?.custom_max_rows ?? 2000} rows.`)
      setCustom({ name: f.name, rows, summary: `${rows.length} rows · ${ph} phishing · ${rows.length - ph} legit${raw.length > rows.length ? ` · ${raw.length - rows.length} skipped` : ''}` })
    } catch (err) {
      setCustom({ error: err.message || 'Could not read that file.' })
    }
  }

  const cats = shown?.per_category ?? []
  const pctDone = job?.total ? Math.round((job.done / job.total) * 100) : 0
  const dlPct = real?.download?.total ? Math.round((real.download.done / real.download.total) * 100) : 0

  const privateList = info?.private ?? []
  const note = useMemo(() => {
    if (!shown) return null
    if (shown.kind === 'real' && ['dev', 'val', 'all'].includes(shown.options?.split)) return 'These splits are the data the rules were diagnosed on and the learned model was trained on, so these scores are NOT accuracy estimates. Use the locked test split for that.'
    if (shown.kind === 'real') return 'Phishing: J. Nazario corpus (CC BY 4.0). Legitimate mail: SpamAssassin, Enron corporate mail and 2025 Apache lists; marketing mail and receipts are not represented. Phishing is split by year and legitimate mail by sender, so the locked test contains later years and different senders than anything trained on. Near-duplicate campaigns can still make results slightly optimistic.'
    if (shown.kind === 'private') return 'Synthetic emails written by this project. They are a regression baseline and a check of the rule logic, not a real-world accuracy estimate.'
    return 'Your own labelled file. Accuracy here reflects how closely it resembles the detector\'s inputs and how well the labels match the truth.'
  }, [shown])

  return (
    <>
      <header className="page-hd">
        <div>
          <h1 className="page-title">Benchmarks</h1>
          <p className="page-sub">Measure detection accuracy on labelled emails. Runs use the same detector as the Analyze tab, with WHOIS off.</p>
        </div>
      </header>

      <div className="analyze-layout">
        <div className="card form-card">
          <div className="form-group">
            <p className="label">Private datasets <span className="optional">(bundled)</span></p>
            <div className="src-list">
              {privateList.map(d => (
                <label key={d.id} className={`src-option${source === d.id ? ' active' : ''}`}>
                  <input type="radio" name="src" checked={source === d.id} onChange={() => setSource(d.id)} />
                  <span>
                    <strong>{d.name}</strong>
                    <small>{d.samples} emails · {d.phishing} phishing · {d.legit} legit</small>
                    <small>{d.description}</small>
                  </span>
                </label>
              ))}
            </div>
          </div>

          <div className="form-group">
            <p className="label">Real public datasets</p>
            <label className={`src-option${source === 'real' ? ' active' : ''}`}>
              <input type="radio" name="src" checked={source === 'real'} onChange={() => setSource('real')} />
              <span>
                <strong>Nazario phishing + SpamAssassin ham</strong>
                <small>Real emails from public research corpora, not written by this project.</small>
              </span>
            </label>

            {source === 'real' && real && (
              <div className="src-detail">
                {Object.keys(real.groups).map(g => {
                  const files = real.files.filter(f => f.group === g)
                  const missing = files.some(f => !f.present)
                  return (
                    <div key={g} className="file-group">
                      <details className="files">
                        <summary>
                          <span className={`notice-dot ${missing ? '' : 'ok'}`} />
                          <span>{real.groups[g]}</span>
                          <span className="muted">{files.filter(f => f.present).length}/{files.length}</span>
                        </summary>
                        <ul className="file-list">
                          {files.map(f => (
                            <li key={f.id}>
                              <span className={`notice-dot ${f.present ? 'ok' : ''}`} />
                              <a href={f.url} target="_blank" rel="noreferrer">{f.name}</a>
                              <span className="muted">{f.present ? mb(f.bytes) : f.role === 'hash' ? 'both splits' : f.role}</span>
                            </li>
                          ))}
                        </ul>
                      </details>
                      {!downloading && missing && (
                        <div className="btn-row">
                          <button type="button" className="btn btn-ghost btn-sm" onClick={() => startDownload(g)}>
                            Download {g} set
                          </button>
                        </div>
                      )}
                    </div>
                  )
                })}
                {downloading && (
                  <div>
                    <div className="progress"><div style={{ width: `${dlPct}%` }} /></div>
                    <p className="hint">Downloading {real.download.current || '…'} ({real.download.file_index}/{real.download.file_count}) {dlPct ? `${dlPct}%` : ''}</p>
                  </div>
                )}
                {!downloading && real.files.some(f => f.present) && (
                  <div className="btn-row">
                    <button type="button" className="btn btn-ghost btn-sm" onClick={removeReal}>Delete downloaded files</button>
                  </div>
                )}
                {real.download.state === 'error' && <div className="form-error">{real.download.error}</div>}
                <p className="hint">{real.note}</p>

                <div className="form-group">
                  <p className="label">Which part</p>
                  <Seg label="Corpus part" value={split} onChange={setSplit} options={[
                    { value: 'test', label: 'Test (locked)' }, { value: 'dev', label: 'Dev' }, { value: 'val', label: 'Val' },
                    { value: 'test_seen', label: 'Seen' }, { value: 'all', label: 'All' }]} />
                  <p className="hint">{real.splits[split]}</p>
                  {!real.ready[split] && <p className="hint">Download the files above to run this part.</p>}
                </div>
                <div className="form-group">
                  <p className="label">Emails per class</p>
                  <Seg label="Size" value={n} onChange={setN} options={[200, 800, 1500, 6000].map(v => ({ value: v, label: v === 6000 ? 'All' : String(v) }))} />
                </div>
                <label className="check">
                  <input type="checkbox" checked={spam} onChange={e => setSpam(e.target.checked)} />
                  <span>Also score SpamAssassin spam <span className="muted">(reported separately; it is spam, not phishing)</span></span>
                </label>
              </div>
            )}
          </div>

          <div className="form-group">
            <p className="label">Your own dataset</p>
            <label className={`src-option${source === 'custom' ? ' active' : ''}`}>
              <input type="radio" name="src" checked={source === 'custom'} onChange={() => setSource('custom')} />
              <span>
                <strong>Upload a labelled file</strong>
                <small>.jsonl, .json or .csv with columns label (phishing / legit), sender, subject, content; optional reply_to, category.</small>
              </span>
            </label>
            {source === 'custom' && (
              <div className="src-detail">
                <input type="file" accept=".jsonl,.json,.csv,.txt" onChange={onFile} />
                {custom?.summary && <p className="hint"><strong>{custom.name}</strong> — {custom.summary}. Processed in memory; not stored.</p>}
                {custom?.error && <div className="form-error">{custom.error}</div>}
              </div>
            )}
          </div>

          {error && <div className="form-error">{error}</div>}

          {running && (
            <div className="form-group">
              <div className="progress"><div style={{ width: `${job.phase === 'loading' ? 4 : pctDone}%` }} /></div>
              <p className="hint">{job.phase === 'loading' ? 'Loading emails…' : `Scoring ${job.done} / ${job.total}`}</p>
            </div>
          )}

          <div className="form-footer">
            <button type="button" className="btn btn-primary" disabled={!canRun} onClick={run}>
              {running && <span className="spinner" />}
              {running ? 'Running' : 'Run benchmark'}
            </button>
          </div>
        </div>

        <div className="results-col">
          {!shown && (
            <div className="card"><div className="empty-state">
              <h3>No results yet</h3>
              <p>Choose a dataset and run a benchmark.</p>
            </div></div>
          )}

          {shown && op && (
            <>
              <div className="card">
                <div className="card-hd">
                  <div>
                    <h3 className="card-title">{shown.name}{shown.kind === 'real' ? ` · ${({ test: 'locked test (unseen 2024–25)', dev: 'dev split', val: 'validation split', test_seen: 'seen 2024–25', all: 'all splits' })[shown.options?.split] ?? ''}` : ''}</h3>
                    <p className="card-sub">
                      {shown.counts.phishing} phishing · {shown.counts.legit} legit
                      {shown.counts.spam ? ` · ${shown.counts.spam} spam` : ''} · {shown.duration_s}s · {when(shown.finished_at)}
                      {shown.latency_ms ? ` · ${shown.latency_ms.p50} ms median / ${shown.latency_ms.p95} ms p95 per email` : ''}
                      {isSaved ? ' · last saved run' : ''}
                    </p>
                  </div>
                  <Seg label="Flag at" value={cutoff} onChange={setCutoff} options={[
                    { value: 'medium_or_above', label: 'Medium +' }, { value: 'high_only', label: 'High only' }]} />
                </div>
                <div className="stat-grid" style={{ border: 0, borderRadius: 0, marginBottom: 0 }}>
                  <Metric label="Accuracy" value={pct(op.accuracy)} note={`${op.tp + op.tn} of ${op.n} correct`} />
                  <Metric label="Precision" value={pct(op.precision)} note="Flagged that were phishing" />
                  <Metric label="Recall" value={pct(op.recall)} note={`95% CI ${pct(op.recall_ci[0])}–${pct(op.recall_ci[1])}`} />
                  <Metric label="F1 score" value={pct(op.f1)} note={shown.auc != null ? `ROC AUC ${shown.auc.toFixed(3)}` : ''} />
                </div>
                <div className="card-body cm-row">
                  <table className="cm">
                    <thead><tr><th /><th>Flagged</th><th>Not flagged</th></tr></thead>
                    <tbody>
                      <tr><th>Phishing</th><td className="good">{op.tp}</td><td className="bad">{op.fn}</td></tr>
                      <tr><th>Legitimate</th><td className="bad">{op.fp}</td><td className="good">{op.tn}</td></tr>
                    </tbody>
                  </table>
                  <dl className="kv">
                    <div><dt>False-alarm rate</dt><dd>{pct(op.false_positive_rate)}</dd></div>
                    <div><dt>Specificity</dt><dd>{pct(op.specificity)}</dd></div>
                    <div><dt>Balanced accuracy</dt><dd>{pct(op.balanced_accuracy)}</dd></div>
                    {shown.spam_flag_rate != null && <div><dt>Spam flagged</dt><dd>{pct(shown.spam_flag_rate)}</dd></div>}
                    {shown.counts.crashes > 0 && <div><dt>Crashes</dt><dd>{shown.counts.crashes}</dd></div>}
                  </dl>
                </div>
              </div>

              {note && <div className="note">{note}</div>}

              {shown.kind !== 'private' && <RealWorld shown={shown} op={shown.operating_points.medium_or_above} />}

              <div className="card">
                <div className="card-hd"><h3 className="card-title">Cut-off sweep</h3>
                  <p className="card-sub">Trade-off as the score needed to flag an email changes</p></div>
                <div className="chart-body"><ThresholdChart sweep={shown.sweep} theme={theme} /></div>
              </div>

              {shown.per_source?.length > 0 && (
                <div className="card">
                  <div className="card-hd"><h3 className="card-title">By source</h3>
                    <p className="card-sub">Share flagged at Medium +, with 95% interval</p></div>
                  <div className="tbl-wrap">
                    <table className="tbl">
                      <thead><tr><th>Source</th><th>Truth</th><th>Emails</th><th>Flagged</th></tr></thead>
                      <tbody>
                        {shown.per_source.map(r => (
                          <tr key={r.source}>
                            <td>{r.name}</td><td className="muted">{r.label}</td><td className="muted">{r.n}</td>
                            <td>{pct(r.rate)} <span className="muted">({pct(r.ci[0])}–{pct(r.ci[1])})</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {cats.length > 0 ? (
                <div className="card">
                  <div className="card-hd"><h3 className="card-title">By category</h3>
                    <p className="card-sub">Share classified correctly at Medium +</p></div>
                  <div className="chart-body bar-list">
                    {cats.map(c => (
                      <div key={c.label + c.category}>
                        <div className="bar-row-hd">
                          <span>{c.category.replace(/_/g, ' ')} <span className="muted">· {c.label}</span></span>
                          <span>{c.correct}/{c.n} · {pct(c.rate)}</span>
                        </div>
                        <div className="bar-track"><div className="bar-fill" style={{ width: `${c.rate * 100}%`, background: c.rate < 0.6 ? 'var(--danger)' : c.rate < 0.9 ? 'var(--warn)' : 'var(--text-2)' }} /></div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="card">
                  <div className="card-hd"><h3 className="card-title">Signals behind the mistakes</h3></div>
                  <div className="card-body sig-cols">
                    <div><p className="meta-label">On missed phishing</p>
                      {shown.top_signals_missed.length ? shown.top_signals_missed.map(([s, c]) => <p className="sig" key={s}><span>{s.replace(/_/g, ' ').toLowerCase()}</span><span>{c}</span></p>) : <p className="hint">None</p>}</div>
                    <div><p className="meta-label">On false alarms</p>
                      {shown.top_signals_false_positive.length ? shown.top_signals_false_positive.map(([s, c]) => <p className="sig" key={s}><span>{s.replace(/_/g, ' ').toLowerCase()}</span><span>{c}</span></p>) : <p className="hint">None</p>}</div>
                  </div>
                </div>
              )}

              <div className="card">
                <details className="errors">
                  <summary>
                    <span className="card-title">Misclassified emails</span>
                    <span className="card-sub">{shown.error_total} at Medium + {shown.error_total > shown.errors.length ? `(showing ${shown.errors.length})` : ''}</span>
                  </summary>
                  <div className="tbl-wrap">
                    <table className="tbl">
                      <thead><tr><th>Truth</th><th>{shown.kind === 'real' ? 'Sender domain' : 'Sender'}</th><th>Category</th><th>Score</th><th>Signals</th></tr></thead>
                      <tbody>
                        {shown.errors.length === 0
                          ? <tr><td colSpan="5" className="tbl-empty">None.</td></tr>
                          : shown.errors.map((e, i) => (
                            <tr key={i}>
                              <td>{e.label}</td>
                              <td className="mono truncate">{e.who}</td>
                              <td className="muted">{e.category.replace(/_/g, ' ') || '–'}</td>
                              <td><RiskBadge level={e.level} /> <span className="muted">{e.score}</span></td>
                              <td className="muted">{e.signals.filter(s => s !== 'TRUSTED_VERIFIED').map(s => s.replace(/_/g, ' ').toLowerCase()).join(', ') || 'none'}</td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  )
}
