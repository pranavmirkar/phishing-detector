import { useState, useRef } from 'react'
import { api } from '../api/client'
import RiskGauge from '../components/RiskGauge'
import SimilarityBars from '../components/SimilarityBars'
import DPMatrix from '../components/DPMatrix'
import CharDiff from '../components/CharDiff'
import FindingCard from '../components/FindingCard'

const SAMPLE = {
  sender:  'support@paypa1.com',
  replyto: 'reply@protonmail.com',
  subject: 'Urgent: Your PayPal account has been suspended — act now',
  content: `Dear Customer,

We have detected suspicious activity on your account. Your account has been temporarily suspended.

Click here to verify your identity immediately:
<a href="http://paypa1.com/verify?token=abc123">http://paypal.com/account/verify</a>

This is a limited time offer — act now to restore access within 24 hours or your account will be permanently closed.

Guaranteed account recovery. Risk-free process.

PayPal Security Team`,
}

export default function Analyzer() {
  const [form, setForm]       = useState({ sender: '', replyto: '', subject: '', content: '' })
  const [result, setResult]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')
  const [reported, setReported] = useState(false)
  const [extras, setExtras] = useState(null)      // header-derived data from an imported .eml
  const fileRef = useRef(null)
  const resultsRef = useRef(null)

  const set = key => e => setForm(f => ({ ...f, [key]: e.target.value }))

  const loadSample = () => {
    setForm({ sender: SAMPLE.sender, replyto: SAMPLE.replyto, subject: SAMPLE.subject, content: SAMPLE.content })
    setExtras(null)
    setResult(null)
    setReported(false)
  }

  const importEml = async e => {
    const f = e.target.files?.[0]
    e.target.value = ''
    if (!f) return
    setError('')
    try {
      if (f.size > 5_000_000) throw new Error('That file is larger than 5 MB.')
      const p = await api.parse(await f.text())
      setForm({ sender: p.sender || '', replyto: p.reply_to || '', subject: p.subject || '', content: p.content || '' })
      const { auth_results, return_path, recipient, attachments, list_id } = p
      setExtras({ auth_results, return_path, recipient, attachments, list_id })
      setResult(null); setReported(false)
    } catch (err) {
      setError(err.message || 'Could not read that file.')
    }
  }

  const submit = async e => {
    e.preventDefault()
    if (!form.sender.trim()) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const res = await api.analyze({
        sender:   form.sender,
        reply_to: form.replyto,
        subject:  form.subject,
        content:  form.content,
        ...(extras || {}),
      })
      setResult(res)
      setReported(false)
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100)
    } catch {
      setError('Could not reach the API. Make sure the Flask backend is running on port 5000.')
    } finally {
      setLoading(false)
    }
  }

  const handleReport = async () => {
    if (!result?.id) return
    await api.report(result.id, 'Reported by user')
    setReported(true)
  }

  const da = result?.domain_analysis
  const matrixData = da?.matrix
  const editOps    = da?.edit_operations ?? []
  const topMatches = da?.top_matches ?? []
  const warnings   = result?.warnings ?? []

  return (
    <>
      <header className="page-hd">
        <div>
          <h1 className="page-title">Analyze</h1>
          <p className="page-sub">Check an email's sender, links and content for phishing signals.</p>
        </div>
        <div className="btn-row" style={{ marginTop: 0 }}>
          <input ref={fileRef} type="file" accept=".eml,.txt,message/rfc822" hidden onChange={importEml} />
          <button className="btn btn-ghost" onClick={() => fileRef.current?.click()}>Import .eml</button>
          <button className="btn btn-ghost" onClick={loadSample}>Load sample email</button>
        </div>
      </header>

      <div className="analyze-layout">
        {/* Form */}
        <div className="card form-card">
          <form onSubmit={submit}>
            <div className="form-group">
              <label className="label">From <span className="req">*</span></label>
              <input className="input" value={form.sender} onChange={set('sender')}
                placeholder="support@paypa1.com" required />
            </div>
            <div className="form-group">
              <label className="label">Reply-To <span className="optional">(optional)</span></label>
              <input className="input" value={form.replyto} onChange={set('replyto')}
                placeholder="reply@differentdomain.com" />
            </div>
            <div className="form-group">
              <label className="label">Subject</label>
              <input className="input" value={form.subject} onChange={set('subject')}
                placeholder="Urgent: Your account has been suspended" />
            </div>
            <div className="form-group">
              <label className="label">Email Body</label>
              <textarea className="input textarea" value={form.content} onChange={set('content')}
                placeholder="Paste email content here. Supports HTML for link-mismatch detection." />
            </div>
            {extras && (
              <div className="extras">
                <p className="meta-label">From the message headers</p>
                {extras.auth_results && <p><span>Authentication</span><code>{extras.auth_results}</code></p>}
                {extras.return_path && <p><span>Return-Path</span><code>{extras.return_path}</code></p>}
                {extras.recipient && <p><span>Delivered to</span><code>{extras.recipient}</code></p>}
                {extras.attachments?.length > 0 && <p><span>Attachments</span><code>{extras.attachments.map(a => a.filename).join(', ')}</code></p>}
                {extras.list_id && <p><span>Mailing list</span><code>yes</code></p>}
                <button type="button" className="link-btn" onClick={() => setExtras(null)}>Ignore header data</button>
              </div>
            )}
            {error && <div className="form-error">{error}</div>}
            <div className="form-footer">
              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading && <span className="spinner" />}
                {loading ? 'Analyzing' : 'Analyze'}
              </button>
            </div>
          </form>
        </div>

        {/* Results */}
        {result && (
          <div className="results-col" ref={resultsRef}>

            {/* Risk overview */}
            <div className="card">
              <div className="overview-inner">
                <RiskGauge score={result.risk_level} riskScore={result.risk_score} />
                <div style={{ flex: 1 }}>
                  <div className="meta-block">
                    <p className="meta-label">Domain analyzed</p>
                    <code className="domain-code">{result.domain}</code>
                  </div>
                  {da?.homoglyph_detected && (
                    <div className="meta-block">
                      <p className="meta-label">Normalized to</p>
                      <code className="domain-code" style={{ color: 'var(--warn)' }}>{da.normalized}</code>
                    </div>
                  )}
                  {result.model && (
                    <p className="hint" style={{ marginBottom: 10 }}>
                      Scored by a learned model (v{result.model.version}) over the findings below; rules alone would give {result.rule_score}.
                      MEDIUM is the cut-off that flagged about 1% of legitimate training mail, HIGH about 0.1%.
                    </p>
                  )}
                  {warnings.length > 0 && (
                    <div className="warn-summary">
                      {warnings.map((w, i) => (
                        <div className="warn-mini" key={i}>
                          <span className={`warn-mini-dot ${w.severity}`} />
                          {w.message.length > 70 ? w.message.slice(0, 70) + '…' : w.message}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Similarity bars */}
            {topMatches.length > 0 && (
              <div className="card">
                <div className="card-hd">
                  <div>
                    <h3 className="card-title">Domain Similarity</h3>
                    <p className="card-sub">Levenshtein distance vs. trusted domains (top 5)</p>
                  </div>
                </div>
                <SimilarityBars matches={topMatches} />
              </div>
            )}

            {/* DP Matrix */}
            {matrixData && (
              <div className="card">
                <div className="card-hd">
                  <div>
                    <h3 className="card-title">Levenshtein Matrix</h3>
                    <p className="card-sub mono">
                      "{da.normalized}" → "{da.best_match?.trusted_domain ?? da.best_match?.trusted}"
                    </p>
                  </div>
                </div>
                <p className="card-desc">
                  Each cell shows the minimum edits between string prefixes.
                  The <strong style={{ color: 'var(--text)', fontWeight: 600 }}>highlighted path</strong> is
                  the optimal edit sequence. Final cell value = edit distance.
                </p>
                <DPMatrix matrixData={matrixData} />
              </div>
            )}

            {/* Char diff */}
            {editOps.length > 0 && (
              <div className="card">
                <div className="card-hd">
                  <div>
                    <h3 className="card-title">Edit Operations</h3>
                    <p className="card-sub">
                      {editOps.filter(o => o.type !== 'match').length} edit(s) detected
                    </p>
                  </div>
                </div>
                <CharDiff ops={editOps} s1={da.normalized} s2={da.best_match?.trusted_domain ?? ''} />
              </div>
            )}

            {/* Findings */}
            {warnings.length > 0 && (
              <div className="card">
                <div className="card-hd">
                  <h3 className="card-title">Detection Findings</h3>
                </div>
                <div className="findings-list">
                  {warnings.map((w, i) => <FindingCard key={i} warning={w} />)}
                </div>
              </div>
            )}

            {/* Report bar */}
            {result.risk_score !== 'LOW' && (
              <div className="card">
                <div className="report-bar-inner">
                  <div>
                    <p className="report-title">{reported ? 'Reported' : 'Report as phishing'}</p>
                    <p className="report-sub">
                      {reported ? 'This email has been flagged.' : 'Flag this email so it is recorded as phishing.'}
                    </p>
                  </div>
                  <button className="btn btn-danger" onClick={handleReport} disabled={reported}>
                    {reported ? 'Reported' : 'Report'}
                  </button>
                </div>
              </div>
            )}

          </div>
        )}
      </div>
    </>
  )
}
