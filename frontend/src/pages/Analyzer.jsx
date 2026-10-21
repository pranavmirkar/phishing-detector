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
  const resultsRef = useRef(null)

  const set = key => e => setForm(f => ({ ...f, [key]: e.target.value }))

  const loadSample = () => {
    setForm({ sender: SAMPLE.sender, replyto: SAMPLE.replyto, subject: SAMPLE.subject, content: SAMPLE.content })
    setResult(null)
    setReported(false)
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
        <button className="btn btn-ghost" onClick={loadSample}>Load sample email</button>
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
            {error && (
              <div className="form-error">{error}</div>
            )}
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
