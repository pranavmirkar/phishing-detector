// PhishGuard extension: shared helpers (content script, popup, service worker, and Node tests).
// Pure functions only: no DOM, no chrome.* calls, so they can be unit-tested.
(function (root) {
  const DEFAULTS = { apiUrl: 'http://localhost:5000/api', apiKey: '', useHeaders: true, persist: false }
  const SEVERITY_RANK = { HIGH: 0, MEDIUM: 1, LOW: 2 }
  const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])
  const MAX_CONTENT = 60000
  const MAX_RAW = 2000000

  /** Validate and normalise the server URL. https, or http only for the local machine. null if unusable. */
  function normalizeApiUrl(input) {
    let u
    try { u = new URL(String(input || '').trim()) } catch { return null }
    const local = LOCAL_HOSTS.has(u.hostname)
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) return null
    if (u.username || u.password) return null
    let path = u.pathname.replace(/\/+$/, '')
    if (path === '') path = '/api'
    return `${u.origin}${path}`
  }

  /** Chrome match pattern for the server's origin (what host permission to request). */
  function originPattern(apiUrl) {
    const u = new URL(apiUrl)
    return `${u.origin}/*`
  }

  function isLocalApi(apiUrl) {
    try { return LOCAL_HOSTS.has(new URL(apiUrl).hostname) } catch { return false }
  }

  /** "Name" <a@b.com> when a display name is known; plain address otherwise. */
  function formatSender(email, name) {
    const addr = String(email || '').trim().toLowerCase()
    const n = String(name || '').replace(/["\r\n<>]/g, '').trim()
    return n && n.toLowerCase() !== addr ? `"${n}" <${addr}>` : addr
  }

  /** Mailbox owner from Gmail's tab title: "Inbox (3) - user@example.com - Gmail". */
  function accountFromTitle(title) {
    const m = String(title || '').match(/[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+/)
    return m ? m[0].toLowerCase() : ''
  }

  /** Body for the API: HTML when present (links and forms live there), else text. Bounded. */
  function buildPayload({ email, name, subject, html, text, recipient, persist }) {
    return {
      sender: formatSender(email, name),
      subject: String(subject || '').slice(0, 500),
      content: String(html || text || '').slice(0, MAX_CONTENT),
      recipient: recipient || '',
      persist: persist === true,
    }
  }

  /** Gmail's hexadecimal legacy message id -> the decimal id used by msg-f:<id> permanent ids. */
  function messageIdToDecimal(hex) {
    const h = String(hex || '').trim().replace(/^0x/i, '')
    if (!/^[0-9a-f]{6,24}$/i.test(h)) return null
    try { return BigInt('0x' + h).toString() } catch { return null }
  }

  /** URL of Gmail's "show original" for a message, relative to the account the page is on. */
  function originalMessageUrl(origin, pathname, hexId) {
    const dec = messageIdToDecimal(hexId)
    if (!dec) return null
    const m = String(pathname || '').match(/^(\/mail\/u\/\d+)/)
    return `${origin}${m ? m[1] : '/mail/u/0'}/?view=om&permmsgid=msg-f%3A${dec}`
  }

  /** Does this text look like a raw RFC 822 message (and not a Gmail HTML page)? */
  function looksLikeRawEmail(text) {
    const t = String(text || '')
    if (t.length < 40 || /^\s*<(!doctype|html)/i.test(t)) return false
    const head = t.slice(0, 4000)
    return /^(Delivered-To|Received|Return-Path|From|Message-ID|MIME-Version|X-Received|ARC-|Authentication-Results):/im.test(head) && /^From:/im.test(t.slice(0, 60000))
  }

  function limitRaw(raw) { return String(raw || '').slice(0, MAX_RAW) }

  /** Findings worth showing, worst first. The "verified domain" note is shown separately. */
  function topFindings(result, n = 6) {
    const w = (result && result.warnings) || []
    return w.filter(x => x && x.type !== 'TRUSTED_VERIFIED' && x.message)
      .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 3) - (SEVERITY_RANK[b.severity] ?? 3))
      .slice(0, n)
  }

  /** Plain-language verdict. `label` is the short badge text; `headline` / `advice` are for the panel. */
  function verdict(result) {
    const level = result && result.risk_score
    if (level === 'HIGH') return { level, label: 'HIGH RISK', headline: 'Likely phishing', advice: "Don't click links, open attachments or reply." }
    if (level === 'MEDIUM') return { level, label: 'LOOK TWICE', headline: 'Suspicious', advice: 'Check the sender before you click or reply.' }
    return { level: 'LOW', label: 'NO ALERT', headline: 'No warning signs', advice: '' }
  }

  /** What the popup keeps as "last scan". */
  function summarize(result, email) {
    const v = verdict(result)
    return {
      email, domain: result.domain, riskScore: v.level, riskLevel: result.risk_level, safe: v.level === 'LOW',
      warnings: topFindings(result, 4).map(x => ({ severity: x.severity, message: x.message })),
      source: 'server', timestamp: Date.now(),
    }
  }

  const api = {
    DEFAULTS, normalizeApiUrl, originPattern, isLocalApi, formatSender, accountFromTitle, buildPayload,
    messageIdToDecimal, originalMessageUrl, looksLikeRawEmail, limitRaw, topFindings, verdict, summarize,
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = api
  else root.PG = api
})(typeof self !== 'undefined' ? self : globalThis)
