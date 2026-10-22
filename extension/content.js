// PhishGuard — Gmail phishing detector (analysis by the PhishGuard server; local fallback when it is unreachable)

let activePanel = null
let mouseX = 0, mouseY = 0
let pollTimer = null
let fastTimer = null
let closeTimer = null
let _pgEnabled = true
const EMAIL_RE = /[\w.+\-]+@[\w.\-]+\.[a-z]{2,}/i

chrome.storage?.local?.get(['enabled'], data => {
  if (data?.enabled === false) _pgEnabled = false
  if (_pgEnabled) showStartupBadge()
})
chrome.storage?.onChanged?.addListener((changes, area) => {
  if (area === 'local' && 'enabled' in changes) _pgEnabled = changes.enabled.newValue
})

// ── Startup indicator (proves script loaded) ──────────────────────────────────
function showStartupBadge() {
  const b = document.createElement('div')
  b.style.cssText = 'position:fixed;bottom:16px;left:16px;z-index:2147483647;background:#18181b;color:#fff;padding:6px 12px;border-radius:6px;font-size:12px;font-family:sans-serif;pointer-events:none;box-shadow:0 2px 8px rgba(0,0,0,.3)'
  b.textContent = '🛡️ PhishGuard active'
  document.body.appendChild(b)
  setTimeout(() => b.remove(), 3000)
}

document.addEventListener('mousemove', e => { mouseX = e.clientX; mouseY = e.clientY }, { passive: true })

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')
}
function extractDomain(email) {
  const m = String(email).match(/@([\w.\-]+\.\w+)/)
  return m ? m[1].toLowerCase() : null
}
function riskColor(s) {
  return s === 'HIGH' ? '#ef4444' : s === 'MEDIUM' ? '#f59e0b' : '#22c55e'
}

// ── Panel ─────────────────────────────────────────────────────────────────────
// The PhishGuard server (same detector and learned model as the dashboard) does the analysis. If it
// cannot be reached, the older, simpler local check in domains.js / levenshtein.js / spam.js runs instead
// and the panel says so.

const resultCache = new Map()           // key -> { outcome, at }
const CACHE_MS = 5 * 60 * 1000
let panelToken = 0

function sendMessage(msg) {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage(msg, res => {
        if (chrome.runtime.lastError) resolve({ ok: false, offline: true, error: chrome.runtime.lastError.message })
        else resolve(res || { ok: false, offline: true, error: 'No answer from the extension' })
      })
    } catch (e) { resolve({ ok: false, offline: true, error: String(e) }) }
  })
}

/** What Gmail shows about this sender: name, subject, and (if the message is open) its body and id. */
function messageContext(anchorEl, email) {
  const box = anchorEl.closest?.('.adn, [data-legacy-message-id], [data-message-id]')
  const scope = box || document
  const senderEl = [...scope.querySelectorAll('span[email]')]
    .find(e => (e.getAttribute('email') || '').toLowerCase() === email)
  const bodyEl = senderEl ? (box || document).querySelector('.a3s.aiL, .a3s') : null
  const row = anchorEl.closest?.('tr') || anchorEl.closest?.('[role="row"]')
  const subject = (senderEl ? document.querySelector('h2.hP')?.textContent : '')
    || row?.querySelector('.bog, .y6 span')?.textContent || ''
  const name = senderEl?.getAttribute('name') || anchorEl.getAttribute?.('name')
    || row?.querySelector(`[email="${CSS.escape(email)}"]`)?.getAttribute('name') || ''
  const idEl = box?.matches?.('[data-legacy-message-id]') ? box : box?.querySelector?.('[data-legacy-message-id]')
  return {
    name, subject, opened: !!bodyEl,
    html: bodyEl ? bodyEl.innerHTML : '',
    text: bodyEl ? bodyEl.innerText : (row?.querySelector('.y2')?.textContent || ''),
    legacyId: idEl?.getAttribute('data-legacy-message-id') || '',
  }
}

/** Gmail's "original message" (raw RFC 822 with headers), fetched from Gmail itself. Best effort: null on any problem. */
async function fetchOriginal(legacyId) {
  const url = PG.originalMessageUrl(location.origin, location.pathname, legacyId)
  if (!url) return null
  try {
    const res = await fetch(url, { credentials: 'include' })
    if (!res.ok) return null
    const text = await res.text()
    return PG.looksLikeRawEmail(text) ? text : null
  } catch { return null }
}

async function analyzeViaServer(ctx, email) {
  const payload = PG.buildPayload({
    email, name: ctx.name, subject: ctx.subject, html: ctx.html, text: ctx.text,
    recipient: PG.accountFromTitle(document.title),
  })
  const raw = ctx.opened && ctx.legacyId ? await fetchOriginal(ctx.legacyId) : null
  return sendMessage({ type: 'PG_ANALYZE', payload, raw })
}

function mountPanel(html) {
  const panel = document.createElement('div')
  panel.id = 'phishguard-panel'
  panel.className = 'pg-panel'
  panel.innerHTML = html
  document.body.appendChild(panel)
  activePanel = panel
  let top = mouseY - 20, left = mouseX + 20
  if (left + 310 > window.innerWidth) left = mouseX - 320
  if (top < 8) top = 8
  panel.style.top = `${top}px`
  panel.style.left = `${left}px`
  requestAnimationFrame(() => panel.classList.add('pg-visible'))
  return panel
}

const SHIELD = color => `
  <svg class="pg-shield" viewBox="0 0 24 24" fill="none">
    <path d="M12 2L4 6v6c0 5.25 3.75 10.15 8 11.35C16.25 22.15 20 17.25 20 12V6L12 2z"
      fill="${color}" fill-opacity=".15" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/>
    <path d="M9 12l2 2 4-4" stroke="${color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`
const head = color => `
  <div class="pg-header">${SHIELD(color)}<span class="pg-title">PhishGuard</span>
    <button class="pg-close" id="pg-close-btn" aria-label="Close">×</button></div>`

function loadingHtml(domain) {
  return `${head('#6366f1')}
    <div class="pg-domain-row"><span class="pg-label">Domain</span><code class="pg-code">${esc(domain)}</code></div>
    <div class="pg-skeleton"><span></span><span></span><span></span></div>
    <div class="pg-mode">Analysing…</div>`
}

function renderServer(result, usedHeaders, ctx) {
  const v = PG.verdict(result)
  const da = result.domain_analysis || {}
  const findings = PG.topFindings(result, 6)
  const mode = usedHeaders ? 'message headers + body'
    : ctx.opened ? 'message body (open the message once more for headers)' : 'sender and subject only (open the message for a full check)'
  const trust = da.is_trusted
    ? `<div class="pg-match-row pg-safe">✓ Verified domain${findings.length ? ' — but the message has warning signs' : ''}</div>`
    : da.is_freemail ? `<div class="pg-match-row">Free mailbox provider: the sender's identity is not verified</div>` : ''
  return `${head(v.color)}
    <div class="pg-domain-row"><span class="pg-label">Domain</span><code class="pg-code">${esc(result.domain)}</code></div>
    <div class="pg-risk" style="background:${v.color}15;border-color:${v.color}25">
      <span class="pg-dot" style="background:${v.color}"></span>
      <span class="pg-risk-label" style="color:${v.color}">${v.label}</span>
      <span class="pg-score" style="color:${v.color}">${result.risk_level}/100</span>
    </div>
    ${trust}
    ${findings.map(w => `
      <div class="pg-warning pg-warning-${esc(String(w.severity).toLowerCase())}">
        <span class="pg-warn-dot"></span><span>${esc(w.message)}</span>
      </div>`).join('') || (v.level === 'LOW' ? '<div class="pg-match-row pg-safe">No warning signs found</div>' : '')}
    <div class="pg-mode">Analysed by your PhishGuard server · ${esc(mode)}</div>`
}

function renderLocal(email, domain, anchorEl, reason) {
  let result
  try { result = analyzeDomain(domain) } catch (e) { return `${head('#6366f1')}<div class="pg-mode">Could not analyse ${esc(domain)}</div>` }
  let spam = { spamScore: 0, spamLevel: 'LOW', signals: [] }
  try {
    const row = anchorEl.closest?.('tr') || anchorEl.closest?.('[role="row"]')
    const subject = document.querySelector('h2.hP')?.textContent || row?.querySelector('.bog, .y6 span')?.textContent || ''
    const preview = document.querySelector('.a3s.aiL')?.innerText?.slice(0, 500) || row?.querySelector('.y2')?.textContent || ''
    spam = analyzeSpam(subject, preview)
  } catch (e) { /* subject/body not available */ }
  const combined = Math.min(result.riskLevel + Math.round(spam.spamScore * 0.4), 100)
  const topRisk = combined >= 55 ? 'HIGH' : combined >= 25 ? 'MEDIUM' : 'LOW'
  const color = riskColor(topRisk)
  const warn = [...(result.warnings || []), ...(spam.signals || [])]
  chrome.storage?.local?.set({ lastResult: { email, domain, ...result, spam, combinedScore: combined, source: 'local', timestamp: Date.now() } })
  return `${head(color)}
    <div class="pg-offline">${esc(reason || 'Server not reachable')}: showing the simplified offline check. Start the PhishGuard server or set its address in the extension popup.</div>
    <div class="pg-domain-row"><span class="pg-label">Domain</span><code class="pg-code">${esc(domain)}</code></div>
    <div class="pg-risk" style="background:${color}15;border-color:${color}25">
      <span class="pg-dot" style="background:${color}"></span>
      <span class="pg-risk-label" style="color:${color}">${topRisk === 'LOW' ? 'NO ALERT' : topRisk + ' RISK'}</span>
      <span class="pg-score" style="color:${color}">${combined}/100</span>
    </div>
    ${result.safe ? '<div class="pg-match-row pg-safe">Trusted domain name. Sender identity and message content were not checked.</div>'
      : `<div class="pg-match-row"><span class="pg-label">Closest trusted</span>
         <span class="pg-match-val">${esc(result.bestMatch?.trusted ?? '—')} (d=${esc(result.bestMatch?.distance ?? '—')})</span></div>`}
    ${warn.slice(0, 5).map(w => `
      <div class="pg-warning pg-warning-${esc(String(w.severity).toLowerCase())}">
        <span class="pg-warn-dot"></span><span>${esc(w.message)}</span>
      </div>`).join('')}`
}

async function showPanel(anchorEl, email, domain) {
  removePanel()
  const token = ++panelToken
  const ctx = messageContext(anchorEl, email)
  const panel = mountPanel(loadingHtml(domain))
  panel.querySelector('#pg-close-btn')?.addEventListener('click', removePanel)

  const key = ctx.legacyId ? `${ctx.legacyId}|${email}` : `${email}|${ctx.subject}`
  const hit = resultCache.get(key)
  let outcome = hit && Date.now() - hit.at < CACHE_MS ? hit.outcome : null
  if (!outcome) {
    outcome = await analyzeViaServer(ctx, email)
    if (outcome.ok) resultCache.set(key, { outcome, at: Date.now() })
  }
  if (token !== panelToken || activePanel !== panel) return          // the user moved on

  if (outcome.ok) {
    panel.innerHTML = renderServer(outcome.result, outcome.usedHeaders, ctx)
    chrome.storage?.local?.set({ lastResult: PG.summarize(outcome.result, email) })
  } else {
    panel.innerHTML = renderLocal(email, domain, anchorEl, outcome.status === 401 ? 'API key rejected' : outcome.offline ? 'Server not reachable' : outcome.error)
  }
  panel.querySelector('#pg-close-btn')?.addEventListener('click', removePanel)
}

function removePanel() {
  panelToken++
  if (activePanel) { activePanel.remove(); activePanel = null }
}

// ── Email search at a single point ────────────────────────────────────────────

function emailAtPoint(x, y) {
  try {
    const stack = document.elementsFromPoint(x, y)
    for (const el of stack) {
      if (!el || el.id === 'phishguard-panel') continue
      if (el === document.body || el === document.documentElement) break

      // Attributes
      const attr = el.getAttribute('email') || el.getAttribute('data-email') ||
                   el.getAttribute('data-hovercard-id') || el.getAttribute('data-mailto') || ''
      if (attr.includes('@')) return { el, email: attr.toLowerCase() }

      // mailto href
      if (el.tagName === 'A' && String(el.href).startsWith('mailto:')) {
        const e2 = decodeURIComponent(el.href.slice(7)).split('?')[0].trim().toLowerCase()
        if (EMAIL_RE.test(e2)) return { el, email: e2 }
      }

      // Text (compact elements only — avoids large container nodes)
      const text = el.textContent || ''
      if (text.length >= 5 && text.length <= 300) {
        const m = EMAIL_RE.exec(text)
        if (m) return { el, email: m[0].toLowerCase() }
      }
    }
  } catch(e) {}
  return null
}

// ── Poll: sample a grid around the cursor every 150 ms ───────────────────────
// Gmail's contact card is an overlay that isn't at the exact cursor position.
// We sample 16 points in the region where the card typically appears.

function stopPolling() {
  clearInterval(pollTimer); pollTimer = null
  clearTimeout(fastTimer);  fastTimer = null
  clearTimeout(closeTimer); closeTimer = null
}

function startPolling() {
  stopPolling()
  let ticks = 0
  pollTimer = setInterval(() => {
    if (++ticks > 20 || activePanel) { stopPolling(); return }

    // Grid: right/below the cursor (where Gmail positions its card)
    const offsets = [
      [0,0],[0,25],[0,50],[0,75],[0,100],
      [80,25],[80,50],[80,75],[80,100],
      [160,25],[160,50],[160,75],[160,100],
      [240,25],[240,50],[240,75],
      [-80,25],[-80,50],[-80,75],
    ]

    for (const [dx, dy] of offsets) {
      const x = mouseX + dx, y = mouseY + dy
      if (x < 0 || y < 0 || x > window.innerWidth || y > window.innerHeight) continue
      const found = emailAtPoint(x, y)
      if (found) {
        console.log('[PhishGuard] found email via poll offset', dx, dy, found.email)
        const domain = extractDomain(found.email)
        if (domain) { stopPolling(); showPanel(found.el, found.email, domain); return }
      }
    }
  }, 150)
}

// ── Hover listeners ───────────────────────────────────────────────────────────
// Use capture:true so Gmail's own stopPropagation() doesn't block us.

document.addEventListener('mouseover', e => {
  if (activePanel) return
  if (!_pgEnabled) return
  console.log('[PhishGuard] mouseover', e.target.tagName, e.target.className?.slice?.(0,40))

  // Fast path: email in DOM attribute right on the element or an ancestor
  let el = e.target
  while (el && el !== document.body) {
    const v = el.getAttribute?.('email') || el.getAttribute?.('data-email') ||
              el.getAttribute?.('data-hovercard-id') || el.getAttribute?.('data-mailto') || ''
    if (v.includes('@')) {
      console.log('[PhishGuard] fast-path email:', v)
      const domain = extractDomain(v.toLowerCase())
      if (domain) {
        stopPolling()
        fastTimer = setTimeout(() => { fastTimer = null; if (!activePanel) showPanel(el, v.toLowerCase(), domain) }, 300)
        return
      }
    }
    el = el.parentElement
  }

  startPolling()
}, { capture: true, passive: true })

document.addEventListener('mouseout', e => {
  if (e.target.closest?.('#phishguard-panel')) return
  stopPolling()
  closeTimer = setTimeout(removePanel, 200)
}, { capture: true, passive: true })

document.addEventListener('mouseover', e => {
  if (e.target.closest?.('#phishguard-panel')) {
    clearTimeout(closeTimer); closeTimer = null
  }
}, { capture: true, passive: true })

document.addEventListener('click', e => {
  if (!e.target.closest('#phishguard-panel')) { removePanel(); stopPolling() }
}, { passive: true })

// SPA navigation cleanup
let lastUrl = location.href
new MutationObserver(() => {
  if (location.href !== lastUrl) { lastUrl = location.href; removePanel(); stopPolling() }
}).observe(document.body, { subtree: true, childList: true })
