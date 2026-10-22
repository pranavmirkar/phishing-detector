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
})
chrome.storage?.onChanged?.addListener((changes, area) => {
  if (area === 'local' && 'enabled' in changes) _pgEnabled = changes.enabled.newValue
})

document.addEventListener('mousemove', e => { mouseX = e.clientX; mouseY = e.clientY }, { passive: true })

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')
}
function extractDomain(email) {
  const m = String(email).match(/@([\w.\-]+\.\w+)/)
  return m ? m[1].toLowerCase() : null
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

function mountPanel(level, html) {
  const panel = document.createElement('div')
  panel.id = 'phishguard-panel'
  panel.className = `pg-panel pg-lvl-${level}`
  panel.setAttribute('role', 'dialog')
  panel.setAttribute('aria-label', 'PhishGuard analysis')
  panel.innerHTML = html
  document.body.appendChild(panel)
  activePanel = panel
  const w = Math.min(320, window.innerWidth - 16)
  let left = mouseX + 20, top = mouseY - 20
  if (left + w > window.innerWidth - 8) left = Math.max(8, mouseX - w - 20)
  top = Math.max(8, Math.min(top, window.innerHeight - 260))
  panel.style.top = `${top}px`
  panel.style.left = `${left}px`
  bindPanel(panel)
  requestAnimationFrame(() => panel.classList.add('pg-visible'))
  return panel
}

function setPanel(panel, level, html) {
  panel.className = `pg-panel pg-lvl-${level} pg-visible`
  panel.innerHTML = html
  bindPanel(panel)
}

function bindPanel(panel) {
  panel.querySelector('.pg-close')?.addEventListener('click', removePanel)
  panel.querySelector('.pg-more')?.addEventListener('click', e => {
    panel.querySelectorAll('.pg-item[hidden]').forEach(li => { li.hidden = false })
    e.currentTarget.remove()
  })
}

const GLYPHS = {
  low: '<path d="M5.5 12.5l4.2 4.2 8.8-9" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>',
  alert: '<path d="M12 6.5v7M12 17.4v.1" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/>',
  info: '<path d="M12 11v6M12 7.6v.1" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/>',
}
const CLOSE_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>'
const SEV = { HIGH: 'High', MEDIUM: 'Medium', LOW: 'Note' }

/** The verdict hero: a shape whose edge gets sharper with the danger, the headline, and what to do. */
function verdictBlock(level, headline, advice) {
  const glyph = level === 'low' ? GLYPHS.low : level === 'off' || level === 'wait' ? GLYPHS.info : GLYPHS.alert
  const blob = PG.levelShape(level.toUpperCase())
  return `<div class="pg-hero pg-has-close">
    <span class="pg-shape"><svg viewBox="-1 -1 2 2" aria-hidden="true"><path class="pg-blob" d="${blob}"/></svg>
      <svg class="pg-glyph" viewBox="0 0 24 24" aria-hidden="true">${glyph}</svg></span>
    <div class="pg-hero-text"><div class="pg-headline">${esc(headline)}</div>${advice ? `<div class="pg-advice">${esc(advice)}</div>` : ''}</div>
    <button class="pg-close" aria-label="Close">${CLOSE_ICON}</button></div>`
}

function senderBlock(name, email, tag) {
  const shown = name && name.toLowerCase() !== email ? name : email
  return `<div class="pg-sender"><span class="pg-avatar" aria-hidden="true">${esc(shown.replace(/^[^a-z0-9]+/i, '').charAt(0) || '?')}</span>
    <div class="pg-who"><div class="pg-from">${esc(shown)}</div>${shown !== email ? `<div class="pg-addr">${esc(email)}</div>` : ''}</div>
    ${tag ? `<span class="pg-tag">${esc(tag)}</span>` : ''}</div>`
}

const SHOWN = 3
function findingsBlock(findings, emptyText) {
  if (!findings.length) return emptyText ? `<div class="pg-empty">${esc(emptyText)}</div>` : ''
  const items = findings.map((w, i) => `<div class="pg-item"${i >= SHOWN ? ' hidden' : ''}><span class="pg-sev pg-sev-${esc(String(w.severity).toLowerCase())}">${SEV[w.severity] || 'Note'}</span><span class="pg-msg">${esc(w.message)}</span></div>`).join('')
  return `<div class="pg-label">Why</div><div class="pg-list pg-findings">${items}</div>
    ${findings.length > SHOWN ? `<button class="pg-more">Show ${findings.length - SHOWN} more</button>` : ''}`
}

function loadingHtml(name, email) {
  return `${verdictBlock('wait', 'Checking…', 'Looking at the sender and message')}
    <div class="pg-body">${senderBlock(name, email)}</div>
    <div class="pg-skeleton"><span></span><span></span><span></span></div>`
}

function renderServer(result, usedHeaders, ctx, email) {
  const v = PG.verdict(result)
  const level = v.level.toLowerCase()
  const da = result.domain_analysis || {}
  const findings = PG.topFindings(result, 8)
  const how = usedHeaders ? 'Sender, headers, message'
    : ctx.opened ? 'Sender and message' : 'Sender and subject only'
  const hint = !usedHeaders && !ctx.opened ? '<div class="pg-hint">Open the message for a fuller check.</div>' : ''
  const tag = da.is_trusted ? 'Known domain' : da.is_freemail ? 'Free mailbox' : ''
  const none = level === 'low' ? 'Nothing suspicious found in the sender, links or wording.' : ''
  return `${verdictBlock(level, v.headline, v.advice)}
    <div class="pg-body">${senderBlock(ctx.name, email, tag)}${findingsBlock(findings, none)}${hint}</div>
    <div class="pg-chips"><span class="pg-chip">${how}</span><span class="pg-chip">Risk ${result.risk_level}/100</span></div>`
}

function renderLocal(email, domain, anchorEl, reason, ctx) {
  let result
  try { result = analyzeDomain(domain) } catch (e) { result = null }
  let spam = { spamScore: 0, signals: [] }
  try { spam = analyzeSpam(ctx.subject, (ctx.text || '').slice(0, 500)) } catch (e) { /* no text available */ }
  const warn = result ? [...(result.warnings || []), ...(spam.signals || []).map(x => ({ ...x, severity: 'LOW' }))] : []
  if (result) chrome.storage?.local?.set({ lastResult: { email, domain, ...result, spam, source: 'local', timestamp: Date.now() } })
  return `${verdictBlock('off', 'Server not reachable', 'Showing a limited offline check. It cannot tell whether a message is forged.')}
    <div class="pg-body">${senderBlock(ctx.name, email)}
    ${findingsBlock(warn.slice(0, 6).map(w => ({ severity: w.severity, message: w.message })), 'The offline check found nothing, which is not the same as safe.')}
    <div class="pg-hint">${esc(reason)}. Start the PhishGuard server, or set its address in the extension popup.</div></div>
    <div class="pg-chips"><span class="pg-chip">Offline check</span></div>`
}

async function showPanel(anchorEl, email, domain) {
  removePanel()
  const token = ++panelToken
  const ctx = messageContext(anchorEl, email)
  const panel = mountPanel('wait', loadingHtml(ctx.name, email))

  const key = ctx.legacyId ? `${ctx.legacyId}|${email}` : `${email}|${ctx.subject}`
  const hit = resultCache.get(key)
  let outcome = hit && Date.now() - hit.at < CACHE_MS ? hit.outcome : null
  if (!outcome) {
    outcome = await analyzeViaServer(ctx, email)
    if (outcome.ok) resultCache.set(key, { outcome, at: Date.now() })
  }
  if (token !== panelToken || activePanel !== panel) return          // the user moved on

  if (outcome.ok) {
    setPanel(panel, PG.verdict(outcome.result).level.toLowerCase(), renderServer(outcome.result, outcome.usedHeaders, ctx, email))
    chrome.storage?.local?.set({ lastResult: PG.summarize(outcome.result, email) })
  } else {
    const why = outcome.status === 401 ? 'The API key was rejected' : outcome.offline ? 'Could not reach the server' : outcome.error
    setPanel(panel, 'off', renderLocal(email, domain, anchorEl, why, ctx))
  }
}

document.addEventListener('keydown', e => { if (e.key === 'Escape' && activePanel) removePanel() }, true)

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
