// Popup UI logic

// ── Google Auth UI ─────────────────────────────────────────────────────────────

function renderAuthState(user) {
  const banner    = document.getElementById('auth-banner')
  const userRow   = document.getElementById('auth-user-row')
  const avatar    = document.getElementById('auth-avatar')
  const nameEl    = document.getElementById('auth-user-name')
  const emailEl   = document.getElementById('auth-user-email')

  if (user) {
    banner.style.display   = 'none'
    userRow.style.display  = 'flex'
    avatar.src             = user.picture || ''
    nameEl.textContent     = user.name    || '—'
    emailEl.textContent    = user.email   || '—'
  } else {
    banner.style.display   = 'flex'
    userRow.style.display  = 'none'
  }
}

chrome.storage?.local?.get(['authUser'], data => renderAuthState(data?.authUser ?? null))

document.getElementById('auth-signin-btn')?.addEventListener('click', () => {
  const btn = document.getElementById('auth-signin-btn')
  btn.textContent = 'Signing in…'
  btn.disabled = true

  chrome.runtime.sendMessage({ type: 'AUTH_SIGN_IN' }, res => {
    btn.textContent = 'Sign in'
    btn.disabled    = false
    if (res?.success) renderAuthState(res.user)
    else console.error('Auth error:', res?.error)
  })
})

document.getElementById('auth-signout-btn')?.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'AUTH_SIGN_OUT' }, res => {
    if (res?.success) renderAuthState(null)
  })
})

function formatTime(ts) {
  if (!ts) return ''
  const diff = Date.now() - ts
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  return `${Math.floor(m / 60)}h ago`
}

// ── Load last scan result ──────────────────────────────────────
chrome.storage?.local?.get(['lastResult', 'enabled'], data => {
  const r = data?.lastResult

  // Sync toggle
  const toggle = document.getElementById('toggle-enabled')
  if (toggle && data?.enabled !== undefined) toggle.checked = data.enabled

  if (!r) return

  document.getElementById('last-scan-empty').style.display  = 'none'
  document.getElementById('last-scan-result').style.display = 'block'

  const domain = document.getElementById('scan-domain')
  const badge  = document.getElementById('scan-badge')
  const meta   = document.getElementById('scan-meta')
  const warns  = document.getElementById('scan-warnings')

  domain.textContent = r.domain
  const label = r.safe ? 'SAFE' : r.riskScore
  const via = r.source === 'server' ? 'PhishGuard server' : 'offline check'
  badge.textContent  = label
  badge.className    = `scan-badge ${label}`
  meta.textContent   = `Scanned ${formatTime(r.timestamp)} · ${via}`

  if (r.warnings?.length) {
    warns.innerHTML = ''
    r.warnings.forEach(w => {
      const div = document.createElement('div')
      div.className = `scan-warn ${w.severity === 'HIGH' ? '' : 'medium'}`
      div.textContent = w.message
      warns.appendChild(div)
    })
  }
})

// ── Toggle on/off ──────────────────────────────────────────────
document.getElementById('toggle-enabled')?.addEventListener('change', e => {
  chrome.storage?.local?.set({ enabled: e.target.checked })
})

// ── Quick check ────────────────────────────────────────────────
document.getElementById('quick-btn')?.addEventListener('click', runQuickCheck)
document.getElementById('quick-input')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') runQuickCheck()
})

async function runQuickCheck() {
  const input = document.getElementById('quick-input')
  const val   = input?.value?.trim()
  if (!val) return

  const domain = val.includes('@') ? val.split('@')[1] : val
  const wrap   = document.getElementById('quick-result')
  if (!wrap) return

  // The server's analysis (same detector as the dashboard); the simplified local check if it is unreachable.
  const sender = val.includes('@') ? val : `check@${domain}`
  const res = await new Promise(resolve => chrome.runtime.sendMessage(
    { type: 'PG_ANALYZE', payload: PG.buildPayload({ email: sender, subject: '', html: '', text: '' }) },
    r => resolve(chrome.runtime.lastError ? { ok: false } : (r || { ok: false }))))
  if (res.ok) { renderQuickServer(wrap, res.result); return }

  const result = analyzeDomain(domain.toLowerCase())

  const color = result.safe ? '#22c55e' : result.riskScore === 'HIGH' ? '#ef4444' : '#f59e0b'
  const label = result.safe ? 'SAFE' : result.riskScore + ' RISK'

  wrap.style.display = 'block'
  wrap.innerHTML = ''

  const box = document.createElement('div')
  box.className = 'quick-result-box'

  const row = document.createElement('div')
  row.className = 'qr-row'
  const domainSpan = document.createElement('span')
  domainSpan.className = 'qr-domain'
  domainSpan.textContent = domain
  const badge = document.createElement('span')
  badge.className = `scan-badge ${result.safe ? 'SAFE' : result.riskScore}`
  badge.style.color = color
  badge.textContent = label
  row.appendChild(domainSpan)
  row.appendChild(badge)
  box.appendChild(row)

  if (!result.safe && result.bestMatch) {
    const p = document.createElement('p')
    p.className = 'qr-warn'
    p.textContent = `Closest match: ${result.bestMatch.trusted} (d=${result.bestMatch.distance})`
    box.appendChild(p)
  }
  result.warnings?.forEach(w => {
    const p = document.createElement('p')
    p.className = 'qr-warn'
    p.textContent = w.message
    box.appendChild(p)
  })
  wrap.appendChild(box)
}

function renderQuickServer(wrap, result) {
  const v = PG.verdict(result)
  wrap.style.display = 'block'
  wrap.innerHTML = ''
  const box = document.createElement('div')
  box.className = 'quick-result-box'
  const row = document.createElement('div')
  row.className = 'qr-row'
  const d = document.createElement('span')
  d.className = 'qr-domain'
  d.textContent = result.domain
  const badge = document.createElement('span')
  badge.className = `scan-badge ${v.level === 'LOW' ? 'SAFE' : v.level}`
  badge.style.color = v.color
  badge.textContent = v.label
  row.append(d, badge)
  box.appendChild(row)
  const note = document.createElement('p')
  note.className = 'qr-warn'
  note.textContent = 'Sender domain only. Hover a message in Gmail for the full analysis.'
  box.appendChild(note)
  PG.topFindings(result, 4).forEach(w => {
    const p = document.createElement('p')
    p.className = 'qr-warn'
    p.textContent = w.message
    box.appendChild(p)
  })
  wrap.appendChild(box)
}

// ── Server settings ───────────────────────────────────────────

function setServerStatus(kind, text) {
  document.getElementById('srv-dot').className = `srv-dot ${kind}`
  document.getElementById('srv-text').textContent = text
}

function testServer() {
  setServerStatus('', 'Checking…')
  chrome.runtime.sendMessage({ type: 'PG_HEALTH' }, res => {
    if (chrome.runtime.lastError || !res) return setServerStatus('bad', 'Extension error: reload the extension')
    if (res.ok) setServerStatus('ok', 'Connected: full analysis is on')
    else if (res.status === 401) setServerStatus('bad', 'Server reachable, but the API key was rejected')
    else setServerStatus('bad', `${res.error || 'Not reachable'}: using the simplified offline check`)
  })
}

chrome.storage?.local?.get(['apiUrl', 'apiKey', 'useHeaders', 'persist'], d => {
  document.getElementById('srv-url').value = d.apiUrl || PG.DEFAULTS.apiUrl
  document.getElementById('srv-key').value = d.apiKey || ''
  document.getElementById('srv-headers').checked = d.useHeaders ?? PG.DEFAULTS.useHeaders
  document.getElementById('srv-persist').checked = d.persist ?? PG.DEFAULTS.persist
  testServer()
})

document.getElementById('srv-save')?.addEventListener('click', async () => {
  const note = document.getElementById('srv-note')
  const url = PG.normalizeApiUrl(document.getElementById('srv-url').value)
  if (!url) {
    setServerStatus('bad', 'Use an https address (http is only allowed for localhost)')
    return
  }
  // Non-local servers need the user's explicit permission for that one origin.
  if (!PG.isLocalApi(url)) {
    const granted = await chrome.permissions.request({ origins: [PG.originPattern(url)] })
    if (!granted) { setServerStatus('bad', 'Permission for that server was not granted'); return }
  }
  chrome.storage.local.set({
    apiUrl: url, apiKey: document.getElementById('srv-key').value.trim(),
    useHeaders: document.getElementById('srv-headers').checked, persist: document.getElementById('srv-persist').checked,
  }, () => {
    document.getElementById('srv-url').value = url
    if (note) note.textContent = 'Saved. Messages you hover over are sent to this server for analysis, and nowhere else.'
    testServer()
  })
})
