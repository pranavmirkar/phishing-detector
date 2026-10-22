// Popup UI logic

const $ = id => document.getElementById(id)
const send = msg => new Promise(resolve => chrome.runtime.sendMessage(msg, r => resolve(chrome.runtime.lastError ? null : r)))

$('ver').textContent = chrome.runtime.getManifest().version

// ── Tabs ───────────────────────────────────────────────────────

function showTab(name) {
  for (const t of ['overview', 'settings']) {
    $(`view-${t}`).hidden = t !== name
    $(`tab-${t}`).setAttribute('aria-selected', String(t === name))
    $(`tab-${t}`).classList.toggle('active', t === name)
  }
}
$('tab-overview').addEventListener('click', () => showTab('overview'))
$('tab-settings').addEventListener('click', () => showTab('settings'))
$('goto-settings').addEventListener('click', () => showTab('settings'))

// ── Protection switch ──────────────────────────────────────────

$('toggle-enabled').addEventListener('change', e => chrome.storage.local.set({ enabled: e.target.checked }))

// ── Connection status ──────────────────────────────────────────

function setStatus(kind, text) {
  $('status').className = `status ${kind}`
  $('status-text').textContent = text
  $('setup-callout').hidden = kind === 'ok' || kind === ''
}

async function checkServer() {
  setStatus('', 'Checking…')
  const res = await send({ type: 'PG_HEALTH' })
  if (!res) setStatus('bad', 'Extension error')
  else if (res.ok) setStatus('ok', 'Connected')
  else if (res.status === 401) setStatus('bad', 'API key rejected')
  else setStatus('bad', 'Server offline')
  return res
}

// ── Last scan ──────────────────────────────────────────────────

function ago(ts) {
  const m = Math.floor((Date.now() - ts) / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m} min ago`
  const h = Math.floor(m / 60)
  return h < 24 ? `${h} h ago` : `${Math.floor(h / 24)} d ago`
}

/** Stored scans come from the server (riskScore HIGH/MEDIUM/LOW) or the offline check (HIGH/MEDIUM/LOW/SAFE). */
function levelOf(r) {
  return r.safe || r.riskScore === 'SAFE' || r.riskScore === 'LOW' ? 'LOW' : r.riskScore
}

function fillFindings(ul, items) {
  ul.replaceChildren(...items.map(w => {
    const li = document.createElement('li')
    li.className = String(w.severity || '').toLowerCase()
    li.textContent = w.message
    return li
  }))
}

chrome.storage.local.get(['lastResult', 'enabled'], data => {
  if (data.enabled !== undefined) $('toggle-enabled').checked = data.enabled
  const r = data.lastResult
  if (!r) return
  $('last-empty').hidden = true
  $('last-result').hidden = false
  const level = levelOf(r)
  const v = PG.verdict({ risk_score: level })
  const offline = r.source !== 'server'
  $('last-verdict').className = `verdict ${offline ? '' : level.toLowerCase()}`
  $('last-headline').textContent = offline ? 'Offline check only' : v.headline
  $('last-meta').textContent = ago(r.timestamp)
  $('last-sender').textContent = r.email || r.domain
  fillFindings($('last-findings'), (r.warnings || []).slice(0, 3))
})

// ── Quick check ────────────────────────────────────────────────

$('quick-form').addEventListener('submit', async e => {
  e.preventDefault()
  const val = $('quick-input').value.trim()
  if (!val) return
  const domain = (val.includes('@') ? val.split('@')[1] : val).toLowerCase()
  const btn = $('quick-btn')
  btn.disabled = true
  const res = await send({ type: 'PG_ANALYZE', payload: PG.buildPayload({ email: val.includes('@') ? val : `check@${domain}`, subject: '', html: '', text: '' }) })
  btn.disabled = false
  const wrap = $('quick-result')
  wrap.hidden = false
  wrap.replaceChildren()

  const row = document.createElement('div')
  row.className = 'verdict'
  const dot = document.createElement('span'); dot.className = 'verdict-dot'
  const head = document.createElement('span'); head.className = 'verdict-text'
  const list = document.createElement('ul'); list.className = 'findings'
  const dom = document.createElement('p'); dom.className = 'sender'; dom.textContent = domain

  if (res && res.ok) {
    const v = PG.verdict(res.result)
    row.classList.add(v.level.toLowerCase())
    head.textContent = v.headline
    fillFindings(list, PG.topFindings(res.result, 4))
  } else {
    // Server unreachable: the simplified local check, labelled as such.
    let r = null
    try { r = analyzeDomain(domain) } catch { /* invalid input */ }
    head.textContent = 'Offline check only'
    fillFindings(list, r ? (r.warnings || []).slice(0, 4) : [{ message: 'Could not check this address.' }])
  }
  row.append(dot, head)
  wrap.append(row, dom, list)
})

// ── Settings ───────────────────────────────────────────────────

chrome.storage.local.get(['apiUrl', 'apiKey', 'useHeaders', 'persist'], d => {
  $('srv-url').value = d.apiUrl || PG.DEFAULTS.apiUrl
  $('srv-key').value = d.apiKey || ''
  $('srv-headers').checked = d.useHeaders ?? PG.DEFAULTS.useHeaders
  $('srv-persist').checked = d.persist ?? PG.DEFAULTS.persist
  checkServer()
})

function saveMsg(kind, text) {
  $('srv-msg').className = `msg ${kind}`
  $('srv-msg').textContent = text
}

$('srv-save').addEventListener('click', async () => {
  const btn = $('srv-save')
  const url = PG.normalizeApiUrl($('srv-url').value)
  if (!url) return saveMsg('bad', 'Use https, or http://localhost')
  // A non-local server needs the user's explicit permission for that one origin.
  if (!PG.isLocalApi(url)) {
    const granted = await chrome.permissions.request({ origins: [PG.originPattern(url)] })
    if (!granted) return saveMsg('bad', 'Permission not granted')
  }
  btn.disabled = true
  saveMsg('', 'Testing…')
  await chrome.storage.local.set({
    apiUrl: url, apiKey: $('srv-key').value.trim(),
    useHeaders: $('srv-headers').checked, persist: $('srv-persist').checked,
  })
  $('srv-url').value = url
  const res = await checkServer()
  btn.disabled = false
  if (res && res.ok) saveMsg('ok', 'Saved. Connected.')
  else if (res && res.status === 401) saveMsg('bad', 'Saved, but the key was rejected')
  else saveMsg('bad', 'Saved, but the server is not reachable')
})

// ── Google account ─────────────────────────────────────────────

function renderAuth(user) {
  $('auth-out').hidden = !!user
  $('auth-in').hidden = !user
  if (!user) return
  $('auth-avatar').src = user.picture || ''
  $('auth-user-name').textContent = user.name || 'Signed in'
  $('auth-user-email').textContent = user.email || ''
}
chrome.storage.local.get(['authUser'], d => renderAuth(d.authUser ?? null))

$('auth-signin-btn').addEventListener('click', async () => {
  const btn = $('auth-signin-btn')
  btn.disabled = true
  btn.textContent = 'Signing in…'
  const res = await send({ type: 'AUTH_SIGN_IN' })
  btn.disabled = false
  btn.textContent = 'Sign in with Google'
  if (res && res.success) renderAuth(res.user)
})

$('auth-signout-btn').addEventListener('click', async () => {
  const res = await send({ type: 'AUTH_SIGN_OUT' })
  if (res && res.success) renderAuth(null)
})
