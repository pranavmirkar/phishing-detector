importScripts('api.js')

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['enabled', 'scanCount'], d => {
    chrome.storage.local.set({ enabled: d.enabled ?? true, scanCount: d.scanCount ?? 0 })
  })
})

// ── Settings + server calls ──────────────────────────────────────────────────
// The worker (not the Gmail page) talks to the PhishGuard server: with host permission an extension
// worker is not subject to CORS, and Gmail's own content-security policy never sees the request.

const TIMEOUT_MS = 9000          // WHOIS on a brand-new domain can take a few seconds server-side

function getSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get(['apiUrl', 'apiKey', 'useHeaders', 'persist'], d => resolve({
      apiUrl: PG.normalizeApiUrl(d.apiUrl) || PG.DEFAULTS.apiUrl,
      apiKey: d.apiKey || '',
      useHeaders: d.useHeaders ?? PG.DEFAULTS.useHeaders,
      persist: d.persist ?? PG.DEFAULTS.persist,
    }))
  })
}

class ApiError extends Error {
  constructor(message, { offline = false, status = 0 } = {}) {
    super(message)
    this.offline = offline
    this.status = status
  }
}

async function callApi(settings, path, body) {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS)
  try {
    const headers = { 'Content-Type': 'application/json' }
    if (settings.apiKey) headers['X-API-Key'] = settings.apiKey
    const res = await fetch(settings.apiUrl + path, {
      method: body === undefined ? 'GET' : 'POST', headers,
      body: body === undefined ? undefined : JSON.stringify(body), signal: ctrl.signal,
    })
    let json = null
    try { json = await res.json() } catch { /* not JSON */ }
    if (!res.ok) throw new ApiError(json?.error || `Server answered ${res.status}`, { status: res.status })
    return json
  } catch (e) {
    if (e instanceof ApiError) throw e
    throw new ApiError(e.name === 'AbortError' ? 'The server took too long to answer' : 'Cannot reach the PhishGuard server', { offline: true })
  } finally {
    clearTimeout(timer)
  }
}

/** Analyse one message. With `raw` (Gmail's "original message") the headers are parsed by the server too. */
async function analyzeMessage({ payload, raw }) {
  const settings = await getSettings()
  let body = { ...payload, persist: settings.persist }
  let usedHeaders = false
  if (raw && settings.useHeaders) {
    try {
      const parsed = await callApi(settings, '/parse', { raw: PG.limitRaw(raw) })
      // Header evidence from the parsed message; the visible HTML Gmail rendered stays the body.
      body = { ...parsed, ...body, sender: parsed.sender || payload.sender, subject: parsed.subject || payload.subject, auth_results: parsed.auth_results, return_path: parsed.return_path,
               attachments: parsed.attachments, list_id: parsed.list_id, reply_to: parsed.reply_to || '',
               recipient: parsed.recipient || payload.recipient, content: payload.content || parsed.content }
      usedHeaders = !!(parsed.auth_results || parsed.return_path || (parsed.attachments || []).length)
    } catch (e) {
      if (e.offline) throw e                   // server down: do not try again
      /* the message could not be parsed: analyse what the page showed */
    }
  }
  const result = await callApi(settings, '/analyze', body)
  return { result, usedHeaders }
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

function startGoogleAuth() {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: true }, token => {
      if (chrome.runtime.lastError) return reject(chrome.runtime.lastError.message)
      if (!token) return reject('No token returned')
      resolve(token)
    })
  })
}

async function fetchUserInfo(token) {
  const res = await fetch('https://www.googleapis.com/oauth2/v1/userinfo?alt=json', {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new Error('Failed to fetch user info')
  return res.json()
}

function signOut() {
  return new Promise(resolve => {
    chrome.storage.local.get(['authToken'], data => {
      const token = data.authToken
      chrome.storage.local.remove(['authToken', 'authUser'], () => {
        // Revoke the token so re-login shows the account picker
        if (token) {
          fetch(`https://accounts.google.com/o/oauth2/revoke?token=${token}`).catch(() => {})
          chrome.identity.removeCachedAuthToken({ token }, resolve)
        } else {
          resolve()
        }
      })
    })
  })
}

// ── Message router ────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'PG_ANALYZE') {
    analyzeMessage(msg)
      .then(({ result, usedHeaders }) => sendResponse({ ok: true, result, usedHeaders }))
      .catch(e => sendResponse({ ok: false, error: e.message, offline: !!e.offline, status: e.status || 0 }))
    return true
  }

  if (msg.type === 'PG_HEALTH') {
    getSettings()
      .then(s => callApi(s, '/health').then(() => callApi(s, '/stats').catch(e => { if (e.status === 401) throw e; return null })))
      .then(() => sendResponse({ ok: true }))
      .catch(e => sendResponse({ ok: false, error: e.message, status: e.status || 0 }))
    return true
  }

  if (msg.type === 'AUTH_SIGN_IN') {
    startGoogleAuth()
      .then(token => fetchUserInfo(token).then(user => ({ token, user })))
      .then(({ token, user }) => {
        chrome.storage.local.set({ authToken: token, authUser: user })
        sendResponse({ success: true, user })
      })
      .catch(err => sendResponse({ success: false, error: String(err) }))
    return true // keep message channel open for async response
  }

  if (msg.type === 'AUTH_SIGN_OUT') {
    signOut().then(() => sendResponse({ success: true }))
    return true
  }
})
