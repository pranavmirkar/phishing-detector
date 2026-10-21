chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ enabled: true, scanCount: 0 })
})

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
