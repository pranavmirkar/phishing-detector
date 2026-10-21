const BASE = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) || 'http://localhost:5000/api'

async function req(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) throw new Error(`API error ${res.status}`)
  return res.json()
}

export const api = {
  analyze:     (data)        => req('/analyze',       { method: 'POST', body: JSON.stringify(data) }),
  emails:      ()            => req('/emails'),
  email:       (id)          => req(`/emails/${id}`),
  stats:       ()            => req('/stats'),
  report:      (id, reason)  => req('/report',        { method: 'POST', body: JSON.stringify({ email_id: id, reason }) }),
  matrix:      (s1, s2)      => req('/matrix',        { method: 'POST', body: JSON.stringify({ s1, s2 }) }),
  health:      ()            => req('/health'),
  intelStatus: ()            => req('/intel/status'),
  intelUpdate: ()            => req('/intel/update',  { method: 'POST' }),
  intelWhois:  (domain)      => req('/intel/whois',   { method: 'POST', body: JSON.stringify({ domain }) }),
}
