const BASE = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) || 'http://localhost:5000/api'

async function req(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!res.ok) {
    // Prefer the server's own message ("A benchmark is already running.") over a bare status code.
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || `API error ${res.status}`)
  }
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

  benchDatasets:     ()        => req('/benchmarks/datasets'),
  benchResults:      ()        => req('/benchmarks/results'),
  benchRun:          (spec)    => req('/benchmarks/run',           { method: 'POST',   body: JSON.stringify(spec) }),
  benchJob:          (id)      => req(`/benchmarks/jobs/${id}`),
  benchDownload:     (spam)    => req('/benchmarks/real/download', { method: 'POST',   body: JSON.stringify({ include_spam: spam }) }),
  benchDeleteReal:   ()        => req('/benchmarks/real',          { method: 'DELETE' }),
}
