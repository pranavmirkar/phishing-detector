// Levenshtein Distance — pure JS, runs entirely in the browser.
// No server call needed — analysis completes in < 10ms.
// Domain data loaded from domains.js (50K Tranco list bundled with extension).

function levenshteinDistance(s1, s2) {
  const m = s1.length, n = s2.length
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  )
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = s1[i-1] === s2[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
  return dp[m][n]
}

function similarityPercent(s1, s2) {
  const dist = levenshteinDistance(s1, s2)
  const max = Math.max(s1.length, s2.length, 1)
  return +((1 - dist / max) * 100).toFixed(1)
}

const HOMOGLYPHS = {
  'а':'a','е':'e','о':'o','р':'p','с':'c','у':'y','х':'x','і':'i',
  '0':'o','1':'l','3':'e','4':'a','5':'s','@':'a','$':'s',
}
const MULTI = { 'rn':'m', 'vv':'w' }

function normalizeHomoglyphs(domain) {
  let s = domain.toLowerCase()
  for (const [k,v] of Object.entries(MULTI)) s = s.split(k).join(v)
  for (const [k,v] of Object.entries(HOMOGLYPHS)) s = s.split(k).join(v)
  return s
}

// Fallback if domains.js hasn't loaded yet
const _FALLBACK = [
  'google.com','gmail.com','microsoft.com','outlook.com','hotmail.com',
  'amazon.com','apple.com','icloud.com','paypal.com','facebook.com',
  'instagram.com','twitter.com','linkedin.com','github.com','netflix.com',
  'yahoo.com','ebay.com','dropbox.com','adobe.com','zoom.us',
  'slack.com','bankofamerica.com','chase.com','wellsfargo.com',
]

function getTrustedSet()  { return typeof TRUSTED_SET  !== 'undefined' ? TRUSTED_SET  : new Set(_FALLBACK) }
function getTrustedPool() { return typeof TRUSTED_POOL !== 'undefined' ? TRUSTED_POOL : _FALLBACK }

function analyzeDomain(rawDomain) {
  const domain = rawDomain.toLowerCase()
  const trustedSet  = getTrustedSet()
  const trustedPool = getTrustedPool()

  // Exact match — O(1) against all 50K domains
  if (trustedSet.has(domain)) {
    return { safe: true, domain, riskScore: 'LOW', riskLevel: 0, warnings: [], topMatches: [] }
  }

  // Subdomain of a trusted domain (e.g. accounts.google.com → google.com)
  const parts = domain.split('.')
  if (parts.length > 2) {
    const baseDomain = parts.slice(-2).join('.')
    if (trustedSet.has(baseDomain)) {
      return { safe: true, domain, riskScore: 'LOW', riskLevel: 0, warnings: [], topMatches: [] }
    }
  }

  const normalized = normalizeHomoglyphs(domain)
  const homoglyphDetected = normalized !== domain

  // Levenshtein against top-1K pool
  const results = trustedPool.map(td => ({
    trusted: td,
    distance: levenshteinDistance(normalized, td),
    similarity: similarityPercent(normalized, td),
  })).sort((a, b) => a.distance - b.distance)

  const best = results[0]
  const warnings = []

  if (best.distance <= 2) {
    warnings.push({ severity: 'HIGH', message: `Lookalike domain — ${best.distance} edit(s) from "${best.trusted}"` })
  } else if (best.distance <= 4) {
    warnings.push({ severity: 'MEDIUM', message: `Resembles "${best.trusted}" (${best.similarity}% similar)` })
  }

  if (homoglyphDetected) {
    warnings.push({ severity: 'HIGH', message: `Unicode homoglyph characters detected` })
  }

  // Subdomain abuse check against pool
  const subParts = domain.split('.')
  if (subParts.length > 2) {
    const prefix = subParts.slice(0, -2).join('.')
    const actual = subParts.slice(-2).join('.')
    for (const td of trustedPool.slice(0, 200)) {
      if (prefix.includes(td.split('.')[0]) && td.split('.')[0].length >= 4 && actual !== td) {
        warnings.push({ severity: 'HIGH', message: `Subdomain abuse — actual domain is "${actual}"` })
        break
      }
    }
  }

  let riskLevel = 0
  if (best.distance <= 2)      riskLevel = 75
  else if (best.distance <= 4) riskLevel = 40
  if (homoglyphDetected)       riskLevel = Math.min(riskLevel + 20, 100)

  const riskScore = riskLevel >= 60 ? 'HIGH' : riskLevel >= 30 ? 'MEDIUM' : 'LOW'

  return {
    safe: false, domain, normalized, homoglyphDetected,
    bestMatch: best, topMatches: results.slice(0, 3),
    warnings, riskScore, riskLevel,
    domainCount: trustedPool.length === _FALLBACK.length ? 24 : 50000,
  }
}
