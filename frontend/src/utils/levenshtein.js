// Levenshtein Distance — pure JS, no libraries.
// Shared between the web app and the Chrome extension.

export function levenshteinDistance(s1, s2) {
  const m = s1.length, n = s2.length
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  )
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = s1[i-1] === s2[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
  return dp[m][n]
}

export function similarityPercent(s1, s2) {
  const dist = levenshteinDistance(s1, s2)
  const maxLen = Math.max(s1.length, s2.length, 1)
  return +((1 - dist / maxLen) * 100).toFixed(1)
}

export function getDPMatrix(s1, s2) {
  const m = s1.length, n = s2.length
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  )
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = s1[i-1] === s2[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])

  // Traceback
  const path = new Set()
  let i = m, j = n
  while (i > 0 || j > 0) {
    path.add(`${i},${j}`)
    if (i > 0 && j > 0 && s1[i-1] === s2[j-1]) { i--; j-- }
    else if (i > 0 && j > 0 && dp[i][j] === dp[i-1][j-1] + 1) { i--; j-- }
    else if (j > 0 && dp[i][j] === dp[i][j-1] + 1) { j-- }
    else { i-- }
  }
  path.add('0,0')
  return { matrix: dp, path, s1, s2, distance: dp[m][n] }
}

export function getEditOperations(s1, s2) {
  const m = s1.length, n = s2.length
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  )
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = s1[i-1] === s2[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])

  const ops = []
  let i = m, j = n
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && s1[i-1] === s2[j-1]) {
      ops.push({ type: 'match', char: s1[i-1] }); i--; j--
    } else if (i > 0 && j > 0 && dp[i][j] === dp[i-1][j-1] + 1) {
      ops.push({ type: 'substitute', from: s1[i-1], to: s2[j-1], description: `'${s1[i-1]}' → '${s2[j-1]}' at position ${i}` }); i--; j--
    } else if (j > 0 && dp[i][j] === dp[i][j-1] + 1) {
      ops.push({ type: 'insert', char: s2[j-1], description: `insert '${s2[j-1]}' at position ${j}` }); j--
    } else {
      ops.push({ type: 'delete', char: s1[i-1], description: `delete '${s1[i-1]}' at position ${i}` }); i--
    }
  }
  return ops.reverse()
}

// Trusted domains list (shared with backend)
export const TRUSTED_DOMAINS = [
  'google.com','gmail.com','microsoft.com','outlook.com','hotmail.com',
  'amazon.com','apple.com','icloud.com','paypal.com','facebook.com',
  'instagram.com','twitter.com','linkedin.com','github.com','netflix.com',
  'yahoo.com','ebay.com','dropbox.com','adobe.com','zoom.us',
  'slack.com','salesforce.com','bankofamerica.com','chase.com',
]

export function analyzeLocalDomain(domain) {
  domain = domain.toLowerCase()
  if (TRUSTED_DOMAINS.includes(domain)) return { isTrusted: true, domain }

  const results = TRUSTED_DOMAINS.map(td => ({
    trusted: td,
    distance: levenshteinDistance(domain, td),
    similarity: similarityPercent(domain, td),
  })).sort((a, b) => a.distance - b.distance)

  return {
    isTrusted: false,
    domain,
    bestMatch: results[0],
    topMatches: results.slice(0, 5),
  }
}
