// PhishGuard Spam Detection — runs entirely in-browser, no server needed.
// Scores email subject + body preview using 4 signals:
//   1. Spam keyword density
//   2. ALL CAPS ratio
//   3. Exclamation mark density
//   4. Bulk sender header patterns

const SPAM_KEYWORDS = [
  // Urgency / pressure
  'urgent', 'act now', 'action required', 'immediately', 'don\'t delay',
  'limited time', 'expires soon', 'last chance', 'today only', 'offer ends',
  'respond now', 'before it\'s too late',

  // Prize / lottery scams
  'you have won', 'you\'ve won', 'winner', 'prize', 'free gift', 'claim your',
  'congratulations', 'you\'ve been selected', 'lucky winner', 'jackpot',
  'lottery', 'sweepstakes', 'giveaway',

  // Financial fraud
  'wire transfer', 'bank account', 'credit card', 'social security',
  'billing information', 'update your payment', 'payment failed',
  'invoice attached', 'outstanding balance', 'debt collection',
  'make money fast', 'earn $', 'extra income', 'work from home',
  'financial freedom', 'investment opportunity', 'double your money',

  // Health / pharma spam
  'lose weight', 'weight loss', 'diet pill', 'miracle cure', 'fda approved',
  'no prescription', 'cheap meds', 'viagra', 'cialis',

  // Clickbait / engagement bait
  'click here', 'click now', 'click below', 'click the link',
  'open now', 'see inside', 'check this out', 'don\'t miss',
  'read more', 'view now', 'watch now',

  // Identity phishing
  'verify your account', 'confirm your identity', 'account suspended',
  'account on hold', 'security alert', 'unusual activity',
  'login attempt', 'reset your password', 'update your info',
  'dear customer', 'dear user', 'dear valued member', 'dear account holder',

  // Marketing spam
  'unsubscribe', 'opt out', 'you are receiving this',
  'this is not spam', 'remove me', 'this email was sent to',
  '100% free', 'no cost', 'risk-free', 'guaranteed', 'no obligation',
  'satisfaction guaranteed', 'money back',

  // Suspicious offers
  'as seen on', 'as seen on tv', 'order now', 'buy now', 'shop now',
  'discount', 'exclusive deal', 'special offer', 'best price',
]

const BULK_HEADERS = [
  'unsubscribe', 'opt-out', 'opt out',
  'this email was sent', 'you are receiving this email because',
  'to unsubscribe', 'manage preferences', 'email preferences',
  'view in browser', 'view this email in your browser',
  'add us to your address book', 'list-unsubscribe',
]

// Extract subject and preview from a Gmail list-row element
function extractGmailContext(rowEl) {
  if (!rowEl) return { subject: '', preview: '' }

  // Subject selectors Gmail uses
  const subjectEl = (
    rowEl.querySelector('.bog') ||
    rowEl.querySelector('.y6 span') ||
    rowEl.querySelector('[data-thread-id] .y6')
  )

  // Preview / snippet
  const previewEl = (
    rowEl.querySelector('.y2') ||
    rowEl.querySelector('.Zt')
  )

  // If email is open, also grab full subject and body
  const openSubject = document.querySelector('h2.hP')
  const openBody    = document.querySelector('.a3s.aiL') || document.querySelector('.ii.gt')

  return {
    subject: openSubject?.textContent || subjectEl?.textContent || '',
    preview: openBody?.innerText?.slice(0, 500) || previewEl?.textContent || '',
  }
}

function analyzeSpam(subject, preview) {
  const text  = (subject + ' ' + preview).toLowerCase()

  if (!text.trim()) return { spamScore: 0, spamLevel: 'UNKNOWN', signals: [] }

  const signals  = []
  let   spamScore = 0

  // ── 1. Spam keyword matches ───────────────────────────────────────────────
  const hitKeywords = SPAM_KEYWORDS.filter(kw => text.includes(kw))
  if (hitKeywords.length > 0) {
    const pts = Math.min(hitKeywords.length * 10, 40)
    spamScore += pts
    signals.push({
      type:     'SPAM_KEYWORDS',
      severity: hitKeywords.length >= 3 ? 'HIGH' : 'MEDIUM',
      message:  `${hitKeywords.length} spam keyword(s) detected`,
      detail:   hitKeywords.slice(0, 4).map(k => `"${k}"`).join(', '),
    })
  }

  // ── 2. ALL CAPS ratio ─────────────────────────────────────────────────────
  const allWords   = subject.split(/\s+/).filter(w => w.length > 2)
  const capsWords  = allWords.filter(w => w === w.toUpperCase() && /[A-Z]/.test(w))
  const capsRatio  = allWords.length > 0 ? capsWords.length / allWords.length : 0
  if (capsRatio >= 0.4) {
    const pts = Math.round(capsRatio * 25)
    spamScore += pts
    signals.push({
      type:     'EXCESSIVE_CAPS',
      severity: capsRatio >= 0.6 ? 'HIGH' : 'MEDIUM',
      message:  `${Math.round(capsRatio * 100)}% of subject words are ALL CAPS`,
      detail:   `Spammers use caps to create false urgency`,
    })
  }

  // ── 3. Exclamation mark density ───────────────────────────────────────────
  const exclamations = (subject.match(/!/g) || []).length
  if (exclamations >= 2) {
    const pts = Math.min(exclamations * 5, 20)
    spamScore += pts
    signals.push({
      type:     'EXCESSIVE_EXCLAMATIONS',
      severity: exclamations >= 4 ? 'HIGH' : 'MEDIUM',
      message:  `${exclamations} exclamation mark(s) in subject line`,
      detail:   `Aggressive punctuation is a classic spam pattern`,
    })
  }

  // ── 4. Bulk sender patterns ───────────────────────────────────────────────
  const bulkHits = BULK_HEADERS.filter(h => text.includes(h))
  if (bulkHits.length > 0) {
    spamScore += 15
    signals.push({
      type:     'BULK_SENDER',
      severity: 'MEDIUM',
      message:  'Bulk/marketing email patterns detected',
      detail:   `Contains: "${bulkHits[0]}"`,
    })
  }

  // ── 5. URL density in preview ─────────────────────────────────────────────
  const urlCount = (preview.match(/https?:\/\//gi) || []).length
  if (urlCount >= 3) {
    spamScore += Math.min(urlCount * 4, 15)
    signals.push({
      type:     'HIGH_URL_DENSITY',
      severity: 'MEDIUM',
      message:  `${urlCount} URLs found in email body`,
      detail:   'High link density is a common spam indicator',
    })
  }

  spamScore = Math.min(spamScore, 100)
  const spamLevel = spamScore >= 60 ? 'HIGH' : spamScore >= 30 ? 'MEDIUM' : 'LOW'

  return { spamScore, spamLevel, signals, keywords: hitKeywords }
}
