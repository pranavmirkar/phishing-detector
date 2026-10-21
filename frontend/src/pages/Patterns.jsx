const PATTERNS = [
  {
    type: 'Digit Substitution',
    name: 'Leet-speak Attack',
    desc: 'Letters replaced with visually similar digits. Extremely common — attackers exploit fast reading habits.',
    examples: [
      { fake: 'g00gle.com',   real: 'google.com',    dist: 2, level: 'high' },
      { fake: 'amaz0n.com',   real: 'amazon.com',    dist: 1, level: 'high' },
      { fake: 'micr0soft.com',real: 'microsoft.com', dist: 1, level: 'high' },
    ],
  },
  {
    type: 'Letter Substitution',
    name: 'Homograph Attack',
    desc: 'Visually identical letters swapped — often lowercase L for digit 1, or capital I for lowercase l.',
    examples: [
      { fake: 'paypa1.com',   real: 'paypal.com',   dist: 1, level: 'high' },
      { fake: 'appIe.com',    real: 'apple.com',    dist: 1, level: 'high' },
      { fake: 'linkedln.com', real: 'linkedin.com', dist: 1, level: 'high' },
    ],
  },
  {
    type: 'Character Insertion',
    name: 'Typosquatting',
    desc: 'Extra characters inserted into a trusted brand name. Users misread or fail to notice the extra letter.',
    examples: [
      { fake: 'microsofft.com', real: 'microsoft.com', dist: 1, level: 'high' },
      { fake: 'googgle.com',    real: 'google.com',    dist: 1, level: 'high' },
      { fake: 'paypall.com',    real: 'paypal.com',    dist: 1, level: 'high' },
    ],
  },
  {
    type: 'Character Deletion',
    name: 'Missing Letter',
    desc: 'A letter is removed from a trusted domain name — easy to miss at a glance, especially in longer domains.',
    examples: [
      { fake: 'micosoft.com',  real: 'microsoft.com', dist: 2, level: 'high' },
      { fake: 'gogle.com',     real: 'google.com',    dist: 1, level: 'high' },
      { fake: 'amazn.com',     real: 'amazon.com',    dist: 1, level: 'high' },
    ],
  },
  {
    type: 'TLD Swapping',
    name: 'Wrong Extension',
    desc: 'Attacker registers the same brand name with a different top-level domain (.net, .org, .info).',
    examples: [
      { fake: 'google.net',     real: 'google.com',    dist: 3, level: 'med' },
      { fake: 'microsoft.org',  real: 'microsoft.com', dist: 3, level: 'med' },
      { fake: 'paypal.info',    real: 'paypal.com',    dist: 4, level: 'med' },
    ],
  },
  {
    type: 'Unicode Homoglyph',
    name: 'Invisible Unicode Attack',
    desc: 'Cyrillic or other Unicode characters that look pixel-perfect identical to Latin letters. Bypasses naive string comparison — Levenshtein works after normalization.',
    examples: [
      { fake: 'раурal.com',  real: 'paypal.com',    dist: 2, level: 'high', note: 'Cyrillic р,а' },
      { fake: 'gооgle.com',  real: 'google.com',    dist: 2, level: 'high', note: 'Cyrillic о,о' },
      { fake: 'аmazon.com',  real: 'amazon.com',    dist: 1, level: 'high', note: 'Cyrillic а' },
    ],
  },
  {
    type: 'Subdomain Abuse',
    name: 'Brand in Subdomain',
    desc: 'Attacker puts a trusted brand name in the subdomain. The actual registered domain is different — and attacker-controlled.',
    examples: [
      { fake: 'paypal.com.verify.ru',   real: 'paypal.com', dist: 0, level: 'high', note: 'Actual: verify.ru' },
      { fake: 'apple.com.support.tk',   real: 'apple.com',  dist: 0, level: 'high', note: 'Actual: support.tk' },
      { fake: 'amazon.com.deals.xyz',   real: 'amazon.com', dist: 0, level: 'high', note: 'Actual: deals.xyz' },
    ],
  },
  {
    type: 'Transposition',
    name: 'Swapped Letters',
    desc: 'Two adjacent characters are swapped — exploits fast reading where the brain auto-corrects familiar words.',
    examples: [
      { fake: 'googel.com',  real: 'google.com',  dist: 2, level: 'high' },
      { fake: 'amaozn.com',  real: 'amazon.com',  dist: 2, level: 'high' },
      { fake: 'microsft.com',real: 'microsoft.com',dist: 2, level: 'high' },
    ],
  },
]

function PatternCard({ p }) {
  return (
    <div className="pattern-card">
      <p className="pattern-type">{p.type}</p>
      <p className="pattern-name">{p.name}</p>
      <p className="pattern-desc">{p.desc}</p>
      <div className="pattern-examples">
        {p.examples.map((ex, i) => (
          <div className="pattern-ex-row" key={i}>
            <span className="pattern-fake">{ex.fake}</span>
            <span className="pattern-arrow">→</span>
            <span className="pattern-real">{ex.real}</span>
            {ex.note && <span className="pattern-arrow">({ex.note})</span>}
            <span className="pattern-dist">
              <span className={`dist-tag ${ex.level}`}>d={ex.dist}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function Patterns() {
  return (
    <>
      <header className="page-hd">
        <div>
          <h1 className="page-title">Attack patterns</h1>
          <p className="page-sub">Common lookalike-domain techniques and how edit distance detects them.</p>
        </div>
      </header>

      {/* Algorithm explainer */}
      <div className="card explainer-card">
        <div className="card-body">
          <div>
            <h3>
              How Levenshtein distance works
            </h3>
            <p>
              The algorithm fills a dynamic programming table where each cell <code className="inline-code">dp[i][j]</code> contains
              the minimum edits to convert the first <em>i</em> characters of the suspicious domain
              into the first <em>j</em> characters of the trusted domain.
            </p>
            <div className="threshold-list">
              {[
                { cls: 'd0', label: 'dist 0',   desc: 'Exact match: trusted' },
                { cls: 'd1', label: 'dist 1–2', desc: 'Lookalike: high risk' },
                { cls: 'd2', label: 'dist 3–4', desc: 'Similar: needs review' },
                { cls: 'd3', label: 'dist 5+',  desc: 'Low similarity: likely unrelated' },
              ].map(r => (
                <div className="threshold-row" key={r.cls}>
                  <span className={`dist-pill ${r.cls}`}>{r.label}</span>
                  <span>{r.desc}</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h3>
              Examples
            </h3>
            <div className="ex-list">
              {[
                { fake: <>g<mark>0</mark><mark>0</mark>gle.com</>, real: 'google.com', dist: 2, level: 'high' },
                { fake: <>amaz<mark>0</mark>n.com</>,             real: 'amazon.com', dist: 1, level: 'high' },
                { fake: <>paypa<mark>1</mark>.com</>,             real: 'paypal.com', dist: 1, level: 'high' },
                { fake: <>app<mark>I</mark>e.com</>,              real: 'apple.com',  dist: 1, level: 'high' },
              ].map((ex, i) => (
                <div className="ex-row" key={i}>
                  <code className="ex-domain">{ex.fake}</code>
                  <span className="ex-arrow">→</span>
                  <code className="ex-trusted">{ex.real}</code>
                  <span className={`ex-d ${ex.level}`}>d={ex.dist}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="patterns-grid">
        {PATTERNS.map((p, i) => <PatternCard key={i} p={p} />)}
      </div>
    </>
  )
}
