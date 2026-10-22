const test = require('node:test')
const assert = require('node:assert/strict')
const PG = require('../api.js')

test('normalizeApiUrl accepts https and local http only', () => {
  assert.equal(PG.normalizeApiUrl('http://localhost:5000/api/'), 'http://localhost:5000/api')
  assert.equal(PG.normalizeApiUrl('http://127.0.0.1:5000'), 'http://127.0.0.1:5000/api')
  assert.equal(PG.normalizeApiUrl('https://pg.example.com/api'), 'https://pg.example.com/api')
  assert.equal(PG.normalizeApiUrl('http://pg.example.com/api'), null)
  assert.equal(PG.normalizeApiUrl('https://user:pw@pg.example.com/api'), null)
  assert.equal(PG.normalizeApiUrl('javascript:alert(1)'), null)
  assert.equal(PG.normalizeApiUrl(''), null)
  assert.equal(PG.normalizeApiUrl(undefined), null)
})

test('originPattern and isLocalApi', () => {
  assert.equal(PG.originPattern('https://pg.example.com:8443/api'), 'https://pg.example.com:8443/*')
  assert.ok(PG.isLocalApi('http://localhost:5000/api'))
  assert.ok(!PG.isLocalApi('https://pg.example.com/api'))
  assert.ok(!PG.isLocalApi('not a url'))
})

test('formatSender', () => {
  assert.equal(PG.formatSender('A@B.com', 'Pay Pal'), '"Pay Pal" <a@b.com>')
  assert.equal(PG.formatSender('a@b.com', ''), 'a@b.com')
  assert.equal(PG.formatSender('a@b.com', 'a@b.com'), 'a@b.com')
  assert.equal(PG.formatSender('a@b.com', 'Evil" <x@y.com'), '"Evil x@y.com" <a@b.com>')
})

test('accountFromTitle', () => {
  assert.equal(PG.accountFromTitle('Inbox (3) - Me.Name+x@Example.co.uk - Gmail'), 'me.name+x@example.co.uk')
  assert.equal(PG.accountFromTitle('Gmail'), '')
})

test('buildPayload bounds and prefers html', () => {
  const p = PG.buildPayload({ email: 'a@b.com', subject: 's'.repeat(900), html: '<p>x</p>'.repeat(20000), text: 'plain' })
  assert.equal(p.subject.length, 500)
  assert.equal(p.content.length, 60000)
  assert.ok(p.content.startsWith('<p>'))
  assert.equal(p.persist, false)
  assert.equal(PG.buildPayload({ email: 'a@b.com', text: 'hi' }).content, 'hi')
})

test('message id conversion and original URL', () => {
  assert.equal(PG.messageIdToDecimal('ff'), null)           // too short to be a Gmail id
  assert.equal(PG.messageIdToDecimal('18c3a4f5b6d7e8f9'), BigInt('0x18c3a4f5b6d7e8f9').toString())
  assert.equal(PG.messageIdToDecimal('zzzzzzzz'), null)
  assert.equal(PG.messageIdToDecimal(''), null)
  const url = PG.originalMessageUrl('https://mail.google.com', '/mail/u/2/', '18c3a4f5b6d7e8f9')
  assert.equal(url, 'https://mail.google.com/mail/u/2/?view=om&permmsgid=msg-f%3A1783690113213802745'.replace('1783690113213802745', BigInt('0x18c3a4f5b6d7e8f9').toString()))
  assert.ok(PG.originalMessageUrl('https://mail.google.com', '/', '18c3a4f5b6d7e8f9').includes('/mail/u/0/'))
  assert.equal(PG.originalMessageUrl('https://mail.google.com', '/mail/u/0/', 'nope'), null)
})

test('looksLikeRawEmail', () => {
  assert.ok(PG.looksLikeRawEmail('Delivered-To: me@x.com\nReceived: by a\nFrom: A <a@b.com>\nSubject: hi\n\nbody body body'))
  assert.ok(!PG.looksLikeRawEmail('<!DOCTYPE html><html><body>Sign in to Gmail ................</body></html>'))
  assert.ok(!PG.looksLikeRawEmail('short'))
  assert.ok(!PG.looksLikeRawEmail(null))
})

test('topFindings sorts by severity and drops the verified-domain note', () => {
  const result = { warnings: [
    { severity: 'LOW', message: 'c' }, { severity: 'HIGH', message: 'a' },
    { severity: 'MEDIUM', message: 'b' }, { severity: 'LOW', type: 'TRUSTED_VERIFIED', message: 'ok' }, { severity: 'HIGH' },
  ] }
  assert.deepEqual(PG.topFindings(result).map(w => w.message), ['a', 'b', 'c'])
  assert.equal(PG.topFindings(result, 1).length, 1)
  assert.deepEqual(PG.topFindings(null), [])
})

test('verdict and summarize', () => {
  assert.equal(PG.verdict({ risk_score: 'HIGH' }).headline, 'Likely phishing')
  assert.equal(PG.verdict({ risk_score: 'MEDIUM' }).level, 'MEDIUM')
  assert.equal(PG.verdict({}).level, 'LOW')
  const s = PG.summarize({ domain: 'x.com', risk_score: 'HIGH', risk_level: 80, warnings: [{ severity: 'HIGH', message: 'm', detail: 'd' }] }, 'a@x.com')
  assert.equal(s.safe, false)
  assert.equal(s.source, 'server')
  assert.deepEqual(s.warnings, [{ severity: 'HIGH', message: 'm' }])
})

test('limitRaw caps size', () => {
  assert.equal(PG.limitRaw('x'.repeat(3000000)).length, 2000000)
})

test('shapePath is a closed path inside the unit circle', () => {
  for (const d of [PG.shapePath(), PG.shapePath(12, 0.14, true), PG.levelShape('HIGH'), PG.levelShape('LOW')]) {
    assert.match(d, /^M[-\d. L]+Z$/)
    const nums = d.slice(1, -1).split(/[L ]/).map(Number)
    assert.ok(nums.every(n => Number.isFinite(n) && Math.abs(n) <= 1.0001))
  }
  assert.notEqual(PG.levelShape('HIGH'), PG.levelShape('LOW'))
})
