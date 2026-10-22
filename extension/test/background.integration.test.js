// Runs the real service worker (background.js) against the real Flask backend.
const test = require('node:test')
const assert = require('node:assert/strict')
const { spawn } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const vm = require('node:vm')

const PORT = 5871
const BACKEND = path.resolve(__dirname, '../../backend')
const EML = fs.readFileSync(path.resolve(__dirname, '../../docs/samples/forged-paypal.eml'), 'utf8')
let server, tmp

function loadWorker(store) {
  const listeners = []
  const chrome = {
    runtime: { onInstalled: { addListener() {} }, onMessage: { addListener: f => listeners.push(f) }, lastError: null },
    storage: { local: {
      get: (keys, cb) => cb(Object.fromEntries([].concat(keys).filter(k => k in store).map(k => [k, store[k]]))),
      set: (o, cb) => { Object.assign(store, o); cb && cb() }, remove: (k, cb) => { [].concat(k).forEach(x => delete store[x]); cb && cb() },
    } },
    identity: {},
  }
  const ctx = vm.createContext({ chrome, fetch, AbortController, setTimeout, clearTimeout, URL, BigInt, console,
    importScripts: f => vm.runInContext(fs.readFileSync(path.resolve(__dirname, '..', f), 'utf8'), ctx), self: null })
  ctx.self = ctx
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, '../background.js'), 'utf8'), ctx)
  return msg => new Promise(resolve => { listeners[0](msg, {}, resolve) })
}

test.before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-ext-'))
  server = spawn(process.env.PYTHON || 'python', ['app.py'], {
    cwd: BACKEND, stdio: 'ignore',
    env: { ...process.env, PG_PORT: String(PORT), PG_WHOIS: 'off', PG_DB: path.join(tmp, 'db.sqlite'), PG_BENCH_DATA: tmp, PG_BENCH_RUNS: tmp },
  })
  for (let i = 0; i < 80; i++) {
    try { if ((await fetch(`http://127.0.0.1:${PORT}/api/health`)).ok) return } catch {}
    await new Promise(r => setTimeout(r, 250))
  }
  throw new Error('backend did not start')
})
test.after(() => { server && server.kill(); try { fs.rmSync(tmp, { recursive: true, force: true }) } catch {} })

const settings = (extra = {}) => ({ apiUrl: `http://127.0.0.1:${PORT}/api`, ...extra })

test('health check succeeds against the real server', async () => {
  const send = loadWorker(settings())
  assert.equal((await send({ type: 'PG_HEALTH' })).ok, true)
})

test('a lookalike-domain phishing message is HIGH', async () => {
  const send = loadWorker(settings())
  const res = await send({ type: 'PG_ANALYZE', payload: {
    sender: '"PayPal Security" <service@paypa1-secure-login.com>', subject: 'Urgent: your account is suspended',
    content: '<p>Dear customer, verify your password immediately: <a href="http://paypa1-secure-login.com/verify">Log in now</a></p>', recipient: 'me@example.com', persist: false } })
  assert.equal(res.ok, true)
  assert.equal(res.result.risk_score, 'HIGH')
  assert.ok(res.result.warnings.length > 0)
})

test('raw message headers are parsed server-side and used', async () => {
  const send = loadWorker(settings())
  const res = await send({ type: 'PG_ANALYZE', raw: EML, payload: { sender: 'x@y.com', subject: '', content: '', recipient: '' } })
  assert.equal(res.ok, true)
  assert.equal(res.usedHeaders, true)
  assert.notEqual(res.result.risk_score, 'LOW')
})

test('persist=false leaves the history empty', async () => {
  const send = loadWorker(settings())
  await send({ type: 'PG_ANALYZE', payload: { sender: 'a@example.org', subject: 'hello', content: 'hi', recipient: '' } })
  const stats = await (await fetch(`http://127.0.0.1:${PORT}/api/stats`)).json()
  assert.equal(stats.total_scans ?? stats.total ?? 0, 0)
})

test('server down is reported as offline', async () => {
  const send = loadWorker({ apiUrl: 'http://127.0.0.1:1/api' })
  const res = await send({ type: 'PG_ANALYZE', payload: { sender: 'a@b.com', subject: '', content: '', recipient: '' } })
  assert.equal(res.ok, false)
  assert.equal(res.offline, true)
})
