import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { createPlugin, DEFAULT_CONFIG } from '../lib/index.js'

// 运行正式宿主产物；仅构造测试上下文、临时数据和真实 PTY，不读取 DSH 用户配置。
// node --no-warnings --loader ./test/fixtures/default-only-pty-loader.mjs scripts/check-local-pty.mjs
if (process.platform === 'win32') throw new Error('本隔离检查使用 /bin/sh，Windows 需要独立的真实 PTY 验收。')
const loaded = await import('node-pty')
assert.equal(typeof loaded.spawn, 'undefined', '请使用上方 default-only 测试加载器运行。')
assert.equal(typeof loaded.default?.spawn, 'function')
const root = await mkdtemp(join(tmpdir(), 'dsh-zterm-local-pty-'))
const config = { ...DEFAULT_CONFIG, allowLocalTerminal: false, maxSessions: 3 }
let revision = 1
const sessionId = 'local-pty-fixture-session', pageId = 'local-pty-fixture-page'
const context = {
  tools: { register() {} }, systemPrompt: { section() {} },
  credentials: { resolve: async () => undefined, describe: async () => ({ configured: false }) },
  sessions: { get: (id) => id === sessionId ? { header: { cwd: root } } : undefined },
  settings: { describe: () => [{ ns: 'zterm', value: config, revision }] },
  connection: { fetch: { register: () => () => {} } },
  inject: (_names, body) => body(context), on() {}, effect: (body) => body(),
}
const plugin = createPlugin(context, {}, { dataRoot: root }), runtime = plugin.runtime
async function waitFor(check, label) {
  const deadline = Date.now() + 8000
  while (!check()) { assert(Date.now() < deadline, `等待超时：${label}`); await delay(25) }
}
const output = (id) => runtime.poll(sessionId, -1).snapshots.find((s) => s.terminalId === id)?.text ?? ''
const lines = (id) => output(id).split(/\r?\n/)
async function ready(id) {
  await waitFor(() => {
    const terminal = runtime.workspace(sessionId).terminals.find((t) => t.id === id)
    assert(terminal?.state !== 'error', terminal?.error)
    return terminal?.state === 'ready'
  }, '真实 Shell 启动')
}
try {
  runtime.attachClient(sessionId, pageId)
  await assert.rejects(runtime.connect(sessionId, { kind: 'local' }), /本地终端尚未启用/)
  config.allowLocalTerminal = true; revision++
  const terminals = await Promise.all(Array.from({ length: 3 }, () => runtime.connect(sessionId, { kind: 'local' })))
  await Promise.all(terminals.map((t) => ready(t.id)))
  assert.equal(new Set(terminals.map((t) => t.id)).size, 3)
  await assert.rejects(runtime.connect(sessionId, { kind: 'local' }), /终端数量已达上限/)
  terminals.forEach((t, index) => runtime.manualInput(sessionId, t.id, t.generation, `ZT_PTY_FIXTURE=${index + 1}\r`))
  const observed = []
  for (const [index, terminal] of terminals.entries()) {
    const prefix = `ZT_PTY_RESULT_${index + 1}:`
    runtime.manualInput(sessionId, terminal.id, terminal.generation, `printf '\\n${prefix}%s:%s\\n' "$$" "$ZT_PTY_FIXTURE"\r`)
    await waitFor(() => lines(terminal.id).some((line) => line.startsWith(prefix)), '真实终端输出')
    const match = lines(terminal.id).find((line) => line.startsWith(prefix)).match(/^ZT_PTY_RESULT_\d+:(\d+):(\d+)$/)
    assert(match, '真实输出未形成预期回执')
    assert.equal(Number(match[2]), index + 1, '不同终端的 Shell 变量应相互独立')
    observed.push({ terminalId: terminal.id, pid: Number(match[1]), value: Number(match[2]) })
  }
  assert.equal(new Set(observed.map((t) => t.pid)).size, 3, '应存在三个不同的真实 Shell 进程')
  const first = terminals[0]
  const resized = await plugin.handler('zterm/resize', { sessionId, pageId, terminalId: first.id, generation: first.generation, cols: 92, rows: 24 }, new AbortController().signal)
  assert.equal(resized.ok, true)
  runtime.manualInput(sessionId, first.id, first.generation, "printf '\\nZT_PTY_SIZE:'; stty size\r")
  await waitFor(() => lines(first.id).includes('ZT_PTY_SIZE:24 92'), 'PTY 行列调整')
  runtime.disconnect(sessionId, terminals[1].id, true)
  assert.equal(runtime.workspace(sessionId).terminals.length, 2)
  const reopened = await runtime.connect(sessionId, { kind: 'local' }); await ready(reopened.id)
  assert(!terminals.some((t) => t.id === reopened.id), '重新打开应创建新终端标识')
  runtime.manualInput(sessionId, reopened.id, reopened.generation, "printf '\\nZT_PTY_REOPEN:%s\\n' \"${ZT_PTY_FIXTURE-unset}\"\r")
  await waitFor(() => lines(reopened.id).includes('ZT_PTY_REOPEN:unset'), '新 Shell 不继承旧终端变量')
  const receipt = { packageVersion: JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version,
    hostSha256: createHash('sha256').update(await readFile(new URL('../lib/index.js', import.meta.url))).digest('hex'),
    checkedAt: new Date().toISOString(), platform: process.platform, node: process.version,
    defaultOnlyExport: true, nativePty: true, observed, independentVariables: true, resize: { cols: 92, rows: 24 },
    limitEnforced: true, closeAndReopen: true, reopenedTerminalId: reopened.id, userConfigurationLoaded: false }
  await mkdir(new URL('../out/', import.meta.url), { recursive: true })
  await writeFile(new URL('../out/local-pty-check.json', import.meta.url), `${JSON.stringify(receipt, null, 2)}\n`)
  console.log(JSON.stringify(receipt))
} finally {
  runtime.dispose(); await delay(150); await rm(root, { recursive: true, force: true })
}
