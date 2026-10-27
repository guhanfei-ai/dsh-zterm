// issue #3 排查产出的回归测试：工具执行期间宿主事件循环必须保持可调度，
// 执行标识按行追加而不是每次调用全量重写，长操作有 >2s 进度文案。
// 判别实验数据见 _tacp/20261027-* 留言。
import { describe, it, expect, vi, afterEach } from 'vitest'
import { monitorEventLoopDelay } from 'node:perf_hooks'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TerminalSession } from '../src/core/terminalSessionManager'
import { TerminalBridge } from '../src/core/terminalBridge'
import { ZtermRuntime } from '../src/host/runtime'
import { RecordStore } from '../src/host/store'
import { DEFAULT_CONFIG } from '../src/host/config'
import { progressElapsed } from '../src/client/api'
import type { Config, HostTarget } from '../src/shared/types'

class FakeTerminal extends TerminalSession {
  inputs: string[] = []
  async connect(options: any) { this.connected = true; this.currentHost = options; this.verifiedHostKey = { algorithm: 'ssh-ed25519', fingerprint: `SHA256:${'A'.repeat(43)}` } }
  async openShell() {}
  isShellReady() { return this.connected }
  write(value: string) { this.inputs.push(value) }
  disconnect() { this.connected = false; this.emit('closed') }
}
const owned: Array<{ root: string; runtime: ZtermRuntime }> = []
afterEach(() => { vi.restoreAllMocks(); for (const fixture of owned.splice(0)) { fixture.runtime.dispose(); rmSync(fixture.root, { recursive: true, force: true }) } })
const host: HostTarget = { id: 'h1', label: '测试主机', kind: 'ssh', host: 'host.example.invalid', port: 22, username: 'operator', authType: 'password', credentialRef: 'DSH_ZTERM_TEST_PASSWORD' }
async function setup(patch: Partial<Config> = {}) {
  const root = mkdtempSync(join(tmpdir(), 'dsh-zterm-event-loop-')), config = { ...DEFAULT_CONFIG, hosts: [host], ...patch }
  const runtime = new ZtermRuntime({ config: () => config, credentials: { resolve: async () => ({ value: 'test-secret-value' }) }, store: new RecordStore(root), sessionCwd: () => root,
    terminalFactory: (id, generation) => new FakeTerminal(id, generation) })
  owned.push({ root, runtime }); const terminal = await runtime.connect('s1', { targetId: 'h1' })
  await vi.waitFor(() => expect(runtime.workspace('s1').terminals[0].state).toBe('ready'))
  runtime.bind('s1', terminal.id, terminal.generation)
  return { root, runtime, terminal, config }
}

describe('issue#3 事件循环与记录写入回归', () => {
  it('执行标识按行追加：每次调用 O(1) 写入，旧 calls.json 仍可合并读取', () => {
    const root = mkdtempSync(join(tmpdir(), 'dsh-zterm-calls-'))
    try {
      const store = new RecordStore(root)
      const legacy = join(root, `${createHash('sha256').update('s1').digest('hex')}.calls.json`)
      writeFileSync(legacy, JSON.stringify(['legacy-call']))
      store.addCall('s1', 'call-1'); store.addCall('s1', 'call-2')
      const journal = join(root, `${createHash('sha256').update('s1').digest('hex')}.calls.jsonl`)
      // 每个标识一行：追加日志不能是整集合重写。
      expect(readFileSync(journal, 'utf8').trim().split('\n')).toEqual([JSON.stringify('call-1'), JSON.stringify('call-2')])
      store.addCall('s1', 'call-2')
      expect([...store.calls('s1')].sort()).toEqual(['call-1', 'call-2', 'legacy-call'])
      // 末尾半行（宿主崩溃）只丢该标识，不能让整个会话不可用。
      writeFileSync(journal, readFileSync(journal, 'utf8') + '{"trunca', { mode: 0o600 })
      expect([...store.calls('s1')].sort()).toEqual(['call-1', 'call-2', 'legacy-call'])
      expect(() => store.addCall('s1', 'x'.repeat(257))).toThrow('执行标识记录无效')
    } finally { rmSync(root, { recursive: true, force: true }) }
  })

  it('长调用 + 2MB 重输出期间事件循环最大阻塞保持在毫秒级', async () => {
    const { root, runtime, terminal } = await setup()
    runtime.setMode('s1', terminal.id, 1, 'readwrite')
    let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve })
    vi.spyOn(TerminalBridge.prototype, 'executeAgentCommand').mockImplementation(async () => {
      await gate; return { command: 'x', completion: 'verified' as const, commandSent: true, exitCode: 0, output: 'ok', duration: 1 }
    })
    const running = runtime.execute('s1', { callId: 'long-call' }, 'zterm_execute', 'printf run')
    await vi.waitFor(() => expect(vi.mocked(TerminalBridge.prototype.executeAgentCommand)).toHaveBeenCalled())
    const fake = (runtime as any).states.get('s1').entries.get(terminal.id).terminal
    const histogram = monitorEventLoopDelay({ resolution: 5 }); histogram.enable()
    const chunk = Buffer.from('A'.repeat(32 * 1024))
    for (let i = 0; i < 64; i++) {
      fake.emit('data', chunk)
      for (let j = 0; j < 3; j++) { runtime.workspace('s1'); runtime.records('s1', 200) }
      if (i % 8 === 0) await new Promise((resolve) => setTimeout(resolve, 1))
    }
    release(); await running
    histogram.disable()
    const maxDelayMs = histogram.max / 1e6
    // 实测约 5ms（issue #3 基准）；上限放宽到 250ms 以容忍慢速 CI 机器。
    expect(maxDelayMs).toBeLessThan(250)
    expect(runtime.records('s1')[0].status).toBe('completed')
    // 每次调用只追加执行标识日志，不随集合增长重写全量文件。
    const journal = join(root, `${createHash('sha256').update('s1').digest('hex')}.calls.jsonl`)
    expect(existsSync(journal)).toBe(true)
    expect(readFileSync(journal, 'utf8').trim().split('\n')).toEqual([JSON.stringify('long-call')])
  }, 30000)

  it('长操作超过 2 秒给出已用时进度文案，短操作不打扰', () => {
    const now = Date.parse('2026-10-27T12:00:30.000Z')
    expect(progressElapsed('2026-10-27T12:00:29.000Z', now)).toBeUndefined()
    expect(progressElapsed('2026-10-27T12:00:28.000Z', now)).toBe('已 2 秒')
    expect(progressElapsed('2026-10-27T11:59:25.000Z', now)).toBe('已 1 分 5 秒')
    expect(progressElapsed(undefined, now)).toBeUndefined()
    expect(progressElapsed('not-a-time', now)).toBeUndefined()
  })
})
