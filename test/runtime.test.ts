import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TerminalSession } from '../src/core/terminalSessionManager'
import { TerminalBridge } from '../src/core/terminalBridge'
import { ZtermRuntime } from '../src/host/runtime'
import { RecordStore } from '../src/host/store'
import { DEFAULT_CONFIG } from '../src/host/config'
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
  const root = mkdtempSync(join(tmpdir(), 'dsh-zterm-runtime-')), config = { ...DEFAULT_CONFIG, hosts: [host], ...patch }
  const runtime = new ZtermRuntime({ config: () => config, credentials: { resolve: async () => ({ value: 'test-secret-value' }) }, store: new RecordStore(root), sessionCwd: () => root,
    terminalFactory: (id, generation) => new FakeTerminal(id, generation) })
  owned.push({ root, runtime }); const terminal = await runtime.connect('s1', { targetId: 'h1' })
  await vi.waitFor(() => expect(runtime.workspace('s1').terminals[0].state).toBe('ready'))
  runtime.bind('s1', terminal.id, terminal.generation)
  return { root, runtime, terminal, config }
}
function verified() {
  return vi.spyOn(TerminalBridge.prototype, 'executeAgentCommand').mockImplementation(async (command, _timeout, _signal, authorize) => authorize && !authorize()
    ? { command, completion: 'aborted', commandSent: false, authorizationDenied: true, output: '', duration: 0 }
    : { command, completion: 'verified', commandSent: true, exitCode: 0, output: 'observed', duration: 1 })
}
describe('DSH 终端授权与执行协调', () => {
  it('默认只读在执行边界拒绝通用命令，不调用终端', async () => {
    const { runtime } = await setup(), spy = verified()
    const result = await runtime.execute('s1', { callId: 'call1' }, 'zterm_execute', 'printf ok')
    expect(result.details.error).toBe('permission_denied'); expect(spy).not.toHaveBeenCalled(); expect(runtime.records('s1')[0].status).toBe('blocked')
  })
  it('手工开启后可连续执行，重复调用不会再下发', async () => {
    const { runtime, terminal } = await setup(), spy = verified()
    runtime.setMode('s1', terminal.id, 1, 'readwrite')
    await runtime.execute('s1', { callId: 'call1' }, 'zterm_execute', 'printf one')
    await runtime.execute('s1', { callId: 'call2' }, 'zterm_execute', 'printf two')
    await runtime.execute('s1', { callId: 'call1' }, 'zterm_execute', 'printf altered')
    expect(spy).toHaveBeenCalledTimes(2); expect(runtime.workspace('s1').binding?.writeCalls).toBe(2)
    expect(runtime.records('s1').map((r) => r.status)).toEqual(['completed', 'completed'])
  })
  it('等待发送时撤销，再开启也不能复活旧调用', async () => {
    const { runtime, terminal } = await setup(); runtime.setMode('s1', terminal.id, 1, 'readwrite')
    let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve })
    const spy = vi.spyOn(TerminalBridge.prototype, 'executeAgentCommand').mockImplementation(async (command, _timeout, _signal, authorize) => {
      await gate; return { command, completion: 'aborted', commandSent: authorize!(), authorizationDenied: !authorize!(), output: '', duration: 1 }
    })
    const running = runtime.execute('s1', { callId: 'old-call' }, 'zterm_execute', 'printf old')
    await vi.waitFor(() => expect(spy).toHaveBeenCalled())
    runtime.setMode('s1', terminal.id, 1, 'read'); runtime.setMode('s1', terminal.id, 1, 'readwrite'); release(); await running
    expect(runtime.records('s1')[0].status).toBe('not_sent')
  })
  it('写模式也保留命令限制，未知脚本不下发', async () => {
    const { runtime, terminal } = await setup(), spy = verified(); runtime.setMode('s1', terminal.id, 1, 'readwrite')
    const result = await runtime.execute('s1', { callId: 'blocked' }, 'zterm_execute', 'sh -c "printf bypass"')
    expect(result.details.error).toBe('command_blocked'); expect(spy).not.toHaveBeenCalled()
  })
  it('换目标、重连与刷新均不继承写权限；绑定原目标不续期', async () => {
    const { runtime, terminal } = await setup(); runtime.attachClient('s1', 'page1'); runtime.setMode('s1', terminal.id, 1, 'readwrite')
    runtime.bind('s1', terminal.id, 1); expect(runtime.workspace('s1').binding?.mode).toBe('readwrite')
    runtime.attachClient('s1', 'page2'); expect(runtime.workspace('s1').binding?.mode).toBe('read'); expect(() => runtime.assertClient('s1', 'page1')).toThrow('客户端已变化')
    const second = await runtime.connect('s1', { targetId: 'h1' }); await vi.waitFor(() => expect(runtime.workspace('s1').terminals[1].state).toBe('ready'))
    runtime.bind('s1', second.id, 1); expect(runtime.workspace('s1').binding?.mode).toBe('read')
    await runtime.reconnect('s1', second.id); expect(runtime.workspace('s1').binding).toBeUndefined()
    expect(runtime.workspace('s1').terminals[1].generation).toBe(2)
  })
  it('终端属于会话，AI 不能借另一会话的 ID 绑定或写入', async () => {
    const { runtime, terminal } = await setup()
    expect(() => runtime.bind('s2', terminal.id, 1)).toThrow('不属于当前会话')
    expect(() => runtime.manualInput('s2', terminal.id, 1, 'echo x')).toThrow('不属于当前会话')
  })
  it('手工输入撤销读写并要求人类确认回到 Shell', async () => {
    const { runtime, terminal } = await setup(); runtime.setMode('s1', terminal.id, 1, 'readwrite')
    runtime.manualInput('s1', terminal.id, 1, 'vim file\r')
    expect(runtime.workspace('s1').binding?.mode).toBe('read'); expect(runtime.workspace('s1').terminals[0].agentReady).toBe(false)
    expect(() => runtime.setMode('s1', terminal.id, 1, 'readwrite')).toThrow('未处于可执行状态')
    runtime.acknowledgeShell('s1', terminal.id, 1); expect(runtime.workspace('s1').terminals[0].agentReady).toBe(true)
  })
  it('结果不明会隔离真实终端，不能靠模式或绑定解除', async () => {
    const { runtime, terminal } = await setup(); runtime.setMode('s1', terminal.id, 1, 'readwrite')
    vi.spyOn(TerminalBridge.prototype, 'executeAgentCommand').mockImplementation(async (command) => ({ command, completion: 'timedOut', commandSent: true, output: 'partial', duration: 1 }))
    await runtime.execute('s1', { callId: 'unknown' }, 'zterm_execute', 'printf x')
    expect(runtime.records('s1')[0].status).toBe('unknown'); expect(runtime.workspace('s1').terminals[0].uncertain).toBe(true)
    expect(() => runtime.acknowledgeShell('s1', terminal.id, 1)).toThrow('重建')
    expect(() => runtime.bind('s1', terminal.id, 1)).toThrow()
  })
  it('每次人类授权有命令预算，同目标重绑定不能重置', async () => {
    const { runtime, terminal } = await setup({ maxWriteCalls: 1 }), spy = verified(); runtime.setMode('s1', terminal.id, 1, 'readwrite')
    await runtime.execute('s1', { callId: 'once' }, 'zterm_execute', 'printf one'); runtime.bind('s1', terminal.id, 1)
    const denied = await runtime.execute('s1', { callId: 'twice' }, 'zterm_execute', 'printf two')
    expect(denied.details.error).toBe('budget_exhausted'); expect(spy).toHaveBeenCalledTimes(1)
  })
  it('输出包含已知凭据时在记录和工具结果中脱敏', async () => {
    const { runtime, terminal } = await setup(); runtime.setMode('s1', terminal.id, 1, 'readwrite')
    vi.spyOn(TerminalBridge.prototype, 'executeAgentCommand').mockImplementation(async (command) => ({ command, completion: 'verified', commandSent: true, exitCode: 0, output: 'value=test-secret-value', duration: 1 }))
    const result = await runtime.execute('s1', { callId: 'redact' }, 'zterm_execute', 'printf ok')
    expect(JSON.stringify(result)).not.toContain('test-secret-value'); expect(JSON.stringify(runtime.records('s1'))).not.toContain('test-secret-value')
  })
  it('并发建连仍遵守终端总数上限', async () => {
    const { runtime } = await setup({ maxSessions: 2 })
    const results = await Promise.allSettled([runtime.connect('s1', { targetId: 'h1' }), runtime.connect('s1', { targetId: 'h1' })])
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1)
    expect(runtime.workspace('s1').terminals).toHaveLength(2)
  })
  it('断开等待指纹的终端后不遗留确认请求', async () => {
    const { runtime, terminal } = await setup()
    const entry = (runtime as any).states.get('s1').entries.get(terminal.id)
    entry.trust = { kind: 'changed', host: host.host, port: 22 }
    runtime.disconnect('s1', terminal.id)
    expect(runtime.workspace('s1').terminals[0].trust).toBeUndefined()
  })
  it('恢复部分列表失败仍保留原始目标列表', async () => {
    const { runtime, terminal, root } = await setup(), targets = [{ targetId: 'h1' }, { targetId: 'missing' }]
    runtime.disconnect('s1', terminal.id, true)
    new RecordStore(root).saveWorkspace('s1', targets)
    await expect(runtime.restoreWorkspace('s1')).rejects.toThrow('未配置')
    expect(runtime.savedWorkspace('s1')).toEqual(targets)
  })
  it('已执行操作的记录保存失败会明确失败并释放占用', async () => {
    const { runtime, terminal } = await setup(); runtime.setMode('s1', terminal.id, 1, 'readwrite'); verified()
    const store = (runtime as any).deps.store as RecordStore
    vi.spyOn(store, 'append').mockImplementationOnce(() => {}).mockImplementationOnce(() => { throw new Error('test disk failure') })
    await expect(runtime.execute('s1', { callId: 'storage-failure' }, 'zterm_execute', 'printf ok')).rejects.toThrow('操作记录保存失败')
    expect(runtime.workspace('s1').terminals[0].busy).toBe(false)
    expect(runtime.records('s1')[0].status).toBe('completed')
  })
  it('客户端输出保留 SSH 数据包边界拆开的中文 UTF-8', async () => {
    const { runtime, terminal } = await setup(), entry = (runtime as any).states.get('s1').entries.get(terminal.id), bytes = Buffer.from('机器状态正常')
    for (let i = 0; i < bytes.length; i += 2) entry.terminal.emit('data', bytes.subarray(i, i + 2))
    expect(runtime.poll('s1', 0).output.map((frame) => frame.text).join('')).toBe('机器状态正常')
  })
  it('多条大记录不会使轮询或模型结果无限放大，标记传输截断', async () => {
    const { runtime } = await setup(), state = (runtime as any).states.get('s1')
    state.operations = Array.from({ length: 100 }, (_, i) => ({ id: String(i), label: 'command', command: 'printf x', output: 'x'.repeat(64000), status: 'completed', truncated: false }))
    const size = (records: any[]) => records.reduce((sum, record) => sum + (record.output?.length ?? 0) + (record.command?.length ?? 0) + (record.label?.length ?? 0), 0)
    expect(size(runtime.workspace('s1').operations)).toBeLessThanOrEqual(16000)
    expect(size(runtime.records('s1', 200))).toBeLessThanOrEqual(64000)
    expect(runtime.records('s1', 200).some((record) => record.truncated)).toBe(true)
  })
})
