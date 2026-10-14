// Adapted from zterm (MIT); Pi adapter assertions are covered by DSH runtime tests.
import { EventEmitter } from 'node:events'
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as pty from 'node-pty'
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest'
import { TerminalBridge, type AnyTerminalSession } from '../../src/core/terminalBridge'
import { TerminalOutputBuffer } from '../../src/core/terminalOutputBuffer'
import { prepareBuiltinRead } from '../../src/core/agentReadTools'
const protocolRoot = mkdtempSync(join(tmpdir(), 'dsh-zterm-protocol-'))
afterAll(() => rmSync(protocolRoot, { recursive: true, force: true }))

const protocolShells = new Set<ChildProcessWithoutNullStreams>()
afterEach(async () => {
  await Promise.all([...protocolShells].map((child) => new Promise<void>((resolve) => {
    child.once('close', () => resolve())
    child.kill('SIGKILL')
  })))
})

/** 短命 POSIX 子进程通过 stdin 接收协议数据，不接触真实终端。 */
function posixProtocolSender(events: EventEmitter, cwd?: string) {
  let receiver: ChildProcessWithoutNullStreams | undefined
  return (input: string): void => {
    if (input.includes("'__ZTERM_AGENT_READY_'")) {
      events.emit('data', execFileSync('/bin/sh', ['-c', input], { cwd, timeout: 3000 }))
    } else if (input.includes("'__ZTERM_AGENT_INPUT_'")) {
      receiver = spawn('/bin/sh', ['-c', input], { cwd })
      const child = receiver
      protocolShells.add(child)
      child.on('close', () => protocolShells.delete(child))
      child.on('error', (error) => events.emit('error', error))
      child.stdout.on('data', (data) => events.emit('data', data))
      child.stderr.on('data', (data) => events.emit('data', data))
    } else {
      receiver!.stdin.write(input)
    }
  }
}

/** Only an in-memory terminal: never starts a shell, SSH connection or service. */
function fakeTerminal(options?: { answerProbe?: boolean; answerReceiver?: boolean; probeExitCode?: number; autoComplete?: boolean; completeAll?: boolean; exitCode?: number; onProbe?: () => void; onReceiver?: () => void }) {
  const events = new EventEmitter() as EventEmitter & { connected: boolean; tabId: string; sessionMeta: object; getRecentOutput: () => string; write: (data: string) => void }
  events.connected = true
  events.tabId = `agent-protocol-${Math.random()}`
  events.sessionMeta = { source: 'direct', displayName: 'test' }
  const buffer = new TerminalOutputBuffer()
  events.on('data', (value: Buffer | string) => buffer.push(String(value)))
  events.getRecentOutput = () => buffer.recent(200)
  Object.assign(events, {
    beginAgentOutput: () => buffer.beginAgentOutput(), endAgentOutput: () => buffer.endAgentOutput(),
    getRecentOutputForAgent: (lines: number) => buffer.recent(lines, false),
  })
  const writes: string[] = []
  const payloads: string[] = []
  let finish: ((output?: string) => void) | undefined
  events.write = (input) => {
    const ready = input.match(/'__ZTERM_AGENT_READY_' '([a-f0-9]{32})__'/)
    const done = input.match(/'__ZTERM_AGENT_END_' '([a-f0-9]{32})__'/)
    if (!ready && !done) { payloads.push(input); return }
    writes.push(input)
    if (ready && options?.answerProbe !== false) {
      options?.onProbe?.()
      events.emit('data', Buffer.from(`\r\n__ZTERM_AGENT_READY_${ready[1]}__:${options?.probeExitCode ?? 37}\r\n`))
    }
    if (done) {
      finish = (output = '命令输出') => {
        events.emit('data', Buffer.from(`\r\n__ZTERM_AGENT_BEGIN_${done[1]}__`))
        // Split the UTF-8 stream across chunks, as a real PTY/SSH channel may.
        events.emit('data', Buffer.from(`\r\n${output}\r\n__ZTERM_AGENT_END_${done[1].slice(0, 12)}`))
        events.emit('data', Buffer.from(`${done[1].slice(12)}__:${options?.exitCode ?? 0}\r\n`))
      }
      if (options?.answerReceiver !== false) {
        options?.onReceiver?.()
        events.emit('data', `\r\n__ZTERM_AGENT_INPUT_${done[1]}__\r\n`)
      }
      if (options?.completeAll || options?.autoComplete && writes.length === 2) finish()
    }
  }
  return { bridge: new TerminalBridge(events as unknown as AnyTerminalSession), events, writes, payloads, complete: (text?: string) => finish?.(text) }
}

describe('DSH 复用的终端完成协议', () => {
  it('接收器确认前不发送脚本，未确认时的结束标记不能冒充完成', async () => {
    const fake = fakeTerminal({ answerReceiver: false })
    const pending = fake.bridge.executeAgentCommand('printf result', 120)
    await vi.waitFor(() => expect(fake.writes).toHaveLength(2))
    expect(fake.payloads).toEqual([])
    fake.complete('尚未执行')
    expect(await pending).toMatchObject({ completion: 'timedOut', commandSent: true, output: '' })
    expect(fake.payloads).toEqual([])
  })
  it('接收器握手期间撤销授权后不发送脚本，等待中的子进程结果保持未验证', async () => {
    let authorized = true
    const fake = fakeTerminal({ onReceiver: () => { authorized = false } })
    const authorize = vi.fn(() => authorized)
    const result = await fake.bridge.executeAgentCommand('printf result', 1000, undefined, authorize)
    expect(result).toMatchObject({ completion: 'aborted', commandSent: true, output: '' })
    expect(authorize).toHaveBeenCalledTimes(2)
    expect(fake.payloads).toEqual([])
  })
  it.runIf(process.platform !== 'win32')('真实 POSIX 包装执行复杂引号查询，回显模板不能制造搜索命中', async () => {
    const root = mkdtempSync(join(protocolRoot, 'protocol-read-'))
    const marker = join(root, 'injected')
    const path = join(root, "file' space $HOME `literal`.txt")
    const query = "ssh 'literal' $HOME `printf unintended` $(touch injected)"
    writeFileSync(path, query + '\nordinary\n')
    const fake = fakeTerminal()
    const send = posixProtocolSender(fake.events, root)
    fake.events.write = (input) => {
      fake.events.emit('data', '\x1b[32mroot#\x1b[0m ' + input.replace(/(.{40})/g, '$1\r\n'))
      send(input)
    }
    const command = prepareBuiltinRead('search_bound_text', { path, query }).command
    const result = await fake.bridge.executeAgentCommand(command, 2000)
    expect(result).toMatchObject({ completion: 'verified', exitCode: 0 })
    expect(result.output).toContain('1:' + query)
    expect(result.output).not.toMatch(/\*\/\.ssh|__ZTERM_AGENT|command sh|root#|\x1b/)
    expect(existsSync(marker)).toBe(false)
    const noMatch = await fake.bridge.executeAgentCommand(prepareBuiltinRead('search_bound_text', { path, query: '.ssh' }).command, 2000)
    expect(noMatch.output).not.toContain('.ssh')
    expect(noMatch.output).not.toContain('FILE ')
  })
  it('窄终端折行回显、ANSI 和前后提示符不会污染真实结果', async () => {
    const fake = fakeTerminal()
    const pending = fake.bridge.executeAgentCommand('grep ssh /etc/hosts', 1000)
    await vi.waitFor(() => expect(fake.writes).toHaveLength(2))
    const input = fake.writes[1]
    const nonce = input.match(/'__ZTERM_AGENT_END_' '([a-f0-9]{32})__'/)![1]
    // 输入回显被硬折行，里面也包含关键词与分段协议字符串。
    fake.events.emit('data', '\x1b[32mroot#\x1b[0m ' + input.replace(/(.{40})/g, '$1\r\n'))
    const fold = (value: string): string => value.slice(0, 39) + '\r\n' + value.slice(39)
    const stream = `\r\n${fold('__ZTERM_AGENT_BEGIN_' + nonce + '__')}\r\n\x1b[32m真实结果\x1b[0m\r\n${fold('__ZTERM_AGENT_END_' + nonce + '__')}:0\r\nroot# `
    // 包含中文 UTF-8、ANSI 和标记的任意分块。
    const bytes = Buffer.from(stream)
    for (let i = 0; i < bytes.length; i += 3) fake.events.emit('data', bytes.subarray(i, i + 3))
    const result = await pending
    expect(result).toMatchObject({ completion: 'verified', exitCode: 0, output: '真实结果' })
    expect(result.output).not.toMatch(/grep|ssh|root#|__ZTERM|\x1b/)
  })

  it('结束标记缺少开始边界时拒绝验证；退出码完整换行前不能提前收尾', async () => {
    const missing = fakeTerminal()
    const rejected = missing.bridge.executeAgentCommand('printf value', 80)
    await vi.waitFor(() => expect(missing.writes).toHaveLength(2))
    const nonce = missing.writes[1].match(/'__ZTERM_AGENT_END_' '([a-f0-9]{32})__'/)![1]
    missing.events.emit('data', `echoed command\r\n__ZTERM_AGENT_END_${nonce}__:0\r\n`)
    expect(await rejected).toMatchObject({ completion: 'timedOut', output: '', commandSent: true })

    const split = fakeTerminal()
    let settled = false
    const pending = split.bridge.executeAgentCommand('missing-query', 1000).then((result) => { settled = true; return result })
    await vi.waitFor(() => expect(split.writes).toHaveLength(2))
    const token = split.writes[1].match(/'__ZTERM_AGENT_END_' '([a-f0-9]{32})__'/)![1]
    split.events.emit('data', `\r\n__ZTERM_AGENT_BEGIN_${token}__\r\nquery missing\r\n__ZTERM_AGENT_END_${token}__:1`)
    await Promise.resolve()
    expect(settled).toBe(false)
    split.events.emit('data', '27\r\n')
    expect(await pending).toMatchObject({ completion: 'verified', exitCode: 127, output: 'query missing' })
  })

  it('同一真实终端的新 bridge 仍能读取最近查询结果，独立于旧屏幕缓冲', async () => {
    const fake = fakeTerminal({ completeAll: true })
    Object.assign(fake.events, { currentHost: { host: 'first.test', port: 22, username: 'test' },
      verifiedHostKey: { algorithm: 'ssh-ed25519', fingerprint: 'SHA256:first' } })
    for (let i = 0; i < 7; i++) await fake.bridge.executeAgentCommand('printf result', 1000)
    const another = new TerminalBridge(fake.events as unknown as AnyTerminalSession)
    const history = another.getTerminalContext().recentAgentResults
    expect(history).toHaveLength(6)
    expect(history?.every((item) => item.output === '命令输出' && item.exitCode === 0)).toBe(true)
    expect(another.getTerminalContext().agentRecentOutput).toBe('')
    expect(another.getTerminalContext().recentOutput).toContain('__ZTERM_AGENT_')
    Object.assign(fake.events, { currentHost: { host: 'second.test', port: 22, username: 'test' } })
    expect(another.getTerminalContext().recentAgentResults).toEqual([])
  })
  it('按发送区间清洗上下文，折行回显消失，用户的同名文本和查询结果保留', async () => {
    const fake = fakeTerminal()
    fake.events.emit('data', '\x1b[32mmanual __ZTERM_AGENT_BEGIN_example__\x1b[0m\r\n')
    const pending = fake.bridge.executeAgentCommand('printf result', 1000)
    await vi.waitFor(() => expect(fake.writes).toHaveLength(2))
    fake.events.emit('data', fake.writes[1].replace(/(.{40})/g, '$1\r\n'))
    fake.complete('query __ZTERM_AGENT_BEGIN_example__')
    await pending
    fake.events.emit('data', 'after\r\n')
    const context = new TerminalBridge(fake.events as unknown as AnyTerminalSession).getTerminalContext()
    expect(context.agentRecentOutput).toBe('manual __ZTERM_AGENT_BEGIN_example__\nafter\n')
    expect(context.agentRecentOutput).not.toContain('command sh')
    expect(context.recentAgentResults?.[0].output).toBe('query __ZTERM_AGENT_BEGIN_example__')
    expect(context.recentOutput.replace(/[\r\n]/g, '')).toContain('command sh')
  })

  it('未验证的发送区间不把迟到协议或输出升级为模型历史', async () => {
    const fake = fakeTerminal()
    fake.events.emit('data', 'before\n')
    const pending = fake.bridge.executeAgentCommand('printf pending', 80)
    await vi.waitFor(() => expect(fake.writes).toHaveLength(2))
    fake.events.emit('data', 'late echo\r\n')
    expect(await pending).toMatchObject({ completion: 'timedOut' })
    fake.events.emit('data', '__ZTERM_AGENT_END_late__\r\n')
    expect(fake.bridge.getTerminalContext().agentRecentOutput).toBe('before\n')
    expect(fake.bridge.getTerminalContext().recentOutput).toContain('__ZTERM_AGENT_END_late__')
  })

  it.runIf(process.platform !== 'win32')('超长且含引号的命令按物理行分段，shell 参数仍保持原样', async () => {
    const fake = fakeTerminal()
    const text = "single' $HOME `literal` 中文".repeat(400)
    let maxLineBytes = 0
    const send = posixProtocolSender(fake.events)
    fake.events.write = (input) => {
      maxLineBytes = Math.max(maxLineBytes, ...input.split('\n').map((line) => Buffer.byteLength(line)))
      send(input)
    }
    const quoted = "'" + text.replace(/'/g, "'\\''") + "'"
    const result = await fake.bridge.executeAgentCommand("printf '%s' " + quoted, 4000)
    expect(result).toMatchObject({ completion: 'verified', exitCode: 0, output: text })
    expect(maxLineBytes + 1).toBeLessThan(1024)
  })
  it.runIf(process.platform === 'darwin').each([
    { mode: '规范输入', shellPath: '/bin/zsh', args: ['-f', '+Z', '-i'] },
    { mode: '交互编辑', shellPath: '/bin/zsh', args: ['-f', '-i'] },
    { mode: 'bash 交互编辑', shellPath: '/bin/bash', args: ['--noprofile', '--norc', '-i'] },
  ])('macOS $mode PTY 完整执行进程、系统和复杂引号文件查询', async ({ shellPath, args }) => {
    // 禁用 ZLE 的用例覆盖探测输出刚到达、编辑器尚未恢复时的规范输入状态。
    // 只使用测试自己的短命 PTY，退出时强制回收，不连接用户终端或 SSH。
    const shell = pty.spawn(shellPath, args, {
      name: 'xterm-256color', cols: 80, rows: 24, cwd: protocolRoot,
      env: { PATH: process.env.PATH, LANG: 'en_US.UTF-8', ZDOTDIR: protocolRoot,
        PS1: 'ZTERM_TEST> ', PS2: 'quote> ' },
    })
    const exited = new Promise<void>((resolve) => shell.onExit(() => resolve()))
    const fake = fakeTerminal()
    let transcript = ''
    const subscription = shell.onData((data) => { transcript += data; fake.events.emit('data', data) })
    fake.events.write = (input) => { fake.writes.push(input); shell.write(input) }
    try {
      await vi.waitFor(() => expect(transcript).toContain('ZTERM_TEST> '))
      const processes = await fake.bridge.executeAgentCommand(prepareBuiltinRead('list_bound_processes', {}).command, 3000)
      expect(processes, transcript.slice(-2800)).toMatchObject({ completion: 'verified', exitCode: 0 })
      expect(processes.output).toMatch(/PID\s+PPID\s+USER/)
      const processResult = await fake.bridge.executeAgentCommand(
        prepareBuiltinRead('list_bound_processes', { pid: process.pid }).command, 3000,
      )
      expect(processResult).toMatchObject({ completion: 'verified', exitCode: 0 })
      expect(processResult.output).toContain(String(process.pid))
      const system = await fake.bridge.executeAgentCommand(prepareBuiltinRead('read_bound_system', {}).command, 3000)
      expect(system, transcript.slice(-1800)).toMatchObject({ completion: 'verified', exitCode: 0 })
      expect(system.output).toContain('Darwin')
      const path = join(protocolRoot, "file' 中文 $HOME `literal`.txt")
      writeFileSync(path, 'first\n你好\nthird\n')
      const file = await fake.bridge.executeAgentCommand(prepareBuiltinRead('read_bound_file', { path }).command, 3000)
      expect(file).toMatchObject({ completion: 'verified', exitCode: 0 })
      expect(file.output).toContain('你好')
      const text = "single' $HOME `literal` 中文\nlast".repeat(400)
      const quoted = "'" + text.replace(/'/g, "'\\''") + "'"
      const literal = await fake.bridge.executeAgentCommand("printf '%s' " + quoted, 3000)
      expect(literal).toMatchObject({ completion: 'verified', exitCode: 0, output: text })
      // macOS MAX_CANON 是 1024；断言包括协议前后缀与续行字符的整个物理行。
      expect(Math.max(...fake.writes.flatMap((input) => input.split('\n').map((line) => Buffer.byteLength(line) + 1)))).toBeLessThan(1024)
    } finally {
      subscription.dispose()
      shell.kill('SIGKILL')
      await exited
    }
  }, 15_000)
  it('探测等待期间降权后，真实发送边界拒绝业务命令', async () => {
    let allowed = true
    const fake = fakeTerminal({ onProbe: () => { allowed = false } })
    const result = await fake.bridge.executeAgentCommand('touch /test-marker', 1000, undefined, () => allowed)
    expect(result).toMatchObject({ completion: 'aborted', commandSent: false, authorizationDenied: true })
    expect(fake.writes).toHaveLength(1)
    expect(fake.writes[0]).not.toContain('touch /test-marker')
  })
  it('输出静默不等于命令结束：必须等随机完成标记和退出码', async () => {
    const fake = fakeTerminal({ exitCode: 7 })
    let settled = false
    const pending = fake.bridge.executeAgentCommand('printf hello', 1000).then((result) => { settled = true; return result })
    await vi.waitFor(() => expect(fake.writes).toHaveLength(2))
    fake.events.emit('data', Buffer.from('\r\n已输出部分内容\r\n'))
    await new Promise((resolve) => setTimeout(resolve, 250))
    expect(settled).toBe(false)
    fake.complete('最后一段输出')
    const result = await pending
    expect(result.completion).toBe('verified')
    expect(result.exitCode).toBe(7)
    expect(result.commandSent).toBe(true)
    expect(result.output).toContain('最后一段输出')
    expect(fake.payloads[0]).toContain('printf hello')
    // 用户命令可能不以换行结束；协议须主动起新行打印标记。
    expect(fake.writes[1]).toContain('printf "\\n%s%s:%d\\n"')
    expect(fake.writes[1]).not.toMatch(/__ZTERM_AGENT_END_[a-f0-9]{32}__/)
  })

  it('探测不支持 POSIX 协议时绝不下发用户命令', async () => {
    const fake = fakeTerminal({ answerProbe: false })
    const result = await fake.bridge.executeAgentCommand('touch /test-marker', 30)
    expect(result.completion).toBe('timedOut')
    expect(result.commandSent).toBe(false)
    expect(fake.writes).toHaveLength(1)
    expect(fake.writes[0]).toContain("sh -c 'exit 37'")
    expect(fake.writes[0]).not.toContain('touch /test-marker')
  })

  it('非 POSIX Shell 可打印标记却无法证明退出码时,不下发业务命令', async () => {
    const fake = fakeTerminal({ probeExitCode: 0 })
    const result = await fake.bridge.executeAgentCommand('touch /test-marker', 100)
    expect(result.completion).toBe('unsupported')
    expect(result.commandSent).toBe(false)
    expect(fake.writes).toHaveLength(1)
    expect(fake.writes[0]).not.toContain('touch /test-marker')
  })

  it('大量输出被截断但末尾真实完成标记仍能验证', async () => {
    const fake = fakeTerminal({ autoComplete: true })
    const result = await fake.bridge.executeAgentCommand('cat /large', 1000)
    expect(result.completion).toBe('verified')
    // 同一 session 上每条命令都重探测，防止用户手工切换交互 shell 后沿用旧缓存。
    const second = fake.bridge.executeAgentCommand('cat /another-large', 1000)
    await vi.waitFor(() => expect(fake.writes).toHaveLength(4))
    fake.complete('x'.repeat(70_000))
    expect((await second).output).toContain('[前段输出已截断]')
  })

  it('用户命令已下发而未收到标记:超时和断线都不伪造退出码', async () => {
    const timed = fakeTerminal()
    const timedResult = await timed.bridge.executeAgentCommand('uptime', 35)
    expect(timedResult).toMatchObject({ completion: 'timedOut', commandSent: true })
    expect(timedResult.exitCode).toBeUndefined()

    const closed = fakeTerminal()
    const waiting = closed.bridge.executeAgentCommand('uptime', 1000)
    await vi.waitFor(() => expect(closed.writes).toHaveLength(2))
    closed.events.connected = false
    closed.events.emit('closed')
    const disconnected = await waiting
    expect(disconnected).toMatchObject({ completion: 'disconnected', commandSent: true })
    expect(disconnected.exitCode).toBeUndefined()
  })
})
