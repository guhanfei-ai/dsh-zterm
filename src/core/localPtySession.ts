/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
import { TerminalOutputBuffer } from './terminalOutputBuffer'
import { EventEmitter } from 'events'
import * as fs from 'fs'
import type * as pty from 'node-pty'
import type { SessionMeta } from './terminalSessionManager'

/**
 * 本地 PTY 会话：通过 node-pty 在当前主机上启动本地 shell。
 * 与 TerminalSession（SSH2）共享相同的事件接口，
 * 使 IPC 层的 registerSessionEvents 可以统一处理两种会话。
 */
export class LocalPtySession extends EventEmitter {
  public tabId: string
  public generation: number
  public connected = false
  public sessionMeta?: SessionMeta
  private ptyProcess: pty.IPty | null = null
  private outputBuffer = new TerminalOutputBuffer()
  private hadOutput = false // 是否曾收到 shell 输出，用于区分“启动失败”与“运行中退出”
  private disconnectRequested = false // 主动断开标记：grace 期内的 kill 不判“启动失败”

  constructor(tabId: string, generation: number, private readonly cwd?: string) {
    super()
    this.tabId = tabId
    this.generation = generation
  }

  /**
   * 启动本地 shell 进程。
   * shell 由调用方根据三平台策略选择传入。
   *
   * P1-3：pty.spawn 同步不会抛异常，真正失败要等 onExit 才回调。
   * 修复：spawn 成功后等待 100ms "grace period"——若 100ms 内 exit 且没收到输出，
   * 视为启动失败（shell 路径无效 / 权限不足等），直接 reject。
   * 若 100ms 后仍在运行，则视为启动成功 resolve，让 UI 显示 connected。
   */
  async connect(shell: string, cols: number, rows: number): Promise<void> {
    // 复位主动断开标记：当前架构每实例只 connect 一次，但若未来复用实例重连，
    // 残留的 disconnectRequested=true 会把真正的启动失败吞成 resolve
    this.disconnectRequested = false
    const pty = await import('node-pty')
    return new Promise<void>((resolve, reject) => {
      try {
        this.ptyProcess = pty.spawn(shell, [], {
          name: 'xterm-256color',
          cols,
          rows,
          cwd: this.cwd ?? process.env.HOME ?? process.env.USERPROFILE,
          env: process.env as { [key: string]: string | undefined }
        })

        this.connected = true
        this.emit('connected', { shell })

        this.ptyProcess.onData((data: string) => {
          this.hadOutput = true
          this.outputBuffer.push(data)
          this.emit('data', Buffer.from(data, 'utf-8'))
        })

        // P1-3：grace period 检测。设一个定时器在 100ms 后 mark = 'started'；
        // 若在 100ms 内 onExit 触发，则 mark 仍为 'pending'，onExit 中据此 reject。
        let phase: 'pending' | 'started' = 'pending'
        const graceTimer = setTimeout(() => {
          phase = 'started'
          if (this.connected) {
            resolve()
          }
        }, 100)

        this.ptyProcess.onExit(({ exitCode, signal }) => {
          // 清掉 grace timer，避免悬挂
          clearTimeout(graceTimer)
          this.connected = false
          this.ptyProcess = null
          // 用户主动断开（如 grace 期内的 disconnect() kill 了 shell）：
          // 不是启动失败，Promise 按 resolve 收尾，closed 事件已由 disconnect() 发出
          if (this.disconnectRequested) {
            if (phase === 'pending') {
              resolve()
            }
            return
          }
          // 启动期退出：100ms 内非零退出且无输出 → 启动失败
          if (phase === 'pending' && !this.hadOutput && exitCode !== 0) {
            const err = new Error(`本地 shell「${shell}」启动失败，exitCode=${exitCode}，signal=${signal}`)
            this.emit('error', err, 'local-pty')
            this.emit('closed', { reason: 'startup-failed', hadError: true })
            reject(err)
            return
          }
          // 运行中退出（无输出且非零）→ 异常退出
          if (!this.hadOutput && exitCode !== 0) {
            this.emit(
              'error',
              new Error(`本地 shell「${shell}」退出异常，exitCode=${exitCode}，signal=${signal}`),
              'local-pty'
            )
            this.emit('closed', { reason: 'transport-error', hadError: true })
            return
          }
          // 正常退出
          this.emit('shell-closed', {
            reason: `本地 shell 进程退出，code=${exitCode}，signal=${signal}`,
            exitCode,
            signal
          })
          this.emit('closed', { reason: 'normal', hadError: false })
          // grace period 内的干净退出（如 shell 立即 exit 0）：graceTimer 已清除，
          // Promise 尚处 pending，补一次 resolve 避免悬挂；已 resolve 时此调用无副作用
          if (phase === 'pending') {
            resolve()
          }
        })
      } catch (err: unknown) {
        this.emit('error', err instanceof Error ? err : new Error(String(err)), 'local-pty')
        reject(err)
      }
    })
  }

  isShellReady(): boolean {
    return this.connected && this.ptyProcess !== null
  }

  write(data: string): void {
    if (this.ptyProcess) {
      this.ptyProcess.write(data)
    }
  }

  resize(cols: number, rows: number): void {
    if (this.ptyProcess) {
      this.ptyProcess.resize(cols, rows)
    }
  }

  getRecentOutput(lines: number): string {
    // 与 TerminalSession.getRecentOutput 保持一致的"行数"语义。
    // outputBuffer 元素是任意大小的输出块，块边界与行边界无关：
    // 按 chunk 数截取会把一行腰斩、长度完全不可控，
    // Agent 的行级 diff（extractLineDelta）与观察提取会拿到错位内容
    return this.outputBuffer.recent(lines)
  }

  beginAgentOutput(): void { this.outputBuffer.beginAgentOutput() }
  endAgentOutput(): void { this.outputBuffer.endAgentOutput() }
  getRecentOutputForAgent(lines: number): string { return this.outputBuffer.recent(lines, false) }

  disconnect(): void {
    this.disconnectRequested = true
    try {
      if (this.ptyProcess) {
        this.ptyProcess.kill()
        this.ptyProcess = null
      }
    } catch {
      // 忽略清理错误
    }
    this.connected = false
    this.hadOutput = false
    this.outputBuffer.clear()
    // 统一 closed 事件签名（C1）
    this.emit('closed', { reason: 'user-disconnect', hadError: false })
    this.removeAllListeners()
  }
}

/**
 * 三平台 shell 选择策略（按优先级依次兜底，前一个不可用才取下一个）：
 * - macOS: process.env.SHELL → /bin/zsh → /bin/bash
 * - Linux: process.env.SHELL → /bin/bash → /bin/sh
 * - Windows: process.env.COMSPEC → PowerShell → cmd.exe
 *
 * Unix 候选为绝对路径，用 existsSync 探测；Windows 后两级走 System32 标准路径探测。
 * 全部探测失败时返回末位候选，交由 node-pty spawn 报明确错误（见 LocalPtySession.onExit）。
 */
function shellExists(p: string | undefined): p is string {
  return !!p && fs.existsSync(p)
}

export function getPlatformShell(): string {
  if (process.platform === 'win32') {
    if (shellExists(process.env.COMSPEC)) return process.env.COMSPEC
    const sysRoot = process.env.SystemRoot || process.env.windir || 'C:\\Windows'
    const powershell = `${sysRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
    if (shellExists(powershell)) return powershell
    const cmd = `${sysRoot}\\System32\\cmd.exe`
    if (shellExists(cmd)) return cmd
    return 'powershell.exe' // 探测全部失败，交给 spawn 报错
  }

  // Unix-like（macOS / Linux）：按平台给出三级候选，取第一个真实存在的
  const fallbackShells = process.platform === 'darwin'
    ? ['/bin/zsh', '/bin/bash']
    : ['/bin/bash', '/bin/sh']
  const candidates = [process.env.SHELL, ...fallbackShells].filter(shellExists)
  if (candidates.length > 0) return candidates[0]
  return fallbackShells[fallbackShells.length - 1]
}

/**
 * 返回当前平台的显示名称，用于终端标签标题。
 */
export function getPlatformDisplayName(): string {
  if (process.platform === 'win32') return '本地终端 (Windows)'
  if (process.platform === 'darwin') return '本地终端 (macOS)'
  return '本地终端 (Linux)'
}
