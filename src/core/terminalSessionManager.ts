/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
import { TerminalOutputBuffer } from './terminalOutputBuffer'
import ssh2 from 'ssh2'
import type { Client, ConnectConfig, ClientChannel } from 'ssh2'
import { EventEmitter } from 'events'
import { randomUUID } from 'node:crypto'
import type {
  SshHostTrustCandidate,
  SshHostTrustRequiredEvent,
  SshHostTrustResponse,
  SshHostTrustResponseResult
} from './sshHostTrustTypes'
import {
  memoryHostTrustStore,
  inspectSshHostKey,
  type HostTrustStore
} from './sshHostTrust'

export interface SshConnectionOptions {
  host: string
  port: number
  username: string
  password?: string
  privateKey?: string
  passphrase?: string
  agent?: string
  requireHostTrust?: boolean
}

export interface SshConnectionIdentity {
  host: string
  port: number
  username: string
}

export interface SessionMeta {
  source: 'direct' | 'jumpserver' | 'local'
  displayName: string
  displaySecondary?: string
  /** Jumpserver 的稳定配置/资产/账号 ID；展示名称不足以验证恢复目标。 */
  targetId?: string
}

export interface TerminalEvent {
  data?: Buffer
  exit?: { code: number; signal: string }
}

/**
 * Represents a single SSH session tied to a terminal tab.
 * Emits events scoped to this session only.
 */
type HostTrustFailure = 'unconfirmed' | 'rejected' | 'timeout' | 'changed' | 'invalid' | 'save-failed' | null

interface PendingHostTrust {
  requestId: string
  candidate: SshHostTrustCandidate
  verify: (allowed: boolean) => void
  timer: ReturnType<typeof setTimeout>
}

const HOST_TRUST_TIMEOUT_MS = 60_000

export class TerminalSession extends EventEmitter {
  public tabId: string
  public generation: number
  private conn: Client | null = null
  private stream: ClientChannel | null = null
  /** 前端测得的准确尺寸；SSH ready 到 Shell channel 就绪之间也必须保留。 */
  private terminalSize: { cols: number; rows: number } | null = null
  public connected = false
  public currentHost?: SshConnectionIdentity
  public sessionMeta?: SessionMeta
  /** 本连接实际通过校验的 SSH host key；trust-once 也必须进入 Agent 目标身份。 */
  public verifiedHostKey?: { algorithm: string; fingerprint: string }
  private outputBuffer = new TerminalOutputBuffer()
  private connHadError = false
  private keepaliveTriggered = false
  private closedEmitted = false
  private pendingHostTrust: PendingHostTrust | null = null
  private hostTrustFailure: HostTrustFailure = null
  private rejectConnect: ((error: Error) => void) | null = null
  private connectSettled = false

  constructor(
    tabId: string,
    generation: number,
    private readonly clientFactory: () => Client = () => new ssh2.Client(),
    private readonly trust: HostTrustStore = memoryHostTrustStore()
  ) {
    super()
    this.tabId = tabId
    this.generation = generation
  }

  private emitClosedOnce(reason: 'user-disconnect' | 'keepalive-timeout' | 'transport-error' | 'normal', hadError: boolean): void {
    if (this.closedEmitted) return
    this.closedEmitted = true
    this.emit('closed', { reason, hadError })
  }

  private getHostTrustError(): Error | null {
    const messages: Record<Exclude<HostTrustFailure, null>, string> = {
      unconfirmed: 'SSH 主机身份未确认，连接已阻断',
      rejected: 'SSH 主机身份未获信任，连接已阻断',
      timeout: 'SSH 主机身份未确认，连接已超时',
      changed: 'SSH 主机身份已变更，连接已阻断',
      invalid: '无法验证 SSH 主机身份，连接已阻断',
      'save-failed': '无法保存 SSH 主机信任记录，连接已阻断'
    }
    return this.hostTrustFailure ? new Error(messages[this.hostTrustFailure]) : null
  }

  private settleConnectReject(error: Error): void {
    if (this.connectSettled) return
    this.connectSettled = true
    const reject = this.rejectConnect
    this.rejectConnect = null
    reject?.(error)
  }

  private settlePendingHostTrust(allowed: boolean, failure: HostTrustFailure = null): void {
    const pending = this.pendingHostTrust
    if (!pending) return
    this.pendingHostTrust = null
    clearTimeout(pending.timer)
    this.hostTrustFailure = failure
    if (allowed) {
      this.verifiedHostKey = {
        algorithm: pending.candidate.algorithm,
        fingerprint: pending.candidate.fingerprint,
      }
    }
    pending.verify(allowed)
  }

  private emitHostTrustRequired(
    kind: 'unknown' | 'changed',
    candidate: SshHostTrustCandidate,
    trusted?: { algorithm: string; fingerprint: string },
    requestId = randomUUID()
  ): string {
    const event: SshHostTrustRequiredEvent = {
      tabId: this.tabId,
      generation: this.generation,
      requestId,
      kind,
      host: candidate.host,
      port: candidate.port,
      username: candidate.username,
      algorithm: candidate.algorithm,
      fingerprint: candidate.fingerprint,
      ...(trusted ? { trustedAlgorithm: trusted.algorithm, trustedFingerprint: trusted.fingerprint } : {})
    }
    this.emit('host-trust-required', event)
    return requestId
  }

  private verifyHostKey(opts: SshConnectionOptions, rawHostKey: Buffer, verify: (allowed: boolean) => void): void {
    const candidate = inspectSshHostKey(rawHostKey, opts)
    if (!candidate || this.pendingHostTrust) {
      this.hostTrustFailure = 'invalid'
      verify(false)
      return
    }

    const existing = this.trust.get(candidate.host, candidate.port)
    if (existing) {
      if (existing.algorithm === candidate.algorithm && existing.fingerprint === candidate.fingerprint) {
        this.verifiedHostKey = { algorithm: candidate.algorithm, fingerprint: candidate.fingerprint }
        verify(true)
        return
      }
      this.hostTrustFailure = 'changed'
      this.emitHostTrustRequired('changed', candidate, existing)
      verify(false)
      return
    }

    const requestId = randomUUID()
    const timer = setTimeout(() => {
      this.settlePendingHostTrust(false, 'timeout')
    }, HOST_TRUST_TIMEOUT_MS)
    this.pendingHostTrust = { requestId, candidate, verify, timer }
    this.emitHostTrustRequired('unknown', candidate, undefined, requestId)
  }

  respondHostTrust(response: SshHostTrustResponse): SshHostTrustResponseResult {
    const pending = this.pendingHostTrust
    if (
      !pending ||
      response.tabId !== this.tabId ||
      response.generation !== this.generation ||
      response.requestId !== pending.requestId
    ) {
      return { success: false, error: '主机信任请求已失效' }
    }

    if (!['trust-once', 'trust-always', 'reject'].includes(response.decision)) {
      return { success: false, error: '主机信任决定无效' }
    }

    if (response.decision === 'trust-always') {
      try {
        this.trust.save(pending.candidate)
      } catch {
        this.settlePendingHostTrust(false, 'save-failed')
        return { success: false, error: '无法保存主机信任记录' }
      }
      this.settlePendingHostTrust(true)
      return { success: true }
    }

    if (response.decision === 'trust-once') {
      this.settlePendingHostTrust(true)
      return { success: true }
    }

    this.settlePendingHostTrust(false, 'rejected')
    return { success: true }
  }

  async connect(opts: SshConnectionOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      this.currentHost = { host: opts.host, port: opts.port || 22, username: opts.username }
      this.verifiedHostKey = undefined
      this.connectSettled = false
      this.rejectConnect = reject
      const conn = this.clientFactory()
      this.conn = conn

      const config: ConnectConfig = {
        host: opts.host,
        port: opts.port || 22,
        username: opts.username,
        readyTimeout: 10000,
        keepaliveInterval: 30000,
        keepaliveCountMax: 3
      }

      // 所有 SSH 通道（含 Koko）都必须验证服务端身份，调用方不能省略保护。
      config.hostVerifier = (key: Buffer, verify: (allowed: boolean) => void) => this.verifyHostKey(opts, key, verify)

      if (opts.agent) config.agent = opts.agent
      if (opts.privateKey) {
        config.privateKey = opts.privateKey
        if (opts.passphrase) config.passphrase = opts.passphrase
      } else if (opts.password) {
        config.password = opts.password
      }

      conn.on('ready', () => {
        if (this.connectSettled || this.hostTrustFailure || this.pendingHostTrust) return
        this.connected = true
        this.connectSettled = true
        this.rejectConnect = null
        this.emit('connected')
        resolve()
      })

      conn.on('error', (err: Error) => {
        this.connected = false
        if (/keepalive/i.test(err.message) || /Timed out/i.test(err.message)) {
          this.keepaliveTriggered = true
        }
        const error = this.getHostTrustError() || err
        this.emit('error', error, 'ssh-connection')
        this.settleConnectReject(error)
      })

      conn.on('close', (hadError?: boolean) => {
        this.connected = false
        this.connHadError = hadError === true
        this.settlePendingHostTrust(false, 'unconfirmed')
        this.settleConnectReject(this.getHostTrustError() || new Error('SSH 连接已关闭'))
        const reason = this.keepaliveTriggered
          ? 'keepalive-timeout'
          : hadError === true
            ? 'transport-error'
            : 'normal'
        this.emitClosedOnce(reason, hadError === true)
      })

      conn.connect(config)
    })
  }

  openShell(cols: number, rows: number): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.conn || !this.connected) {
        reject(new Error('SSH 连接不存在'))
        return
      }

      const requestedSize = this.terminalSize ?? { cols, rows }
      this.conn.shell(
        {
          term: 'xterm-256color',
          cols: requestedSize.cols,
          rows: requestedSize.rows
        },
        (err: Error | undefined, stream: ClientChannel) => {
          if (err) {
            reject(err)
            return
          }

          this.stream = stream
          // 打开 Shell 的异步窗口里可能再次缩放；用最后一次准确尺寸修正远端 PTY。
          const latestSize = this.terminalSize
          if (latestSize && (latestSize.cols !== requestedSize.cols || latestSize.rows !== requestedSize.rows)) {
            stream.setWindow(latestSize.rows, latestSize.cols, 0, 0)
          }

          stream.on('data', (data: Buffer) => {
            this.outputBuffer.push(data.toString())
            this.emit('data', data)
          })

          stream.on('close', () => {
            this.connected = false
            // 诊断：区分是 SSH 连接层先断（connHadError）还是 shell channel 独立关闭
            const reason = this.connHadError
              ? 'shell channel closed after SSH transport error'
              : 'shell channel closed (SSH transport still up or normal close)'
            this.emit('shell-closed', { reason })
          })

          stream.on('error', (err: Error) => {
            this.connected = false
            this.emit('error', err, 'ssh-shell')
          })

          resolve()
        }
      )
    })
  }

  isShellReady(): boolean {
    return this.connected && !!this.stream?.writable
  }

  write(data: string): void {
    if (this.stream && this.stream.writable) {
      this.stream.write(data)
    }
  }

  resize(cols: number, rows: number): void {
    if (!Number.isInteger(cols) || !Number.isInteger(rows) || cols < 1 || rows < 1) return
    this.terminalSize = { cols, rows }
    if (this.stream) {
      this.stream.setWindow(rows, cols, 0, 0)
    }
  }

  getRecentOutput(lines: number): string {
    // 先 join 再按 \n split，确保按行截断而非按 buffer 元素截取
    return this.outputBuffer.recent(lines)
  }

  beginAgentOutput(): void { this.outputBuffer.beginAgentOutput() }
  endAgentOutput(): void { this.outputBuffer.endAgentOutput() }
  getRecentOutputForAgent(lines: number): string { return this.outputBuffer.recent(lines, false) }

  disconnect(): void {
    this.settlePendingHostTrust(false, 'unconfirmed')
    if (!this.connected) {
      this.settleConnectReject(this.getHostTrustError() || new Error('SSH 连接已取消'))
    }
    try {
      if (this.stream) {
        this.stream.end()
        this.stream.destroy()
        this.stream = null
      }
      if (this.conn) {
        this.conn.end()
        this.conn.destroy()
        this.conn = null
      }
    } catch {
      // ignore cleanup errors
    }
    this.connected = false
    this.terminalSize = null
    this.currentHost = undefined
    this.sessionMeta = undefined
    this.outputBuffer.clear()
    this.emitClosedOnce('user-disconnect', false)
    this.removeAllListeners()
  }
}

/**
 * Manages multiple terminal sessions, each keyed by tabId.
 * Replaces the global single SshManager usage.
 */
export class TerminalSessionManager {
  private sessions = new Map<string, TerminalSession>()
  private generations = new Map<string, number>() // tabId -> generation counter

  createSession(tabId: string): TerminalSession {
    // If a session already exists for this tab, disconnect it first
    const existing = this.sessions.get(tabId)
    if (existing) {
      existing.disconnect()
    }

    // Increment generation for this tabId
    const gen = (this.generations.get(tabId) || 0) + 1
    this.generations.set(tabId, gen)

    const session = new TerminalSession(tabId, gen)
    this.sessions.set(tabId, session)
    return session
  }

  getSession(tabId: string): TerminalSession | undefined {
    return this.sessions.get(tabId)
  }

  getGeneration(tabId: string): number {
    return this.generations.get(tabId) || 0
  }

  removeSession(tabId: string): void {
    const session = this.sessions.get(tabId)
    if (session) {
      session.disconnect()
      this.sessions.delete(tabId)
    }
  }

  hasSession(tabId: string): boolean {
    return this.sessions.has(tabId)
  }

  getAllSessions(): TerminalSession[] {
    return Array.from(this.sessions.values())
  }

  dispose(): void {
    for (const session of this.sessions.values()) {
      session.disconnect()
    }
    this.sessions.clear()
    this.generations.clear()
  }
}
