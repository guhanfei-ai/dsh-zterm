/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
import { randomBytes } from 'node:crypto'
import { stripVTControlCharacters } from 'node:util'
import { TerminalSession } from './terminalSessionManager'
import { LocalPtySession } from './localPtySession'

/** 统一会话类型：TerminalSession（SSH/JMP）与 LocalPtySession 的共同接口 */
export type AnyTerminalSession = TerminalSession | LocalPtySession

export interface TerminalContext {
  hostName: string
  hostDetails: string
  source: 'direct' | 'jumpserver' | 'local'
  recentOutput: string
  /** 排除宿主 Agent 发送区间后清洗的历史；原始终端缓冲仍用于界面。 */
  agentRecentOutput?: string
  isConnected: boolean
  /** 同一真实终端最近的已验证 Agent 查询，独立于交互终端的滚动缓冲。 */
  recentAgentResults?: Array<{ output: string; exitCode: number; observedAt: string; truncated?: boolean }>
}

export interface CommandResult {
  command: string
  output: string
  exitCode?: number
  duration: number
}

export interface AgentCommandResult extends CommandResult {
  completion: 'verified' | 'timedOut' | 'aborted' | 'disconnected' | 'unsupported'
  /** 是否尝试将用户命令送入终端（探测失败时为 false）。 */
  commandSent: boolean
  /** 已通过探测，但宿主在业务命令发送前撤销授权；确定没有业务副作用。 */
  authorizationDenied?: boolean
  captureTruncated?: boolean
}

const CAPTURE_LIMIT = 64_000
const PROBE_TIMEOUT_MS = 3_000
const recentAgentResults = new WeakMap<AnyTerminalSession, {
  targetId: string | null
  results: NonNullable<TerminalContext['recentAgentResults']>
}>()

type BoundTerminalTarget =
  | { source: 'jumpserver'; tabId: string; targetId: string; hostKeyAlgorithm: string; hostKeyFingerprint: string }
  | { source: 'local'; tabId: string }
  | {
      source: 'direct'
      tabId: string
      host: string
      port: number
      username: string
      hostKeyAlgorithm: string
      hostKeyFingerprint: string
    }

function serializeBoundTerminalTarget(target: BoundTerminalTarget): string {
  return JSON.stringify(target)
}

/** POSIX 单引号转义：用户命令始终是 sh -c 的一个参数，不参与外层协议解析。 */
function quoteForSh(text: string): string {
  const chunks: string[] = []
  let chunk = ''
  let bytes = 0
  // 在单引号字符串之间用反斜杠续行，shell 会拼回同一个参数。
  // macOS 规范输入上限是 1024 字节；为引号、续行和协议前后缀留足空间。
  // 不往命令/路径中插入换行，也不改用户终端的 stty 设置。
  for (const character of text) {
    const atom = character === "'" ? "'\\''" : character
    const size = Buffer.byteLength(atom)
    if (bytes + size > 512) { chunks.push("'" + chunk + "'"); chunk = ''; bytes = 0 }
    chunk += atom; bytes += size
  }
  chunks.push("'" + chunk + "'")
  return chunks.join('\\\n')
}

/** 反斜杠加倍，其余非 ASCII/控制字节用 POSIX 八进制转义；接收后按原字节解码。 */
function encodeAgentScript(script: string): string {
  const lines: string[] = []
  let line = ''
  for (const byte of Buffer.from(script)) {
    const atom = byte === 92 ? '\\\\'
      : byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '\\0' + byte.toString(8).padStart(3, '0')
    if (line.length + atom.length > 512) { lines.push(line); line = '' }
    line += atom
  }
  lines.push(line)
  return lines.join('\n')
}

export class TerminalBridge {
  private session: AnyTerminalSession
  private disposed = false

  constructor(session: AnyTerminalSession) {
    this.session = session
  }

  /**
   * 释放 bridge 持有的引用。TerminalBridge 本身不订阅 session 事件，
   * 但保留这个方法以便 agent:bind 等场景能显式声明旧 bridge 不再使用，
   * 让 GC 立刻回收（而不是等 controller 引用被覆盖）。
   */
  dispose(): void {
    this.disposed = true
  }

  isDisposed(): boolean {
    return this.disposed
  }

  /**
   * 终端互斥锁的 key:底层真实 session 实例。
   * 两个聊天标签可对同一 session 创建不同 TerminalBridge 包装,
   * 命令串行必须按真实终端身份加锁,不能按 bridge 包装对象
   * (验收退回 F02)。模型侧不可指定该值。
   */
  getTerminalLockKey(): unknown {
    return this.session
  }

  /** SSH 的 connected 先于 shell channel 就绪；Agent 必须等到可写的 Shell。 */
  private isAgentReady(): boolean {
    if (!this.isConnected()) return false
    const ready = (this.session as { isShellReady?: () => boolean }).isShellReady
    return typeof ready !== 'function' || ready.call(this.session)
  }

  /**
   * 可跨应用重启核对的目标身份。不能用 displayName/displayDetail：
   * 同名资产、不同账号或同标签重连到另一主机都不能继承旧任务。
   * 旧快照未保存此身份时恢复须拒绝，而不是凭展示名猜测。
   */
  getBoundTargetId(): string | null {
    if (!this.isAgentReady()) return null
    const meta = this.session.sessionMeta
    if (meta?.source === 'jumpserver') {
      const hostKey = (this.session as TerminalSession).verifiedHostKey
      return meta.targetId && hostKey
        ? serializeBoundTerminalTarget({ source: 'jumpserver', tabId: this.session.tabId, targetId: meta.targetId,
          hostKeyAlgorithm: hostKey.algorithm, hostKeyFingerprint: hostKey.fingerprint })
        : null
    }
    if (meta?.source === 'local') {
      return serializeBoundTerminalTarget({ source: 'local', tabId: this.session.tabId })
    }
    const host = this.getCurrentHost()
    const hostKey = (this.session as TerminalSession).verifiedHostKey
    return host && hostKey
      ? serializeBoundTerminalTarget({
          source: 'direct',
          tabId: this.session.tabId,
          host: host.host,
          port: host.port,
          username: host.username,
          hostKeyAlgorithm: hostKey.algorithm,
          hostKeyFingerprint: hostKey.fingerprint,
        })
      : null
  }

  isConnected(): boolean {
    if (this.disposed) return false
    return this.session.connected
  }

  getCurrentHost(): { host: string; port: number; username: string } | null {
    // 本地会话没有 currentHost，SSH/JMP 会话才有
    const s = this.session as TerminalSession
    if (!s.currentHost) return null
    return {
      host: s.currentHost.host,
      port: s.currentHost.port,
      username: s.currentHost.username
    }
  }

  getDisplayIdentity(): { displayName: string; displayDetail: string; source: string } | null {
    const meta = this.session.sessionMeta
    if (meta) {
      // 本地会话：展示「本地终端 (macOS)」等可读名称
      if (meta.source === 'local') {
        return {
          displayName: meta.displayName || '本地终端',
          displayDetail: meta.displayName || '本地终端',
          source: 'local'
        }
      }
      // Jumpserver 会话：展示身份为「资产名 / 账号名」，确保绑定名能对上资产
      if (meta.source === 'jumpserver') {
        const detail = meta.displaySecondary
          ? `${meta.displayName} / ${meta.displaySecondary}`
          : meta.displayName
        return {
          displayName: meta.displayName,
          displayDetail: detail,
          source: meta.source
        }
      }
      // 直连模式：保持现有展示风格
      return {
        displayName: meta.displayName,
        displayDetail: meta.displaySecondary || meta.displayName,
        source: meta.source
      }
    }
    // 无元信息时回落底层 SSH 信息（仅 TerminalSession 有 currentHost）
    const s = this.session as TerminalSession
    const host = s.currentHost
    if (host) {
      return {
        displayName: `${host.username}@${host.host}`,
        displayDetail: `${host.username}@${host.host}:${host.port}`,
        source: 'direct'
      }
    }
    return null
  }

  getTerminalContext(lines = 200): TerminalContext {
    const identity = this.getDisplayIdentity()
    const journal = recentAgentResults.get(this.session)
    return {
      hostName: identity?.displayName || '未连接',
      hostDetails: identity?.displayDetail || '',
      source: (identity?.source as 'direct' | 'jumpserver' | 'local') || 'direct',
      recentOutput: this.session.getRecentOutput(lines),
      agentRecentOutput: stripVTControlCharacters(this.session.getRecentOutputForAgent?.(lines) ?? this.session.getRecentOutput(lines))
        .replace(/\r\n/g, '\n').replace(/\r/g, '\n'),
      isConnected: this.session.connected,
      recentAgentResults: journal?.targetId === this.getBoundTargetId() ? journal.results : []
    }
  }

  /**
   * Pi 专用命令协议：先验证交互 shell 能运行子 sh 并读取退出码，再由一个独立
   * sh -c 子进程执行用户命令；只有子进程退出且收到随机标记/退出码才算完成。
   * 子进程内 wait 等待其普通后台任务。cd/export 等不会改变交互 shell 状态。
   * Windows 或非 POSIX 终端在探测失败时不会收到用户命令。
   * 上层必须持有真实 session 锁，并在未验证结束时隔离整个 session。
   */
  async executeAgentCommand(command: string, timeout = 30_000, signal?: AbortSignal, authorizeBeforeSend?: () => boolean,
    summarizeOutput?: (output: string) => { text: string; truncated: boolean }): Promise<AgentCommandResult> {
    const startedAt = Date.now()
    const result = (completion: AgentCommandResult['completion'], output: string, commandSent: boolean, exitCode?: number, captureTruncated = false): AgentCommandResult => ({
      command,
      output,
      completion,
      commandSent,
      captureTruncated,
      ...(exitCode === undefined ? {} : { exitCode }),
      duration: Date.now() - startedAt
    })
    if (!this.isConnected()) return result('disconnected', '终端已断开', false)
    if (signal?.aborted) return result('aborted', '执行前已取消', false)
    if (!this.isAgentReady()) return result('unsupported', '终端 Shell 尚未就绪', false)
    if (process.platform === 'win32' && this.session.sessionMeta?.source === 'local') {
      return result('unsupported', '本地 Windows cmd/PowerShell 尚未实现可信完成协议', false)
    }
    const targetId = this.getBoundTargetId()

    const probeNonce = randomBytes(16).toString('hex')
    const probeMarker = `__ZTERM_AGENT_READY_${probeNonce}__`
    // 每条业务命令都重探测：用户可在同一 PTY 中手工切换 shell，不能沿用旧能力缓存。
    // 标记在输入中分成两个字符串，PTY 命令回显不会冒充完成信号。
    // printf 可在 fish/tcsh 上工作,不足以证明后续的 $? / var=... 语法。
    // 用无副作用子进程 exit 37 完整演练同一外层协议，退出码不符即拒绝业务命令。
    const probe = `command sh -c 'exit 37'; __zterm_agent_probe=$?; printf '\\n%s%s:%d\\n' '__ZTERM_AGENT_READY_' '${probeNonce}__' "$__zterm_agent_probe"\n`
    const handshake = await this.captureAgentMarker(probeMarker, probe, Math.min(timeout, PROBE_TIMEOUT_MS), signal, true)
    if (handshake.completion !== 'verified') {
      return result(handshake.completion, `终端不支持 Agent POSIX 完成协议或探测失败：${handshake.output}`, false)
    }
    if (handshake.exitCode !== 37) {
      return result('unsupported', '交互 Shell 未通过退出码探测，业务命令未下发', false)
    }

    // 探测是异步的；这段等待期间用户可能已切回只读或撤销绑定。
    if (authorizeBeforeSend && !authorizeBeforeSend()) {
      return { ...result('aborted', '执行授权已撤销，业务命令未下发', false), authorizationDenied: true }
    }

    const nonce = randomBytes(16).toString('hex')
    const marker = `__ZTERM_AGENT_END_${nonce}__`
    const startMarker = `__ZTERM_AGENT_BEGIN_${nonce}__`
    // 用户命令解码后仍作为 sh -c 的一个参数，不能提前结束外层完成协议。
    // wait 只等待该子 shell 自身的后台任务；显式脱离该 shell 的守护进程
    // 不属于同步命令结果，不能据此推断外部异步副作用已结束。
    const script = `${command}\n__zterm_agent_ec=$?\nwait\nexit "$__zterm_agent_ec"`
    // 就绪探测结束时，交互 Shell 的编辑器未必已经恢复。先用一个短行启动接收器，
    // 等它确认后再传脚本，由 read 消费短行，不经过 ZLE/Readline 的多行编辑。
    // 不修改 stty，不创建目标临时文件；EOF 或缺少随机发送边界时不执行脚本。
    const receiverMarker = `__ZTERM_AGENT_INPUT_${nonce}__`
    const sendMarker = `__ZTERM_AGENT_SEND_${nonce}__`
    const receiver = String.raw`printf "\n%s%s\n" "$1" "$4"; code=; received=; while IFS= read -r line; do if [ "$line" = "__ZTERM_AGENT_SEND_$4" ]; then received=1; break; fi; code="$code$line"; done; [ "$received" = 1 ] || exit 1; printf "\n%s%s\n" "$2" "$4"; command sh -c "$(printf "%b" "$code")"; ec=$?; printf "\n%s%s:%d\n" "$3" "$4" "$ec"`
    const wrapped = `command sh -c ${quoteForSh(receiver)} sh '__ZTERM_AGENT_INPUT_' '__ZTERM_AGENT_BEGIN_' '__ZTERM_AGENT_END_' '${nonce}__'\n`
    const execution = await this.captureAgentMarker(marker, wrapped, timeout, signal, true, startMarker, {
      marker: receiverMarker, input: `${encodeAgentScript(script)}\n${sendMarker}\n`, authorize: authorizeBeforeSend,
    })
    if (execution.completion === 'verified' && execution.exitCode !== undefined) {
      const journal = recentAgentResults.get(this.session)
      // 查询元数据供工具解析；历史与界面保留对应的可读结果，不暴露内部文件帧。
      let summary = { text: execution.output, truncated: false }
      try { summary = summarizeOutput?.(execution.output) ?? summary }
      catch { summary = { text: '查询已结束，历史摘要不可用。', truncated: true } }
      recentAgentResults.set(this.session, { targetId, results: [
        ...(journal?.targetId === targetId ? journal.results : []),
        { output: summary.text.slice(0, 8000), exitCode: execution.exitCode, observedAt: new Date().toISOString(),
          truncated: summary.truncated || summary.text.length > 8000 || execution.truncated },
      ].slice(-6) })
    }
    return result(execution.completion, execution.output, execution.sent, execution.exitCode, execution.truncated)
  }

  private captureAgentMarker(
    marker: string,
    input: string,
    timeout: number,
    signal?: AbortSignal,
    withExitCode = false,
    startMarker?: string,
    receiver?: { marker: string; input: string; authorize?: () => boolean },
  ): Promise<{ completion: AgentCommandResult['completion']; output: string; sent: boolean; truncated: boolean; exitCode?: number }> {
    if (!this.isAgentReady()) return Promise.resolve({ completion: 'disconnected', output: '终端 Shell 未就绪或已断开', sent: false, truncated: false })
    if (signal?.aborted) return Promise.resolve({ completion: 'aborted', output: '执行前已取消', sent: false, truncated: false })
    return new Promise((resolve) => {
      const decoder = new TextDecoder()
      // 只允许边界标记内部的折行，不对业务结果拼行或解析命令回显。
      const foldedMarker = (value: string): string => value.split('').join('[\\r\\n]*')
      const pattern = withExitCode
        ? new RegExp(`(?:^|\\r?\\n)${foldedMarker(marker)}[\\r\\n]*:([0-9](?:[\\r\\n]*[0-9]){0,2})(?=\\r?\\n)`)
        : new RegExp(`(?:^|\\r?\\n)${foldedMarker(marker)}(?=\\r?\\n)`)
      const startPattern = startMarker
        ? new RegExp(`(?:^|\\r?\\n)${foldedMarker(startMarker)}\\r?\\n`) : undefined
      const receiverPattern = receiver
        ? new RegExp(`(?:^|\\r?\\n)${foldedMarker(receiver.marker)}\\r?\\n`) : undefined
      let dispatched = false
      let started = !startPattern
      let capture = ''
      let truncated = false
      let settled = false
      let sent = false
      let timer: ReturnType<typeof setTimeout> | undefined
      const finish = (completion: AgentCommandResult['completion'], exitCode?: number, markerIndex?: number): void => {
        if (settled) return
        settled = true
        if (timer) clearTimeout(timer)
        this.session.removeListener('data', onData)
        this.session.removeListener('closed', onDisconnect)
        this.session.removeListener('shell-closed', onDisconnect)
        this.session.removeListener('error', onDisconnect)
        signal?.removeEventListener('abort', onAbort)
        // 未验证完成的区间继续隔离，防止迟到回显进入模型历史；新会话重置缓冲。
        if (sent && completion === 'verified') this.session.endAgentOutput?.()
        const clean = stripVTControlCharacters(capture)
        const output = !started ? '' : markerIndex === undefined ? clean : clean.slice(0, markerIndex)
        resolve({
          completion,
          output: `${truncated ? '[前段输出已截断]\n' : ''}${output.replace(/\r\n/g, '\n')}`,
          sent,
          truncated,
          ...(exitCode === undefined ? {} : { exitCode })
        })
      }
      const onData = (raw: Buffer | string): void => {
        capture += typeof raw === 'string' ? raw : decoder.decode(raw, { stream: true })
        if (receiver && receiverPattern && !dispatched && receiverPattern.test(stripVTControlCharacters(capture))) {
          dispatched = true
          // 接收器握手也是异步边界，执行数据发送前再次检查权限。
          if (signal?.aborted || receiver.authorize && !receiver.authorize()) { finish('aborted'); return }
          try { this.session.write(receiver.input) }
          catch { finish('disconnected'); return }
          if (settled) return
        }
        if (!started && startPattern && (!receiver || dispatched)) {
          const clean = stripVTControlCharacters(capture)
          const start = startPattern.exec(clean)
          if (start) {
            capture = clean.slice(start.index + start[0].length)
            started = true
          }
        }
        if (capture.length > CAPTURE_LIMIT) {
          capture = capture.slice(-CAPTURE_LIMIT)
          truncated ||= started
        }
        if (!started) return
        const match = pattern.exec(stripVTControlCharacters(capture))
        if (match) finish('verified', withExitCode ? Number(match[1].replace(/[\r\n]/g, '')) : undefined, match.index)
      }
      const onDisconnect = (): void => finish('disconnected')
      const onAbort = (): void => finish('aborted')
      this.session.on('data', onData)
      this.session.on('closed', onDisconnect)
      this.session.on('shell-closed', onDisconnect)
      this.session.on('error', onDisconnect)
      signal?.addEventListener('abort', onAbort, { once: true })
      timer = setTimeout(() => finish('timedOut'), timeout)
      if (signal?.aborted || !this.isAgentReady()) {
        finish(signal?.aborted ? 'aborted' : 'disconnected')
        return
      }
      try {
        sent = true
        this.session.beginAgentOutput?.()
        this.session.write(input)
      } catch {
        finish('disconnected')
      }
    })
  }

}
