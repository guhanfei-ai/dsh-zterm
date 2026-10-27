import { randomUUID } from 'node:crypto'
import { homedir } from 'node:os'
import { StringDecoder } from 'node:string_decoder'
import { TerminalSession } from '../core/terminalSessionManager'
import { LocalPtySession, getPlatformShell } from '../core/localPtySession'
import { TerminalBridge, type AnyTerminalSession } from '../core/terminalBridge'
import { checkCommand } from '../core/safetyGuard'
import { isAgentTerminalBusy, isAgentTerminalUncertain, markAgentTerminalUncertain, noteManualTerminalInput, withAgentTerminalLock } from '../core/agentTerminalCoordinator'
import { createBuiltinReadTools, type PreparedRead, type ReadExecutionDetails } from '../core/agentReadTools'
import { fetchJumpserverAssets, fetchJumpserverNodes, fetchJumpserverNodeAssets, fetchJumpserverAccounts, testJumpserverConnection, createJumpserverFreshToken, resolveKokoSshParams, type JumpserverConnectionParams } from '../core/jumpserverClient'
import { normalizeSshHost, normalizeSshPort } from '../core/sshHostTrust'
import type { AgentToolResult } from '../core/toolTypes'
import type { Config, ConnectTarget, AutomaticTarget, TargetIdentity, TerminalView, BindingView, Operation, WorkspaceView, OutputFrame, PollResult, HostTarget, ToolExec } from '../shared/types'
import { id, label, integer, hostAuthentication } from './config'
import { RecordStore } from './store'
import { readDefaultPrivateKey } from './defaultSsh'
import { ZtermError, checkCancelled } from './errors'

export { ZtermError } from './errors'
function fail(code: string, message: string): never { throw new ZtermError(code, message) }
interface Entry {
  id: string; owner: string; generation: number; target: TargetIdentity; descriptor: ConnectTarget
  terminal: AnyTerminalSession; bridge: TerminalBridge; state: TerminalView['state']; error?: string
  agentReady: boolean; trust?: TerminalView['trust']; createdAt: string; controllers: Set<AbortController>
  decoder: StringDecoder
}
interface State {
  entries: Map<string, Entry>; binding?: BindingView & { token: string; identity: string }
  operations: Operation[]; frames: OutputFrame[]; frameChars: number; cursor: number; revision: number; calls: Set<string>; pageId?: string; restoring?: boolean
}
export interface RuntimeDeps {
  config: () => Config; credentials: { resolve(ref: string): Promise<{ value: string } | undefined> }
  store: RecordStore; sessionCwd: (sessionId: string) => string | undefined
  terminalFactory?: (terminalId: string, generation: number, local: boolean, cwd?: string) => AnyTerminalSession
  resolveAutomaticTarget?: (target: AutomaticTarget, signal?: AbortSignal) => Promise<ConnectTarget>
  defaultSshHome?: string
  configRevision?: () => number | undefined
}
export class ZtermRuntime {
  private states = new Map<string, State>()
  private secrets = new Set<string>()
  private disposed = false
  readonly readTools = createBuiltinReadTools(() => { throw new Error('读取工具必须在当前会话内创建') })
  constructor(private readonly deps: RuntimeDeps) {}
  sanitize(text: string): string {
    let result = text
    for (const secret of this.secrets) if (secret.length >= 4) result = result.replaceAll(secret, '[凭据已隐藏]')
    return result.replace(/(authorization\s*[:=]\s*(?:bearer|basic)\s+)\S+/ig, '$1[已隐藏]')
  }
  private state(sessionId: string): State {
    if (this.disposed) fail('disposed', '插件已卸载')
    id(sessionId, 'DSH 会话标识')
    if (!this.states.has(sessionId)) {
      if (this.states.size >= 256) fail('session_limit', '插件会话数量已达上限')
      this.states.set(sessionId, { entries: new Map(), operations: this.deps.store.history(sessionId), frames: [], frameChars: 0, cursor: 0, revision: 0, calls: this.deps.store.calls(sessionId) })
    }
    return this.states.get(sessionId)!
  }
  private entry(sessionId: string, terminalId: string, generation?: number): Entry {
    const entry = this.state(sessionId).entries.get(terminalId)
    if (!entry || entry.owner !== sessionId) fail('unknown_terminal', '终端不存在或不属于当前会话')
    if (generation !== undefined && generation !== entry.generation) fail('stale_connection', '连接已变化，请刷新当前目标')
    return entry
  }
  private touch(sessionId: string): void { this.state(sessionId).revision++ }
  private async secret(ref?: string): Promise<string | undefined> {
    if (!ref) return undefined
    const result = await this.deps.credentials.resolve(ref)
    if (!result?.value) fail('credential_missing', `尚未配置凭据 ${ref}`)
    this.secrets.add(result.value); return result.value
  }
  private async sshOptions(host: HostTarget, signal?: AbortSignal) {
    const auth = hostAuthentication(host, this.deps.config())
    let defaultKey: string | undefined
    let filePassphrase: string | undefined
    if (auth.authType === 'key-file') {
      filePassphrase = await this.secret(auth.passphraseRef)
      defaultKey = await readDefaultPrivateKey(auth.privateKeyPath || this.deps.config().defaultPrivateKeyPath, filePassphrase, signal, this.deps.defaultSshHome)
      this.secrets.add(defaultKey)
    }
    return { host: host.host, port: host.port, username: host.username, requireHostTrust: true,
      ...(auth.authType === 'password' ? { password: await this.secret(auth.credentialRef) } : {}),
      ...(auth.authType === 'key' ? { privateKey: await this.secret(auth.credentialRef), passphrase: await this.secret(auth.passphraseRef) } : {}),
      ...(auth.authType === 'key-file' ? { privateKey: defaultKey, passphrase: filePassphrase } : {}) }
  }
  private async jumpParams(instanceId: string): Promise<JumpserverConnectionParams> {
    const profile = this.deps.config().jumpservers.find((p) => p.id === instanceId)
    if (!profile) fail('unknown_instance', '未配置该 JumpServer 实例')
    const credential = await this.secret(profile.credentialRef)
    return { baseUrl: profile.baseUrl, authMode: profile.authMode, username: profile.username, verifyTls: profile.verifyTls,
      ...(profile.authMode === 'access_key' ? { accessKeyId: await this.secret(profile.accessKeyIdRef), accessKeySecret: credential } : { credential }) }
  }
  async jumpQuery(instanceId: string, operation: string, args: any = {}): Promise<unknown> {
    const params = await this.jumpParams(id(instanceId))
    const limit = integer(args.limit, 100, 1, 200), offset = integer(args.offset, 0, 0, 1000000)
    let result: any
    if (operation === 'status') result = await testJumpserverConnection(params)
    else if (operation === 'nodes') {
      if (args.parentKey !== undefined && (typeof args.parentKey !== 'string' || args.parentKey.length > 2000 || /[\x00-\x1f\x7f]/.test(args.parentKey))) fail('invalid_query', '节点路径标识无效')
      result = await fetchJumpserverNodes(params, args.parentKey)
    }
    else if (operation === 'assets') result = args.nodeId ? await fetchJumpserverNodeAssets(params, id(args.nodeId), { limit, offset, keyword: typeof args.query === 'string' ? args.query.slice(0, 100) : undefined })
      : await fetchJumpserverAssets(params, { limit, offset, keyword: typeof args.query === 'string' ? args.query.slice(0, 100) : undefined })
    else if (operation === 'accounts') result = await fetchJumpserverAccounts(params, id(args.assetId))
    else fail('invalid_query', 'JumpServer 查询类型无效')
    if (!result.success) fail('jumpserver_error', this.sanitize(result.error || 'JumpServer 查询失败'))
    // 树与账号同样有输出上限，原始结果不进入模型上下文。
    if (Array.isArray(result.nodes) && result.nodes.length > 500) result = { ...result, nodes: result.nodes.slice(0, 500), truncated: true }
    if (Array.isArray(result.accounts) && result.accounts.length > 200) result = { ...result, accounts: result.accounts.slice(0, 200), truncated: true }
    return this.publicValue(result)
  }
  private async resolveTarget(raw: any, signal?: AbortSignal): Promise<{ descriptor: ConnectTarget; target: TargetIdentity; options?: any }> {
    const config = this.deps.config()
    if (!raw || typeof raw !== 'object') fail('invalid_target', '缺少连接目标')
    if ((raw.kind === undefined || raw.kind === 'auto') && !('targetId' in raw)) {
      if (!this.deps.resolveAutomaticTarget) fail('resolver_unavailable', '自动主机查找服务不可用')
      return this.resolveTarget(await this.deps.resolveAutomaticTarget(raw, signal), signal)
    }
    if ('targetId' in raw) {
      const host = config.hosts.find((h) => h.id === id(raw.targetId))
      if (!host) fail('unknown_target', '未配置该主机')
      return { descriptor: { targetId: host.id }, target: { source: 'ssh', assetId: host.id, label: host.label, host: host.host, port: host.port, username: host.username }, options: await this.sshOptions(host, signal) }
    }
    if (raw.kind === 'local') {
      if (!config.allowLocalTerminal) fail('local_disabled', '本地终端尚未启用；它对应 DSH 宿主机器')
      return { descriptor: { kind: 'local' }, target: { source: 'local', assetId: 'dsh-host', label: `DSH 宿主 (${process.platform})`, username: '当前宿主用户' } }
    }
    if (raw.kind === 'external') {
      if (!config.allowExternalTargets) fail('external_disabled', '尚未允许使用配置的凭据连接外部资产地址')
      const profile = config.hosts.find((h) => h.id === id(raw.profileId))
      const host = normalizeSshHost(raw.host), port = normalizeSshPort(raw.port ?? 22)
      if (!profile || !host || /[\s/@?#\\]/.test(host) || !port) fail('invalid_target', '外部资产地址或凭据主机配置无效')
      const descriptor: ConnectTarget = { kind: 'external', assetId: id(raw.assetId), profileId: profile.id, host, port, label: label(raw.label, host) }
      return { descriptor, target: { source: 'external', assetId: descriptor.assetId, label: descriptor.label!, host, port, username: profile.username }, options: await this.sshOptions({ ...profile, host, port }, signal) }
    }
    if (raw.kind === 'jumpserver') {
      const instanceId = id(raw.instanceId), assetId = id(raw.assetId), accountId = id(raw.accountId)
      const params = await this.jumpParams(instanceId)
      const token = await createJumpserverFreshToken(params, assetId, accountId)
      if (!token.success || !token.token) fail('jumpserver_error', this.sanitize(token.error || '连接令牌创建失败'))
      this.secrets.add(token.token.value)
      const endpoint = resolveKokoSshParams(token.token, token.token.clientUrl, params.baseUrl)
      if (!endpoint.success || !endpoint.params) fail('jumpserver_error', this.sanitize(endpoint.error || '无法解析 SSH 网关'))
      const descriptor: ConnectTarget = { kind: 'jumpserver', instanceId, assetId, accountId, label: label(raw.label, assetId), accountName: label(raw.accountName, accountId) }
      return { descriptor, target: { source: 'jumpserver', assetId, instanceId, accountId, label: descriptor.label!, username: descriptor.accountName }, options: { ...endpoint.params, requireHostTrust: true } }
    }
    return fail('invalid_target', '不支持的连接目标')
  }
  async connect(sessionId: string, raw: unknown, reuseId?: string, signal?: AbortSignal): Promise<TerminalView> {
    checkCancelled(signal)
    const state = this.state(sessionId), config = this.deps.config()
    if (!reuseId && state.entries.size >= config.maxSessions) fail('terminal_limit', '当前会话终端数量已达上限，请关闭不用的标签')
    const previous = reuseId ? this.entry(sessionId, reuseId) : undefined
    if (previous && isAgentTerminalBusy(previous.terminal)) fail('terminal_busy', '请先停止正在执行的操作再重连')
    const resolved = await this.resolveTarget(raw, signal)
    checkCancelled(signal)
    if (this.disposed) fail('disposed', '插件已卸载')
    if (!reuseId && state.entries.size >= this.deps.config().maxSessions) fail('terminal_limit', '当前会话终端数量已达上限，请关闭不用的标签')
    if (previous && (state.entries.get(reuseId!) !== previous || isAgentTerminalBusy(previous.terminal))) fail('stale_connection', '连接或操作状态已变化，请重新确认目标')
    const terminalId = reuseId ?? randomUUID(), generation = (previous?.generation ?? 0) + 1
    if (previous) { previous.controllers.forEach((c) => c.abort()); previous.bridge.dispose(); previous.terminal.disconnect() }
    if (state.binding?.terminalId === terminalId) state.binding = undefined
    const local = resolved.target.source === 'local'
    const terminal = this.deps.terminalFactory?.(terminalId, generation, local, this.deps.sessionCwd(sessionId))
      ?? (local ? new LocalPtySession(terminalId, generation, this.deps.sessionCwd(sessionId) ?? homedir()) : new TerminalSession(terminalId, generation, undefined, this.deps.store))
    terminal.sessionMeta = { source: local ? 'local' : resolved.target.source === 'jumpserver' ? 'jumpserver' : 'direct',
      displayName: resolved.target.label, displaySecondary: resolved.target.username,
      ...(resolved.target.source === 'jumpserver' ? { targetId: JSON.stringify([resolved.target.instanceId, resolved.target.assetId, resolved.target.accountId]) } : {}) }
    const entry: Entry = { id: terminalId, owner: sessionId, generation, descriptor: resolved.descriptor, target: resolved.target,
      terminal, bridge: new TerminalBridge(terminal), state: 'connecting', agentReady: false, createdAt: new Date().toISOString(), controllers: new Set(), decoder: new StringDecoder('utf8') }
    state.entries.set(terminalId, entry)
    const current = () => state.entries.get(terminalId) === entry && !this.disposed
    terminal.on('data', (bytes: Buffer) => { if (!current()) return; const decoded = entry.decoder.write(bytes); if (!decoded) return
      const text = this.sanitize(decoded).slice(-64000)
      state.frames.push({ seq: ++state.cursor, terminalId, generation, text }); state.frameChars += text.length
      while (state.frames.length > 1000 || state.frameChars > 1000000) state.frameChars -= state.frames.shift()!.text.length })
    terminal.on('host-trust-required', (event: any) => { if (current()) { entry.trust = { requestId: event.requestId, kind: event.kind, host: event.host, port: event.port,
      username: event.username, algorithm: event.algorithm, fingerprint: event.fingerprint, trustedFingerprint: event.trustedFingerprint }; this.touch(sessionId) } })
    const closed = () => { if (!current()) return; entry.state = 'disconnected'; entry.agentReady = false; entry.controllers.forEach((c) => c.abort());
      if (state.binding?.terminalId === terminalId) state.binding = undefined; this.touch(sessionId) }
    terminal.on('closed', closed); terminal.on('shell-closed', closed)
    terminal.on('error', (error: Error) => { if (current()) { entry.error = this.sanitize(error.message); entry.state = 'error'; this.touch(sessionId) } })
    this.touch(sessionId)
    // 建连后台完成，浏览器仍可轮询指纹请求，不能让 UI 等待请求时失去确认入口。
    void (async () => {
      try {
        if (local) await (terminal as LocalPtySession).connect(getPlatformShell(), 100, 30)
        else { await (terminal as TerminalSession).connect(resolved.options); if (!current()) return; await (terminal as TerminalSession).openShell(100, 30) }
        if (!current()) return
        if (!terminal.connected || !terminal.isShellReady()) fail('shell_unavailable', '连接已结束或 Shell 尚未就绪')
        entry.state = 'ready'; entry.agentReady = true; entry.error = undefined; entry.trust = undefined
      } catch (error) { if (current()) { entry.state = 'error'; entry.agentReady = false; entry.error = this.sanitize(error instanceof Error ? error.message : '连接失败') } }
      finally { if (current()) { this.touch(sessionId); this.saveWorkspace(sessionId) } }
    })()
    return this.view(entry)
  }
  private view(entry: Entry): TerminalView {
    return { id: entry.id, generation: entry.generation, target: entry.target, state: entry.state, error: entry.error,
      busy: isAgentTerminalBusy(entry.terminal), uncertain: isAgentTerminalUncertain(entry.terminal), agentReady: entry.agentReady,
      fingerprint: (entry.terminal as TerminalSession).verifiedHostKey?.fingerprint, trust: entry.trust, createdAt: entry.createdAt }
  }
  workspace(sessionId: string): WorkspaceView {
    const state = this.state(sessionId), { token: _token, identity: _identity, ...binding } = state.binding ?? {} as any
    return { terminals: [...state.entries.values()].map((e) => this.view(e)), ...(state.binding ? { binding } : {}),
      operations: this.boundedRecords(state.operations.slice(-100), 16000), revision: state.revision,
      capabilities: { local: this.deps.config().allowLocalTerminal, external: this.deps.config().allowExternalTargets, automatic: Boolean(this.deps.resolveAutomaticTarget) },
      hostPlatform: process.platform, catalogRevision: this.deps.configRevision?.() }
  }
  poll(sessionId: string, cursor: number): PollResult {
    const state = this.state(sessionId), oldest = state.frames[0]?.seq ?? state.cursor + 1
    const reset = !Number.isInteger(cursor) || cursor < oldest - 1 || cursor > state.cursor
    return { workspace: this.workspace(sessionId), cursor: state.cursor, reset,
      output: reset ? [] : state.frames.filter((f) => f.seq > cursor),
      ...(reset ? { snapshots: [...state.entries.values()].map((e) => ({ terminalId: e.id, generation: e.generation, text: this.sanitize(e.terminal.getRecentOutput(5000)).slice(-250000) })) } : {}) }
  }
  bind(sessionId: string, terminalId: string, generation: number): BindingView {
    const entry = this.entry(sessionId, terminalId, generation), state = this.state(sessionId)
    const identity = entry.bridge.getBoundTargetId()
    if (entry.state !== 'ready' || !identity) fail('not_connected', '目标尚未连接到可用 Shell')
    if (!entry.agentReady) fail('shell_not_ready', '手工输入后，请在终端工具栏确认已回到空闲 Shell')
    if (isAgentTerminalUncertain(entry.terminal)) fail('result_unknown', '前次结果不明，请核实并重建连接')
    if (state.binding?.terminalId === terminalId && state.binding.generation === generation) return this.publicBinding(state.binding)
    state.binding = { terminalId, generation, identity, token: randomUUID(), mode: 'read', writeCalls: 0, maxWriteCalls: this.deps.config().maxWriteCalls }
    this.touch(sessionId); return this.publicBinding(state.binding)
  }
  setMode(sessionId: string, terminalId: string, generation: number, mode: unknown): BindingView {
    if (mode !== 'read' && mode !== 'readwrite') fail('invalid_mode', '模式无效')
    const entry = this.entry(sessionId, terminalId, generation), state = this.state(sessionId)
    if (!state.binding || state.binding.terminalId !== terminalId || state.binding.generation !== generation) fail('not_bound', '请先将该终端明确绑定给 AI')
    if (mode === 'readwrite' && (entry.state !== 'ready' || !entry.agentReady || isAgentTerminalUncertain(entry.terminal))) fail('not_ready', '终端未处于可执行状态')
    const previous = state.binding
    if (previous.mode !== mode) state.binding = { ...previous, mode, token: randomUUID(),
      writeCalls: mode === 'readwrite' ? 0 : previous.writeCalls, maxWriteCalls: this.deps.config().maxWriteCalls }
    this.touch(sessionId); return this.publicBinding(state.binding!)
  }
  private publicBinding(binding: BindingView): BindingView { return { terminalId: binding.terminalId, generation: binding.generation, mode: binding.mode, writeCalls: binding.writeCalls, maxWriteCalls: binding.maxWriteCalls } }
  attachClient(sessionId: string, pageId: string): void {
    id(pageId, '客户端标识'); const state = this.state(sessionId)
    if (state.pageId !== pageId) { state.pageId = pageId; if (state.binding) state.binding = { ...state.binding, token: randomUUID(), mode: 'read' }; this.touch(sessionId) }
  }
  assertClient(sessionId: string, pageId: string): void { if (this.state(sessionId).pageId !== pageId) fail('stale_client', '客户端已变化，请刷新工作台后重新确认模式') }
  trust(sessionId: string, terminalId: string, generation: number, requestId: string, decision: any): void {
    const entry = this.entry(sessionId, terminalId, generation)
    if (entry.target.source === 'local') fail('invalid_trust', '本地终端没有 SSH 指纹请求')
    const result = (entry.terminal as TerminalSession).respondHostTrust({ tabId: terminalId, generation, requestId, decision })
    if (!result.success) fail('trust_expired', result.error)
    entry.trust = undefined; this.touch(sessionId)
  }
  resetTrust(sessionId: string, terminalId: string): void {
    const entry = this.entry(sessionId, terminalId)
    if (entry.trust?.kind !== 'changed') fail('invalid_trust', '当前没有指纹变更需要核实')
    this.deps.store.resetTrust(entry.trust.host, entry.trust.port); entry.trust = undefined; this.touch(sessionId)
  }
  manualInput(sessionId: string, terminalId: string, generation: number, data: unknown): void {
    const entry = this.entry(sessionId, terminalId, generation)
    if (typeof data !== 'string' || Buffer.byteLength(data) > 64000) fail('invalid_input', '终端输入无效或过长')
    if (entry.state !== 'ready') fail('not_connected', '终端尚未连接')
    if (isAgentTerminalBusy(entry.terminal)) fail('terminal_busy', 'AI 正在占用终端，请先停止并接管')
    noteManualTerminalInput(entry.terminal, data)
    if (!/^\x1b\[(?:\d+;\d+R|[?>][\d;]*c)$/.test(data)) { entry.agentReady = false;
      const state = this.state(sessionId); if (state.binding?.terminalId === terminalId) state.binding = { ...state.binding, mode: 'read', token: randomUUID() }; this.touch(sessionId) }
    entry.terminal.write(data)
  }
  acknowledgeShell(sessionId: string, terminalId: string, generation: number): void {
    const entry = this.entry(sessionId, terminalId, generation)
    if (entry.state !== 'ready' || isAgentTerminalBusy(entry.terminal) || isAgentTerminalUncertain(entry.terminal)) fail('not_ready', '请先结束操作或重建结果不明的连接')
    noteManualTerminalInput(entry.terminal, '\x03'); entry.agentReady = true; this.touch(sessionId)
  }
  resize(sessionId: string, terminalId: string, generation: number, cols: unknown, rows: unknown): void {
    this.entry(sessionId, terminalId, generation).terminal.resize(integer(cols, 100, 2, 500), integer(rows, 30, 2, 300))
  }
  stop(sessionId: string, terminalId: string, generation: number): void {
    const entry = this.entry(sessionId, terminalId, generation)
    entry.controllers.forEach((c) => c.abort()); const binding = this.state(sessionId).binding
    if (binding?.terminalId === terminalId) binding.mode = 'read'; this.touch(sessionId)
  }
  disconnect(sessionId: string, terminalId: string, close = false): void {
    const entry = this.entry(sessionId, terminalId), state = this.state(sessionId)
    entry.controllers.forEach((c) => c.abort()); entry.bridge.dispose(); entry.terminal.disconnect(); entry.state = 'disconnected'; entry.agentReady = false; entry.trust = undefined
    if (state.binding?.terminalId === terminalId) state.binding = undefined
    if (close) state.entries.delete(terminalId)
    this.touch(sessionId); this.saveWorkspace(sessionId)
  }
  reconnect(sessionId: string, terminalId: string) { return this.connect(sessionId, this.entry(sessionId, terminalId).descriptor, terminalId) }
  private saveWorkspace(sessionId: string): void {
    const state = this.state(sessionId)
    if (state.restoring) return
    try { this.deps.store.saveWorkspace(sessionId, [...state.entries.values()].map((e) => e.descriptor)) }
    catch (error) { for (const entry of state.entries.values()) entry.error = `终端列表未保存：${this.sanitize(error instanceof Error ? error.message : '存储失败')}`; this.touch(sessionId) }
  }
  savedWorkspace(sessionId: string) { return this.deps.store.workspace(sessionId) }
  async restoreWorkspace(sessionId: string): Promise<TerminalView[]> {
    const state = this.state(sessionId)
    if (state.entries.size || state.restoring) fail('workspace_not_empty', '当前已有终端或正在恢复，请先关闭后再恢复')
    const targets = this.savedWorkspace(sessionId), results: TerminalView[] = []
    state.restoring = true
    try { for (const target of targets) results.push(await this.connect(sessionId, target)); return results }
    finally {
      state.restoring = false
      // 部分目标失败时保留原列表，维护者修复配置后仍能再次恢复。
      this.deps.store.saveWorkspace(sessionId, targets)
    }
  }
  private boundedRecords(records: Operation[], budget: number): Operation[] {
    const summaries = records.map((record) => ({ ...record, label: record.label.slice(0, 96), truncated: record.truncated || record.label.length > 96 }))
    budget -= summaries.reduce((sum, record) => sum + record.label.length, 0)
    return summaries.reverse().map((record) => {
      let truncated = record.truncated
      const take = (text: string | undefined) => { if (text === undefined) return undefined; const value = text.slice(0, Math.max(0, budget)); budget -= value.length; if (value.length < text.length) truncated = true; return value }
      const command = take(record.command), error = take(record.error), output = take(record.output)!
      return { ...record, error, output, command, truncated }
    }).reverse()
  }
  records(sessionId: string, limit = 100) { return this.boundedRecords(this.state(sessionId).operations.slice(-Math.min(200, Math.max(1, limit))), 64000) }
  context(sessionId: string) {
    const state = this.state(sessionId), binding = state.binding
    if (!binding) fail('not_bound', '请先绑定明确的终端目标')
    const entry = this.entry(sessionId, binding.terminalId, binding.generation)
    return this.publicValue({ target: entry.target, context: entry.bridge.getTerminalContext(200), mode: binding.mode, agentReady: entry.agentReady, historyLimited: true })
  }
  publicValue(value: any): any {
    if (typeof value === 'string') return this.sanitize(value)
    if (Array.isArray(value)) return value.map((item) => this.publicValue(item))
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, this.publicValue(item)]))
    return value
  }
  async execute(sessionId: string, exec: ToolExec, tool: string, command: string, prepared?: PreparedRead): Promise<AgentToolResult<ReadExecutionDetails>> {
    const state = this.state(sessionId), callId = exec.callId || randomUUID()
    if (state.calls.has(callId)) return { content: [{ type: 'text', text: '重复调用已跳过；命令未再次执行。请查看已有操作记录。' }], details: { skipped: true, error: 'duplicate_call_id' } }
    if (state.calls.size >= 10000 || callId.length > 256) fail('call_limit', '当前会话执行标识已达上限，请开启新的 DSH 会话')
    state.calls.add(callId)
    try { this.deps.store.addCall(sessionId, callId) } catch (error) { state.calls.delete(callId); throw error }
    return this.run(sessionId, callId, exec.signal, tool, command, prepared)
  }
  finalizeRead(sessionId: string, callId: string, tool: string, result: AgentToolResult<ReadExecutionDetails>): void {
    if (result.details.skipped) return
    const state = this.state(sessionId), record = state.operations.find((r) => r.callId === callId)
    if (!record) return
    const observations = result.content.flatMap((item) => { try { return [JSON.parse(item.text)] } catch { return [] } })
    const error = observations.find((value) => value.status === 'error')?.error
    if (error && record.completion === 'verified') { record.status = 'failed'; record.error = this.sanitize(error.message) }
    record.tool = tool; record.output = this.sanitize(result.details.displayOutput ?? record.output).slice(0, 64000)
    record.truncated = Boolean(result.details.truncated ?? record.truncated)
    this.deps.store.append(record); this.touch(sessionId)
  }
  private async run(sessionId: string, callId: string, signal: AbortSignal | undefined, tool: string, command: string, prepared?: PreparedRead): Promise<AgentToolResult<ReadExecutionDetails>> {
    const state = this.state(sessionId), binding = state.binding
    if (!binding) fail('not_bound', '请先将明确的终端绑定给 AI')
    const entry = this.entry(sessionId, binding.terminalId, binding.generation), controller = new AbortController()
    const abort = () => controller.abort(signal?.reason)
    if (signal?.aborted) abort(); else signal?.addEventListener('abort', abort, { once: true })
    entry.controllers.add(controller)
    const valid = () => !this.disposed && state.binding?.token === binding.token && entry.generation === binding.generation
      && entry.state === 'ready' && entry.agentReady && entry.bridge.getBoundTargetId() === binding.identity
    const allowed = () => valid() && (Boolean(prepared) || state.binding?.mode === 'readwrite') && !controller.signal.aborted
    const record: Operation = { version: 1, id: randomUUID(), callId, tool, sessionId, terminalId: entry.id, generation: entry.generation,
      target: entry.target, startedAt: new Date().toISOString(), status: 'executing', label: this.sanitize(prepared?.label ?? command),
      ...(prepared ? {} : { command: this.sanitize(command) }), exitCode: null, output: '', truncated: false }
    const save = () => { const index = state.operations.findIndex((r) => r.id === record.id); if (index >= 0) state.operations[index] = { ...record }; else state.operations.push({ ...record });
      state.operations = state.operations.slice(-200); this.deps.store.append(record); this.touch(sessionId) }
    let result: AgentToolResult<ReadExecutionDetails>
    try {
      result = await withAgentTerminalLock(entry.terminal, controller.signal, async () => {
        if (!allowed()) fail('permission_denied', '绑定、模式或连接已变化，命令未下发')
        if (isAgentTerminalUncertain(entry.terminal)) fail('result_unknown', '前次结果不明，请核实并重建连接')
        if (!prepared) {
          if (command.length > 16000 || /[\x00-\x1f\x7f]/.test(command)) fail('invalid_command', '命令不能包含控制字符或超过长度上限')
          const check = checkCommand(command, true)
          if (check.blocked) fail('command_blocked', check.reason ?? '命令被策略拒绝')
          if (binding.writeCalls >= binding.maxWriteCalls) fail('budget_exhausted', '本次读写授权的命令预算已用尽，请总结并由人类重新授权')
          binding.writeCalls++
        }
        save()
        const completed = await entry.bridge.executeAgentCommand(command, this.deps.config().commandTimeoutMs, controller.signal,
          () => allowed() && (Boolean(prepared) || !checkCommand(command, true).blocked), prepared?.summarizeOutput)
        record.completion = completed.completion; record.exitCode = completed.exitCode ?? null
        record.output = this.sanitize(prepared?.summarizeOutput?.(completed.output).text ?? completed.output).slice(0, 64000)
        record.truncated = Boolean(completed.captureTruncated || completed.output.length > 64000)
        record.status = completed.completion === 'verified' ? completed.exitCode === 0 ? 'completed' : 'failed' : completed.commandSent ? 'unknown' : 'not_sent'
        if (record.status === 'unknown') { markAgentTerminalUncertain(entry.terminal); entry.agentReady = false; if (state.binding?.terminalId === entry.id) state.binding.mode = 'read' }
        const output = prepared ? completed.output : record.output
        return { content: [{ type: 'text' as const, text: output }], details: { output, exitCode: completed.exitCode,
          fidelity: completed.completion, truncated: record.truncated, truncationReasons: record.truncated ? ['capture_buffer' as const] : [],
          ...(completed.authorizationDenied ? { error: 'permission_denied' } : {}) } }
      })
    } catch (error) {
      record.error = this.sanitize(error instanceof Error ? error.message : '执行失败')
      if (record.completion === undefined) record.status = 'blocked'
      result = { content: [{ type: 'text', text: record.error }], details: { error: error instanceof ZtermError ? error.code : 'execution_error' } }
    } finally {
      record.finishedAt = new Date().toISOString(); entry.controllers.delete(controller); signal?.removeEventListener('abort', abort)
      try { save() } catch { throw new ZtermError('record_store_failed', '操作记录保存失败；请核实工作台中的实际结果，不要自动重试') }
    }
    return result!
  }
  builtinReads(sessionId: string, exec: ToolExec) {
    return createBuiltinReadTools(async (callId, prepare, signal) => {
      try { const prepared = prepare(); return await this.execute(sessionId, { ...exec, callId: exec.callId ?? callId, signal: exec.signal ?? signal }, prepared.toolName, prepared.command, prepared) }
      catch (error) { return { content: [{ type: 'text', text: error instanceof Error ? error.message : '读取失败' }], details: { error: 'invalid_read_parameters', readErrorCode: (error as any)?.code } } }
    })
  }
  dispose(): void {
    if (this.disposed) return
    for (const state of this.states.values()) for (const entry of state.entries.values()) { entry.controllers.forEach((c) => c.abort()); entry.bridge.dispose(); entry.terminal.disconnect() }
    this.disposed = true; this.secrets.clear()
  }
}
