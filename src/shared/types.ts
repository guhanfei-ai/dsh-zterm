export interface HostTarget {
  id: string; label: string; folderId?: string; kind: 'ssh'; host: string; port: number; username: string
  authType: 'password' | 'key' | 'key-file'; credentialId?: string; credentialRef?: string; passphraseRef?: string; privateKeyPath?: string
}
export interface SavedCredential {
  id: string; label: string; authType: HostTarget['authType']; credentialRef?: string; passphraseRef?: string; privateKeyPath?: string
}
export interface HostFolder { id: string; label: string; parentId?: string }
export interface JumpProfile {
  id: string; label: string; baseUrl: string; authMode: 'access_key' | 'token' | 'password'; username?: string
  credentialRef: string; accessKeyIdRef?: string; verifyTls: boolean
}
export interface Config {
  hosts: HostTarget[]; folders: HostFolder[]; jumpservers: JumpProfile[]; credentials: SavedCredential[]; allowLocalTerminal: boolean
  allowExternalTargets: boolean; temporarilyDisabled: boolean; defaultSshUsername: string; defaultPrivateKeyPath: string; defaultCredentialId: string
  defaultPanelWidth: number; maxSessions: number; maxWriteCalls: number; commandTimeoutMs: number
}
export interface AutomaticTarget { kind?: 'auto'; host: string; username?: string; port?: number; label?: string }
export type ConnectTarget = { targetId: string } | { kind: 'local' } | AutomaticTarget
  | { kind: 'jumpserver'; instanceId: string; assetId: string; accountId: string; label?: string; accountName?: string }
  | { kind: 'external'; assetId: string; profileId: string; host: string; port?: number; label?: string }
export interface TargetIdentity {
  source: 'ssh' | 'jumpserver' | 'local' | 'external'; assetId: string; label: string; host?: string; port?: number; username?: string
  instanceId?: string; accountId?: string
}
export interface TerminalView {
  id: string; generation: number; target: TargetIdentity; state: 'connecting' | 'ready' | 'disconnected' | 'error'
  error?: string; busy: boolean; uncertain: boolean; agentReady: boolean; fingerprint?: string; createdAt: string
  trust?: { requestId: string; kind: 'unknown' | 'changed'; host: string; port: number; username: string; algorithm: string; fingerprint: string; trustedFingerprint?: string }
}
export interface BindingView { terminalId: string; generation: number; mode: 'read' | 'readwrite'; writeCalls: number; maxWriteCalls: number }
export interface Operation {
  version: 1; id: string; callId: string; tool: string; sessionId: string; terminalId: string; generation: number
  target: TargetIdentity; startedAt: string; finishedAt?: string; status: 'executing' | 'completed' | 'failed' | 'unknown' | 'not_sent' | 'blocked'
  completion?: string; command?: string; label: string; exitCode: number | null; output: string; truncated: boolean; error?: string
}
export interface WorkspaceView {
  terminals: TerminalView[]; binding?: BindingView; operations: Operation[]; revision: number
  capabilities: { local: boolean; external: boolean; automatic?: boolean }; hostPlatform: string; catalogRevision?: number
}
export interface OutputFrame { seq: number; terminalId: string; generation: number; text: string }
export interface PollResult { workspace: WorkspaceView; cursor: number; output: OutputFrame[]; reset: boolean; snapshots?: Array<{ terminalId: string; generation: number; text: string }> }
export interface ToolExec { callId?: string; rootCallId?: string; agent?: { id?: string; session?: { header?: { id?: string; cwd?: string } } }; signal?: AbortSignal }
export interface RpcResult<T = unknown> { ok: boolean; value?: T; error?: { code: string; message: string; details: object } }
export interface ClientContext { [key: string]: any }
