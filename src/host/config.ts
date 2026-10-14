import Schema from '@deepseek-ai/schemastery'
import { isAbsolute } from 'node:path'
import { normalizeSshHost, normalizeSshPort, normalizeSshUsername } from '../core/sshHostTrust'
import type { Config, HostTarget, HostFolder, JumpProfile } from '../shared/types'

export const DEFAULT_CONFIG: Config = {
  hosts: [], folders: [], jumpservers: [], allowLocalTerminal: false, allowExternalTargets: false,
  defaultSshUsername: '', defaultPrivateKeyPath: '',
  defaultPanelWidth: 60, maxSessions: 12, maxWriteCalls: 100, commandTimeoutMs: 30000,
}
export const ConfigSchema = Schema.object({
  hosts: Schema.any().default([]).volatile().description('远程主机；凭据使用 DSH_ZTERM_ 引用。'),
  folders: Schema.any().default([]).volatile().description('主机文件夹。'),
  jumpservers: Schema.any().default([]).volatile().description('JumpServer 实例与凭据引用。'),
  allowLocalTerminal: Schema.boolean().default(false).volatile().description('允许打开 DSH 宿主的本地终端。'),
  allowExternalTargets: Schema.boolean().default(false).volatile().description('允许使用已配置 SSH 凭据连接上层提供的资产地址。'),
  defaultSshUsername: Schema.string().default('').volatile().description('新主机默认登录账号；留空使用 DSH 宿主当前用户，对话明确指定账号时优先采用。'),
  defaultPrivateKeyPath: Schema.string().default('').volatile().description('DSH 宿主的默认 SSH 私钥文件；留空查找 ~/.ssh/id_ed25519、id_rsa、id_ecdsa。'),
  defaultPanelWidth: Schema.number().default(60).volatile().description('独立面板默认宽度百分比（30–80）。'),
  maxSessions: Schema.number().default(12).volatile().description('每个 DSH 会话的终端上限（1–32）。'),
  maxWriteCalls: Schema.number().default(100).volatile().description('每次人类开启读写后的命令上限（1–1000）。'),
  commandTimeoutMs: Schema.number().default(30000).volatile().description('单次执行超时（1000–120000 毫秒）。'),
})
export function plain(value: any): any {
  if (value && typeof value === 'object' && typeof value.get === 'function') return plain(value.get())
  if (Array.isArray(value)) return value.map(plain)
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]))
  return value
}
export function id(value: unknown, label = '标识'): string {
  if (typeof value !== 'string' || !/^[\w.:-]{1,100}$/.test(value)) throw new Error(`${label}无效`)
  return value
}
export function label(value: unknown, fallback = ''): string {
  if (typeof value !== 'string') return fallback
  const result = value.trim()
  if (!result || result.length > 200 || /[\x00-\x1f\x7f]/.test(result)) throw new Error('名称无效')
  return result
}
export function credentialRef(value: unknown, optional = false): string | undefined {
  if (optional && (value === undefined || value === '')) return undefined
  if (typeof value !== 'string' || !/^DSH_ZTERM_[A-Z0-9_]{1,150}$/.test(value)) throw new Error('凭据引用须使用 DSH_ZTERM_ 前缀和大写字母、数字、下划线')
  return value
}
export function integer(value: unknown, fallback: number, min: number, max: number): number {
  if (value === undefined) return fallback
  if (!Number.isInteger(value) || Number(value) < min || Number(value) > max) throw new Error(`整数须在 ${min}–${max} 范围内`)
  return Number(value)
}
function boolean(value: unknown, fallback: boolean): boolean { if (value === undefined) return fallback; if (typeof value !== 'boolean') throw new Error('开关必须为布尔值'); return value }
function array(value: unknown, max: number): any[] { if (!Array.isArray(value) || value.length > max) throw new Error(`列表无效或超过 ${max} 项`); return value }
export function validateHost(raw: any): HostTarget {
  if (!raw || raw.kind !== 'ssh' || ['password', 'privateKey', 'passphrase'].some((key) => key in raw)) throw new Error('主机必须使用凭据引用，不接受凭据值')
  const host = normalizeSshHost(raw.host), port = normalizeSshPort(raw.port ?? 22), username = normalizeSshUsername(raw.username)
  // 旧 Agent／默认文件配置保留主机，统一转为宿主私钥文件认证。
  const authType = ['agent', 'default-key'].includes(raw.authType) ? 'key-file' : raw.authType
  if (!host || !port || !username || /[\s/@?#\\]/.test(host) || !['password', 'key', 'key-file'].includes(authType)) throw new Error('SSH 地址、端口、账号或认证方式无效')
  const privateKeyPath = authType === 'key-file' ? keyFilePath(raw.privateKeyPath ?? '') : ''
  return { id: id(raw.id), label: label(raw.label), kind: 'ssh', host, port, username, authType,
    ...(raw.folderId ? { folderId: id(raw.folderId) } : {}),
    ...(['password', 'key'].includes(authType) ? { credentialRef: credentialRef(raw.credentialRef)! } : {}),
    ...(['key', 'key-file'].includes(authType) && raw.passphraseRef ? { passphraseRef: credentialRef(raw.passphraseRef) } : {}),
    ...(privateKeyPath ? { privateKeyPath } : {}) }
}
function optionalText(value: unknown, max: number): string {
  if (typeof value !== 'string' || value.length > max || /[\x00-\x1f\x7f]/.test(value)) throw new Error('默认 SSH 设置无效')
  return value.trim()
}
function keyFilePath(value: unknown): string {
  const path = optionalText(value, 4096)
  if (path && !path.startsWith('~/') && !isAbsolute(path)) throw new Error('私钥文件请填写 DSH 宿主的绝对路径或 ~/ 路径')
  return path
}
export function validateJump(raw: any): JumpProfile {
  if (!raw || typeof raw.baseUrl !== 'string' || ['credential', 'accessKeySecret', 'password', 'token'].some((key) => key in raw)) throw new Error('JumpServer 配置只接受凭据引用')
  const url = new URL(raw.baseUrl)
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('JumpServer URL 无效')
  if (!['access_key', 'token', 'password'].includes(raw.authMode)) throw new Error('JumpServer 认证方式无效')
  return { id: id(raw.id), label: label(raw.label), baseUrl: url.toString().replace(/\/$/, ''), authMode: raw.authMode,
    credentialRef: credentialRef(raw.credentialRef)!, verifyTls: boolean(raw.verifyTls, true),
    ...(raw.authMode === 'access_key' ? { accessKeyIdRef: credentialRef(raw.accessKeyIdRef)! } : {}),
    ...(raw.authMode === 'password' ? { username: label(raw.username) } : {}) }
}
export function validateConfig(value: unknown): Config {
  const raw = { ...DEFAULT_CONFIG, ...plain(value) }
  const hosts = array(raw.hosts, 20000).map(validateHost)
  const folders: HostFolder[] = array(raw.folders, 2000).map((f) => ({ id: id(f.id), label: label(f.label), ...(f.parentId ? { parentId: id(f.parentId) } : {}) }))
  const jumpservers = array(raw.jumpservers, 32).map(validateJump)
  for (const entries of [hosts, folders, jumpservers]) if (new Set(entries.map((entry) => entry.id)).size !== entries.length) throw new Error('列表包含重复标识')
  const folderMap = new Map(folders.map((f) => [f.id, f]))
  for (const folder of folders) {
    const seen = new Set([folder.id]); let next = folder.parentId
    while (next) { if (seen.has(next) || !folderMap.has(next)) throw new Error('文件夹父节点不存在或存在循环'); seen.add(next); next = folderMap.get(next)!.parentId }
  }
  for (const host of hosts) if (host.folderId && !folderMap.has(host.folderId)) throw new Error('主机所属文件夹不存在')
  return { hosts, folders, jumpservers, allowLocalTerminal: boolean(raw.allowLocalTerminal, false), allowExternalTargets: boolean(raw.allowExternalTargets, false),
    defaultSshUsername: optionalText(raw.defaultSshUsername, 200), defaultPrivateKeyPath: keyFilePath(raw.defaultPrivateKeyPath),
    defaultPanelWidth: integer(raw.defaultPanelWidth, 60, 30, 80), maxSessions: integer(raw.maxSessions, 12, 1, 32),
    maxWriteCalls: integer(raw.maxWriteCalls, 100, 1, 1000), commandTimeoutMs: integer(raw.commandTimeoutMs, 30000, 1000, 120000) }
}
