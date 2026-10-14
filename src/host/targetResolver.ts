import { createHash } from 'node:crypto'
import { normalizeSshHost, normalizeSshPort, normalizeSshUsername } from '../core/sshHostTrust'
import type { JumpserverAsset, JumpserverAccount } from '../core/jumpserverClient'
import type { AutomaticTarget, Config, ConnectTarget, HostTarget } from '../shared/types'
import { defaultSshUsername } from './defaultSsh'
import { checkCancelled, ZtermError } from './errors'
import { label } from './config'

interface ResolverDeps {
  config(): Config
  query(instanceId: string, operation: string, args: any): Promise<any>
  saveHost(host: HostTarget, signal?: AbortSignal): Promise<HostTarget>
}
export function parseAutomaticTarget(raw: AutomaticTarget): AutomaticTarget {
  if (typeof raw.host !== 'string' || !raw.host.trim() || raw.host.length > 253 || /[\x00-\x1f\x7f]/.test(raw.host)) throw new ZtermError('invalid_target', '请提供明确的主机名或 IP')
  let host = raw.host.trim(), username = raw.username, port = raw.port
  const at = host.lastIndexOf('@')
  if (at >= 0) {
    const embedded = host.slice(0, at)
    if (username && username !== embedded) throw new ZtermError('invalid_target', '目标包含不一致的登录账号')
    username = embedded; host = host.slice(at + 1)
  }
  const endpoint = host.match(/^\[([^\]]+)\](?::(\d+))?$|^([^:]+):(\d+)$/)
  if (endpoint) {
    host = endpoint[1] ?? endpoint[3]
    const embeddedPort = endpoint[2] ?? endpoint[4]
    if (embeddedPort) {
      if (port !== undefined && port !== Number(embeddedPort)) throw new ZtermError('invalid_target', '目标包含不一致的 SSH 端口')
      port = Number(embeddedPort)
    }
  }
  if (!host || /[/@?#\\]/.test(host) || (username !== undefined && !normalizeSshUsername(username)) || (port !== undefined && !normalizeSshPort(port))) throw new ZtermError('invalid_target', '主机地址、账号或端口无效')
  return { host, ...(username !== undefined ? { username: normalizeSshUsername(username)! } : {}), ...(port !== undefined ? { port } : {}), ...(raw.label !== undefined ? { label: label(raw.label) } : {}) }
}
function sameName(a: string, b: string): boolean { return a.toLowerCase() === b.toLowerCase() }
function sameAddress(a: string, b: string): boolean { const left = normalizeSshHost(a); return Boolean(left && left === normalizeSshHost(b)) }
function ambiguous(candidates: ConnectTarget[]): never {
  throw new ZtermError('ambiguous_target', `目标有多个匹配，请让用户明确选择后按对应标识连接：${JSON.stringify(candidates.slice(0, 20))}`)
}
export class TargetResolver {
  constructor(private readonly deps: ResolverDeps) {}
  async resolve(raw: AutomaticTarget, signal?: AbortSignal): Promise<ConnectTarget> {
    const request = parseAutomaticTarget(raw); checkCancelled(signal)
    const config = this.deps.config()
    const saved = config.hosts.filter((host) => (sameName(host.id, request.host) || sameName(host.label, request.host) || sameAddress(host.host, request.host))
      && (request.username === undefined || host.username === request.username) && (request.port === undefined || host.port === request.port))
    if (saved.length > 1) ambiguous(saved.map((host) => ({ targetId: host.id })))
    if (saved.length) return { targetId: saved[0].id }

    const candidates: ConnectTarget[] = []; let pages = 0
    for (const instance of config.jumpservers) {
      const assets = new Map<string, JumpserverAsset>(); let offset = 0
      for (;;) {
        checkCancelled(signal)
        if (++pages > 100) throw new ZtermError('search_incomplete', 'JumpServer 搜索尚未完成，请提供更明确的目标；没有新增远程主机')
        const result = await this.deps.query(instance.id, 'assets', { query: request.host, offset, limit: 200 }); checkCancelled(signal)
        if (!result.success || !Array.isArray(result.assets)) throw new ZtermError('jumpserver_error', '无法完成 JumpServer 授权检查，没有新增远程主机')
        for (const asset of result.assets as JumpserverAsset[]) if (sameName(asset.name, request.host) || sameAddress(asset.address, request.host)) assets.set(asset.assetId, asset)
        if (!result.hasMore) break
        if (!result.assets.length) throw new ZtermError('search_incomplete', 'JumpServer 分页结果不完整，没有新增远程主机')
        offset += result.assets.length
      }
      for (const asset of assets.values()) {
        checkCancelled(signal)
        const result = await this.deps.query(instance.id, 'accounts', { assetId: asset.assetId }); checkCancelled(signal)
        if (!result.success || !Array.isArray(result.accounts) || result.truncated) throw new ZtermError('search_incomplete', 'JumpServer 账号授权检查未完成，没有新增远程主机')
        let accounts = (result.accounts as JumpserverAccount[]).filter((account) => account.canConnect && (request.username === undefined || account.username === request.username))
        if (request.username === undefined && accounts.length > 1) {
          const preferred = accounts.filter((account) => account.username === defaultSshUsername(config.defaultSshUsername))
          if (preferred.length === 1) accounts = preferred
        }
        for (const account of accounts) candidates.push({ kind: 'jumpserver', instanceId: instance.id, assetId: asset.assetId, accountId: account.accountId, label: asset.name, accountName: account.username || account.name })
      }
    }
    if (candidates.length > 1) ambiguous(candidates)
    if (candidates.length) return candidates[0]

    checkCancelled(signal)
    const host = normalizeSshHost(request.host)
    if (!host || host.length > 253 || /[\s/@?#\\]/.test(host)) throw new ZtermError('invalid_target', '未找到目标，请提供可连接的主机名或 IP')
    const username = request.username ?? defaultSshUsername(config.defaultSshUsername), port = request.port ?? 22
    const hostId = `auto-${createHash('sha256').update(JSON.stringify([host, port, username])).digest('hex').slice(0, 32)}`
    const latest = this.deps.config(), credential = latest.credentials.find((c) => c.id === latest.defaultCredentialId)
    const savedHost = await this.deps.saveHost({ id: hostId, kind: 'ssh', label: request.label ?? host, host, port, username,
      authType: credential?.authType ?? 'key-file', ...(credential ? { credentialId: credential.id } : {}) }, signal)
    checkCancelled(signal)
    return { targetId: savedHost.id }
  }
}
