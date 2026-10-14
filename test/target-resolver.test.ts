import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { generateKeyPairSync } from 'node:crypto'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { DEFAULT_CONFIG } from '../src/host/config'
import { TargetResolver, parseAutomaticTarget } from '../src/host/targetResolver'
import { readDefaultPrivateKey } from '../src/host/defaultSsh'
import type { Config, HostTarget } from '../src/shared/types'

const roots: string[] = []
afterEach(() => roots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true })))
const saved: HostTarget = { id: 'h1', kind: 'ssh', label: '应用服务 01', host: '192.0.2.21', port: 22, username: 'operator', authType: 'key-file' }
const jump = { id: 'jump1', label: 'J', baseUrl: 'https://jump.example.invalid', authMode: 'token' as const, credentialRef: 'DSH_ZTERM_JUMP', verifyTls: true }
function fixture(patch: Partial<Config> = {}, query = vi.fn(async (_instance: string, operation: string, _args: any): Promise<any> => operation === 'assets' ? { success: true, assets: [], hasMore: false } : { success: true, accounts: [] })) {
  const config: Config = { ...DEFAULT_CONFIG, defaultSshUsername: 'operator', ...patch, hosts: [...(patch.hosts ?? [])] }
  const saveHost = vi.fn(async (host: HostTarget) => { config.hosts.push(host); return host })
  return { config, query, saveHost, resolver: new TargetResolver({ config: () => config, query, saveHost }) }
}
describe('对话目标按人类习惯解析', () => {
  it('支持 user@host、端口与 IPv6，拒绝不一致账号和控制字符', () => {
    expect(parseAutomaticTarget({ host: 'root@[2001:db8::1]:2222' })).toEqual({ host: '2001:db8::1', username: 'root', port: 2222 })
    expect(() => parseAutomaticTarget({ host: 'root@192.0.2.21', username: 'other' })).toThrow('不一致')
    expect(() => parseAutomaticTarget({ host: 'host\ncommand' })).toThrow('明确')
  })
  it.each(['192.0.2.21', '应用服务 01', 'h1'])('优先复用已保存主机 %s，不访问 JumpServer 或保存新配置', async (host) => {
    const f = fixture({ hosts: [saved], jumpservers: [jump] })
    expect(await f.resolver.resolve({ host })).toEqual({ targetId: 'h1' })
    expect(f.query).not.toHaveBeenCalled(); expect(f.saveHost).not.toHaveBeenCalled()
  })
  it('明确账号和端口选择对应保存配置，多候选返回标识供选择', async () => {
    const f = fixture({ hosts: [saved, { ...saved, id: 'root', username: 'root', port: 2222 }] })
    await expect(f.resolver.resolve({ host: saved.host })).rejects.toThrow('多个匹配')
    expect(await f.resolver.resolve({ host: saved.host, username: 'root', port: 2222 })).toEqual({ targetId: 'root' })
    expect(f.saveHost).not.toHaveBeenCalled()
  })
  it('没有保存配置时分页检查授权资产，只选可连接账号且不新增主机', async () => {
    const query = vi.fn(async (_instance: string, operation: string, args: any): Promise<any> => operation === 'assets'
      ? { success: true, hasMore: args.offset === 0, assets: [{ assetId: args.offset === 0 ? 'other' : 'wanted', name: '服务', address: args.offset === 0 ? '192.0.2.22' : saved.host }] }
      : { success: true, accounts: [{ accountId: 'denied', username: 'root', canConnect: false }, { accountId: 'allowed', username: 'operator', canConnect: true }] })
    const f = fixture({ jumpservers: [jump] }, query)
    expect(await f.resolver.resolve({ host: saved.host })).toMatchObject({ kind: 'jumpserver', instanceId: jump.id, assetId: 'wanted', accountId: 'allowed' })
    expect(query.mock.calls.map((call) => call[2].offset)).toEqual([0, 1, undefined]); expect(f.saveHost).not.toHaveBeenCalled()
  })
  it('相似 IP 不是精确匹配，无授权时才新增，并保留明确账号和端口', async () => {
    const query = vi.fn(async (_instance: string, _operation: string, _args: any): Promise<any> => ({ success: true, hasMore: false, assets: [{ assetId: 'prefix', name: 'other', address: '192.0.2.210' }] }))
    const f = fixture({ jumpservers: [jump] }, query)
    const result = await f.resolver.resolve({ host: 'root@192.0.2.21:2222' })
    expect(result).toEqual({ targetId: f.config.hosts[0].id })
    expect(f.config.hosts[0]).toMatchObject({ host: saved.host, username: 'root', port: 2222, authType: 'key-file' })
    expect(f.config.hosts[0]).not.toHaveProperty('credentialRef')
  })
  it('授权资产没有可连接账号时允许默认私钥路径，不冒用不可连接账号', async () => {
    const query = vi.fn(async (_instance: string, operation: string, _args: any): Promise<any> => operation === 'assets'
      ? { success: true, assets: [{ assetId: 'wanted', name: '服务', address: saved.host }], hasMore: false }
      : { success: true, accounts: [{ accountId: 'denied', username: 'operator', canConnect: false }] })
    const f = fixture({ jumpservers: [jump] }, query)
    await f.resolver.resolve({ host: saved.host }); expect(f.saveHost).toHaveBeenCalledOnce()
  })
  it('跨实例和账号的多个授权目标不静默选取，不新增主机', async () => {
    const query = vi.fn(async (_instance: string, operation: string, _args: any): Promise<any> => operation === 'assets'
      ? { success: true, assets: [{ assetId: 'wanted', name: '服务', address: saved.host }], hasMore: false }
      : { success: true, accounts: [{ accountId: 'one', username: 'user1', canConnect: true }, { accountId: 'two', username: 'user2', canConnect: true }] })
    const f = fixture({ jumpservers: [jump] }, query)
    await expect(f.resolver.resolve({ host: saved.host })).rejects.toThrow('多个匹配'); expect(f.saveHost).not.toHaveBeenCalled()
  })
  it('查询失败和分页不完整不是无授权，均不新增主机', async () => {
    const failed = fixture({ jumpservers: [jump] }, vi.fn(async () => { throw new Error('fixture network failure') }))
    await expect(failed.resolver.resolve({ host: saved.host })).rejects.toThrow('network failure'); expect(failed.saveHost).not.toHaveBeenCalled()
    const truncated = fixture({ jumpservers: [jump] }, vi.fn(async () => ({ success: true, assets: [], hasMore: true })))
    await expect(truncated.resolver.resolve({ host: saved.host })).rejects.toThrow('不完整'); expect(truncated.saveHost).not.toHaveBeenCalled()
  })
  it('查询途中取消后不新增、不继续查账号，也不返回可连接目标', async () => {
    const controller = new AbortController()
    const f = fixture({ jumpservers: [jump] }, vi.fn(async () => { controller.abort(); return { success: true, assets: [], hasMore: false } }))
    await expect(f.resolver.resolve({ host: saved.host }, controller.signal)).rejects.toThrow('取消'); expect(f.saveHost).not.toHaveBeenCalled()
  })
})
describe('默认 SSH 私钥只由宿主文件读取', () => {
  function home() { const root = mkdtempSync(join(tmpdir(), 'dsh-zterm-default-key-')); roots.push(root); mkdirSync(join(root, '.ssh')); return root }
  function key(passphrase?: string) { return generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs1', format: 'pem', ...(passphrase ? { cipher: 'aes-256-cbc', passphrase } : {}) }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey }
  it('读取默认文件和明确 ~/ 路径，文件缺失不生成密钥', async () => {
    const root = home(), pem = key(); writeFileSync(join(root, '.ssh/id_rsa'), pem)
    expect(await readDefaultPrivateKey('', undefined, undefined, root)).toBe(pem)
    expect(await readDefaultPrivateKey('~/.ssh/id_rsa', undefined, undefined, root)).toBe(pem)
    await expect(readDefaultPrivateKey('~/.ssh/missing', undefined, undefined, root)).rejects.toThrow('无法读取')
    await expect(readDefaultPrivateKey('', undefined, undefined, home())).rejects.toThrow('未找到')
  })
  it('加密私钥需要口令，拒绝公钥和相对路径', async () => {
    const root = home(), pem = key('fixture-passphrase'); writeFileSync(join(root, '.ssh/id_rsa'), pem)
    await expect(readDefaultPrivateKey('', undefined, undefined, root)).rejects.toThrow('口令')
    expect(await readDefaultPrivateKey('', 'fixture-passphrase', undefined, root)).toBe(pem)
    writeFileSync(join(root, '.ssh/id_ed25519'), 'ssh-ed25519 AAAA fixture-public-key')
    await expect(readDefaultPrivateKey('', undefined, undefined, root)).rejects.toThrow('私钥')
    await expect(readDefaultPrivateKey('relative/path', undefined, undefined, root)).rejects.toThrow('绝对路径')
  })
})
