import { afterEach, describe, expect, it } from 'vitest'
import { AssetTreeCache } from '../src/client/asset-tree-cache'

class MemoryStorage {
  values = new Map<string, string>()
  get length() { return this.values.size }
  getItem(key: string) { return this.values.get(key) ?? null }
  setItem(key: string, value: string) { this.values.set(key, value) }
  removeItem(key: string) { this.values.delete(key) }
  key(index: number) { return [...this.values.keys()][index] ?? null }
}
const caches: AssetTreeCache[] = []
afterEach(() => caches.splice(0).forEach((cache) => cache.dispose()))
const create = (session: string, storage = new MemoryStorage(), now = () => 10000) => { const cache = new AssetTreeCache(session, storage, now); caches.push(cache); return cache }
const host = { id: 'host-1', kind: 'ssh', label: '虚构主机', host: '192.0.2.21', port: 22, username: 'operator', credentialRef: 'DO_NOT_CACHE_REF', privateKeyPath: '/private/example/key', authType: 'key-file', password: 'DO_NOT_CACHE_PASSWORD' }
const asset = { assetId: 'a', name: '虚构资产', address: '192.0.2.31', platform: 'Linux', token: 'DO_NOT_CACHE_TOKEN' }
const page = (items: any[]) => ({ items, total: items.length, hasMore: false })
function fill(cache: AssetTreeCache) {
  cache.catalog = { folders: [{ id: 'apps', label: '应用目录' }], jumpservers: [{ id: 'jump-1', label: '堡垒机', credentialRef: 'DO_NOT_CACHE_REF' }, { id: 'jump-2', label: '第二堡垒机' }], credentials: [{ password: 'DO_NOT_CACHE_PASSWORD' }], revision: 7 }
  cache.host.seed('hosts:', page([host])); cache.host.reveal(['apps']); cache.host.setScroll('tree', 360)
  cache.jump('jump-1').seed('assets:leaf', page([asset])); cache.jump('jump-1').reveal(['leaf'])
  cache.preferences = { source: 'jumpserver', instanceId: 'jump-1', folder: 'apps' }; cache.flush()
}
describe('资产树本地展示缓存', () => {
  it('新工作台同步恢复内容、来源、实例、展开、页码与滚动，并将页标为待更新', async () => {
    const storage = new MemoryStorage(), original = create('session-a', storage); fill(original)
    await original.host.load('hosts:apps', async () => page([host]), 200); original.flush()
    const restored = create('session-a', storage)
    expect(restored.catalog.revision).toBe(7); expect(restored.preferences).toEqual(original.preferences)
    expect(restored.host.expanded.has('apps')).toBe(true); expect(restored.host.scroll.get('tree')).toBe(360)
    expect(restored.host.page('hosts:apps')).toMatchObject({ offset: 200, status: 'ready', stale: true })
    expect(restored.jump('jump-1').page<any>('assets:leaf')?.data?.items[0].name).toBe('虚构资产')
  })
  it('白名单仅保存展示字段，搜索、账号和凭据不进入本地快照', () => {
    const storage = new MemoryStorage(), cache = create('session-a', storage); fill(cache)
    cache.host.seed('search:private', page([host])); cache.jump('jump-1').seed('accounts:a', page([{ password: 'secret' }]))
    cache.flush(); const raw = storage.getItem(cache.key)!
    for (const secret of ['DO_NOT_CACHE', 'credentialRef', 'privateKeyPath', 'password', 'search:', 'accounts:', 'token']) expect(raw).not.toContain(secret)
    expect(raw).toContain('192.0.2.21'); expect(raw).toContain('虚构资产')
  })
  it('相同节点 ID 按实例隔离，工作台之间不读取对方快照', () => {
    const storage = new MemoryStorage(), cache = create('session-a', storage); fill(cache)
    cache.jump('jump-2').seed('assets:leaf', page([{ ...asset, name: '第二实例资产' }])); cache.flush()
    const same = create('session-a', storage), other = create('session-b', storage)
    expect(same.jump('jump-1').page<any>('assets:leaf')?.data?.items[0].name).toBe('虚构资产')
    expect(same.jump('jump-2').page<any>('assets:leaf')?.data?.items[0].name).toBe('第二实例资产')
    expect(other.catalog).toBeUndefined(); expect(other.host.page('hosts:')).toBeUndefined()
  })
  it('过期、未来时间、错误版本、损坏 JSON 和不完整分页均安全回退', () => {
    const storage = new MemoryStorage(), cache = create('session', storage); fill(cache)
    const raw = storage.getItem(cache.key)!, valid = JSON.parse(raw)
    for (const entry of ['{broken', JSON.stringify({ ...valid, schema: 99 }), JSON.stringify({ ...valid, writtenAt: 20000 }), JSON.stringify({ ...valid, writtenAt: 0 })]) {
      storage.setItem(cache.key, entry)
      expect(create('session', storage, () => entry.includes('"writtenAt":0') ? 86_400_000 : 10000).catalog).toBeUndefined()
    }
    valid.host.pages = [['hosts:', { offset: 0, data: page([{ id: 'broken' }]) }]]
    storage.setItem(cache.key, JSON.stringify(valid)); expect(create('session', storage).host.page('hosts:')).toBeUndefined()
  })
  it('存储拒绝和配额不足不影响内存列表', () => {
    const storage = new MemoryStorage(); storage.getItem = () => { throw new Error('denied') }; storage.setItem = () => { throw new Error('quota') }
    const cache = create('session', storage); expect(() => fill(cache)).not.toThrow()
    expect(cache.host.page('hosts:')?.data?.items).toHaveLength(1)
  })
  it('万级缓存限制分页数量和体积，保留节点列表且不自动抓取后续页', () => {
    const storage = new MemoryStorage(), cache = create('session', storage); fill(cache)
    for (let index = 0; index < 100; index++) cache.jump('jump-1').seed(`assets:${index}`, page(Array.from({ length: 100 }, (_, i) => ({ ...asset, assetId: `${index}-${i}`, name: '机器'.repeat(100) }))))
    cache.jump('jump-1').seed('nodes', page([{ nodeId: 'leaf', key: '1:0', name: '目录', hasChildren: false, assetCount: 10000 }]))
    cache.flush(); const raw = storage.getItem(cache.key)!, result = JSON.parse(raw)
    expect(raw.length).toBeLessThanOrEqual(600000)
    expect(result.host.pages.length + result.jumps.flatMap(([, tree]: any) => tree.pages).length).toBeLessThanOrEqual(64)
    expect(create('session', storage).jump('jump-1').page('nodes')?.data?.items).toHaveLength(1)
  })
  it('只清理本插件最旧的工作台快照，保留其它本地偏好', () => {
    const storage = new MemoryStorage(); storage.setItem('unrelated', 'keep')
    for (let i = 0; i < 5; i++) fill(create(`session-${i}`, storage, () => 10000 + i))
    expect([...storage.values.keys()].filter((key) => key.startsWith('dsh-zterm.asset-tree-cache'))).toHaveLength(3)
    expect(storage.getItem('unrelated')).toBe('keep')
    expect(create('session-0', storage).catalog).toBeUndefined()
  })
})
