import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs'
import { generateKeyPairSync } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createPlugin, DEFAULT_CONFIG } from '../src/index'
import { TerminalSession } from '../src/core/terminalSessionManager'
const dirs: string[] = []
afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })))
function setup(initial: any = {}, credentialValues = new Map<string, string>(), deps: any = {}) {
  const root = mkdtempSync(join(tmpdir(), 'dsh-zterm-plugin-')); dirs.push(root)
  let config: any = { ...DEFAULT_CONFIG, ...initial }, revision = 1, gate: any
  const routes = new Map<string, any>()
  const registered: any[] = [], credentials = credentialValues, disposers: any[] = []
  const ctx: any = { tools: { register: (tool: any) => registered.push(tool) }, systemPrompt: { section: () => {} },
    credentials: { resolve: async (ref: string) => credentials.has(ref) ? { value: credentials.get(ref) } : undefined, set: async (ref: string, value: string) => { credentials.set(ref, value) }, unset: async (ref: string) => { credentials.delete(ref) } },
    sessions: { get: (id: string) => id === 'session-1' ? { header: { cwd: root } } : undefined },
    settings: { describe: () => [{ ns: 'zterm', value: config, revision }], update: async (_ns: string, next: any, expected: number) => { if (expected !== revision) throw new Error('配置修订号已变化'); config = next; revision++ } },
    connection: { fetch: { register: (route: any) => { routes.set(route.path, route); return () => routes.delete(route.path) } }, rpc: { intercept: () => { throw new Error('共享拦截器不得被插件占用') } } },
    inject: (_names: any, body: any) => body(ctx), on: (_name: string, body: any) => { gate = body }, effect: (body: any) => { const disposer = body(); disposers.push(disposer) } }
  const plugin = createPlugin(ctx, {}, { ...deps, dataRoot: root, defaultSshHome: root })
  const call = async (method: string, payload: any = {}) => {
    const path = `/api/zterm/${method}`, response = await routes.get(path).fetch(new Request(`http://localhost${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'client-request', rpcId: 'test-rpc', method: `zterm/${method}`, payload }) }))
    return (await response.json()).result
  }
  return { root, call, routes, registered, credentials, gate, plugin, ctx, dispose: () => disposers.forEach((d) => d?.()) }
}
describe('DSH 宿主接口', () => {
  it('只在认证 Connection 通道登记工作台接口，工具没有修改模式入口', () => {
    const fixture = setup()
    expect(fixture.registered.length).toBe(14)
    expect(fixture.registered.map((t) => t.name)).not.toContain('zterm_set_mode')
    for (const tool of fixture.registered) expect(tool.output.schema).toEqual({ type: 'string' })
    fixture.dispose()
  })
  it('主机秘密只写凭据库，配置及 catalog 不返回密码', async () => {
    const fixture = setup()
    const result = await fixture.call('host/save', { host: { label: 'H', host: 'host.example.invalid', port: 22, username: 'operator', authType: 'password' }, secret: 'fixture-password', revision: 1 })
    expect(result.ok).toBe(true); expect([...fixture.credentials.values()]).toContain('fixture-password')
    const catalog = await fixture.call('catalog'); expect(catalog.value.hosts).toHaveLength(1); expect(JSON.stringify(catalog)).not.toContain('fixture-password')
    fixture.dispose()
  })
  it('未知 DSH 会话和过期配置更新拒绝；宿主的 ask/deny 不被覆盖', async () => {
    const fixture = setup()
    const bad = await fixture.call('poll', { sessionId: 'unknown' }); expect(bad.ok).toBe(false)
    const stale = await fixture.call('config', { patch: { allowLocalTerminal: true }, revision: 0 }); expect(stale.ok).toBe(false)
    expect(await fixture.gate({ name: 'zterm_execute' }, async () => ({ kind: 'ask' }))).toEqual({ kind: 'ask' })
    expect(await fixture.gate({ name: 'zterm_execute' }, async () => ({ kind: 'deny', reason: 'policy' }))).toEqual({ kind: 'deny', reason: 'policy' })
    fixture.dispose()
  })
  it('只读工具失败使用宿主失败通道，不包装为成功', async () => {
    const fixture = setup(), tool = fixture.registered.find((t) => t.name === 'zterm_execute')
    await expect(tool.execute({ command: 'printf x' }, { callId: 'c', agent: { id: 'session-1' } })).rejects.toThrow('绑定')
    fixture.dispose()
  })
  it('过期或并发的主机保存不能覆盖在用凭据', async () => {
    const fixture = setup(), host = { id: 'host-1', label: 'H', host: 'host.example.invalid', username: 'operator', authType: 'password' }
    const results = await Promise.all([fixture.call('host/save', { host, secret: 'first-password', revision: 1 }), fixture.call('host/save', { host, secret: 'second-password', revision: 1 })])
    expect(results.map((result) => result.ok)).toEqual([true, false])
    expect([...fixture.credentials.values()]).toEqual(['first-password'])
    const current = (await fixture.call('catalog')).value
    expect((await fixture.call('host/save', { host: current.hosts[0], secret: 'stale-password', revision: 1 })).ok).toBe(false)
    expect([...fixture.credentials.values()]).toEqual(['first-password'])
    fixture.dispose()
  })
  it('空凭据编辑保留自定义引用，切换认证方式要求新的凭据', async () => {
    const host = { id: 'host-1', kind: 'ssh', label: 'H', host: 'host.example.invalid', port: 22, username: 'operator', authType: 'password', credentialRef: 'DSH_ZTERM_SHARED' }
    const fixture = setup({ hosts: [host] }, new Map([['DSH_ZTERM_SHARED', 'existing-password']]))
    expect((await fixture.call('host/save', { host: { ...host, label: 'Renamed' }, secret: '', revision: 1 })).ok).toBe(true)
    const catalog = (await fixture.call('catalog')).value
    expect(catalog.hosts[0].credentialRef).toBe('DSH_ZTERM_SHARED')
    expect((await fixture.call('host/save', { host: { ...catalog.hosts[0], authType: 'key' }, secret: '', revision: 2 })).ok).toBe(false)
    expect([...fixture.credentials.values()]).toEqual(['existing-password'])
    fixture.dispose()
  })
  it('完整配置校验和保存失败不遗留新秘密', async () => {
    const fixture = setup(), host = { id: 'host-1', label: 'H', host: 'host.example.invalid', username: 'operator', authType: 'password' }
    expect((await fixture.call('host/save', { host: { ...host, folderId: 'missing' }, secret: 'invalid-folder-password', revision: 1 })).ok).toBe(false)
    expect(fixture.credentials.size).toBe(0)
    fixture.ctx.settings.update = async () => { throw new Error('test storage unavailable') }
    expect((await fixture.call('host/save', { host, secret: 'new-password', revision: 1 })).ok).toBe(false)
    expect(fixture.credentials.size).toBe(0)
    fixture.dispose()
  })
  it('JumpServer 的空秘密编辑保持既有引用，失败修订不改秘密', async () => {
    const profile = { id: 'jump-1', label: 'Jump', baseUrl: 'https://jump.example.invalid', authMode: 'access_key', credentialRef: 'DSH_ZTERM_JUMP_SHARED', accessKeyIdRef: 'DSH_ZTERM_ID_SHARED', verifyTls: true }
    const fixture = setup({ jumpservers: [profile] }, new Map([['DSH_ZTERM_JUMP_SHARED', 'secret-key'], ['DSH_ZTERM_ID_SHARED', 'key-id']]))
    expect((await fixture.call('jump/save', { profile: { ...profile, label: 'Renamed' }, secret: '', accessKeyId: '', revision: 1 })).ok).toBe(true)
    expect((await fixture.call('catalog')).value.jumpservers[0].credentialRef).toBe(profile.credentialRef)
    expect((await fixture.call('jump/save', { profile, secret: 'stale-secret', revision: 1 })).ok).toBe(false)
    expect([...fixture.credentials.values()]).toEqual(['secret-key', 'key-id'])
    fixture.dispose()
  })
  it('catalog 使用异步凭据元数据，不为列表读取秘密', async () => {
    const host = { id: 'host-1', kind: 'ssh', label: 'H', host: 'host.example.invalid', port: 22, username: 'operator', authType: 'password', credentialRef: 'DSH_ZTERM_SHARED' }
    const fixture = setup({ hosts: [host] })
    fixture.ctx.credentials.describe = async () => ({ configured: true, writable: true })
    fixture.ctx.credentials.resolve = async () => { throw new Error('秘密不应在 catalog 读取') }
    expect((await fixture.call('catalog')).value.credentialsConfigured.DSH_ZTERM_SHARED).toBe(true)
    fixture.dispose()
  })
  it('工具的本地长度和范围约束不因 SDK Schema 转换而放宽', async () => {
    const fixture = setup(), exec = { callId: 'limits', agent: { id: 'session-1' } }
    await expect(fixture.registered.find((t) => t.name === 'zterm_targets').execute({ limit: 201 }, exec)).rejects.toThrow('超出范围')
    await expect(fixture.registered.find((t) => t.name === 'zterm_search_text').execute({ path: '/tmp/test', query: 'x'.repeat(257) }, exec)).rejects.toThrow('长度')
    fixture.dispose()
  })
  it('两万主机的 catalog 只返回一页并检查当页凭据状态', async () => {
    const hosts = Array.from({ length: 20000 }, (_, i) => ({ id: `h-${i}`, kind: 'ssh', label: `Host ${i}`, host: 'host.example.invalid', port: 22, username: 'operator', authType: 'password', credentialRef: `DSH_ZTERM_H_${i}` }))
    const fixture = setup({ hosts }); let reads = 0
    fixture.ctx.credentials.describe = async () => { reads++; return { configured: true } }
    const result = await fixture.call('catalog', { offset: 19800 })
    expect(result.value.hosts).toHaveLength(200); expect(result.value.total).toBe(20000); expect(reads).toBe(200)
    fixture.dispose()
  })
  it('精确认证路由拒绝错误媒体类型和伪造的方法信封', async () => {
    const fixture = setup(), route = fixture.routes.get('/api/zterm/catalog')
    const badType = await route.fetch(new Request('http://localhost/api/zterm/catalog', { method: 'POST', body: '{}' }))
    expect(badType.status).toBe(415)
    const badMethod = await route.fetch(new Request('http://localhost/api/zterm/catalog', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'client-request', rpcId: 'bad', method: 'zterm/mode', payload: {} }) }))
    expect(badMethod.status).toBe(400)
    fixture.dispose()
  })
  it('自动新增采用同一配置写入队列，并发工具只保存一台，私钥不进入配置或工具结果', async () => {
    const connected: any[] = []
    class FakeTerminal extends TerminalSession {
      async connect(options: any) { connected.push(options); this.connected = true; this.currentHost = options }
      async openShell() {}
      isShellReady() { return this.connected }
      disconnect() { this.connected = false; this.emit('closed') }
    }
    const fixture = setup({ defaultSshUsername: 'operator' }, new Map(), { terminalFactory: (id: string, generation: number) => new FakeTerminal(id, generation) })
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs1', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } })
    mkdirSync(join(fixture.root, '.ssh')); writeFileSync(join(fixture.root, '.ssh/id_rsa'), privateKey)
    try {
      const tool = fixture.registered.find((t) => t.name === 'zterm_connect'), exec = { agent: { id: 'session-1' } }
      const results = await Promise.all([tool.execute({ target: { host: 'root@192.0.2.21' } }, { ...exec, callId: 'one' }), tool.execute({ target: { host: 'root@192.0.2.21' } }, { ...exec, callId: 'two' })])
      const catalog = await fixture.call('catalog')
      expect(catalog.value.hosts).toHaveLength(1)
      expect(catalog.value.hosts[0]).toMatchObject({ authType: 'key-file', username: 'root', host: '192.0.2.21' })
      expect(catalog.value.hosts[0]).not.toHaveProperty('credentialRef'); expect(fixture.credentials.size).toBe(0)
      expect(connected).toHaveLength(2); expect(connected[0].privateKey).toBe(privateKey)
      expect(JSON.stringify([catalog, results])).not.toContain(privateKey)
      expect(fixture.plugin.runtime.workspace('session-1')).toMatchObject({ catalogRevision: 2, capabilities: { automatic: true } })
    } finally { fixture.dispose() }
  })
  it('默认私钥缺失时保存主机供编辑，但不产生假连接；旧配置和默认 SSH 设置均可更新', async () => {
    const fixture = setup()
    try {
      const tool = fixture.registered.find((t) => t.name === 'zterm_connect')
      await expect(tool.execute({ target: { host: '192.0.2.25', username: 'operator' } }, { agent: { id: 'session-1' } })).rejects.toThrow('未找到默认 SSH 私钥')
      expect((await fixture.call('catalog')).value.hosts).toHaveLength(1)
      expect(fixture.plugin.runtime.workspace('session-1').terminals).toHaveLength(0)
      expect((await fixture.call('config', { patch: { defaultSshUsername: 'root', defaultPrivateKeyPath: '~/.ssh/custom_key' }, revision: 2 })).ok).toBe(true)
      expect((await fixture.call('catalog')).value).toMatchObject({ defaultSshUsername: 'root', defaultPrivateKeyPath: '~/.ssh/custom_key' })
    } finally { fixture.dispose() }
  })
  it('每台主机可配置宿主私钥文件路径，口令写凭据库而不是配置和 catalog', async () => {
    const fixture = setup()
    try {
      expect((await fixture.call('host/save', { host: { label: 'File host', host: 'host.example.invalid', username: 'operator', authType: 'key-file', privateKeyPath: '/srv/dsh/.ssh/fixture_key' }, passphrase: 'fixture-passphrase', revision: 1 })).ok).toBe(true)
      const catalog = await fixture.call('catalog')
      expect(catalog.value.hosts[0]).toMatchObject({ authType: 'key-file', privateKeyPath: '/srv/dsh/.ssh/fixture_key' })
      expect(catalog.value.hosts[0]).not.toHaveProperty('credentialRef')
      expect([...fixture.credentials.values()]).toEqual(['fixture-passphrase']); expect(JSON.stringify(catalog)).not.toContain('fixture-passphrase')
    } finally { fixture.dispose() }
  })
})
