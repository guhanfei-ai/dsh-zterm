import { describe, it, expect, vi } from 'vitest'
import { createServer } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { TerminalSession } from '../src/core/terminalSessionManager'
import { ZtermRuntime } from '../src/host/runtime'
import { RecordStore } from '../src/host/store'
import { DEFAULT_CONFIG } from '../src/host/config'
import { TargetResolver } from '../src/host/targetResolver'

describe('隔离 JumpServer HTTP 契约', () => {
  it.each(['token', 'password', 'access_key'] as const)('%s：普通用户分页、子节点、账号权限、fresh token 与公共状态不泄漏令牌', async (authMode) => {
    const root = mkdtempSync(join(tmpdir(), 'dsh-zterm-jump-')), requests: Array<{ url: string; body: any }> = [], connections: any[] = []; let tokens = 0
    const server = createServer(async (request, response) => {
      let body = ''; for await (const chunk of request) body += chunk
      const url = new URL(request.url!, 'http://fixture.invalid'); requests.push({ url: request.url!, body: body ? JSON.parse(body) : undefined })
      let value: any
      if (url.pathname === '/api/v1/perms/users/self/assets/asset-1/accounts/') value = [{ id: 'account-1', name: '运维账号', username: 'operator', actions: [{ value: 'connect' }] }, { id: 'denied', name: '禁止连接', actions: ['view'] }]
      else if (url.pathname === '/api/v1/users/profile/' || url.pathname.endsWith('/accounts/')) { response.statusCode = 403; value = { detail: '您没有执行该操作的权限。', code: 'permission_denied' } }
      else if (url.pathname.endsWith('/nodes/children/')) value = url.searchParams.has('key') ? [{ id: 'child', key: '1:2', name: '子节点', has_children: false, assets_amount: 1 }] : Array.from({ length: 600 }, (_, i) => ({ id: `node-${i}`, key: `1:${i}`, name: `节点 ${i}`, has_children: true }))
      else if (url.pathname === '/api/v1/authentication/connection-token/') { tokens++; response.statusCode = 201; value = { id: `token-${tokens}`, value: `koko-secret-${tokens}` } }
      else if (url.pathname.endsWith('/client-url/')) value = { url: 'jms://' + Buffer.from(JSON.stringify({ endpoint: { host: '127.0.0.1', port: 2222 } })).toString('base64') }
      else if (url.pathname.endsWith('/assets/')) value = { count: url.searchParams.get('search') === '192.0.2.31' ? 1 : 100000, results: [{ id: 'asset-1', name: '测试资产', address: '192.0.2.31', platform: { name: 'Linux' } }] }
      else { response.statusCode = 404; value = {} }
      response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(value))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve)); const port = (server.address() as any).port
    const config = { ...DEFAULT_CONFIG, jumpservers: [{ id: 'jump-1', label: '隔离堡垒机', baseUrl: `http://127.0.0.1:${port}`, authMode, username: 'fixture-user', credentialRef: 'DSH_ZTERM_TEST_JUMP', accessKeyIdRef: 'DSH_ZTERM_TEST_JUMP_ID', verifyTls: true }] }
    class FakeTerminal extends TerminalSession {
      async connect(options: any) { connections.push(options); this.currentHost = options; this.connected = true }
      async openShell() {}
      isShellReady() { return this.connected }
      disconnect() { this.connected = false; this.emit('closed') }
    }
    const resolver = new TargetResolver({ config: () => config, query: (instance, operation, args) => runtime.jumpQuery(instance, operation, args), saveHost: async () => { throw new Error('已有授权不应新增主机') } })
    const runtime: ZtermRuntime = new ZtermRuntime({ config: () => config, credentials: { resolve: async (ref) => ({ value: ref === 'DSH_ZTERM_TEST_JUMP_ID' ? 'fixture-ak-id' : 'api-secret' }) }, store: new RecordStore(root), sessionCwd: () => root, terminalFactory: (id, generation) => new FakeTerminal(id, generation), resolveAutomaticTarget: (target, signal) => resolver.resolve(target, signal) })
    try {
      const nodes = await runtime.jumpQuery('jump-1', 'nodes') as any; expect(nodes.nodes).toHaveLength(500); expect(nodes.truncated).toBe(true)
      const children = await runtime.jumpQuery('jump-1', 'nodes', { parentKey: '1:0' }) as any; expect(children.nodes[0].nodeId).toBe('child')
      const assets = await runtime.jumpQuery('jump-1', 'assets', { query: '测试', offset: 100, limit: 100 }) as any; expect(assets.hasMore).toBe(true); expect(assets.total).toBe(100000)
      expect(requests.some((r) => r.url.includes('key=1%3A0'))).toBe(true)
      await expect(runtime.connect('s', { kind: 'jumpserver', instanceId: 'jump-1', assetId: 'asset-1', accountId: 'denied' })).rejects.toThrow('没有连接权限')
      expect(tokens).toBe(0); expect(connections).toHaveLength(0)
      const terminal = await runtime.connect('s', { host: '192.0.2.31' })
      await vi.waitFor(() => expect(runtime.workspace('s').terminals[0].state).toBe('ready'))
      expect(requests.find((r) => r.body)?.body).toEqual({ asset: 'asset-1', account: '运维账号', protocol: 'ssh', connect_method: 'web_cli' })
      expect(connections[0]).toMatchObject({ host: '127.0.0.1', port: 2222, username: 'JMS-token-1', password: 'koko-secret-1', requireHostTrust: true })
      expect(JSON.stringify(runtime.workspace('s'))).not.toContain('koko-secret-1')
      await runtime.reconnect('s', terminal.id); expect(tokens).toBe(2); expect(connections[1].password).toBe('koko-secret-2')
      expect(requests.some((request) => request.url === '/api/v1/users/profile/')).toBe(false)
      expect(requests.filter((request) => request.url.endsWith('/accounts/')).map((request) => request.url)).toEqual(Array(4).fill('/api/v1/perms/users/self/assets/asset-1/accounts/'))
    } finally { runtime.dispose(); await new Promise<void>((resolve) => server.close(() => resolve())); rmSync(root, { recursive: true, force: true }) }
  })
})
