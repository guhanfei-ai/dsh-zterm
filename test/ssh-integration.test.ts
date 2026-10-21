import { describe, it, expect } from 'vitest'
import { Server, utils } from 'ssh2'
import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto'
import { mkdtempSync, rmSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { LocalPtySession } from '../src/core/localPtySession'
import { ZtermRuntime } from '../src/host/runtime'
import { RecordStore } from '../src/host/store'
import { DEFAULT_CONFIG } from '../src/host/config'
import { definitions } from '../src/tools'
import { createPlugin } from '../src/index'
import type { Config } from '../src/shared/types'

describe('测试拥有的真实 SSH 与 PTY 通道', () => {
  it('对话目标自动保存后读取宿主默认私钥，在真实 SSH 公钥认证和指纹确认后就绪', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-zterm-auto-ssh-')), clients = new Set<any>(), auth: string[] = []
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs1', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } })
    const parsed = utils.parseKey(privateKey)
    if (parsed instanceof Error || Array.isArray(parsed)) throw new Error('测试私钥无效')
    mkdirSync(join(dir, '.ssh')); writeFileSync(join(dir, '.ssh/id_rsa'), privateKey, { mode: 0o600 })
    const server = new Server({ hostKeys: [privateKey] }, (client) => {
      clients.add(client); client.on('error', () => {}); client.on('close', () => clients.delete(client))
      client.on('authentication', (request) => {
        if (request.method !== 'publickey' || request.username !== 'operator' || !request.key.data.equals(parsed.getPublicSSH())) return request.reject()
        if (request.signature && parsed.verify(request.blob!, request.signature, request.hashAlgo) !== true) return request.reject()
        if (request.signature) auth.push(request.username)
        request.accept()
      })
      client.on('ready', () => client.on('session', (accept) => {
        const session = accept(); session.on('pty', (ok) => ok?.())
        session.on('shell', (ok) => { const channel = ok(); channel.write('fixture shell ready\r\n') })
      }))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve)); const port = (server.address() as { port: number }).port
    let config: Config = { ...DEFAULT_CONFIG, hosts: [], defaultSshUsername: 'operator' }, revision = 1
    const tools: any[] = [], cleanup: Array<() => void> = []
    const ctx: any = { tools: { register: (tool: any) => tools.push(tool) }, systemPrompt: { section() {} }, credentials: { resolve: async () => undefined },
      sessions: { get: (id: string) => id === 'auto-session' ? { header: { cwd: dir } } : undefined },
      settings: { describe: () => [{ ns: 'zterm', value: config, revision }], update: async (_ns: string, next: Config, expected: number) => { if (expected !== revision) throw new Error('stale test config'); config = next; revision++ } },
      inject: (_services: any, body: any) => body(ctx), on() {}, connection: { fetch: { register() { return () => {} } } }, effect: (body: any) => { cleanup.push(body()) } }
    const plugin = createPlugin(ctx, {}, { dataRoot: join(dir, 'data'), defaultSshHome: dir })
    try {
      const result = JSON.parse(await tools.find((tool) => tool.name === 'zterm_connect').execute({ target: { host: '127.0.0.1', port } }, { agent: { id: 'auto-session' }, signal: new AbortController().signal }))
      expect(config.hosts).toHaveLength(1); expect(config.hosts[0]).toMatchObject({ authType: 'key-file', username: 'operator', port })
      expect(config.hosts[0]).not.toHaveProperty('credentialRef'); expect(JSON.stringify(config)).not.toContain(privateKey)
      await viWait(() => Boolean(plugin.runtime.workspace('auto-session').terminals[0].trust))
      const terminal = plugin.runtime.workspace('auto-session').terminals[0]
      plugin.runtime.trust('auto-session', terminal.id, terminal.generation, terminal.trust!.requestId, 'trust-always')
      await viWait(() => plugin.runtime.workspace('auto-session').terminals[0].state === 'ready')
      plugin.runtime.bind('auto-session', terminal.id, terminal.generation)
      expect(auth).toEqual(['operator']); expect(plugin.runtime.workspace('auto-session').binding?.mode).toBe('read')
      expect(result.value.target.source).toBe('ssh'); expect(JSON.stringify(result)).not.toContain(privateKey)
      config = { ...config, defaultPrivateKeyPath: join(dir, 'missing-default'), hosts: config.hosts.map((host) => ({ ...host, privateKeyPath: join(dir, '.ssh/id_rsa') })) }; revision++
      await plugin.runtime.reconnect('auto-session', terminal.id)
      await viWait(() => plugin.runtime.workspace('auto-session').terminals[0].state === 'ready')
      expect(auth).toEqual(['operator', 'operator'])
    } finally {
      cleanup.forEach((dispose) => dispose?.()); for (const client of clients) client.end()
      await new Promise<void>((resolve) => server.close(() => resolve())); rmSync(dir, { recursive: true, force: true })
    }
  }, 10000)
  it.each([
    { name: 'RSA', generate: () => generateKeyPairSync('rsa', { modulusLength: 2048 }), hash: 'sha256' },
    { name: 'ECDSA', generate: () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), hash: 'sha256' },
    { name: 'Ed25519', generate: () => generateKeyPairSync('ed25519'), hash: null },
  ].flatMap((algorithm) => [false, true].map((encrypted) => ({ ...algorithm, encrypted }))))('$name PKCS#8（加密：$encrypted）经命名凭证、旧主机和宿主文件完成真实 SSH 认证', async ({ generate, hash, encrypted }) => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-zterm-pkcs8-')), clients = new Set<any>(), authenticated: string[] = []
    const { privateKey, publicKey } = generate(), passphrase = encrypted ? 'fixture-pkcs8-passphrase' : undefined
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem', ...(passphrase ? { cipher: 'aes-256-cbc', passphrase } : {}) }).toString()
    const path = join(dir, 'fixture-key.pem'); writeFileSync(path, pem, { mode: 0o600 })
    const publicDer = publicKey.export({ type: 'spki', format: 'der' })
    const server = new Server({ hostKeys: [utils.generateKeyPairSync('ed25519').private] }, (client) => {
      clients.add(client); client.on('error', () => {}); client.on('close', () => clients.delete(client))
      client.on('authentication', (request) => {
        if (request.method !== 'publickey' || request.username !== 'operator') return request.reject()
        const offered = utils.parseKey(request.key.data)
        if (offered instanceof Error || Array.isArray(offered) || !createPublicKey(offered.getPublicPEM()).export({ type: 'spki', format: 'der' }).equals(publicDer)) return request.reject()
        if (request.signature && !verify(request.hashAlgo ?? hash, request.blob!, publicKey, request.signature)) return request.reject()
        if (request.signature) authenticated.push(request.username)
        request.accept()
      })
      client.on('ready', () => client.on('session', (accept) => {
        const session = accept(); session.on('pty', (ok) => ok?.())
        session.on('shell', (ok) => { const channel = ok(); channel.write('fixture PKCS8 shell ready\r\n') })
      }))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve)); const port = (server.address() as { port: number }).port
    const passphraseRef = passphrase ? 'DSH_ZTERM_PKCS8_PHRASE' : undefined
    const base = { kind: 'ssh' as const, label: 'Fixture PKCS8 host', host: '127.0.0.1', port, username: 'operator' }
    const config: Config = { ...DEFAULT_CONFIG,
      credentials: [{ id: 'named-key', label: 'Fixture PKCS8 key', authType: 'key', credentialRef: 'DSH_ZTERM_PKCS8', passphraseRef }],
      hosts: [{ ...base, id: 'named', authType: 'key', credentialId: 'named-key' }, { ...base, id: 'legacy', authType: 'key', credentialRef: 'DSH_ZTERM_PKCS8', passphraseRef }, { ...base, id: 'file', authType: 'key-file', privateKeyPath: path, passphraseRef }] }
    const runtime = new ZtermRuntime({ config: () => config, credentials: { resolve: async (ref) => ({ value: ref === 'DSH_ZTERM_PKCS8' ? pem : passphrase! }) }, store: new RecordStore(join(dir, 'data')), sessionCwd: () => dir })
    try {
      for (const targetId of ['named', 'legacy', 'file']) {
        const terminal = await runtime.connect('pkcs8-session', { targetId })
        const view = () => runtime.workspace('pkcs8-session').terminals.find((entry) => entry.id === terminal.id)!
        await viWait(() => Boolean(view().trust) || view().state === 'error' || view().state === 'ready')
        if (view().trust) runtime.trust('pkcs8-session', terminal.id, terminal.generation, view().trust!.requestId, 'trust-always')
        await viWait(() => view().state === 'ready' || view().state === 'error')
        expect(view().state, view().error).toBe('ready')
        expect(runtime.bind('pkcs8-session', terminal.id, terminal.generation).mode).toBe('read')
        if (targetId === 'named') {
          runtime.setMode('pkcs8-session', terminal.id, terminal.generation, 'readwrite')
          await runtime.reconnect('pkcs8-session', terminal.id)
          await viWait(() => view().state === 'ready' || view().state === 'error')
          expect(view().state, view().error).toBe('ready')
          expect(runtime.bind('pkcs8-session', terminal.id, terminal.generation + 1).mode).toBe('read')
        }
        const visible = JSON.stringify([runtime.poll('pkcs8-session', -1), runtime.records('pkcs8-session'), config])
        expect(visible).not.toContain(JSON.stringify(pem).slice(1, -1))
        expect(visible).not.toContain('PRIVATE KEY')
        if (passphrase) expect(visible).not.toContain(passphrase)
        runtime.disconnect('pkcs8-session', terminal.id, true)
      }
      expect(authenticated).toEqual(['operator', 'operator', 'operator', 'operator'])
      expect(readFileSync(path, 'utf8')).toBe(pem)
    } finally {
      runtime.dispose(); for (const client of clients) client.end()
      await new Promise<void>((resolve) => server.close(() => resolve())); rmSync(dir, { recursive: true, force: true })
    }
  }, 15000)
  it('指纹确认、真实读取、默认拒绝写入、一揽子写入与实际记录', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-zterm-ssh-')), children = new Set<LocalPtySession>(), clients = new Set<any>(), sizes: Array<{ cols: number; rows: number }> = []
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs1', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } })
    const server = new Server({ hostKeys: [privateKey] }, (client) => {
      clients.add(client); client.on('error', () => {}); client.on('close', () => clients.delete(client))
      client.on('authentication', (request) => request.method === 'password' && request.username === 'operator' && request.password === 'isolated-password' ? request.accept() : request.reject())
      client.on('ready', () => client.on('session', (accept) => {
        const session = accept(); session.on('pty', (ok, _reject, info) => { sizes.push(info); ok?.() })
        session.on('window-change', (ok, _reject, info) => { sizes.push(info); for (const shell of children) shell.resize(info.cols, info.rows); ok?.() })
        session.on('shell', (ok) => {
          const channel = ok(), shell = new LocalPtySession('test-ssh-shell', 1, dir); children.add(shell)
          shell.on('error', () => {}); shell.on('data', (data) => channel.write(data)); channel.on('data', (data: Buffer) => shell.write(data.toString('utf8')))
          channel.on('close', () => { shell.disconnect(); children.delete(shell) }); void shell.connect('/bin/sh', 100, 30)
        })
      }))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve)); const address = server.address() as { port: number }
    const config = { ...DEFAULT_CONFIG, hosts: [{ id: 'test-host', label: '隔离 SSH 测试机器', kind: 'ssh' as const, host: '127.0.0.1', port: address.port, username: 'operator', authType: 'password' as const, credentialRef: 'DSH_ZTERM_TEST' }] }
    const runtime = new ZtermRuntime({ config: () => config, credentials: { resolve: async () => ({ value: 'isolated-password' }) }, store: new RecordStore(join(dir, 'data')), sessionCwd: () => dir })
    const wait = async (condition: () => boolean) => { const until = Date.now() + 7000; while (!condition()) { if (Date.now() > until) throw new Error('测试通道等待超时'); await new Promise((resolve) => setTimeout(resolve, 20)) } }
    try {
      const terminal = await runtime.connect('integration', { targetId: 'test-host' })
      await wait(() => Boolean(runtime.workspace('integration').terminals[0].trust))
      expect(runtime.workspace('integration').terminals[0].state).toBe('connecting')
      const trust = runtime.workspace('integration').terminals[0].trust!
      runtime.trust('integration', terminal.id, 1, trust.requestId, 'trust-always')
      await wait(() => runtime.workspace('integration').terminals[0].state === 'ready')
      runtime.resize('integration', terminal.id, 1, 132, 46)
      await wait(() => sizes.some((size) => size.cols === 132 && size.rows === 46))
      runtime.bind('integration', terminal.id, 1)
      const tools = definitions(runtime, () => config, { get: (id: string) => id === 'integration' ? { header: { cwd: dir } } : undefined })
      const call = (name: string, args: any, callId: string) => tools.find((t) => t.name === name)!.execute(args, { callId, agent: { id: 'integration' }, signal: new AbortController().signal })
      const system = JSON.parse(await call('zterm_read_system', {}, 'read-system')); expect(system.ok).toBe(true)
      const directory = JSON.parse(await call('zterm_read_directory', { path: dir }, 'read-directory')); expect(JSON.stringify(directory)).toContain(dir)
      await expect(call('zterm_execute', { command: 'printf blocked' }, 'blocked-write')).rejects.toThrow('未下发')
      runtime.setMode('integration', terminal.id, 1, 'readwrite')
      const file = join(dir, 'written-by-test.txt')
      const first = JSON.parse(await call('zterm_execute', { command: `printf first > '${file}'` }, 'write-first')); expect(first.value.exitCode).toBe(0)
      const second = JSON.parse(await call('zterm_execute', { command: `printf second >> '${file}'` }, 'write-second')); expect(second.value.exitCode).toBe(0)
      expect(readFileSync(file, 'utf8')).toBe('firstsecond')
      runtime.setMode('integration', terminal.id, 1, 'read')
      const read = JSON.parse(await call('zterm_read_file', { path: file }, 'read-file')); expect(JSON.stringify(read)).toContain('firstsecond')
      expect(runtime.records('integration').find((r) => r.callId === 'read-file')?.output).not.toContain('__ZTERM_FILE_V1__')
      await expect(call('zterm_execute', { command: 'printf denied' }, 'revoked-write')).rejects.toThrow('未下发')
      expect(runtime.records('integration').filter((r) => r.status === 'completed').length).toBeGreaterThanOrEqual(5)
    } finally {
      runtime.dispose(); for (const shell of children) shell.disconnect(); for (const client of clients) client.end()
      await new Promise<void>((resolve) => server.close(() => resolve())); rmSync(dir, { recursive: true, force: true })
    }
  }, 20000)
})
async function viWait(condition: () => boolean): Promise<void> {
  const until = Date.now() + 7000
  while (!condition()) { if (Date.now() > until) throw new Error('测试 SSH 通道等待超时'); await new Promise((resolve) => setTimeout(resolve, 20)) }
}
