import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
import { resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { mkdtemp, rm } from 'node:fs/promises'
import assert from 'node:assert/strict'
import { apply } from '../lib/index.js'

// 仅构造测试拥有的 Cordis 上下文；不启动 DSH 或载入作者配置。
const sdkRoot = process.argv[2]
if (!sdkRoot) throw new Error('用法：node scripts/check-host.mjs <已安装的 DSH 目录>')
const requireSdk = createRequire(join(resolve(sdkRoot), 'package.json'))
const sdk = await import(pathToFileURL(requireSdk.resolve('@deepseek-ai/dsh-tools')).href)
const boot = await import(pathToFileURL(requireSdk.resolve('@deepseek-ai/dsh-app-boot')).href)
const patches = boot.loadOverlayPatches('dsh-zterm', resolve('cordis.patch.yml'))
assert.equal(patches[0]?.insert?.[0]?.name, 'dsh-zterm')
assert.equal(patches[0]?.insert?.[0]?.id, 'zterm')
const { Context } = await import(pathToFileURL(requireSdk.resolve('@deepseek-ai/cordis')).href)
const { HostConnectionService, serverResponseSchema } = await import(pathToFileURL(requireSdk.resolve('@deepseek-ai/dsh-client-connection')).href)
const context = new Context()
context.provide('systemPrompt', { tools() {}, section() {} })
const tools = new sdk.ToolRuntime(context, { mode: 'native' })
context.provide('credentials', { describe: async () => ({ configured: false }), resolve: async () => undefined })
context.provide('sessions', { get: (id) => id === 'sdk-session' ? { header: { id } } : undefined })
const connection = new HostConnectionService(context, [], { isAuthenticated: () => true })
connection.rpc.intercept('/api', (endpoint) => endpoint === 'gateway/ping', () => ({ ok: true, value: 'pong' }))
const root = await mkdtemp(join(tmpdir(), 'dsh-zterm-sdk-'))
try {
  const fiber = context.plugin((ctx) => assert.equal(apply(ctx, {}, { dataRoot: root }), undefined))
  await fiber
  assert.equal(fiber.state, 2, 'Cordis plugin must be active')
  const schemas = tools.wireSchemas().schemas
  for (const definition of schemas) {
    sdk.assertObjectJsonSchema(definition.parameters)
    assert.equal(sdk.validateJsonSchemaValue(definition.parameters, { unexpected: true }, '').length > 0, true, definition.name)
  }
  assert.equal(schemas.length, 14)
  const call = async (method, payload = {}) => {
    const response = await connection.createSharedFetchHandler('/api').fetch(new Request(`http://127.0.0.1/api/${method}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'client-request', rpcId: 'sdk-check', method, payload }) }))
    assert.equal(response.status, 200, method)
    const envelope = await response.json(); assert.equal(serverResponseSchema.safeParse(envelope).success, true, method)
    return envelope.result
  }
  assert.equal((await call('gateway/ping')).value, 'pong')
  const catalog = await call('zterm/catalog')
  assert.equal(catalog.ok, true)
  assert.deepEqual(catalog.value.credentials, [])
  const invalidCredential = await call('zterm/credential/save', { credential: { label: 'SDK fixture', authType: 'key-file' }, content: 'relative-fixture.pem' })
  assert.equal(invalidCredential.ok, false)
  assert.equal(invalidCredential.error.code, 'invalid_request')
  assert.equal((await call('zterm/poll', { sessionId: 'sdk-session', cursor: -1 })).ok, true)
  assert.equal((await call('zterm/poll', { sessionId: 'unknown' })).ok, false)
  assert.equal(connection.admit(new Request('http://127.0.0.1/api/zterm/catalog', { headers: { origin: 'https://untrusted.example.invalid' } })).rejection, 403)
  console.log(`DSH SDK: bundle parsed, Cordis plugin active, ${schemas.length} tools, real Connection envelopes and Gateway coexistence validated.`)
} finally {
  await context.fiber.dispose()
  await rm(root, { recursive: true, force: true })
}
