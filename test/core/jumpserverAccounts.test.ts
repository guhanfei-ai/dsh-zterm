import { afterEach, describe, expect, it } from 'vitest'
import { createHmac } from 'node:crypto'
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http'
import { fetchJumpserverAccounts, createJumpserverFreshToken } from '../../src/core/jumpserverClient'

const accountsPath = '/api/v1/perms/users/self/assets/asset-1/accounts/'
const accounts = [
  { id: 'account-1', name: '运维账号', username: 'operator', actions: [{ value: 'connect' }] },
  { id: 'account-2', name: '只读账号', username: 'viewer', actions: ['view'] },
]
const servers: Server[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve())
  })))
})

async function fixture(statusCode = 200, body = JSON.stringify(accounts)) {
  const requests: Array<{ method?: string; path?: string; headers: IncomingHttpHeaders }> = []
  const server = createServer((request, response) => {
    requests.push({ method: request.method, path: request.url, headers: request.headers })
    response.setHeader('Content-Type', 'application/json')
    if (request.method === 'GET' && request.url === accountsPath) {
      response.statusCode = statusCode
      response.end(body)
    } else if (request.url === '/api/v1/users/profile/') {
      response.end(JSON.stringify({ id: 'fixture-user' }))
    } else {
      // 模拟普通用户：显式 user id 的管理员端点不允许访问。
      response.statusCode = 403
      response.end(JSON.stringify({ detail: '您没有执行该操作的权限。', code: 'permission_denied' }))
    }
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  servers.push(server)
  const port = (server.address() as { port: number }).port
  return {
    requests,
    params: {
      baseUrl: `http://127.0.0.1:${port}/api/`, verifyTls: true,
      authMode: 'access_key' as const, accessKeyId: 'fixture-ak-id', accessKeySecret: 'fixture-ak-secret',
      username: 'fixture-user', credential: 'fixture-credential',
    },
  }
}

describe('JumpServer 当前用户授权账号（issue #2）', () => {
  it.each(['access_key', 'token', 'password'] as const)('%s 直接查询 self 账号，无需 profile 或管理员权限', async (authMode) => {
    const { params, requests } = await fixture()
    const result = await fetchJumpserverAccounts({ ...params, authMode }, 'asset-1')
    expect(result).toEqual({ success: true, accounts: [
      { accountId: 'account-1', name: '运维账号', username: 'operator', canConnect: true, actions: ['connect'] },
      { accountId: 'account-2', name: '只读账号', username: 'viewer', canConnect: false, actions: ['view'] },
    ] })
    expect(requests.map(({ method, path }) => ({ method, path }))).toEqual([{ method: 'GET', path: accountsPath }])
    const { headers } = requests[0]
    expect(headers.accept).toBe('application/json')
    expect(headers['x-jms-org']).toBe('00000000-0000-0000-0000-000000000002')
    if (authMode === 'access_key') {
      const signed = `(request-target): get ${accountsPath}\naccept: application/json\ndate: ${headers.date}`
      const signature = createHmac('sha256', params.accessKeySecret).update(signed).digest('base64')
      expect(headers.date).toBeTruthy()
      expect(headers.authorization).toBe(`Signature keyId="${params.accessKeyId}",algorithm="hmac-sha256",headers="(request-target) accept date",signature="${signature}"`)
    } else if (authMode === 'token') {
      expect(headers.authorization).toBe(`Token ${params.credential}`)
    } else {
      expect(headers.authorization).toBe(`Basic ${Buffer.from(`${params.username}:${params.credential}`).toString('base64')}`)
    }
  })

  it('兼容 self 端点的分页响应', async () => {
    const { params } = await fixture(200, JSON.stringify({ count: 2, next: null, previous: null, results: accounts }))
    const result = await fetchJumpserverAccounts(params, 'asset-1')
    expect(result.success).toBe(true)
    expect(result.accounts.map(({ accountId, canConnect }) => ({ accountId, canConnect }))).toEqual([
      { accountId: 'account-1', canConnect: true }, { accountId: 'account-2', canConnect: false },
    ])
  })

  it('无授权账号时返回空列表，不回退管理员端点', async () => {
    const { params, requests } = await fixture(200, '[]')
    expect(await fetchJumpserverAccounts(params, 'asset-1')).toEqual({ success: true, accounts: [] })
    expect(requests.map(({ path }) => path)).toEqual([accountsPath])
  })

  it.each([
    [401, '认证失败，请检查凭据是否正确'],
    [403, '权限不足，当前账号无权访问此资源'],
    [404, '接口不存在，请确认 JumpServer 版本是否支持该端点'],
  ] as const)('self 返回 %s 时保留错误，不回退管理员端点或创建令牌', async (statusCode, error) => {
    const { params, requests } = await fixture(statusCode, JSON.stringify({ detail: 'fixture denied' }))
    expect(await fetchJumpserverAccounts(params, 'asset-1')).toEqual({ success: false, accounts: [], error })
    expect(await createJumpserverFreshToken(params, 'asset-1', 'account-1')).toEqual({
      success: false, error: `创建连接令牌失败：无法读取账号列表：${error}`,
    })
    expect(requests.map(({ path }) => path)).toEqual([accountsPath, accountsPath])
  })

  it.each([
    ['not-json', '服务器返回了无法解析的响应'],
    ['{"detail":"unexpected"}', '服务器返回了意外的数据格式'],
  ])('拒绝损坏或非账号响应 %s', async (body, error) => {
    const { params } = await fixture(200, body)
    expect(await fetchJumpserverAccounts(params, 'asset-1')).toEqual({ success: false, accounts: [], error })
  })

  it('三种认证缺少凭据时均在发请求前失败', async () => {
    const { params, requests } = await fixture()
    for (const authMode of ['access_key', 'token', 'password'] as const) {
      expect(await fetchJumpserverAccounts({ ...params, authMode, accessKeySecret: undefined, credential: undefined }, 'asset-1')).toEqual({
        success: false, accounts: [], error: '缺少凭据，请先完善配置',
      })
    }
    expect(requests).toEqual([])
  })
})
