/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
import { request as httpsRequest } from 'https'
import { request as httpRequest } from 'http'
import type { IncomingMessage } from 'http'
import { createHmac } from 'crypto'
import { translateError, translateJumpserverHttpStatus } from './errorTranslator'

// ==================== 类型定义 ====================

export interface JumpserverTestResult {
  success: boolean
  user?: {
    id: string
    username: string
    name: string
  }
  error?: string
}

export interface JumpserverAsset {
  assetId: string
  name: string
  address: string
  platform: string
  comment: string
}

export interface JumpserverAssetsQuery {
  keyword?: string
  limit?: number
  offset?: number
}

export interface JumpserverAssetsResult {
  success: boolean
  assets: JumpserverAsset[]
  total: number
  offset: number
  limit: number
  hasMore: boolean
  error?: string
}

export interface JumpserverNode {
  /** 节点主键 id，用于节点资产读取 (nodes/{nodeId}/assets/) */
  nodeId: string
  /** 节点 path key，用于官方子节点接口 (nodes/children/?key=...) */
  key: string
  name: string
  hasChildren: boolean
  assetCount: number
}

export interface JumpserverNodesResult {
  success: boolean
  nodes: JumpserverNode[]
  error?: string
}

export interface JumpserverAccount {
  accountId: string
  name: string
  username: string
  canConnect: boolean
  actions: string[]
}

export interface JumpserverAccountsResult {
  success: boolean
  accounts: JumpserverAccount[]
  error?: string
}

export interface JumpserverSessionParams {
  assetId: string
  accountId: string
  tokenId: string
  clientUrl: string
}

export interface JumpserverSessionParamsResult {
  success: boolean
  params?: JumpserverSessionParams
  error?: string
}

export interface JumpserverConnectParams {
  host: string
  port: number
  username: string
  password?: string
  privateKey?: string
}

export interface JumpserverExchangeResult {
  success: boolean
  connectParams?: JumpserverConnectParams
  error?: string
  /**
   * /exchange/ 真实响应结构摘要（顶层字段名 + 关键值截断）。
   * 仅在解析失败 / 疑似模型冲突时填充，供上层注入到错误文案与回执。
   * 不包含敏感凭据（password / privateKey / token 等已脱敏）。
   */
  rawResponseSummary?: string
  /**
   * 标记当前响应是否与 ssh2 直连模型冲突。
   *
   * 触发条件（任一即可）：
   *  1. 响应中完全没有 host 类字段（host / ip / hostname / address），说明
   *     该模式并不直接返回 SSH 直连参数；
   *  2. 响应中 host 字段是 jms:// 协议地址，说明服务端在告诉客户端走 JMS 协议，
   *     而不是 SSH 直连；
   *  3. 关键字段（username / credential）缺失，无法组成 ssh2 可用连接参数。
   *
   * 该字段只作为信号标记，不强行阻断 success=true（让上层决定如何处置）。
   * 命中模型冲突时上层应停止把响应当 SSH 参数直接连，并明确告知用户
   * 当前 connect_method=web_cli 期望走 clientUrl(jms://) 客户端协议，
   * 本进程并未实现 jms:// 客户端。
   */
  modelConflict?: boolean
}

export interface JumpserverConnectionParams {
  baseUrl: string
  authMode: 'token' | 'password' | 'access_key'
  username?: string
  credential?: string
  accessKeyId?: string
  accessKeySecret?: string
  verifyTls: boolean
}

// ==================== koko SSH 网关参数（v4.3 新增，主进程内部使用）====================

/**
 * fresh 连接令牌完整数据（含 value，仅主进程内部使用）
 *
 * 与 JumpserverSessionParams 的区别：本结构包含 value（koko SSH 登录密码），
 * 仅供主进程内部在「create fresh token → 组装 koko SSH 参数 → ssh2 connect」
 * 这段同步流程内短暂持有，不得跨 IPC 传递给 renderer。
 */
export interface JumpserverFreshTokenInternal {
  id: string
  /** koko SSH 登录密码（敏感），仅主进程内存使用，连接后即用即清 */
  value: string
  clientUrl: string
  assetId: string
  accountId: string
}

export interface JumpserverFreshTokenResult {
  success: boolean
  token?: JumpserverFreshTokenInternal
  error?: string
}

/**
 * koko SSH 网关登录参数（v4.3 新增，独立命名，不污染 JumpserverSessionParams / JumpserverExchangeResult）
 *
 * - username = 'JMS-' + freshToken.id（koko 剥前缀后用 token.id 查回连接令牌）
 * - password = freshToken.value（koko 校验 ConnectToken.Value == password）
 * - host/port 来自 clientUrl 的 jms:// payload endpoint，兜底 baseUrl host + 2222
 */
export interface JumpserverKokoSshParams {
  host: string
  port: number
  username: string
  /** koko SSH 登录密码（敏感），仅主进程内存使用 */
  password: string
}

export interface JumpserverKokoSshResolveResult {
  success: boolean
  params?: JumpserverKokoSshParams
  error?: string
  /** endpoint 来源：jms_payload = 从 clientUrl jms:// payload 解析；fallback_baseurl = 兜底 baseUrl host + 2222 */
  endpointSource: 'jms_payload' | 'fallback_baseurl'
}

// ==================== 分页常量与缓存 ====================

/** 资产列表默认页大小 */
export const JUMPSERVER_DEFAULT_PAGE_SIZE = 20
const JUMPSERVER_DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000002'
const JUMPSERVER_ACCEPT_HEADER = 'application/json'

// ==================== 签名工具 ====================

function normalizeJumpserverBaseUrl(baseUrl: string): string {
  const trimmed = baseUrl.trim()
  if (!trimmed) return trimmed

  try {
    const url = new URL(trimmed)
    const normalizedPath = url.pathname.replace(/\/+$/, '')
    url.pathname = normalizedPath === '/api' ? '' : normalizedPath
    url.search = ''
    url.hash = ''
    return url.toString().replace(/\/$/, '')
  } catch {
    return trimmed.replace(/\/api\/?$/, '').replace(/\/+$/, '')
  }
}

/**
 * 生成 RFC 1123 格式的 HTTP Date
 */
function rfc1123Date(): string {
  return new Date().toUTCString()
}

/**
 * 对 access_key 模式生成 JumpServer 签名
 *
 * JumpServer v3/v4 Access Key 采用 HTTP Signature：
 *   Signature keyId="...",algorithm="hmac-sha256",headers="(request-target) accept date",signature="..."
 */
function buildAccessKeyAuth(
  method: string,
  path: string,
  date: string,
  accessKeyId: string,
  accessKeySecret: string
): string {
  const signatureHeaders = ['(request-target)', 'accept', 'date']
  const requestTarget = `${method.toLowerCase()} ${path}`
  const stringToSign = [
    `(request-target): ${requestTarget}`,
    `accept: ${JUMPSERVER_ACCEPT_HEADER}`,
    `date: ${date}`
  ].join('\n')
  const hmac = createHmac('sha256', accessKeySecret)
  hmac.update(stringToSign)
  const signature = hmac.digest('base64')
  return `Signature keyId="${accessKeyId}",algorithm="hmac-sha256",headers="${signatureHeaders.join(' ')}",signature="${signature}"`
}

// ==================== HTTP 请求封装 ====================

interface RequestOptions {
  method: string
  path: string
  headers: Record<string, string>
  timeout: number
  body?: string
}

function makeRequest(
  baseUrl: string,
  opts: RequestOptions,
  verifyTls: boolean
): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const url = new URL(baseUrl)
    const isHttps = url.protocol === 'https:'

    const reqOpts = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: opts.path,
      method: opts.method,
      headers: opts.headers,
      timeout: opts.timeout,
      rejectUnauthorized: verifyTls
    }

    const requester = isHttps ? httpsRequest : httpRequest

    const req = requester(reqOpts, (res: IncomingMessage) => {
      let data = ''
      res.on('data', (chunk: Buffer) => {
        data += chunk.toString()
      })
      res.on('end', () => {
        resolve({ statusCode: res.statusCode || 0, body: data })
      })
      // 响应阶段错误（连接中途被重置等）必须监听，否则无监听 error 会抛
      // uncaughtException 导致主进程崩溃；req.on('error') 无法覆盖此阶段
      res.on('error', (err: Error) => {
        reject(err)
      })
    })

    req.on('error', (err: Error) => {
      reject(err)
    })

    req.on('timeout', () => {
      req.destroy()
      reject(new Error('请求超时'))
    })

    if (opts.body) {
      req.write(opts.body)
    }

    req.end()
  })
}

function buildJumpserverHeaders(
  date: string,
  extra?: Record<string, string>
): Record<string, string> {
  return {
    'Accept': JUMPSERVER_ACCEPT_HEADER,
    'Date': date,
    'X-JMS-ORG': JUMPSERVER_DEFAULT_ORG_ID,
    ...extra
  }
}

// ==================== 配置校验 ====================

/**
 * 对 JumpServer 实例发起最小配置校验：
 * 使用当前配置请求 GET /api/v1/users/profile/
 *
 * 成功返回用户信息，失败返回明确错误。
 */
export async function testJumpserverConnection(
  params: JumpserverConnectionParams
): Promise<JumpserverTestResult> {
  const normalizedBase = normalizeJumpserverBaseUrl(params.baseUrl)
  const path = '/api/v1/users/profile/'
  const method = 'GET'
  const date = rfc1123Date()
  const headers = buildJumpserverHeaders(date)

  // 根据认证方式构建 Authorization 头
  switch (params.authMode) {
    case 'access_key': {
      if (!params.accessKeyId || !params.accessKeySecret) {
        return { success: false, error: '缺少 Access Key ID 或 Secret' }
      }
      headers['Authorization'] = buildAccessKeyAuth(
        method,
        path,
        date,
        params.accessKeyId,
        params.accessKeySecret
      )
      break
    }
    case 'token': {
      if (!params.credential) {
        return { success: false, error: '缺少 Token' }
      }
      headers['Authorization'] = `Token ${params.credential}`
      break
    }
    case 'password': {
      if (!params.username || !params.credential) {
        return { success: false, error: '缺少用户名或密码' }
      }
      const encoded = Buffer.from(`${params.username}:${params.credential}`).toString('base64')
      headers['Authorization'] = `Basic ${encoded}`
      break
    }
  }

  try {
    const { statusCode, body } = await makeRequest(
      normalizedBase,
      { method, path, headers, timeout: 15000 },
      params.verifyTls
    )

    if (statusCode < 200 || statusCode >= 300) {
      return { success: false, error: translateJumpserverHttpStatus(statusCode, body, '用户信息') }
    }

    let data: unknown
    try {
      data = JSON.parse(body)
    } catch {
      return { success: false, error: '服务器返回了无法解析的响应' }
    }

    const profile = data as Record<string, unknown>

    if (!profile.id && !profile.username) {
      return { success: false, error: '响应中未找到用户信息' }
    }

    return {
      success: true,
      user: {
        id: String(profile.id || ''),
        username: String(profile.username || ''),
        name: String(profile.name || profile.username || '')
      }
    }
  } catch (err: unknown) {
    return { success: false, error: translateError(err, 'jumpserver') }
  }
}

/**
 * 根据认证方式构建 Authorization 头值，返回 null 表示凭据不全
 */
function buildAuthHeader(
  method: string,
  path: string,
  date: string,
  params: JumpserverConnectionParams
): string | null {
  switch (params.authMode) {
    case 'access_key':
      if (!params.accessKeyId || !params.accessKeySecret) return null
      return buildAccessKeyAuth(method, path, date, params.accessKeyId, params.accessKeySecret)
    case 'token':
      if (!params.credential) return null
      return `Token ${params.credential}`
    case 'password':
      if (!params.username || !params.credential) return null
      return `Basic ${Buffer.from(`${params.username}:${params.credential}`).toString('base64')}`
  }
}

/**
 * 拉取 JumpServer 当前用户授权资产列表（支持分页与搜索）
 *
 * 直接请求 /api/v1/perms/users/self/assets/?limit=&offset=&search=，
 * 无需先查 profile 获取 userId，首屏只需一次往返。
 *
 * 兼容数组与分页 { count, next, previous, results } 两种返回格式。
 * 只读资产，不读账号，不创建连接令牌。
 */
export async function fetchJumpserverAssets(
  params: JumpserverConnectionParams,
  query?: JumpserverAssetsQuery
): Promise<JumpserverAssetsResult> {
  const normalizedBase = normalizeJumpserverBaseUrl(params.baseUrl)
  const limit = query?.limit ?? JUMPSERVER_DEFAULT_PAGE_SIZE
  const offset = query?.offset ?? 0

  // 直接请求当前用户资产列表（self 端点，无需先查 profile）
  const queryParams = new URLSearchParams()
  queryParams.set('limit', String(limit))
  queryParams.set('offset', String(offset))
  if (query?.keyword) {
    queryParams.set('search', query.keyword)
  }

  const assetsPath = `/api/v1/perms/users/self/assets/?${queryParams.toString()}`
  const assetsDate = rfc1123Date()
  const assetsAuth = buildAuthHeader('GET', assetsPath, assetsDate, params)

  if (assetsAuth === null) {
    return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: '缺少凭据，请先完善配置' }
  }

  const assetsHeaders = buildJumpserverHeaders(assetsDate, {
    'Authorization': assetsAuth
  })

  try {
    const { statusCode: assetsCode, body: assetsBody } = await makeRequest(
      normalizedBase,
      { method: 'GET', path: assetsPath, headers: assetsHeaders, timeout: 15000 },
      params.verifyTls
    )

    if (assetsCode < 200 || assetsCode >= 300) {
      return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: translateJumpserverHttpStatus(assetsCode, assetsBody, '资产') }
    }

    let data: unknown
    try {
      data = JSON.parse(assetsBody)
    } catch {
      return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: '服务器返回了无法解析的响应' }
    }

    // 兼容数组与分页 { count, next, previous, results } 格式
    let assetItems: Array<Record<string, unknown>>
    let total: number

    if (Array.isArray(data)) {
      assetItems = data as Array<Record<string, unknown>>
      total = assetItems.length
    } else if (
      data &&
      typeof data === 'object' &&
      Array.isArray((data as Record<string, unknown>).results)
    ) {
      const pageData = data as Record<string, unknown>
      assetItems = pageData.results as Array<Record<string, unknown>>
      total = Number(pageData.count ?? assetItems.length)
    } else {
      return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: '服务器返回了意外的数据格式' }
    }

    const assets: JumpserverAsset[] = assetItems.map((item, index) => ({
      assetId: String(item.id || item.asset_id || item.assetId || index),
      name: String(item.name || ''),
      address: String(item.address || item.ip || ''),
      platform: String(
        (item.platform as Record<string, unknown>)?.name || item.platform || ''
      ),
      comment: String(item.comment || item.description || '')
    }))

    const hasMore = offset + assets.length < total

    return { success: true, assets, total, offset, limit, hasMore }
  } catch (err: unknown) {
    return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: translateError(err, 'jumpserver') }
  }
}

/**
 * 拉取 JumpServer 当前用户授权节点列表（按需懒加载）
 *
 * 统一使用 UserPermedNodeChildrenApi：
 * - 不传 parentKey → GET /api/v1/perms/users/self/nodes/children/，返回当前用户可见的顶层节点
 * - 传 parentKey → GET /api/v1/perms/users/self/nodes/children/?key={parentKey}，返回该 key 节点的子节点
 *
 * parentKey 是节点的 path key（对应 JumpserverNode.key），不是 nodeId。
 * nodeId 仅用于 nodes/{nodeId}/assets/ 读取节点下资产。
 *
 * 兼容数组与分页两种返回格式。
 * 只读节点，不拉取资产详情。
 */
export async function fetchJumpserverNodes(
  params: JumpserverConnectionParams,
  parentKey?: string
): Promise<JumpserverNodesResult> {
  const normalizedBase = normalizeJumpserverBaseUrl(params.baseUrl)

  // 根层与子层统一走官方子节点端点 (UserPermedNodeChildrenApi)：
  //   - 顶层节点：GET /api/v1/perms/users/self/nodes/children/  （不传 key）
  //   - 某节点子层：GET /api/v1/perms/users/self/nodes/children/?key={key}
  // 避免使用 /api/v1/perms/users/self/nodes/ (UserAllPermedNodesApi) 返回整棵授权树
  // 从而保证根层展示是真正的顶层节点而非整棵树平铺。
  let path: string
  if (parentKey) {
    const queryParams = new URLSearchParams()
    queryParams.set('key', parentKey)
    path = `/api/v1/perms/users/self/nodes/children/?${queryParams.toString()}`
  } else {
    path = '/api/v1/perms/users/self/nodes/children/'
  }
  const date = rfc1123Date()
  const auth = buildAuthHeader('GET', path, date, params)

  if (auth === null) {
    return { success: false, nodes: [], error: '缺少凭据，请先完善配置' }
  }

  const headers = buildJumpserverHeaders(date, {
    'Authorization': auth
  })

  try {
    const { statusCode, body } = await makeRequest(
      normalizedBase,
      { method: 'GET', path, headers, timeout: 15000 },
      params.verifyTls
    )

    if (statusCode < 200 || statusCode >= 300) {
      return { success: false, nodes: [], error: translateJumpserverHttpStatus(statusCode, body, '节点') }
    }

    let data: unknown
    try {
      data = JSON.parse(body)
    } catch {
      return { success: false, nodes: [], error: '服务器返回了无法解析的响应' }
    }

    // 兼容数组与分页 { count, next, previous, results } 格式
    let nodeItems: Array<Record<string, unknown>>
    if (Array.isArray(data)) {
      nodeItems = data as Array<Record<string, unknown>>
    } else if (
      data &&
      typeof data === 'object' &&
      Array.isArray((data as Record<string, unknown>).results)
    ) {
      nodeItems = (data as Record<string, unknown>).results as Array<Record<string, unknown>>
    } else {
      return { success: false, nodes: [], error: '服务器返回了意外的数据格式' }
    }

    const nodes: JumpserverNode[] = nodeItems.map((item) => {
      const rawHasChildren = item.has_children ?? item.hasChildren ?? item.is_parent
      // 若官方未返回 hasChildren 标记，默认允许展开（点击展开时若返回 0 子节点再收起箭头）
      const hasChildren = typeof rawHasChildren === 'boolean'
        ? rawHasChildren
        : true

      const assetCount = Number(item.assets_amount ?? item.assetCount ?? item.asset_count ?? 0)

      // 官方字段：id (主键，用于 assets 读取) + key (path key，用于 children/?key=)
      // 兼容：若官方未返回 key，回退到 id 兜底
      const nodeId = String(item.id || item.node_id || item.nodeId || '')
      const key = String(item.key || item.value || item.full_value || nodeId)

      return {
        nodeId,
        key,
        name: String(item.name || item.full_value || ''),
        hasChildren,
        assetCount
      }
    })

    return { success: true, nodes }
  } catch (err: unknown) {
    return { success: false, nodes: [], error: translateError(err, 'jumpserver') }
  }
}

/**
 * 拉取 JumpServer 指定节点下的资产列表（支持分页与搜索）
 *
 * 端点：GET /api/v1/perms/users/self/nodes/{nodeId}/assets/?limit=&offset=&search=
 *
 * 返回格式与 fetchJumpserverAssets 一致，复用 JumpserverAssetsResult。
 * 只读资产，不读账号，不创建连接令牌。
 */
export async function fetchJumpserverNodeAssets(
  params: JumpserverConnectionParams,
  nodeId: string,
  query?: JumpserverAssetsQuery
): Promise<JumpserverAssetsResult> {
  const normalizedBase = normalizeJumpserverBaseUrl(params.baseUrl)
  const limit = query?.limit ?? JUMPSERVER_DEFAULT_PAGE_SIZE
  const offset = query?.offset ?? 0

  const queryParams = new URLSearchParams()
  queryParams.set('limit', String(limit))
  queryParams.set('offset', String(offset))
  if (query?.keyword) {
    queryParams.set('search', query.keyword)
  }

  const path = `/api/v1/perms/users/self/nodes/${nodeId}/assets/?${queryParams.toString()}`
  const date = rfc1123Date()
  const auth = buildAuthHeader('GET', path, date, params)

  if (auth === null) {
    return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: '缺少凭据，请先完善配置' }
  }

  const headers = buildJumpserverHeaders(date, {
    'Authorization': auth
  })

  try {
    const { statusCode, body } = await makeRequest(
      normalizedBase,
      { method: 'GET', path, headers, timeout: 15000 },
      params.verifyTls
    )

    if (statusCode < 200 || statusCode >= 300) {
      return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: translateJumpserverHttpStatus(statusCode, body, '节点资产') }
    }

    let data: unknown
    try {
      data = JSON.parse(body)
    } catch {
      return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: '服务器返回了无法解析的响应' }
    }

    // 兼容数组与分页 { count, next, previous, results } 格式
    let assetItems: Array<Record<string, unknown>>
    let total: number

    if (Array.isArray(data)) {
      assetItems = data as Array<Record<string, unknown>>
      total = assetItems.length
    } else if (
      data &&
      typeof data === 'object' &&
      Array.isArray((data as Record<string, unknown>).results)
    ) {
      const pageData = data as Record<string, unknown>
      assetItems = pageData.results as Array<Record<string, unknown>>
      total = Number(pageData.count ?? assetItems.length)
    } else {
      return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: '服务器返回了意外的数据格式' }
    }

    const assets: JumpserverAsset[] = assetItems.map((item, index) => ({
      assetId: String(item.id || item.asset_id || item.assetId || index),
      name: String(item.name || ''),
      address: String(item.address || item.ip || ''),
      platform: String(
        (item.platform as Record<string, unknown>)?.name || item.platform || ''
      ),
      comment: String(item.comment || item.description || '')
    }))

    const hasMore = offset + assets.length < total

    return { success: true, assets, total, offset, limit, hasMore }
  } catch (err: unknown) {
    return { success: false, assets: [], total: 0, offset, limit, hasMore: false, error: translateError(err, 'jumpserver') }
  }
}

/**
 * 按资产读取授权账号列表
 *
 * 两步链路：
 *  1. GET /api/v1/users/profile/ → 获取当前用户 id
 *  2. GET /api/v1/perms/users/{user_id}/assets/{asset_id}/accounts/ → 拉取账号
 *
 * 只读账号，不创建连接令牌。
 */
export async function fetchJumpserverAccounts(
  params: JumpserverConnectionParams,
  assetId: string
): Promise<JumpserverAccountsResult> {
  const normalizedBase = normalizeJumpserverBaseUrl(params.baseUrl)

  // ===== 第一步：获取当前用户信息 =====
  const profilePath = '/api/v1/users/profile/'
  const profileDate = rfc1123Date()
  const profileAuth = buildAuthHeader('GET', profilePath, profileDate, params)

  if (profileAuth === null) {
    return { success: false, accounts: [], error: '缺少凭据，请先完善配置' }
  }

  const profileHeaders = buildJumpserverHeaders(profileDate, {
    'Authorization': profileAuth
  })

  try {
    const { statusCode: profileCode, body: profileBody } = await makeRequest(
      normalizedBase,
      { method: 'GET', path: profilePath, headers: profileHeaders, timeout: 15000 },
      params.verifyTls
    )

    if (profileCode < 200 || profileCode >= 300) {
      return { success: false, accounts: [], error: translateJumpserverHttpStatus(profileCode, profileBody, '用户信息') }
    }

    let profile: Record<string, unknown>
    try {
      profile = JSON.parse(profileBody) as Record<string, unknown>
    } catch {
      return { success: false, accounts: [], error: '服务器返回了无法解析的响应' }
    }

    const userId = String(profile.id || '')
    if (!userId) {
      return { success: false, accounts: [], error: '无法获取当前用户 ID' }
    }

    // ===== 第二步：拉取该资产下的授权账号 =====
    const accountsPath = `/api/v1/perms/users/${userId}/assets/${assetId}/accounts/`
    const accountsDate = rfc1123Date()
    const accountsAuth = buildAuthHeader('GET', accountsPath, accountsDate, params)

    if (accountsAuth === null) {
      return { success: false, accounts: [], error: '缺少凭据，请先完善配置' }
    }

    const accountsHeaders = buildJumpserverHeaders(accountsDate, {
      'Authorization': accountsAuth
    })

    const { statusCode: accountsCode, body: accountsBody } = await makeRequest(
      normalizedBase,
      { method: 'GET', path: accountsPath, headers: accountsHeaders, timeout: 15000 },
      params.verifyTls
    )

    if (accountsCode < 200 || accountsCode >= 300) {
      return { success: false, accounts: [], error: translateJumpserverHttpStatus(accountsCode, accountsBody, '账号') }
    }

    let data: unknown
    try {
      data = JSON.parse(accountsBody)
    } catch {
      return { success: false, accounts: [], error: '服务器返回了无法解析的响应' }
    }

    // 兼容数组与分页格式
    let accountItems: Array<Record<string, unknown>>
    if (Array.isArray(data)) {
      accountItems = data as Array<Record<string, unknown>>
    } else if (
      data &&
      typeof data === 'object' &&
      Array.isArray((data as Record<string, unknown>).results)
    ) {
      accountItems = (data as Record<string, unknown>).results as Array<Record<string, unknown>>
    } else {
      return { success: false, accounts: [], error: '服务器返回了意外的数据格式' }
    }

    const accounts: JumpserverAccount[] = accountItems.map((item, index) => {
      const actionValues = Array.isArray(item.actions)
        ? item.actions
            .map((action) => {
              if (typeof action === 'string') return action
              if (action && typeof action === 'object') {
                const value = (action as Record<string, unknown>).value
                return value ? String(value) : ''
              }
              return ''
            })
            .filter(Boolean)
        : []

      return {
        accountId: String(item.id || item.account_id || item.accountId || index),
        name: String(item.name || item.alias || ''),
        username: String(item.username || item.name || ''),
        canConnect: actionValues.length === 0 || actionValues.includes('connect'),
        actions: actionValues
      }
    })

    return { success: true, accounts }
  } catch (err: unknown) {
    return { success: false, accounts: [], error: translateError(err, 'jumpserver') }
  }
}

/**
 * 主进程内部使用：创建 fresh 连接令牌并返回完整数据（含 value）
 *
 * 与 createJumpserverConnectionToken 的区别：
 *  - 本函数返回 value（koko SSH 登录密码），仅供主进程内部使用
 *  - createJumpserverConnectionToken 是其安全包装，剥离 value 后供 IPC 返回 renderer
 *
 * 收口链路（v3.7.1 真实契约校正后）：
 *  0. fetchJumpserverAccounts(assetId) → 解析 accountId 对应的 account name 字符串
 *  1. POST /api/v1/authentication/connection-token/ → 创建令牌（响应含 id + value）
 *  2. GET  /api/v1/authentication/connection-token/{token_id}/client-url/ → 获取客户端地址
 *
 * 第零步是新增的：v3.7.1 ConnectionToken.account 是 CharField(max_length=128)，必须发送
 * account 名称（如 "root"、"@SPEC"），而上游拿到的只有 accountId（DB 主键），因此需要先
 * 解析回 name。这一步全部封装在主进程内，IPC 签名不变。
 *
 * 关于请求契约（与 v3.7.1 ConnectionTokenSerializer / ConnectionToken 对齐）：
 *  - asset          Asset 的主键 UUID 字符串（ForeignKey）
 *  - account        CharField，存的是 account 名称（如 "root"、"@SPEC"），不是 DB 主键
 *  - protocol       必填 choices 字段（默认 ssh），与 connect_method 区分：protocol 决定协议族，connect_method 决定客户端实现
 *  - user           read_only，服务端从 request.user 派生，不再单独先拉 profile
 *  - connect_method 必填（主人这台真实 Jumpserver 明确报 "该字段是必填项"）。
 *                    接受 ConnectMethodUtil.get_connect_method() 的 name（value）取值。
 *                    当前主链路最终拿到 clientUrl（jms:// 格式），即 Web 客户端方式；
 *                    SSH 协议 + Web 终端 的合理默认是 "web_cli"，其他取值视下一次真实错误再调整。
 *
 * value 安全约束（v4.3 计划 5.3）：
 *  - value 仅存在于主进程内存，仅在「create fresh token → 组装 koko SSH 密码 → ssh2 connect」
 *    这段同步流程内短暂持有
 *  - 调用方在连接成功/失败/超时/取消后必须主动清空持有 value 的引用
 *  - value 不得写入日志、注释、错误文案、回执真实值
 *
 * 不打开终端，不建立 SSH 连接。
 */
export async function createJumpserverFreshToken(
  params: JumpserverConnectionParams,
  assetId: string,
  accountId: string
): Promise<JumpserverFreshTokenResult> {
  const normalizedBase = normalizeJumpserverBaseUrl(params.baseUrl)

  // 同时校验 assetId / accountId 不能为空
  if (!assetId || !accountId) {
    return { success: false, error: '资产 ID 与账号 ID 不能为空' }
  }

  // ===== 第零步：把 accountId 解析为 v3.7.1 ConnectionToken.account 真实所需的 account name 字符串 =====
  // v3.7.1 ConnectionToken.account 是 CharField(max_length=128) 而不是 ForeignKey，
  // 服务端 _validate(user, asset, account_name) 期望的是 account 名称（如 "root"、"@SPEC"），
  // 不是 Account 的 DB 主键。原实现误传 accountId，因此服务端校验永远不通过。
  const accountsResult = await fetchJumpserverAccounts(params, assetId)
  if (!accountsResult.success) {
    return { success: false, error: `创建连接令牌失败：无法读取账号列表：${accountsResult.error || '未知错误'}` }
  }
  const matchedAccount = accountsResult.accounts.find((a) => a.accountId === accountId)
  if (!matchedAccount) {
    return { success: false, error: '创建连接令牌失败：所选账号不在当前资产的授权账号列表中，请刷新后重试' }
  }
  if (!matchedAccount.canConnect) {
    return { success: false, error: '创建连接令牌失败：当前账号对该资产没有连接权限，请联系 JumpServer 管理员授权 connect 动作' }
  }
  // v3.7.1 ConnectionTokenSerializer 把 "account" 字段写入 CharField，
  // 后端按 name 解析；优先用 name（账号资产上的名称字段），缺失则回退 username（登录用户名）
  const accountName = matchedAccount.name || matchedAccount.username
  if (!accountName) {
    return { success: false, error: '创建连接令牌失败：账号缺少有效的 name 字段' }
  }

  // ===== 第一步：创建连接令牌（按 v3.7.1 真实契约）=====
  // - asset: Asset 主键 UUID（ForeignKey）
  // - account: account name 字符串（CharField）
  // - protocol: choices 字段，默认 ssh（保留不被删）
  // - user: read_only，服务端从 request.user 派生（不发送）
  // - connect_method: 维持 "web_cli"。
  //   本轮（plans/20260630-153310-Codex-Jumpserver切换connect_method直连试验计划.md）已对这台真实 Jumpserver
  //   做过 native 试验：create-token 接受 native（201），但 client-url 直接 400
  //   {"error":"Connect method not support: native"}，且 /exchange/ 仍只返回 ConnectionToken 元信息、
  //   不返回 host/port/username/凭据。结论：该实例不支持 native 直连模式，切到 native 反而更早在
  //   client-url 步骤报 400，比 web_cli 的链路更差。故按计划「止损」回到 web_cli，不在本轮混试其它取值，
  //   也不顺手切 Magnus/JMS 客户端方案（留待后续单独 plan）。
  const tokenPath = '/api/v1/authentication/connection-token/'
  const tokenBody = JSON.stringify({
    asset: assetId,
    account: accountName,
    protocol: 'ssh',
    connect_method: 'web_cli'
  })
  const tokenDate = rfc1123Date()
  const tokenAuth = buildAuthHeader('POST', tokenPath, tokenDate, params)

  if (tokenAuth === null) {
    return { success: false, error: '缺少凭据，请先完善配置' }
  }

  const tokenHeaders = buildJumpserverHeaders(tokenDate, {
    'Content-Type': 'application/json',
    'Authorization': tokenAuth
  })

  try {
    const { statusCode: tokenCode, body: tokenRespBody } = await makeRequest(
      normalizedBase,
      { method: 'POST', path: tokenPath, headers: tokenHeaders, timeout: 15000, body: tokenBody },
      params.verifyTls
    )

    if (tokenCode < 200 || tokenCode >= 300) {
      // 阶段语义：明确告诉用户是「创建连接令牌」这一步失败，并透出服务端真实错误
      return {
        success: false,
        error: `创建连接令牌失败：${translateJumpserverHttpStatus(tokenCode, tokenRespBody, '令牌创建')}`
      }
    }

    let tokenData: Record<string, unknown>
    try {
      tokenData = JSON.parse(tokenRespBody) as Record<string, unknown>
    } catch {
      return { success: false, error: '创建连接令牌失败：服务器返回了无法解析的响应' }
    }

    // v3.7.1 真实契约：响应主键就是 `id`，是 token 的 UUID 字符串
    const tokenId = String(tokenData.id || tokenData.token_id || tokenData.tokenId || '')
    if (!tokenId) {
      return { success: false, error: '创建连接令牌失败：未获取到连接令牌 ID' }
    }

    // v4.3：value = koko SSH 登录密码（敏感），仅在主进程内存中短暂持有
    // koko 校验 ConnectToken.Value == password，登录格式 username=JMS-{id}、password={value}
    const tokenValue = String(tokenData.value || '')
    if (!tokenValue) {
      return { success: false, error: '创建连接令牌失败：未获取到连接令牌 value' }
    }

    // ===== 第二步：获取客户端连接地址 =====
    const clientUrlPath = `/api/v1/authentication/connection-token/${tokenId}/client-url/`
    const clientUrlDate = rfc1123Date()
    const clientUrlAuth = buildAuthHeader('GET', clientUrlPath, clientUrlDate, params)

    if (clientUrlAuth === null) {
      return { success: false, error: '缺少凭据，请先完善配置' }
    }

    const clientUrlHeaders = buildJumpserverHeaders(clientUrlDate, {
      'Authorization': clientUrlAuth
    })

    const { statusCode: clientUrlCode, body: clientUrlRespBody } = await makeRequest(
      normalizedBase,
      { method: 'GET', path: clientUrlPath, headers: clientUrlHeaders, timeout: 15000 },
      params.verifyTls
    )

    if (clientUrlCode < 200 || clientUrlCode >= 300) {
      // 阶段语义：明确告诉用户是「获取客户端地址」这一步失败，并透出服务端真实错误
      return {
        success: false,
        error: `获取客户端地址失败：${translateJumpserverHttpStatus(clientUrlCode, clientUrlRespBody, '客户端地址')}`
      }
    }

    let clientUrl = ''
    try {
      const clientUrlData = JSON.parse(clientUrlRespBody) as Record<string, unknown>
      // v3.7.1 真实契约：服务端返回 { url: "jms://<base64...>" }
      // 兼容旧字段名（client_url / clientUrl）作为兜底
      clientUrl = String(clientUrlData.url || clientUrlData.client_url || clientUrlData.clientUrl || '')
    } catch {
      return { success: false, error: '获取客户端地址失败：服务器返回了无法解析的响应' }
    }

    if (!clientUrl) {
      return { success: false, error: '获取客户端地址失败：未获取到有效的客户端连接地址' }
    }

    return {
      success: true,
      token: { id: tokenId, value: tokenValue, clientUrl, assetId, accountId }
    }
  } catch (err: unknown) {
    return { success: false, error: translateError(err, 'jumpserver') }
  }
}

/**
 * 为指定资产 + 账号创建 Jumpserver 连接令牌并获取会话参数（IPC 安全包装）
 *
 * 内部调用 createJumpserverFreshToken 拿到完整令牌数据（含 value），
 * 然后剥离 value，仅返回非敏感的会话参数供 IPC 返回 renderer。
 *
 * 不打开终端，只返回会话参数供下一步使用。
 * IPC 回包结构维持现状，不新增 value。
 */
export async function createJumpserverConnectionToken(
  params: JumpserverConnectionParams,
  assetId: string,
  accountId: string
): Promise<JumpserverSessionParamsResult> {
  const result = await createJumpserverFreshToken(params, assetId, accountId)
  if (!result.success || !result.token) {
    return { success: false, error: result.error }
  }
  return {
    success: true,
    // accountId 仍回传 DB 主键，供上层做账号偏好写入和身份识别
    // value 已剥离，不跨 IPC 传递
    params: {
      assetId: result.token.assetId,
      accountId: result.token.accountId,
      tokenId: result.token.id,
      clientUrl: result.token.clientUrl
    }
  }
}

/**
 * 使用连接令牌兑换真实终端连接参数（SSH host/port/username/password）
 *
 * 四步链路：
 *  1. 已有 tokenId（来自 createJumpserverConnectionToken）
 *  2. POST /api/v1/authentication/connection-token/exchange/ → 兑换终端连接参数
 *  3. 解析响应提取 SSH 连接信息
 *  4. 返回可供 TerminalSession.connect() 直接使用的参数
 *
 * 本轮（v2.9 兑换响应校正）契约说明：
 *  - 之前实现把 /exchange/ 响应直接当作 ssh2 直连参数解析（host/ip/username/gateway.*），
 *    在 connect_method=web_cli 模式下拿到的是 "未获取到目标主机地址" 这种无上下文错误。
 *  - 当前已知事实：clientUrl=jms://...，说明 jumpserver 主链路期望客户端走 JMS 协议
 *    而不是 SSH 直连；/exchange/ 在 web_cli 模式下大概率不会返回 SSH host/port/username。
 *  - 因此本轮不再盲改字段名，而是：
 *      ① 把 /exchange/ 真实响应结构作为摘要带回（脱敏），
 *      ② 在解析阶段就标出 modelConflict 信号（host 缺失 / host 是 jms:// / 关键字段缺失），
 *      ③ 让 terminal:connectJumpserver 入口能基于这些信号给出阶段化错误和冲突说明。
 *  - 若未来有新的真实响应字段被确认（如 native 模式下的 host/port/username），
 *    只需在 resolveExchangeHost / resolveExchangeUsername 处补全字段名，
 *    其它结构不动。
 *
 * 不打开终端，不建立 SSH 连接。
 */

// /exchange/ 响应中需要脱敏的敏感键（避免把凭据写进错误文案 / 回执）
// 顶层 key 名命中即 <redacted>；对象内部子键命中也会被摘要函数递归脱敏。
const EXCHANGE_SENSITIVE_KEYS = new Set([
  // 凭据类
  'password',
  'private_key',
  'privateKey',
  'secret',
  'secret_key',
  'secretKey',
  'access_key',
  'accessKey',
  'access_key_secret',
  'accessKeySecret',
  'credential',
  'token',
  'authorization',
  'bearer',
  'id_token',
  'idToken',
  'auth',
  'apikey',
  'api_key',
  'apiKey',
  'cookie',
  'session',
  'session_id',
  'sessionId',
  // /exchange/ 顶层就有一个名为 value 的 token 凭据字段
  // （v3.1 真实联调确认：value=xxxxx 是 Magnus/JMS token 凭据本身）
  'value',
  'key'
])

/**
 * 判断一段字符串值是否"长得像凭据"，是则整体打码。
 * 用于兜底：即使 key 名不在 EXCHANGE_SENSITIVE_KEYS 里，
 * 值本身若是 jms:// / JWT / 长 base64 形态，也视为敏感。
 */
function isCredentialLikeString(value: string): boolean {
  if (!value) return false
  // jms:// 协议地址（内含 base64 payload）
  if (/^jms:\/\//i.test(value)) return true
  // 标准 JWT：eyJ 开头 + 三段以 . 分隔的 base64url
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) return true
  // 排除 UUID（8-4-4-4-12，含 -，易被 base64url 正则误命中）
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
    return false
  }
  // 长 base64 / base64url 串
  // 阈值定 16：覆盖典型短 token value（实测真实 token 长度 16 字符）
  // 短词（name=production、protocol=ssh 等）天然不命中
  if (value.length >= 16 && /^[A-Za-z0-9+/=_-]+$/.test(value)) {
    return true
  }
  return false
}

/**
 * 递归把任意值压成摘要片段（仅供 summarizeExchangeResponse 调用）。
 *
 *  - string：超过 40 字符截断；命中 isCredentialLikeString 直接 <redacted>
 *  - number / boolean：直接展示
 *  - array：仅报长度，避免长数组塞进错误文案
 *  - object：递归一层；子键命中 EXCHANGE_SENSITIVE_KEYS 一律 <redacted>
 *  - depth<=0 终止递归，object 收口为 {...}
 */
function summarizeValue(value: unknown, depth: number): string {
  if (value === null) return 'null'
  if (value === undefined) return 'undefined'
  if (typeof value === 'string') {
    if (isCredentialLikeString(value)) return '<redacted>'
    const clipped = value.length > 40 ? value.slice(0, 40) + '…' : value
    return clipped
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]'
    return `[${value.length} items]`
  }
  if (typeof value === 'object') {
    if (depth <= 0) return '{...}'
    const obj = value as Record<string, unknown>
    const subParts: string[] = []
    for (const [k, v] of Object.entries(obj)) {
      if (EXCHANGE_SENSITIVE_KEYS.has(k)) {
        subParts.push(`${k}=<redacted>`)
        continue
      }
      subParts.push(`${k}=${summarizeValue(v, depth - 1)}`)
    }
    return `{${subParts.join(',')}}`
  }
  return String(value)
}

/**
 * 把 /exchange/ 真实响应对象扁平化为一段可读摘要，用于错误文案和回执。
 *
 * 规则（v3.1 热修后）：
 *  - 顶层敏感键 → <redacted>；
 *  - 顶层普通值递归一层（对象/数组/基本类型均按 summarizeValue 处理）；
 *  - 字符串值若"长得像凭据"（jms:// / JWT / 长 base64）也 <redacted>；
 *  - 嵌套对象/数组里再次出现的敏感子键同样 <redacted>；
 *  - 整体最长 300 字符，超出截断。
 */
function summarizeExchangeResponse(payload: Record<string, unknown>): string {
  const parts: string[] = []
  for (const [key, value] of Object.entries(payload)) {
    if (EXCHANGE_SENSITIVE_KEYS.has(key)) {
      parts.push(`${key}=<redacted>`)
      continue
    }
    parts.push(`${key}=${summarizeValue(value, 1)}`)
  }
  const joined = parts.join(' ')
  return joined.length > 300 ? joined.slice(0, 300) + '…' : joined
}

export async function exchangeJumpserverConnectionToken(
  params: JumpserverConnectionParams,
  tokenId: string
): Promise<JumpserverExchangeResult> {
  const normalizedBase = normalizeJumpserverBaseUrl(params.baseUrl)
  const path = '/api/v1/authentication/connection-token/exchange/'
  const method = 'POST'
  const date = rfc1123Date()
  const auth = buildAuthHeader(method, path, date, params)

  if (auth === null) {
    return { success: false, error: '缺少凭据，请先完善配置' }
  }

  const headers = buildJumpserverHeaders(date, {
    'Content-Type': 'application/json',
    'Authorization': auth
  })

  const body = JSON.stringify({ id: tokenId })

  try {
    const { statusCode, body: respBody } = await makeRequest(
      normalizedBase,
      { method, path, headers, timeout: 15000, body },
      params.verifyTls
    )

    if (statusCode < 200 || statusCode >= 300) {
      return { success: false, error: translateJumpserverHttpStatus(statusCode, respBody, '令牌兑换') }
    }

    let data: Record<string, unknown>
    try {
      data = JSON.parse(respBody) as Record<string, unknown>
    } catch {
      return { success: false, error: '服务器返回了无法解析的响应' }
    }

    // 真实响应结构摘要：始终带回，供上层注入到错误文案与回执
    // 失败 / 冲突路径都会带上，让"未获取到目标主机地址"不再是空泛报错
    const rawResponseSummary = summarizeExchangeResponse(data)

    // ===== 字段解析：兼容多种字段名（扁平 / 嵌套 gateway） =====
    // host 来源（按优先级）：host > ip > hostname > address > gateway.host > gateway.ip
    const host = String(
      data.host || data.ip || data.hostname || data.address ||
      (data.gateway && (data.gateway as Record<string, unknown>).host) ||
      (data.gateway && (data.gateway as Record<string, unknown>).ip) || ''
    )
    // port 来源：port > ssh_port > gateway.port；缺失默认 22
    const portRaw =
      data.port ?? data.ssh_port ??
      (data.gateway && (data.gateway as Record<string, unknown>).port)
    const port = portRaw !== undefined && portRaw !== null && portRaw !== '' ? Number(portRaw) : 22
    // username 来源：username > user > account > gateway.username
    const username = String(
      data.username || data.user || data.account ||
      (data.gateway && (data.gateway as Record<string, unknown>).username) || ''
    )
    const password = data.password ? String(data.password) : undefined
    const privateKey = data.private_key || data.privateKey
      ? String(data.private_key || data.privateKey)
      : undefined

    // ===== 模型冲突判定 =====
    // 三类触发条件（命中任一即视为冲突）：
    //  1. host 字段缺失（响应里完全没出现 host 类值），说明该模式不返回 SSH 直连参数；
    //  2. host 字段是 jms:// 协议地址，说明服务端在告诉客户端走 JMS 协议；
    //  3. 关键字段（username / credential）缺失，无法组成 ssh2 可用连接参数。
    const isJmsGateway = /^jms:\/\//i.test(host)
    const hasCredential = !!(password || privateKey)
    let modelConflict = false

    if (!host) {
      modelConflict = true
    } else if (isJmsGateway) {
      modelConflict = true
    } else if (!username) {
      modelConflict = true
    } else if (!hasCredential) {
      // host + username 都有但没有凭据 — 仍可能是另一套接入模型（如需要 clientUrl 二次握手）
      modelConflict = true
    }

    // ===== 错误路径：每条都带阶段语义、响应摘要与冲突信号 =====
    if (!host) {
      return {
        success: false,
        error: '未获取到目标主机地址：/exchange/ 响应中未发现 host / ip / hostname / address 字段，且无 gateway 嵌套。' +
               '当前 connect_method=web_cli 期望客户端通过 clientUrl(jms://) 走 JMS 协议，/exchange/ 不会返回 SSH 直连参数。',
        rawResponseSummary,
        modelConflict: true
      }
    }
    if (isJmsGateway) {
      return {
        success: false,
        error: `未获取到目标主机地址：/exchange/ 返回的 host 字段为 "${host}"（jms:// 协议），不是 SSH 直连地址。` +
               '当前 connect_method=web_cli 期望客户端走 clientUrl(jms://)，本进程未实现 jms:// 客户端。',
        rawResponseSummary,
        modelConflict: true
      }
    }
    if (!username) {
      return {
        success: false,
        error: '未获取到登录用户名：/exchange/ 响应中未发现 username / user / account 字段。' +
               '若当前 connect_method=web_cli，该模式大概率不返回 SSH 用户名。',
        rawResponseSummary,
        modelConflict: true
      }
    }

    // ===== 成功路径：仍带回摘要与冲突信号 =====
    // 即便字段都齐，若响应中关键凭据缺失，依然可能是另一套接入模型；
    // 这里把信号交给上层（terminal:connectJumpserver）决定是否继续用 ssh2 直连。
    return {
      success: true,
      connectParams: { host, port, username, password, privateKey },
      rawResponseSummary,
      // modelConflict 仅在确实命中上述条件时为 true；正常返回时为 undefined
      modelConflict: modelConflict || undefined
    }
  } catch (err: unknown) {
    return { success: false, error: translateError(err, 'jumpserver') }
  }
}

// ==================== koko SSH 网关参数解析（v4.3 新增）====================

/**
 * 解析 jms:// clientUrl 的 base64 payload，提取 koko endpoint {host, port}
 *
 * jms:// 格式：jms://<base64 编码的 JSON payload>
 * payload 中 endpoint 字段结构：{ host: "jumpserver.example.com", port: 2222 }
 *
 * 解析失败返回空对象（调用方兜底用 baseUrl host + 2222）。
 * 不返回任何敏感值（payload 中的 token.value 不提取）。
 */
function parseJmsEndpoint(clientUrl: string): { host?: string; port?: number } {
  try {
    const trimmed = clientUrl.trim()
    const match = /^jms:\/\/(.+)$/i.exec(trimmed)
    if (!match) return {}

    const payload = Buffer.from(match[1], 'base64').toString('utf-8')
    const parsed = JSON.parse(payload) as Record<string, unknown>
    const endpoint = parsed.endpoint as Record<string, unknown> | undefined
    if (!endpoint || typeof endpoint !== 'object') return {}

    const host = endpoint.host ? String(endpoint.host) : undefined
    const port =
      endpoint.port !== undefined && endpoint.port !== null && endpoint.port !== ''
        ? Number(endpoint.port)
        : undefined

    return { host, port }
  } catch {
    return {}
  }
}

/**
 * 纯函数：从 fresh create-token 响应组装 koko SSH 登录参数（不发起连接）
 *
 * koko SSH 握手格式（上游源码 pkg/auth/ssh.go 依据，已在本实例第一步真实探测中确认通过）：
 *  - SSH 用户名 = 'JMS-' + token.id（koko 剥前缀后用 token.id 查回连接令牌）
 *  - SSH 密码   = token.value（koko 校验 ConnectToken.Value == password）
 *  - 令牌已编码 asset + account + protocol=ssh，校验通过后 koko 直接把会话代理到目标资产
 *
 * endpoint host/port 来源（v4.3 计划 5.4）：
 *  1. 优先：解析 clientUrl 的 jms:// base64 payload，取 endpoint.host / endpoint.port
 *  2. 兜底：jms payload 解析失败时用 baseUrl host + 默认 2222，并在 endpointSource 标注
 *  3. 严禁用 asset.address 直连——必须连 koko endpoint，由 koko 代理
 *
 * password 为敏感值，仅主进程内部使用，调用方须在连接后即用即清。
 */
export function resolveKokoSshParams(
  freshToken: { id: string; value: string },
  clientUrl: string,
  baseUrl: string
): JumpserverKokoSshResolveResult {
  if (!freshToken.id || !freshToken.value) {
    return {
      success: false,
      error: 'fresh 令牌缺少 id 或 value',
      endpointSource: 'jms_payload'
    }
  }

  // 优先：解析 jms:// payload 取 endpoint
  const jmsEndpoint = parseJmsEndpoint(clientUrl)

  let host: string
  let port: number
  let endpointSource: 'jms_payload' | 'fallback_baseurl'

  if (jmsEndpoint.host) {
    host = jmsEndpoint.host
    port = jmsEndpoint.port || 2222
    endpointSource = 'jms_payload'
  } else {
    // 兜底：baseUrl host + 2222
    let fallbackHost = ''
    try {
      const url = new URL(baseUrl)
      fallbackHost = url.hostname
    } catch {
      // baseUrl 无法解析，尝试直接取 host 部分
      fallbackHost = baseUrl.replace(/^https?:\/\//, '').split('/')[0].split(':')[0]
    }

    if (!fallbackHost) {
      return {
        success: false,
        error: '无法解析 koko endpoint：jms payload 无 endpoint，且 baseUrl 无有效 host',
        endpointSource: 'fallback_baseurl'
      }
    }

    host = fallbackHost
    port = 2222
    endpointSource = 'fallback_baseurl'
  }

  return {
    success: true,
    params: {
      host,
      port,
      username: `JMS-${freshToken.id}`,
      password: freshToken.value
    },
    endpointSource
  }
}
