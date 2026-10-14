/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
/**
 * 统一错误翻译工具 — 消除 IPC handler / aiClient / jumpserverClient 中重复的错误码→中文映射。
 *
 * 用法：
 *   translateError(err, 'ssh')                                // SSH 连接场景
 *   translateError(err, 'ai')                                 // AI / 网络请求场景
 *   translateError(err, 'jumpserver')                         // Jumpserver 通用 Error 翻译
 *   translateError(err, 'jumpserver', '自定义兜底文案')       // 带兜底文案
 *   translateJumpserverHttpStatus(401)                        // HTTP 状态码 → Jumpserver 用户文案
 *   translateJumpserverHttpStatus(404, '资产')                // HTTP 状态码 → Jumpserver 用户文案（带语义提示）
 */

export type ErrorContext = 'ssh' | 'ai' | 'jumpserver'

export function translateError(err: unknown, context: ErrorContext, fallback?: string): string {
  if (!(err instanceof Error)) {
    return fallback || (context === 'ssh' ? '连接失败' : '请求失败')
  }

  const msg = err.message

  // ──── 网络 / DNS 层（所有 context 共用）────
  if (msg.includes('ENOTFOUND') || msg.includes('EAI_AGAIN')) {
    if (context === 'ssh') return '无法解析主机地址，请检查地址是否正确'
    if (context === 'jumpserver') return '无法解析服务器地址，请检查 Base URL 是否正确'
    return '网络连接失败，请检查网络或接口地址'
  }

  if (msg.includes('ECONNREFUSED')) {
    if (context === 'ssh') return '连接被拒绝，请检查端口和防火墙设置'
    if (context === 'jumpserver') return '连接被拒绝，请检查服务器地址和端口'
    return '网络连接失败，请检查网络或接口地址'
  }

  if (msg.includes('CERT') || msg.includes('SSL') || msg.includes('UNABLE_TO_VERIFY')) {
    if (context === 'jumpserver') return 'TLS 证书验证失败，可尝试关闭「验证 TLS 证书」选项'
    if (context === 'ssh') return 'TLS/SSL 证书验证失败'
    return '网络连接失败，请检查网络或接口地址'
  }

  if (msg.includes('ETIMEDOUT') || msg.includes('timed out') || msg.includes('超时')) {
    if (context === 'ssh') return '连接超时，请检查网络和主机地址'
    if (context === 'jumpserver') return '连接超时，请检查网络或服务器地址'
    return '网络连接失败，请检查网络或接口地址'
  }

  // ──── Jumpserver 专有 ────
  if (context === 'jumpserver') {
    // 401 与 403 必须彻底分开：403 → 权限不足（先判）；401 → 认证失败（后判）
    if (msg.includes('403') || msg.includes('Forbidden') || msg.includes('权限不足')) {
      return '权限不足，当前账号无权访问此资源'
    }
    if (msg.includes('401') || msg.includes('Unauthorized') || msg.includes('认证失败')) {
      return '认证失败，请检查凭据是否正确'
    }
    if (msg.includes('404') || msg.includes('接口不存在')) {
      return '接口不存在，请确认 JumpServer 版本是否支持该端点'
    }
    if (msg.includes('缺少凭据') || msg.includes('缺少 Token') || msg.includes('缺少 Access Key') || msg.includes('缺少用户名')) {
      return '缺少凭据，请先完善配置'
    }
    if (msg.includes('令牌')) {
      return '创建连接令牌失败，请重试'
    }
    if (msg.includes('兑换')) {
      return '兑换连接参数失败，请重试'
    }
    if (msg.includes('无法解析')) {
      return '服务器返回了无法解析的响应'
    }
    if (msg.includes('意外的数据格式')) {
      return '服务器返回了意外的数据格式'
    }
    if (msg.includes('500') || msg.includes('502') || msg.includes('503')) {
      return '服务器暂时不可用，请稍后重试'
    }
    if (msg.includes('连接失败')) {
      return msg
    }
    return `连接失败：${msg}`
  }

  // ──── SSH 专有 ────
  if (context === 'ssh') {
    if (msg.includes('All configured authentication methods failed') || msg.includes('Authentication failed') || msg.includes('authentication failed')) {
      return '认证失败，请检查用户名和密码/密钥'
    }
    if (msg.includes('handshake')) {
      return 'SSH 握手失败，请检查主机地址和端口'
    }
    return `连接失败：${msg}`
  }

  // ──── AI / HTTP 专有 ────
  if (msg.includes('401') || msg.includes('Unauthorized')) {
    return 'API 密钥无效，请检查密钥配置'
  }
  if (msg.includes('429') || msg.includes('rate limit')) {
    return '请求过于频繁，请稍后重试'
  }
  if (msg.includes('500') || msg.includes('502') || msg.includes('503')) {
    return '模型服务暂时不可用，请稍后重试'
  }

  return fallback ? `${fallback}：${msg}` : `请求失败：${msg}`
}

/**
 * Jumpserver 凭据缺失场景的统一文案出口。
 *
 * 收口原则：
 * 1. 与 jumpserverClient.ts 主链路（buildAuthHeader 返回 null 时统一回 '缺少凭据，请先完善配置'）
 *    以及 translateError(..., 'jumpserver') 中的「缺少凭据」分支保持同一文案。
 * 2. 让终端连接入口 terminal:connectJumpserver 不再按认证方式散落手写
 *    「缺少 Access Key / 缺少 Token / 缺少用户名或密码」三组文案，
 *    凭据缺失提示统一由本函数产出，保证主链路与终端连接入口语义一致。
 *
 * @param authMode 可选认证方式，仅作为调用方语义标注；当前统一收口为同一文案以保证语义一致
 */
export function translateJumpserverMissingCredential(
  _authMode?: 'token' | 'password' | 'access_key'
): string {
  return '缺少凭据，请先完善配置'
}

/**
 * Jumpserver HTTP 状态码 → 用户可见错误文案的统一收口
 *
 * 收口原则：
 * 1. 不再把 statusCode 原样塞到用户文案里（之前出现的 "HTTP 401/403/404/5xx" 全部不再出现）
 * 2. 401 与 403 彻底分开：401 → 认证失败；403 → 权限不足
 * 3. jumpserverClient.ts 与 terminal:connectJumpserver 都应通过该函数返回错误文案
 * 4. 当提供 responseBody 且能从中解析出明确错误字段（DRF 字段校验 / detail / 非字段错误）时，
 *    必须优先返回真实错误原因；只有拿不到明确错误体时才退回状态码兜底文案。
 *
 * @param statusCode Jumpserver HTTP 响应状态码
 * @param responseBody 可选的服务端响应体（原始字符串）。提供后会优先解析其中的错误信息。
 * @param scopeHint 可选语义提示（如 '资产' / '节点' / '账号' / '令牌'），仅用于 5xx 兜底文案
 */
export function translateJumpserverHttpStatus(
  statusCode: number,
  responseBody?: string,
  scopeHint?: string
): string {
  // 1. 401/403/404 状态码优先：与之前语义一致，避免被错误体覆盖关键安全/接口提示
  if (statusCode === 401) {
    return '认证失败，请检查凭据是否正确'
  }
  if (statusCode === 403) {
    return '权限不足，当前账号无权访问此资源'
  }
  if (statusCode === 404) {
    return '接口不存在，请确认 JumpServer 版本是否支持该端点'
  }

  // 2. 4xx/5xx 且有响应体：尝试从中提取真实错误（字段级、detail、非字段错误）
  if (statusCode >= 400 && responseBody) {
    const extracted = extractErrorFromResponseBody(responseBody)
    if (extracted) {
      return scopeHint ? `${extracted}（${scopeHint}）` : extracted
    }
  }

  // 3. 5xx 兜底
  if (statusCode >= 500) {
    return scopeHint
      ? `服务器暂时不可用，请稍后重试（${scopeHint}）`
      : '服务器暂时不可用，请稍后重试'
  }

  // 4. 其他 4xx：若 scopeHint 有值则附带语义，避免完全无信息
  if (statusCode >= 400) {
    if (scopeHint) {
      return `请求被服务器拒绝（${scopeHint}），请检查参数后重试`
    }
    return '请求被服务器拒绝，请稍后重试'
  }
  return '请求失败'
}

/**
 * 从 Jumpserver 服务端响应体中解析真实错误原因
 *
 * 兼容常见 DRF 错误响应格式：
 *  1. 字段级错误：{ "asset": ["Asset with id ... not found"] }
 *  2. 字段级错误（字符串值）：{ "asset": "Invalid asset id" }
 *  3. 嵌套字段级错误：{ "asset": { "id": ["..."] } }
 *  4. detail 字段：{ "detail": "Authentication credentials were not provided." }
 *  5. 非字段错误：{ "non_field_errors": ["..."] }
 *  6. 直接字符串体：body 整体就是一个错误描述
 *
 * 返回 null 表示未能解析出有效错误信息（让上层退回状态码兜底文案）。
 */
export function extractErrorFromResponseBody(body: string): string | null {
  if (!body || typeof body !== 'string') return null

  const trimmed = body.trim()
  if (!trimmed) return null

  // 非 JSON：直接当作纯文本错误（如 Nginx 默认错误页）
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    // 仅保留较短的纯文本，避免把 HTML 错误页整段塞给用户
    const oneLine = trimmed.replace(/\s+/g, ' ').slice(0, 200)
    return oneLine || null
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    // 看起来像 JSON 但解析失败：当作纯文本
    const oneLine = trimmed.replace(/\s+/g, ' ').slice(0, 200)
    return oneLine || null
  }

  const parts: string[] = []
  collectErrorMessages(parsed, parts, '', 3)

  if (parts.length === 0) {
    return null
  }

  // 最多拼 3 条字段，避免错误信息过长淹没主链路
  const joined = parts.slice(0, 3).join('；')
  return joined
}

/**
 * 递归从 DRF 风格错误对象中收集「字段名: 错误信息」片段
 *
 * @param current 当前节点（对象/数组/基本类型）
 * @param parts 输出缓冲
 * @param fieldPath 当前字段路径（嵌套字段用 `.` 连接）
 * @param depth 递归深度上限，避免异常数据导致栈溢出
 */
function collectErrorMessages(
  current: unknown,
  parts: string[],
  fieldPath: string,
  depth: number
): void {
  if (depth <= 0) return
  if (parts.length >= 3) return

  if (current === null || current === undefined) return

  if (typeof current === 'string') {
    const msg = current.trim()
    if (!msg) return
    if (fieldPath) {
      parts.push(`${fieldPath}: ${msg}`)
    } else {
      parts.push(msg)
    }
    return
  }

  if (Array.isArray(current)) {
    for (const item of current) {
      collectErrorMessages(item, parts, fieldPath, depth - 1)
      if (parts.length >= 3) return
    }
    return
  }

  if (typeof current === 'object') {
    const obj = current as Record<string, unknown>
    for (const key of Object.keys(obj)) {
      // detail / message / non_field_errors：这些是顶级错误，不带字段名前缀
      const isTopLevel =
        !fieldPath && (key === 'detail' || key === 'message' || key === 'non_field_errors')
      const nextPath = isTopLevel ? '' : (fieldPath ? `${fieldPath}.${key}` : key)
      collectErrorMessages(obj[key], parts, nextPath, depth - 1)
      if (parts.length >= 3) return
    }
  }
}