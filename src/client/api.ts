import type { ClientContext } from '../shared/types'
import { PRODUCT_NAME } from '../shared/branding'
export async function rpc<T = any>(ctx: ClientContext, method: string, payload: unknown = {}, signal?: AbortSignal): Promise<T> {
  const connection = ctx.connection
  if (!connection?.rpc?.call) throw new Error('当前 DSH 缺少 Connection RPC，请使用已支持的宿主版本')
  const result = await connection.rpc.call('/api', `zterm/${method}`, payload, signal)
  if (!result.ok) throw new Error(result.error?.message || `${PRODUCT_NAME} 请求失败`)
  return result.value as T
}
export function download(name: string, text: string, contentType = 'text/plain;charset=utf-8'): void {
  const url = URL.createObjectURL(new Blob([text], { type: contentType })), link = document.createElement('a')
  link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url)
}
export function timestamp(): string { return new Date().toISOString().replace(/[-:]/g, '').replace(/T/, '-').slice(0, 15) }
/**
 * 操作进行中超过 2 秒才给出已用时文案，短操作不打扰（issue #3 期望 2）。
 * startedAt 缺失或非法时无文案；调用方用它区分「执行中」与「已用时」。
 */
export function progressElapsed(startedAt: string | undefined, now: number = Date.now()): string | undefined {
  if (!startedAt) return undefined
  const started = Date.parse(startedAt)
  if (!Number.isFinite(started)) return undefined
  const seconds = Math.floor((now - started) / 1000)
  if (seconds < 2) return undefined
  if (seconds < 60) return `已 ${seconds} 秒`
  return `已 ${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`
}
/** 同一连接按序号追加；断流快照替换，不重放人类输入或工具调用。 */
export function mergeFrames(previous: Map<string, { generation: number; text: string; seq: number }>, poll: any) {
  const next = new Map(previous)
  if (poll.reset) {
    next.clear()
    for (const snapshot of poll.snapshots ?? []) next.set(snapshot.terminalId, { generation: snapshot.generation, text: snapshot.text, seq: poll.cursor })
  }
  // 同轮询内的帧先收集，每终端只做一次定长拼接；逐帧拼接在重输出下
  // 每帧都拷贝整段缓冲（issue #3 基准发现的客户端放大项）。
  const appends = new Map<string, { generation: number; seq: number; base: string; parts: string[] }>()
  for (const frame of poll.output ?? []) {
    const old = next.get(frame.terminalId)
    let group = appends.get(frame.terminalId)
    if (!group) {
      const carried = old && old.generation === frame.generation
      group = { generation: frame.generation, seq: carried ? old.seq : Number.NEGATIVE_INFINITY, base: carried ? old.text : '', parts: [] }
      appends.set(frame.terminalId, group)
    } else if (group.generation !== frame.generation) {
      // 同轮询内连接已重建：新代从空缓冲开始。
      group = { generation: frame.generation, seq: Number.NEGATIVE_INFINITY, base: '', parts: [] }
      appends.set(frame.terminalId, group)
    }
    if (frame.seq <= group.seq) continue
    group.seq = frame.seq; group.parts.push(frame.text)
  }
  for (const [terminalId, group] of appends) {
    if (!group.parts.length) continue
    next.set(terminalId, { generation: group.generation, text: `${group.base}${group.parts.join('')}`.slice(-500000), seq: group.seq })
  }
  for (const key of next.keys()) if (!poll.workspace.terminals.some((t: any) => t.id === key)) next.delete(key)
  return next
}
