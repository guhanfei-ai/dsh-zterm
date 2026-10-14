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
/** 同一连接按序号追加；断流快照替换，不重放人类输入或工具调用。 */
export function mergeFrames(previous: Map<string, { generation: number; text: string; seq: number }>, poll: any) {
  const next = new Map(previous)
  if (poll.reset) {
    next.clear()
    for (const snapshot of poll.snapshots ?? []) next.set(snapshot.terminalId, { generation: snapshot.generation, text: snapshot.text, seq: poll.cursor })
  }
  for (const frame of poll.output ?? []) {
    const old = next.get(frame.terminalId)
    if (old && old.generation === frame.generation && frame.seq <= old.seq) continue
    next.set(frame.terminalId, { generation: frame.generation, text: `${old && old.generation === frame.generation ? old.text : ''}${frame.text}`.slice(-500000), seq: frame.seq })
  }
  for (const key of next.keys()) if (!poll.workspace.terminals.some((t: any) => t.id === key)) next.delete(key)
  return next
}
