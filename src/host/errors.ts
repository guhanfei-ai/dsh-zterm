export class ZtermError extends Error { constructor(readonly code: string, message: string) { super(message) } }
export function checkCancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ZtermError('aborted', '连接请求已取消')
}
