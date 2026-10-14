/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
import type { TerminalBridge } from './terminalBridge'

/** 每个真实 terminal session 一条 Agent 命令链，跨对话标签共享。 */
const terminalLocks = new Map<object, Promise<void>>()
const reservations = new Map<object, number>()
let manualInputs = new WeakMap<object, { pending: boolean; paste: boolean }>()
let busyListener: ((key: object, busy: boolean) => void) | undefined

export function isAgentTerminalBusy(key: object): boolean {
  return (reservations.get(key) ?? 0) > 0
}

/** 记录已送出的手动输入；Agent 不能把探针拼在用户尚未提交的半行命令后。 */
export function noteManualTerminalInput(key: object, input: string): void {
  // 终端设备状态响应不是用户编辑命令。
  if (/^\x1b\[(?:\d+;\d+R|[?>][\d;]*c)$/.test(input)) return
  const state = manualInputs.get(key) ?? { pending: false, paste: false }
  for (let index = 0; index < input.length; index++) {
    if (input.startsWith('\x1b[200~', index)) { state.paste = true; state.pending = true; index += 5; continue }
    if (input.startsWith('\x1b[201~', index)) { state.paste = false; index += 5; continue }
    const char = input[index]
    if (!state.paste && ['\r', '\n', '\x03', '\x15'].includes(char)) state.pending = false
    else state.pending = true
  }
  manualInputs.set(key, state)
}

export function setAgentTerminalBusyListener(listener: (key: object, busy: boolean) => void): void {
  busyListener = listener
}

function notifyBusy(key: object, busy: boolean): void {
  try { busyListener?.(key, busy) } catch { /* UI 通知失败不能影响终端锁。 */ }
}
/** 完成标记缺失后隔离真实 session，不能靠换 bridge/引擎/轮次解锁。 */
let uncertainSessions = new WeakSet<object>()

export function getAgentTerminalKey(bridge: TerminalBridge): object {
  const key = bridge.getTerminalLockKey()
  if (!key || (typeof key !== 'object' && typeof key !== 'function')) {
    throw new Error('无法验证底层终端实例，禁止 Agent 命令下发')
  }
  return key
}

export function isAgentTerminalUncertain(key: object): boolean {
  return uncertainSessions.has(key)
}

export function markAgentTerminalUncertain(key: object): void {
  uncertainSessions.add(key)
}

/**
 * 按真实终端实例串行执行。排队期间取消可立即返回，但它的占位 tail 会保留
 * 到前序完成，防止第三条命令绕过仍在执行的第一条。
 */
export async function withAgentTerminalLock<T>(
  key: object,
  signal: AbortSignal | undefined,
  fn: () => Promise<T>
): Promise<T> {
  reservations.set(key, (reservations.get(key) ?? 0) + 1)
  if (reservations.get(key) === 1) notifyBusy(key, true)
  const previous = terminalLocks.get(key) ?? Promise.resolve()
  let release: () => void = () => {}
  const gate = new Promise<void>((resolve) => { release = resolve })
  const tail = previous.catch(() => {}).then(() => gate)
  terminalLocks.set(key, tail)

  try {
    if (signal) {
      await new Promise<void>((resolve, reject) => {
        const onAbort = (): void => {
          signal.removeEventListener('abort', onAbort)
          reject(signal.reason ?? new Error('已取消'))
        }
        if (signal.aborted) {
          onAbort()
          return
        }
        signal.addEventListener('abort', onAbort, { once: true })
        void previous.catch(() => {}).then(() => {
          signal.removeEventListener('abort', onAbort)
          resolve()
        })
      })
    } else {
      await previous.catch(() => {})
    }
    signal?.throwIfAborted()
    if (manualInputs.get(key)?.pending) {
      throw new Error('终端还有未提交的手动输入。请先在终端完成或取消输入，再重试；AI 未发送查询或命令。')
    }
    return await fn()
  } finally {
    release()
    void tail.finally(() => {
      if (terminalLocks.get(key) === tail) terminalLocks.delete(key)
      const remaining = (reservations.get(key) ?? 1) - 1
      if (remaining > 0) reservations.set(key, remaining)
      else { reservations.delete(key); notifyBusy(key, false) }
    })
  }
}

/** 仅供测试清空模块级协调状态；生产只能通过新建真实 session 解锁。 */
export function resetAgentTerminalCoordinatorForTest(): void {
  terminalLocks.clear()
  reservations.clear()
  manualInputs = new WeakMap()
  busyListener = undefined
  uncertainSessions = new WeakSet<object>()
}
