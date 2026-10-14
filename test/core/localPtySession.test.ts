import { afterEach, describe, expect, it, vi } from 'vitest'
import type { LocalPtySession } from '../../src/core/localPtySession'

const sessions: LocalPtySession[] = []
afterEach(() => { sessions.splice(0).forEach((session) => session.disconnect()); vi.doUnmock('node-pty'); vi.resetModules() })

async function setup(defaultOnly: boolean) {
  const terminal = { onData: vi.fn(), onExit: vi.fn(), write: vi.fn(), resize: vi.fn(), kill: vi.fn() }
  const spawn = vi.fn(() => terminal)
  vi.doMock('node-pty', () => defaultOnly ? { default: { spawn }, spawn: undefined } : { default: undefined, spawn })
  const { LocalPtySession } = await import('../../src/core/localPtySession')
  const session = new LocalPtySession('local-fixture', 1, '/tmp/local-pty-fixture')
  session.on('error', () => {})
  sessions.push(session)
  return { session, terminal }
}

describe('本地 PTY 模块导出兼容', () => {
  it('仅有默认导出时仍能启动、输入、调整大小和关闭终端', async () => {
    const { session, terminal } = await setup(true)
    await session.connect('/fixture-shell', 80, 24)
    expect(session.isShellReady()).toBe(true)
    session.write('fixture-input'); expect(terminal.write).toHaveBeenCalledWith('fixture-input')
    session.resize(100, 30); expect(terminal.resize).toHaveBeenCalledWith(100, 30)
    session.disconnect(); expect(session.isShellReady()).toBe(false); expect(terminal.kill).toHaveBeenCalledOnce()
  })
  it('具名导出的加载结果仍可使用', async () => {
    const { session } = await setup(false)
    await session.connect('/fixture-shell', 80, 24)
    expect(session.isShellReady()).toBe(true)
  })
})
