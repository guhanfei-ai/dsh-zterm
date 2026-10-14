// Adapted from zterm (MIT), SSH PTY size regression tests.
import { EventEmitter } from 'node:events'
import type { Client, ClientChannel } from 'ssh2'
import { describe, expect, it, vi } from 'vitest'
import { TerminalSession } from '../../src/core/terminalSessionManager'

async function connectedSession() {
  const client = Object.assign(new EventEmitter(), { connect: vi.fn(), shell: vi.fn(), end: vi.fn(), destroy: vi.fn() })
  const session = new TerminalSession('size-test', 1, () => client as unknown as Client)
  const connecting = session.connect({ host: 'fixture.invalid', port: 22, username: 'test' }); client.emit('ready'); await connecting
  const channel = Object.assign(new EventEmitter(), { writable: true, setWindow: vi.fn() })
  const finishOpen = () => client.shell.mock.calls[0][1](undefined, channel as unknown as ClientChannel)
  return { session, client, channel, finishOpen }
}
describe('SSH PTY 的真实行列数同步', () => {
  it('打开前的准确尺寸覆盖入口估算值', async () => {
    const { session, client, finishOpen } = await connectedSession(); session.resize(120, 42)
    const opened = session.openShell(128, 45); expect(client.shell.mock.calls[0][0]).toMatchObject({ cols: 120, rows: 42 }); finishOpen(); await opened
  })
  it('打开期间连续缩放，就绪后使用最后一组尺寸', async () => {
    const { session, channel, finishOpen } = await connectedSession(), opened = session.openShell(128, 45)
    session.resize(115, 38); session.resize(100, 35); finishOpen(); await opened
    expect(channel.setWindow).toHaveBeenLastCalledWith(35, 100, 0, 0)
  })
  it('缩放遵循 ssh2 的 rows、cols 顺序', async () => {
    const { session, channel, finishOpen } = await connectedSession(), opened = session.openShell(80, 24)
    finishOpen(); await opened; session.resize(140, 50); expect(channel.setWindow).toHaveBeenLastCalledWith(50, 140, 0, 0)
  })
  it('无效尺寸不覆盖准确尺寸', async () => {
    const { session, client, finishOpen } = await connectedSession(); session.resize(120, 42); session.resize(0, 0); session.resize(Number.NaN, 40)
    const opened = session.openShell(128, 45); expect(client.shell.mock.calls[0][0]).toMatchObject({ cols: 120, rows: 42 }); finishOpen(); await opened
  })
})
