import { EventEmitter } from 'node:events'
import type { Client, ConnectConfig } from 'ssh2'
import { describe, it, expect, vi } from 'vitest'
import { TerminalSession } from '../../src/core/terminalSessionManager'
import { memoryHostTrustStore } from '../../src/core/sshHostTrust'

class FakeClient extends EventEmitter {
  config!: ConnectConfig
  connect(config: ConnectConfig) { this.config = config }
  end() { this.emit('close') }
  destroy() {}
}
function key(byte = 1) {
  const name = Buffer.from('ssh-ed25519'), size = Buffer.alloc(4), length = Buffer.alloc(4)
  size.writeUInt32BE(name.length); length.writeUInt32BE(32)
  return Buffer.concat([size, name, length, Buffer.alloc(32, byte)])
}
function fixture(store = memoryHostTrustStore()) {
  const client = new FakeClient(), session = new TerminalSession('t', 1, () => client as unknown as Client, store), events: any[] = []
  session.on('error', () => {}); session.on('host-trust-required', (event) => events.push(event))
  const connecting = session.connect({ host: 'host.example.invalid', port: 22, username: 'operator', password: 'fixture-secret' }).catch(() => {})
  const verify = vi.fn(); (client.config.hostVerifier as (value: Buffer, done: (allowed: boolean) => void) => void)(key(), verify)
  return { client, session, events, connecting, verify }
}
describe('移植后的 SSH 指纹确认', () => {
  it('未知主机等待人类、保存后相同指纹自动通过、变化拒绝', async () => {
    const store = memoryHostTrustStore(), first = fixture(store)
    expect(first.verify).not.toHaveBeenCalled(); expect(JSON.stringify(first.events)).not.toContain('fixture-secret')
    const requestId = first.events[0].requestId
    expect(first.session.respondHostTrust({ tabId: 't', generation: 1, requestId, decision: 'trust-always' }).success).toBe(true)
    expect(first.verify).toHaveBeenCalledWith(true); first.client.emit('ready'); await first.connecting; first.session.disconnect()
    const next = fixture(store); expect(next.events).toHaveLength(0); expect(next.verify).toHaveBeenCalledWith(true)
    const changed = vi.fn(); (next.client.config.hostVerifier as any)(key(2), changed)
    expect(changed).toHaveBeenCalledWith(false); expect(next.events[0].kind).toBe('changed')
    next.session.disconnect(); await next.connecting
  })
  it('过期 ID 或连接代次无法确认当前主机，拒绝不落盘', async () => {
    const store = memoryHostTrustStore(), item = fixture(store), requestId = item.events[0].requestId
    expect(item.session.respondHostTrust({ tabId: 't', generation: 2, requestId, decision: 'trust-always' }).success).toBe(false)
    expect(item.verify).not.toHaveBeenCalled()
    item.session.respondHostTrust({ tabId: 't', generation: 1, requestId, decision: 'reject' })
    expect(item.verify).toHaveBeenCalledWith(false); expect(store.get('host.example.invalid', 22)).toBeNull()
    item.session.disconnect(); await item.connecting
  })
  it('信任记录写入失败时拒绝连接', async () => {
    const store = { get: () => null, save: () => { throw new Error('fixture disk unavailable') } }, item = fixture(store)
    expect(item.session.respondHostTrust({ tabId: 't', generation: 1, requestId: item.events[0].requestId, decision: 'trust-always' }).success).toBe(false)
    expect(item.verify).toHaveBeenCalledWith(false); item.session.disconnect(); await item.connecting
  })
})
