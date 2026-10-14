import { describe, it, expect } from 'vitest'
import { TerminalBridge, type AnyTerminalSession } from '../../src/core/terminalBridge'

describe('TerminalBridge 目标身份', () => {
  function bridge(
    source: 'direct' | 'jumpserver' | 'local',
    targetId?: string,
    host = 'host',
    fingerprint = `SHA256:${host}`
  ): TerminalBridge {
    const session = {
      connected: true,
      tabId: 'terminal-1',
      currentHost: { host, port: 22, username: 'operator' },
      verifiedHostKey: { algorithm: 'ssh-ed25519', fingerprint },
      sessionMeta: { source, displayName: '同名终端', displaySecondary: '同名账号', targetId },
      getRecentOutput: () => '',
      write: () => {},
    } as unknown as AnyTerminalSession
    return new TerminalBridge(session)
  }

  it('直连同一标签连接到不同主机或不同 host key 时身份不同', () => {
    expect(bridge('direct', undefined, 'a').getBoundTargetId())
      .not.toBe(bridge('direct', undefined, 'b').getBoundTargetId())
    expect(bridge('direct', undefined, 'same', 'SHA256:key-a').getBoundTargetId())
      .not.toBe(bridge('direct', undefined, 'same', 'SHA256:key-b').getBoundTargetId())
  })

  it('Jumpserver 同名资产/账号但 ID 不同时身份不同；缺 ID 则拒绝恢复', () => {
    expect(bridge('jumpserver', '["config","asset-a","account"]').getBoundTargetId())
      .not.toBe(bridge('jumpserver', '["config","asset-b","account"]').getBoundTargetId())
    expect(bridge('jumpserver').getBoundTargetId()).toBeNull()
  })

  it('本地终端按标签区分，bridge 被释放后不再提供身份', () => {
    const local = bridge('local')
    expect(local.getBoundTargetId()).toContain('terminal-1')
    local.dispose()
    expect(local.getBoundTargetId()).toBeNull()
  })
})
