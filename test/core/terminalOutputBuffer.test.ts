import { describe, expect, it } from 'vitest'
import { TerminalOutputBuffer } from '../../src/core/terminalOutputBuffer'
describe('终端输出内存边界', () => {
  it('单个巨块和多块均不能超过总量上限', () => {
    const buffer = new TerminalOutputBuffer(10, 3)
    buffer.push('x'.repeat(1000))
    expect(buffer.recent(100)).toHaveLength(10)
    buffer.push('12345'); buffer.push('67890')
    expect(buffer.recent(100)).toBe('1234567890')
  })
  it('保留最近行，并限制碎片数量', () => {
    const buffer = new TerminalOutputBuffer(100, 2)
    buffer.push('old\n'); buffer.push('a\n'); buffer.push('b\nc')
    expect(buffer.recent(2)).toBe('b\nc')
    buffer.clear()
    expect(buffer.recent(100)).toBe('')
  })
  it('原始缓冲与模型历史共用内存边界，按来源排除任意分块和嵌套发送区间', () => {
    const buffer = new TerminalOutputBuffer(80, 10)
    buffer.push('manual __ZTERM_AGENT_BEGIN_example__\n')
    buffer.beginAgentOutput()
    buffer.push('ec'); buffer.push('ho\n')
    buffer.beginAgentOutput(); buffer.push('token\n'); buffer.endAgentOutput()
    buffer.push('result\n'); buffer.endAgentOutput()
    buffer.push('after\n')
    expect(buffer.recent(20, false)).toBe('manual __ZTERM_AGENT_BEGIN_example__\nafter\n')
    expect(buffer.recent(20)).toContain('echo\ntoken\nresult')
    buffer.clear(); buffer.push('new session\n')
    expect(buffer.recent(20, false)).toBe('new session\n')
  })
})
