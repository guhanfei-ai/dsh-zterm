import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'

const key = 'dsh-zterm.terminal-font-size'
let values: Map<string, string>, events: EventTarget
beforeEach(() => {
  vi.resetModules(); values = new Map(); events = new EventTarget()
  vi.stubGlobal('window', events)
  vi.stubGlobal('localStorage', { getItem: (name: string) => values.get(name) ?? null, setItem: (name: string, value: string) => values.set(name, value) })
})
afterEach(() => vi.unstubAllGlobals())
const storageChanged = (name: string | null) => events.dispatchEvent(Object.assign(new Event('storage'), { key: name }))

describe('终端字号偏好', () => {
  it('默认 12；刷新模块后恢复已保存字号', async () => {
    let preference = await import('../src/client/preferences')
    expect(preference.terminalFontSizeSnapshot()).toBe(12)
    preference.setTerminalFontSize(16)
    vi.resetModules(); preference = await import('../src/client/preferences')
    expect(preference.terminalFontSizeSnapshot()).toBe(16)
  })
  it.each(['NaN', '', '7', '33', '12.5'])('损坏的存储 %s 恢复默认值', async (raw) => {
    values.set(key, raw)
    expect((await import('../src/client/preferences')).terminalFontSizeSnapshot()).toBe(12)
  })
  it('同页的多个终端一起收到更新；非法输入与取消订阅不触发', async () => {
    const preference = await import('../src/client/preferences'), first = vi.fn(), second = vi.fn()
    const leaveFirst = preference.subscribeTerminalFontSize(first), leaveSecond = preference.subscribeTerminalFontSize(second)
    for (const value of [NaN, 0, 7, 33, 12.5]) preference.setTerminalFontSize(value)
    expect(first).not.toHaveBeenCalled(); expect(values.has(key)).toBe(false)
    preference.setTerminalFontSize(8); preference.setTerminalFontSize(8)
    expect(first).toHaveBeenCalledTimes(1); expect(second).toHaveBeenCalledTimes(1)
    leaveFirst(); preference.setTerminalFontSize(32)
    expect(first).toHaveBeenCalledTimes(1); expect(second).toHaveBeenCalledTimes(2)
    leaveSecond(); values.set(key, '14'); storageChanged(key)
    expect(second).toHaveBeenCalledTimes(2)
  })
  it('其它页面保存或清除字号会同步；无关存储不干扰', async () => {
    const preference = await import('../src/client/preferences'), listener = vi.fn(), leave = preference.subscribeTerminalFontSize(listener)
    values.set(key, '18'); storageChanged('unrelated')
    expect(preference.terminalFontSizeSnapshot()).toBe(12)
    storageChanged(key); expect(preference.terminalFontSizeSnapshot()).toBe(18)
    values.clear(); storageChanged(null); expect(preference.terminalFontSizeSnapshot()).toBe(12)
    expect(listener).toHaveBeenCalledTimes(2); leave()
  })
  it('浏览器禁用存储时仍保留本页设置，包括面板重新挂载', async () => {
    vi.stubGlobal('localStorage', { getItem: () => { throw new Error('storage disabled') }, setItem: () => { throw new Error('storage disabled') } })
    const preference = await import('../src/client/preferences'), listener = vi.fn()
    preference.setTerminalFontSize(15)
    const leave = preference.subscribeTerminalFontSize(listener)
    expect(preference.terminalFontSizeSnapshot()).toBe(15)
    preference.setTerminalFontSize(16); expect(listener).toHaveBeenCalledTimes(1); leave()
    const leaveAgain = preference.subscribeTerminalFontSize(listener)
    expect(preference.terminalFontSizeSnapshot()).toBe(16); leaveAgain()
  })
})
