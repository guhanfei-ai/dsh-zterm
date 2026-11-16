import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  LAYOUT_PUSH_CSS, PANEL_LAYOUT_EVENT, MINDMAP_PANEL_ID, MINDMAP_WIDTH_VARIABLE, ZTERM_PANEL_ID, ZTERM_WIDTH_VARIABLE,
  emitPanelLayout, installPanel, listenPeerPanelOpen,
} from '../src/client/panel-layout'

// 共享契约 v1（guhanfei-ai/dsh-mindmap#6）回归：L1 逐字一致的布局规则、L3 布局事件、L5 只清理自己。
class FakeStyle { textContent = ''; dataset: Record<string, string> = {}; removed = false; remove() { this.removed = true } }
const contractCss = `#root{
  margin-right:calc(var(--dsh-mindmap-width,0px) + var(--dsh-zterm-width,0px) + var(--dsh-sidebar-width,0px))!important;
  width:calc(100% - var(--dsh-mindmap-width,0px) - var(--dsh-zterm-width,0px) - var(--dsh-sidebar-width,0px))!important;
}`
const normalize = (text: string) => text.replace(/\s+/g, '').replace(/;}/g, '}')

let events: CustomEvent[], headChildren: FakeStyle[], vars: Map<string, string>, windowTarget: EventTarget
beforeEach(() => {
  events = []; headChildren = []; vars = new Map()
  windowTarget = new EventTarget()
  windowTarget.addEventListener(PANEL_LAYOUT_EVENT, (event) => events.push(event as CustomEvent))
  vi.stubGlobal('window', windowTarget)
  vi.stubGlobal('document', {
    createElement: () => new FakeStyle(),
    head: { appendChild: (element: FakeStyle) => { headChildren.push(element) } },
    documentElement: { style: { setProperty: (key: string, value: string) => { vars.set(key, value) }, removeProperty: (key: string) => { vars.delete(key) } } },
  })
})
afterEach(() => vi.unstubAllGlobals())

describe('共享契约 v1：L1 布局规则', () => {
  it('规则同时计入脑图、zTerm、侧栏三个宽度变量，且不含 transition，与契约文本逐字一致', () => {
    expect(LAYOUT_PUSH_CSS).toContain('margin-right:calc(var(--dsh-mindmap-width,0px) + var(--dsh-zterm-width,0px) + var(--dsh-sidebar-width,0px))!important')
    expect(LAYOUT_PUSH_CSS).toContain('width:calc(100% - var(--dsh-mindmap-width,0px) - var(--dsh-zterm-width,0px) - var(--dsh-sidebar-width,0px))!important')
    expect(LAYOUT_PUSH_CSS).toContain('--dsh-zterm-width')
    expect(LAYOUT_PUSH_CSS).toContain('--dsh-mindmap-width')
    expect(LAYOUT_PUSH_CSS).not.toContain('transition')
    expect(normalize(LAYOUT_PUSH_CSS)).toBe(normalize(contractCss))
    const panel = installPanel(ZTERM_PANEL_ID, ZTERM_WIDTH_VARIABLE)
    expect(headChildren).toHaveLength(1)
    expect(headChildren[0].dataset.plugin).toBe(ZTERM_PANEL_ID)
    expect(headChildren[0].textContent).toBe(LAYOUT_PUSH_CSS)
    panel.dispose()
  })
})

describe('共享契约 v1：L3 布局事件', () => {
  it('事件派发在 window 上，detail 为 { id, width }', () => {
    emitPanelLayout(ZTERM_PANEL_ID, 640)
    expect(events.at(-1)?.type).toBe(PANEL_LAYOUT_EVENT)
    expect(events.at(-1)?.detail).toEqual({ id: ZTERM_PANEL_ID, width: 640 })
    emitPanelLayout(ZTERM_PANEL_ID, 0)
    expect(events.at(-1)?.detail).toEqual({ id: ZTERM_PANEL_ID, width: 0 })
  })
  it('打开与拖宽在更新变量之后派发当前宽度，关闭派发 0', () => {
    const seen: Array<{ width: number, variable: string | undefined }> = []
    windowTarget.addEventListener(PANEL_LAYOUT_EVENT, (event) => seen.push({ width: (event as CustomEvent).detail.width, variable: vars.get(ZTERM_WIDTH_VARIABLE) }))
    const panel = installPanel(ZTERM_PANEL_ID, ZTERM_WIDTH_VARIABLE)
    panel.setWidth(600)
    expect(vars.get(ZTERM_WIDTH_VARIABLE)).toBe('600px')
    expect(seen.at(-1)).toEqual({ width: 600, variable: '600px' }) // 派发时变量已更新
    panel.setWidth(480) // 拖宽值变化
    expect(seen.at(-1)).toEqual({ width: 480, variable: '480px' })
    expect(events.filter((event) => event.detail.id === ZTERM_PANEL_ID && event.detail.width > 0)).toHaveLength(2)
    panel.dispose()
    expect(events.at(-1)?.detail).toEqual({ id: ZTERM_PANEL_ID, width: 0 })
  })
  it('监听只在对方 width>0 时触发，忽略自身事件；清理后不再触发', () => {
    const calls: number[] = []
    const dispose = listenPeerPanelOpen(MINDMAP_PANEL_ID, () => calls.push(1))
    emitPanelLayout(MINDMAP_PANEL_ID, 0)
    emitPanelLayout(ZTERM_PANEL_ID, 600) // 自己的事件不触发
    expect(calls).toHaveLength(0)
    emitPanelLayout(MINDMAP_PANEL_ID, 320)
    expect(calls).toHaveLength(1)
    dispose()
    emitPanelLayout(MINDMAP_PANEL_ID, 320)
    expect(calls).toHaveLength(1) // cleanup 已移除监听
  })
})

describe('共享契约 v1：L5 清理', () => {
  it('卸载移除自己的样式与宽度变量；不触碰脑图的变量与样式；之后 setWidth 为空操作', () => {
    vars.set(MINDMAP_WIDTH_VARIABLE, '320px') // 模拟脑图已展开
    const panel = installPanel(ZTERM_PANEL_ID, ZTERM_WIDTH_VARIABLE)
    panel.setWidth(600)
    panel.dispose()
    expect(headChildren[0].removed).toBe(true)
    expect(vars.has(ZTERM_WIDTH_VARIABLE)).toBe(false)
    expect(vars.get(MINDMAP_WIDTH_VARIABLE)).toBe('320px') // 对方变量未被触碰
    panel.setWidth(700)
    expect(vars.has(ZTERM_WIDTH_VARIABLE)).toBe(false)
    expect(events.at(-1)?.detail).toEqual({ id: ZTERM_PANEL_ID, width: 0 }) // 不再派发新值
  })
})
