import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { PANEL_LAYOUT_EVENT, ZTERM_PANEL_ID, ZTERM_WIDTH_VARIABLE } from '../src/client/panel-layout'

// issue #4 回归：standalone 面板宿主层 portal 到 document.body（对齐 guhanfei-ai/dsh-mindmap#5 的
// 0.18.8 修复）。vitest 无真实 DOM，沿用 panel-layout.test 的 FakeStyle / 假 document 手法：
// react、react-dom 换成模块桩（照 mindmap 修复时的 createTestPortal 套路），用小型 hook 驱动器直接
// 渲染 Standalone 组件函数，验证 portal 目标、无 DOM 兜底、卸载无残留与头部槽位结构。
const reactStub = vi.hoisted(() => {
  let active: { cells: any[], effects: Array<() => any>, cursor: number } | undefined
  const useState = (init: any): [any, (next: any) => void] => {
    const state = active!
    const index = state.cursor++
    if (!(index in state.cells)) state.cells[index] = { value: typeof init === 'function' ? init() : init }
    const cell = state.cells[index]
    return [cell.value, (next: any) => { cell.value = typeof next === 'function' ? next(cell.value) : next }]
  }
  const useEffect = (body: () => any) => { active!.effects.push(body) }
  const useRef = (init: any) => {
    const state = active!
    const index = state.cursor++
    if (!(index in state.cells)) state.cells[index] = { current: init }
    return state.cells[index]
  }
  const useSyncExternalStore = (_subscribe: any, getSnapshot: () => any) => getSnapshot()
  const useCallback = (fn: any) => fn, useMemo = (fn: any) => fn(), useLayoutEffect = useEffect, useId = () => 'fixture-hook-id'
  // 小型渲染驱动器：同一实例的 cells 跨渲染保留（useState 状态不丢），mount 时执行 effect 并收集 cleanup。
  function createRenderer() {
    const cells: any[] = [], cleanups: Array<() => any> = [], state = { cells, effects: [] as Array<() => any>, cursor: 0 }
    return {
      render(fn: (props: any) => any, props: any, mount = false) {
        state.effects = []; state.cursor = 0; active = state
        try {
          const output = fn(props)
          if (mount) for (const effect of state.effects) cleanups.push(effect())
          return output
        } finally { active = undefined }
      },
      unmount() { for (const cleanup of cleanups.splice(0)) cleanup?.() },
    }
  }
  return {
    createRenderer,
    module: {
      __esModule: true,
      default: { Fragment: { fixture: 'fragment' }, createElement: () => ({}) },
      useState, useEffect, useRef, useSyncExternalStore, useCallback, useMemo, useLayoutEffect, useId,
    },
  }
})
const reactDomStub = vi.hoisted(() => {
  const calls: Array<{ children: any, container: any }> = []
  return {
    calls,
    createPortal: (children: any, container: any) => { calls.push({ children, container }); return { type: 'react-portal', props: { children }, containerInfo: container } },
  }
})
vi.mock('react', () => reactStub.module)
vi.mock('react/jsx-runtime', () => ({
  jsx: (type: any, props: any, key: any) => ({ type, props: props ?? {}, key }),
  jsxs: (type: any, props: any, key: any) => ({ type, props: props ?? {}, key }),
  Fragment: { fixture: 'fragment' },
}))
vi.mock('react/jsx-dev-runtime', () => ({
  jsxDEV: (type: any, props: any, key: any) => ({ type, props: props ?? {}, key }),
  Fragment: { fixture: 'fragment' },
}))
vi.mock('react-dom', () => ({ createPortal: reactDomStub.createPortal }))
// xterm 及工作台内部不在本测试范围（issue #4 只修宿主层落点），换成轻桩。
vi.mock('../src/client/workbench', () => ({ Workbench: () => null, pageId: 'fixture-page' }))

class FakeStyle { textContent = ''; dataset: Record<string, string> = {}; removed = false; remove() { this.removed = true } }
let events: CustomEvent[], headChildren: FakeStyle[], vars: Map<string, string>, windowTarget: any, documentStub: any, bodyAppends: unknown[], disposers: Array<() => any>
beforeEach(async () => {
  events = []; headChildren = []; vars = new Map(); bodyAppends = []; disposers = []; reactDomStub.calls.length = 0
  windowTarget = new EventTarget(); (windowTarget as any).innerWidth = 1000
  windowTarget.addEventListener(PANEL_LAYOUT_EVENT, (event: Event) => events.push(event as CustomEvent))
  vi.stubGlobal('window', windowTarget)
  vi.stubGlobal('localStorage', { getItem: (key: string) => key === 'dsh-zterm.panel-width' ? '520' : null, setItem: () => {} })
  vi.stubGlobal('getComputedStyle', () => ({ getPropertyValue: () => '' }))
  documentStub = {
    body: { appendChild: (node: unknown) => { bodyAppends.push(node) } },
    createElement: () => new FakeStyle(),
    head: { appendChild: (element: FakeStyle) => { headChildren.push(element) } },
    documentElement: { style: { setProperty: (key: string, value: string) => { vars.set(key, value) }, removeProperty: (key: string) => { vars.delete(key) } } },
  }
  vi.stubGlobal('document', documentStub)
})
afterEach(async () => { for (const dispose of disposers.splice(0)) dispose?.(); vi.unstubAllGlobals() })

describe('issue #4：standalone 面板 portal 到 document.body', () => {
  it('宿主层经 createPortal 落到 document.body，section 结构与行为保持原样', async () => {
    const { Standalone } = await import('../src/client/index')
    const ctx = { connection: { rpc: { call: async () => ({ ok: true, value: { defaultPanelWidth: 60 } }) } } } as any
    const renderer = reactStub.createRenderer()
    const portal = renderer.render(Standalone, { ctx, sessionId: 'session-1', onClose: () => {}, onConflict: () => {} }, true)
    // portal 目标是 document.body；section 不再原地渲染在头部槽位子树里。
    expect(reactDomStub.calls).toHaveLength(1)
    expect(reactDomStub.calls[0].container).toBe(documentStub.body)
    expect(portal.containerInfo).toBe(documentStub.body)
    expect(portal.props.children.type).toBe('section')
    expect(portal.props.children.props.className).toBe('zt-standalone')
    // 类名、内联宽度、拖拽手柄、Workbench key 语义保持不变。
    expect(portal.props.children.props['aria-label']).toBe('zTerm')
    expect(portal.props.children.props.style).toEqual({ width: 520 })
    const [handle, workbench] = portal.props.children.props.children
    expect(handle.type).toBe('div'); expect(handle.props.className).toBe('zt-panel-handle'); expect(handle.props.role).toBe('separator'); expect(typeof handle.props.onMouseDown).toBe('function')
    expect(workbench.key).toBe('session-1'); expect(workbench.props.sessionId).toBe('session-1'); expect(workbench.props.ctx).toBe(ctx)
    // 挂载即写宽度变量并派发契约 v1 事件；面板样式仍在 head，不在 body。
    expect(vars.get(ZTERM_WIDTH_VARIABLE)).toBe('520px')
    expect(events.at(-1)?.detail).toEqual({ id: ZTERM_PANEL_ID, width: 520 })
    expect(headChildren.at(-1)?.dataset.plugin).toBe(ZTERM_PANEL_ID)
    renderer.unmount()
    // 卸载清理：移除布局样式与宽度变量、派发 width=0；全程未向 body 手工 append（portal 的挂载与摘除归 React 管）。
    expect(vars.has(ZTERM_WIDTH_VARIABLE)).toBe(false)
    expect(headChildren.at(-1)?.removed).toBe(true)
    expect(events.at(-1)?.detail).toEqual({ id: ZTERM_PANEL_ID, width: 0 })
    expect(bodyAppends).toHaveLength(0)
  })

  it('document 不可用时退回原位渲染，不调用 portal，也不抛错', async () => {
    const { Standalone } = await import('../src/client/index')
    vi.stubGlobal('document', undefined)
    const renderer = reactStub.createRenderer()
    let host: any
    expect(() => { host = renderer.render(Standalone, { ctx: {}, sessionId: 'session-1', onClose: () => {}, onConflict: () => {} }) }).not.toThrow()
    expect(reactDomStub.calls).toHaveLength(0)
    expect(host.type).toBe('section')
    expect(host.props.className).toBe('zt-standalone')
    expect(host.props.style).toEqual({ width: 520 })
  })

  it('头部槽位树里只有 portal 元素（section 落 body），提示条留在槽位内', async () => {
    const { apply } = await import('../src/client/index')
    const slots = new Map<string, { descriptor: any, component: any }>()
    const ctx: any = {
      slots: { inject: (_name: string, body: () => any) => body(), register: (descriptor: any, component: any) => { slots.set(descriptor.name, { descriptor, component }); return () => slots.delete(descriptor.name) } },
      inject: () => { /* 未注入 betterSidebar：独立壳模式 */ },
      effect: (body: () => any) => { const dispose = body(); disposers.push(dispose); return dispose },
      connection: { rpc: { call: async () => ({ ok: true, value: {} }) } },
    }
    apply(ctx)
    // settings.section 与头部按钮照常注册（issue #4 不改注册行为）。
    expect([...slots.keys()]).toEqual(expect.arrayContaining(['conversation.session.header.actions', 'settings.section']))
    const Header = slots.get('conversation.session.header.actions')!.component
    const renderer = reactStub.createRenderer()
    const closed = renderer.render(Header, { sessionId: 'session-1' }, true)
    expect(closed.props.children[0].type).toBe('button')
    expect(closed.props.children[1]).toBe(false) // 未展开：不渲染面板
    closed.props.children[0].props.onClick() // 人类点击「zTerm」按钮
    const opened = renderer.render(Header, { sessionId: 'session-1' })
    // 头部槽位子树里出现的是 Standalone 组件元素，而不是 section 宿主节点。
    const standalone = opened.props.children[1]
    expect(standalone.type).toBeInstanceOf(Function)
    const flatten = (node: any): any[] => node?.props?.children ? [node, ...[].concat(node.props.children).flatMap(flatten)] : [node]
    expect(flatten(opened).some((node) => node?.type === 'section' && node?.props?.className === 'zt-standalone')).toBe(false)
    expect(reactDomStub.calls).toHaveLength(0) // 头部渲染本身不产生 portal；portal 在 Standalone 渲染时生成
    // 展开 Standalone：section 经 portal 落 document.body，提示条（未触发时）不渲染。
    const portal = reactStub.createRenderer().render(standalone.type, standalone.props, true)
    expect(reactDomStub.calls).toHaveLength(1)
    expect(reactDomStub.calls[0].container).toBe(documentStub.body)
    expect(portal.props.children.props.className).toBe('zt-standalone')
    expect(opened.props.children[2]).toBeFalsy() // message 为空：提示条不渲染
  })
})
