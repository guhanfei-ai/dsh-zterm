import React, { useState, useEffect, useRef, useSyncExternalStore } from 'react'
import { Workbench, pageId } from './workbench'
import { SettingsPanel } from './settings'
import { rpc } from './api'
import { savedNumber, saveNumber, useDrag } from './preferences'
import css from './style.css'
import xtermCss from '@xterm/xterm/css/xterm.css'
import type { ClientContext } from '../shared/types'
import { PRODUCT_NAME } from '../shared/branding'

export const inject = ['slots', 'connection']
const TAB_ID = 'dsh-zterm:workbench'
function icon(size = 16) { return <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3"><rect x="1.5" y="2.5" width="13" height="11" rx="2"/><path d="m4 6 2 2-2 2m4 0h4"/></svg> }
function SidebarWorkbench({ ctx, service, tab, scope, visible }: any) {
  useEffect(() => {
    if (tab?.id && tab.title !== PRODUCT_NAME) service.updateTab?.(tab.id, { title: PRODUCT_NAME })
  }, [service, tab?.id, tab?.title])
  return <Workbench key={scope.sessionId} ctx={ctx} sessionId={scope.sessionId} visible={visible} />
}
export function apply(ctx: ClientContext) {
  const listeners = new Set<() => void>(); let sidebar: any
  const notify = () => listeners.forEach((listener) => listener())
  const useSidebar = () => useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener) }, () => sidebar)
  const style = document.createElement('style'); style.dataset.plugin = 'dsh-zterm'; style.textContent = `${xtermCss}\n${css}`; document.head.appendChild(style)
  ctx.effect(() => () => { style.remove(); listeners.clear() })
  ctx.inject(['betterSidebar'], (sctx: ClientContext) => {
    sidebar = sctx.betterSidebar; notify()
    const dispose = sidebar.registerTab({ id: TAB_ID, title: () => PRODUCT_NAME, description: '连接真实机器，提供读工具和人类开启的读写操作。', icon, single: true, order: 109,
      component: (props: any) => <SidebarWorkbench {...props} ctx={ctx} service={sctx.betterSidebar} /> })
    // 原生侧栏在隐藏页面时释放临时标签记录；标题槽保证旧标签和浮动窗口始终显示产品名。
    const disposeTitle = sctx.slots.inject('sidebar.right.pane.tab.title', () => sctx.slots.register({
      name: 'sidebar.right.pane.tab.title', key: `dsh-better-sidebar:${TAB_ID}`, priority: -1,
    }, () => <><span aria-hidden="true">{icon()}</span>{PRODUCT_NAME}</>))
    return () => { disposeTitle?.(); dispose?.(); sidebar = undefined; notify() }
  })
  function Header(props: any) {
    const service = useSidebar(), [open, setOpen] = useState(false), [message, setMessage] = useState(''), [disabled, setDisabled] = useState(false)
    const sessionId = props.sessionId ?? props.scope?.sessionId, scope = props.scope ?? { sessionId }
    const nodesHook = props.useChat ?? props.useSession
    const nodes = typeof nodesHook === 'function' ? nodesHook((snapshot: any) => snapshot.legacy?.nodes ?? snapshot.nodes) : undefined
    const seen = useRef('')
    const show = () => {
      if (service?.openTab) service.openTab({ type: TAB_ID, title: PRODUCT_NAME, url: 'zterm://workbench' }, scope)
      else if (parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--dsh-mindmap-width')) > 0) setMessage('右侧脑图面板已展开。请先收起脑图，或使用 Better Sidebar 的 Tab 切换。')
      else setOpen(true)
    }
    useEffect(() => { if (sessionId) void rpc(ctx, 'client/attach', { sessionId, pageId }).catch(() => {}) }, [sessionId])
    useEffect(() => {
      let alive = true
      const refresh = () => { void rpc<any>(ctx, 'status').then((value) => { if (alive) setDisabled(Boolean(value?.temporarilyDisabled)) }).catch(() => {}) }
      refresh()
      window.addEventListener('dsh-zterm:state', refresh)
      return () => { alive = false; window.removeEventListener('dsh-zterm:state', refresh) }
    }, [ctx])
    useEffect(() => {
      if (!nodes) return
      const stack = Array.isArray(nodes) ? [...nodes] : [nodes]; let last = ''
      for (let count = 0; stack.length && count < 5000; count++) { const node: any = stack.pop(); if (!node || typeof node !== 'object') continue
        const name = node.name ?? node.call?.name ?? node.toolName
        if (['zterm_connect', 'zterm_bind'].includes(name)) { last = String(node.id ?? node.callId ?? node.call?.id ?? name); break }
        for (const key of ['children', 'nodes', 'body', 'calls', 'subCalls']) {
          const children = node[key]
          // 不能用 spread：超大子节点数组会抛 RangeError，逐个限幅入栈。
          if (Array.isArray(children)) for (const child of children) { if (stack.length >= 5000) break; stack.push(child) }
        }
      }
      if (last && last !== seen.current) { seen.current = last; show() }
    }, [nodes, service, sessionId])
    return <><button className="zt-header-button" title={disabled ? `${PRODUCT_NAME} 已临时禁用：AI 不会使用本插件工具` : `打开 ${PRODUCT_NAME}`} onClick={show}>{icon(15)}{PRODUCT_NAME}{disabled && <span className="zt-header-badge">AI禁用</span>}</button>
      {open && !service && sessionId && <Standalone ctx={ctx} sessionId={sessionId} onClose={() => setOpen(false)} onConflict={() => { setOpen(false); setMessage(`脑图面板已展开，${PRODUCT_NAME} 独立面板已收起。可以从 ${PRODUCT_NAME} 入口重新打开。`) }} />}
      {message && <div className="zt-standalone-error" role="alert">{message}<button onClick={() => setMessage('')}>关闭</button></div>}</>
  }
  ctx.slots.inject('conversation.session.header.actions', () => ctx.slots.register({ name: 'conversation.session.header.actions', id: 'dsh-zterm', order: 109 }, Header))
  ctx.slots.inject('settings.section', () => ctx.slots.register({ name: 'settings.section', id: 'dsh-zterm', order: 109, label: PRODUCT_NAME, icon }, () => <SettingsPanel ctx={ctx} />))
}
function Standalone({ ctx, sessionId, onClose, onConflict }: { ctx: ClientContext; sessionId: string; onClose: () => void; onConflict: () => void }) {
  const bounds = (value: number) => Math.min(window.innerWidth * .8, Math.max(Math.min(480, window.innerWidth * .8), value))
  const [width, setWidth] = useState(() => bounds(savedNumber('dsh-zterm.panel-width', window.innerWidth * .6, 0, window.innerWidth))), startDrag = useDrag()
  useEffect(() => {
    let alive = true
    void rpc(ctx, 'catalog').then((catalog) => { if (alive) setWidth(bounds(savedNumber('dsh-zterm.panel-width', window.innerWidth * catalog.defaultPanelWidth / 100, 0, window.innerWidth))) }).catch(() => {})
    return () => { alive = false }
  }, [ctx])
  useEffect(() => {
    const check = () => { if (parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--dsh-mindmap-width')) > 0) onConflict() }
    const observer = new MutationObserver(check); observer.observe(document.documentElement, { attributes: true, attributeFilter: ['style'] }); check()
    return () => observer.disconnect()
  }, [onConflict])
  useEffect(() => { const handler = () => setWidth((value) => Math.min(window.innerWidth * .8, Math.max(Math.min(480, window.innerWidth * .8), value))); window.addEventListener('resize', handler); return () => window.removeEventListener('resize', handler) }, [])
  useEffect(() => {
    document.documentElement.style.setProperty('--dsh-zterm-width', `${width}px`)
    const style = document.createElement('style'); style.dataset.plugin = 'dsh-zterm'; style.textContent = '#root{margin-right:calc(var(--dsh-zterm-width,0px) + var(--dsh-sidebar-width,0px))!important;width:calc(100% - var(--dsh-zterm-width,0px) - var(--dsh-sidebar-width,0px))!important}'
    document.head.appendChild(style); return () => { style.remove(); document.documentElement.style.removeProperty('--dsh-zterm-width') }
  }, [width])
  const resize = (event: React.MouseEvent) => {
    const start = event.clientX, initial = width
    startDrag(event, (e) => { const value = bounds(initial + start - e.clientX); setWidth(value); saveNumber('dsh-zterm.panel-width', value) })
  }
  return <section className="zt-standalone" style={{ width }} aria-label={PRODUCT_NAME}><div className="zt-panel-handle" role="separator" aria-label={`调整 ${PRODUCT_NAME} 面板宽度`} onMouseDown={resize} /><Workbench key={sessionId} ctx={ctx} sessionId={sessionId} onClose={onClose} /></section>
}
