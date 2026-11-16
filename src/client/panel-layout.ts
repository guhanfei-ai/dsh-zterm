// 共享契约 v1（guhanfei-ai/dsh-mindmap#6）：未装 Better Sidebar 时，
// zTerm 独立面板与 dsh-mindmap 共用 #root 布局。L1 规则公式与 L3 事件通道
// 与 dsh-mindmap 侧逐字一致，任何改动都必须同步对方仓库，否则重新引入冲突。

/** L3：布局变更事件，派发在 window 上；detail 形如 { id, width }（width 为像素数，关闭=0）。 */
export const PANEL_LAYOUT_EVENT = 'dsh:panel-layout'
export const MINDMAP_PANEL_ID = 'dsh-mindmap', ZTERM_PANEL_ID = 'dsh-zterm'
export const MINDMAP_WIDTH_VARIABLE = '--dsh-mindmap-width', ZTERM_WIDTH_VARIABLE = '--dsh-zterm-width'

/** L1：唯一一份 layout-push 规则（两仓库逐字相同，公式一致故插入顺序不影响结果）；基础规则不得声明 transition。 */
export const LAYOUT_PUSH_CSS = '#root{margin-right:calc(var(--dsh-mindmap-width,0px) + var(--dsh-zterm-width,0px) + var(--dsh-sidebar-width,0px))!important;width:calc(100% - var(--dsh-mindmap-width,0px) - var(--dsh-zterm-width,0px) - var(--dsh-sidebar-width,0px))!important}'

/** L3：更新自身 CSS 变量之后派发一次（open/resize=当前值，close=0）。 */
export function emitPanelLayout(id: string, width: number): void {
  window.dispatchEvent(new CustomEvent(PANEL_LAYOUT_EVENT, { detail: { id, width } }))
}

/** L3：监听对方面板展开（仅 width>0 触发）；返回清理函数，供 effect cleanup 移除监听，不轮询。 */
export function listenPeerPanelOpen(peerId: string, onOpen: () => void): () => void {
  const handler = (event: Event) => {
    const detail = (event as CustomEvent<{ id?: string, width?: number }>).detail
    if (detail?.id === peerId && Number(detail.width) > 0) onOpen()
  }
  window.addEventListener(PANEL_LAYOUT_EVENT, handler)
  return () => window.removeEventListener(PANEL_LAYOUT_EVENT, handler)
}

export interface PanelLayoutHandle { setWidth(width: number): void, dispose(): void }

/** 挂载期间持有自己的 L1 `<style>` 与宽度变量；L5 清理只移除自己的，不触碰对方。 */
export function installPanel(id: string, widthVariable: string): PanelLayoutHandle {
  const style = document.createElement('style'); style.dataset.plugin = id; style.textContent = LAYOUT_PUSH_CSS
  document.head.appendChild(style)
  let disposed = false
  return {
    setWidth(width: number) { if (disposed) return; document.documentElement.style.setProperty(widthVariable, `${width}px`); emitPanelLayout(id, width) },
    dispose() { if (disposed) return; disposed = true; style.remove(); document.documentElement.style.removeProperty(widthVariable); emitPanelLayout(id, 0) },
  }
}
