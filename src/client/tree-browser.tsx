import React, { useEffect, useLayoutEffect, useRef, useSyncExternalStore } from 'react'
import { AssetTreeState, type PageLoader, type PageState } from './asset-tree-state'

export const treeIndent = (depth: number) => ({ paddingLeft: `min(${Math.min(8, depth) * 12}px, 25%)` })
export function useTreeState(state: AssetTreeState) { return useSyncExternalStore(state.subscribe, state.snapshot, state.snapshot) }
export function useTreePage<T>(state: AssetTreeState, pageKey: string, loader: PageLoader<T>, enabled = true, temporary = false) {
  const version = useTreeState(state), latest = useRef(loader); latest.current = loader
  useEffect(() => { if (enabled) state.ensure(pageKey, (offset, signal) => latest.current(offset, signal), true) }, [state, pageKey, enabled])
  useEffect(() => { if (enabled) state.ensure(pageKey, (offset, signal) => latest.current(offset, signal)) }, [state, pageKey, enabled, version])
  useEffect(() => () => { temporary ? state.forget(pageKey) : state.cancel(pageKey) }, [state, pageKey, temporary])
  return { page: state.page<T>(pageKey), load: (offset?: number) => { void state.load(pageKey, (start, signal) => latest.current(start, signal), offset) } }
}
export function TreeScroll({ state, view, label, children }: { state: AssetTreeState; view: string; label: string; children: React.ReactNode }) {
  const root = useRef<HTMLElement>(null)
  useLayoutEffect(() => { if (root.current) root.current.scrollTop = state.scroll.get(view) ?? 0 }, [state, view])
  return <nav ref={root} className="zt-asset-tree" aria-label={label} onScroll={(event) => state.setScroll(view, event.currentTarget.scrollTop)}>{children}</nav>
}
export function DirectoryRow({ label, expanded, depth, selected, onToggle, actions }: { label: string; expanded: boolean; depth: number; selected?: boolean; onToggle: () => void; actions?: React.ReactNode }) {
  return <div className={`zt-directory-row${selected ? ' active' : ''}`} style={treeIndent(depth)}>
    <button className="zt-directory-name" aria-expanded={expanded} aria-label={`${expanded ? '收起' : '展开'}文件夹 ${label}`} title={label} onClick={onToggle}><span className="zt-directory-arrow" aria-hidden="true">{expanded ? '▾' : '▸'}</span><span className="zt-directory-label">▱ {label}</span></button>{actions}
  </div>
}
export function PageFeedback<T>({ page, label, retry }: { page?: PageState<T>; label: string; retry: () => void }) {
  if (page?.data) return page.error ? <div className="zt-tree-message" role="status"><span title={page.error}>{label}更新失败，当前显示缓存</span><button onClick={retry}>重试</button></div> : null
  if (!page || page.status === 'idle' || page.status === 'loading') return <p className="zt-tree-message" role="status">正在加载{label}…</p>
  if (page.status === 'error') return <div className="zt-tree-message zt-error" role="alert"><span>{label}：{page.error}</span><button onClick={retry}>重试</button></div>
  return null
}
export function PageControls<T>({ page, size, label, load }: { page?: PageState<T>; size: number; label: string; load: (offset: number) => void }) {
  if (page?.status !== 'ready' || (!page.offset && !page.data?.hasMore)) return null
  return <div className="zt-pagination" aria-label={`${label}分页`}><span>{page.data?.total ?? 0} 台 · 第 {Math.floor(page.offset / size) + 1} 页</span>
    <button aria-label={`${label}上一页`} disabled={!page.offset} onClick={() => load(Math.max(0, page.offset - size))}>‹</button><button aria-label={`${label}下一页`} disabled={!page.data?.hasMore} onClick={() => load(page.offset + size)}>›</button></div>
}
