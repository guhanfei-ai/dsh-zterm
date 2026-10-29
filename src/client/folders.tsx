import React, { useEffect, useId, useMemo, useRef, useState } from 'react'
import type { ClientContext, HostFolder, HostTarget } from '../shared/types'
import { rpc } from './api'
import { AssetTreeState, visibleTree } from './asset-tree-state'
import { DirectoryRow, PageControls, PageFeedback, TreeScroll, treeIndent, useTreePage, useTreeState } from './tree-browser'

export function folderRows(folders: HostFolder[]): Array<HostFolder & { depth: number }> {
  const children = new Map<string, HostFolder[]>()
  for (const folder of folders) { const key = folder.parentId ?? ''; children.set(key, [...(children.get(key) ?? []), folder]) }
  const stack = (children.get('') ?? []).slice().reverse().map((folder) => ({ ...folder, depth: 0 })), result = [], seen = new Set<string>()
  while (stack.length) { const folder = stack.pop()!; if (seen.has(folder.id)) continue; seen.add(folder.id); result.push(folder)
    for (const child of (children.get(folder.id) ?? []).slice().reverse()) stack.push({ ...child, depth: folder.depth + 1 }) }
  return result
}
function FolderActions({ folder, busy, onEdit, onDelete }: { folder: HostFolder; busy: boolean; onEdit: (folder: HostFolder) => void; onDelete: (folder: HostFolder) => void }) {
  const menu = useRef<HTMLDivElement>(null), trigger = useRef<HTMLButtonElement>(null), menuId = useId(), [open, setOpen] = useState(false)
  useEffect(() => {
    const element = menu.current!
    element.setAttribute('popover', 'auto')
    trigger.current!.setAttribute('popovertarget', menuId)
    const sync = () => {
      const visible = element.matches(':popover-open'); setOpen(visible)
      if (!visible) return
      const anchor = trigger.current!.getBoundingClientRect()
      element.style.left = `${Math.max(8, Math.min(anchor.right - element.offsetWidth, window.innerWidth - element.offsetWidth - 8))}px`
      element.style.top = `${Math.max(8, anchor.bottom + element.offsetHeight + 4 <= window.innerHeight - 8 ? anchor.bottom + 4 : anchor.top - element.offsetHeight - 4)}px`
      element.querySelector('button')?.focus({ preventScroll: true })
    }
    element.addEventListener('toggle', sync)
    return () => element.removeEventListener('toggle', sync)
  }, [menuId])
  useEffect(() => {
    if (!open) return
    const close = () => menu.current?.hidePopover()
    window.addEventListener('resize', close); document.addEventListener('scroll', close, true)
    return () => { window.removeEventListener('resize', close); document.removeEventListener('scroll', close, true) }
  }, [open])
  const choose = (action: (folder: HostFolder) => void) => { menu.current?.hidePopover(); action(folder) }
  const navigate = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
    event.preventDefault()
    const items = [...event.currentTarget.querySelectorAll('button')], current = items.indexOf(document.activeElement as HTMLButtonElement)
    const index = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (current + (event.key === 'ArrowUp' ? -1 : 1) + items.length) % items.length
    items[index]?.focus()
  }
  return <><button ref={trigger} disabled={busy} className="zt-folder-action" aria-label={`文件夹操作 ${folder.label}`} title="文件夹操作" aria-haspopup="menu" aria-controls={menuId} aria-expanded={open}>⋯</button>
    <div ref={menu} id={menuId} className="zt-folder-menu" role="menu" aria-label={`文件夹操作 ${folder.label}`} onKeyDown={navigate}>
      <button role="menuitem" disabled={busy} onClick={() => choose(onEdit)}>更名</button><button role="menuitem" disabled={busy} onClick={() => choose(onDelete)}>删除</button>
    </div></>
}
interface FolderTreeProps {
  ctx: ClientContext; state: AssetTreeState; folders: HostFolder[]; query: string; selected: string; busy: boolean
  onSelect: (id: string) => void; onEdit: (folder: HostFolder) => void; onDelete: (folder: HostFolder) => void
  onConnect: (host: HostTarget) => void; onHostEdit: (host: HostTarget) => void; onHostDelete: (host: HostTarget) => void
}
function HostPage({ props, folder, depth, hasChildren = false }: { props: FolderTreeProps; folder?: HostFolder; depth: number; hasChildren?: boolean }) {
  const { ctx, state, query, busy, onConnect, onHostEdit, onHostDelete } = props
  const pageKey = folder ? `hosts:${folder.id}` : `search:${query}`, label = folder?.label ?? '搜索结果'
  const { page, load } = useTreePage<HostTarget>(state, pageKey, async (offset, signal) => {
    const result = await rpc(ctx, 'catalog', { offset, query: folder ? undefined : query, folderId: folder ? folder.id || 'root' : undefined }, signal)
    return { items: result.hosts, total: result.total, hasMore: offset + 200 < result.total }
  }, true, !folder)
  return <div className="zt-tree-content" style={treeIndent(depth)} data-host-folder={folder?.id ?? 'search'}>
    <PageFeedback page={page} label={label} retry={() => load()} />
    {page?.status === 'ready' && <>{page.data?.items.map((host) => <div className="zt-host-row" key={host.id}>
      <button className="zt-host-connect" disabled={busy} onClick={() => onConnect(host)} title={`连接 ${host.username}@${host.host}:${host.port}`}><span className="zt-host-glyph">▤</span><span><strong>{host.label}</strong><small>{host.username}@{host.host}</small></span></button>
      <button disabled={busy} title="编辑主机" aria-label={`编辑主机 ${host.label}`} onClick={() => onHostEdit(host)}>⋯</button><button disabled={busy} title="移除主机配置" aria-label={`移除主机 ${host.label}`} onClick={() => onHostDelete(host)}>×</button>
    </div>)}{!page.data?.items.length && !hasChildren && <p className="zt-tree-message">{folder ? '此目录为空' : '没有匹配的主机'}</p>}</>}
    <PageControls page={page} size={200} label={label} load={load} />
  </div>
}
export function FolderTree(props: FolderTreeProps) {
  const { state, folders, query, selected, onSelect, onEdit, onDelete } = props
  useTreeState(state)
  const children = useMemo(() => {
    const map = new Map<string, HostFolder[]>()
    for (const folder of folders) { const key = folder.parentId ?? ''; if (!map.has(key)) map.set(key, []); map.get(key)!.push(folder) }
    return map
  }, [folders])
  const { rows } = visibleTree<HostFolder>([{ id: '', label: '根目录' }], (node) => node.id, (node) => children.get(node.id) ?? [], state.expanded, Number.MAX_SAFE_INTEGER)
  return <TreeScroll state={state} view={query ? `search:${query}` : 'tree'} label={query ? '主机搜索结果' : '主机文件夹'}>
    {query ? <HostPage key={`search:${query}`} props={props} depth={0} /> : rows.map(({ node, depth, content }) => content
      ? <HostPage key={`content:${node.id}`} props={props} folder={node} depth={depth + 1} hasChildren={Boolean(children.get(node.id)?.length)} />
      : <DirectoryRow key={`directory:${node.id}`} label={node.label} depth={depth} selected={selected === node.id} expanded={state.expanded.has(node.id)} onToggle={() => { onSelect(node.id); state.toggle(node.id) }}
        actions={node.id ? <FolderActions folder={node} busy={props.busy} onEdit={onEdit} onDelete={onDelete} /> : undefined} />)}
  </TreeScroll>
}
