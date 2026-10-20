import React, { useEffect, useId, useRef, useState } from 'react'
import type { HostFolder } from '../shared/types'

export function folderRows(folders: HostFolder[]): Array<HostFolder & { depth: number }> {
  const children = new Map<string, HostFolder[]>()
  for (const folder of folders) { const key = folder.parentId ?? ''; children.set(key, [...(children.get(key) ?? []), folder]) }
  const stack = (children.get('') ?? []).slice().reverse().map((folder) => ({ ...folder, depth: 0 })), result = [], seen = new Set<string>()
  while (stack.length) { const folder = stack.pop()!; if (seen.has(folder.id)) continue; seen.add(folder.id); result.push(folder)
    for (const child of (children.get(folder.id) ?? []).slice().reverse()) stack.push({ ...child, depth: folder.depth + 1 }) }
  return result
}
function FolderActions({ folder, onEdit, onDelete }: { folder: HostFolder; onEdit: (folder: HostFolder) => void; onDelete: (folder: HostFolder) => void }) {
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
  return <><button ref={trigger} className="zt-folder-action" aria-label={`文件夹操作 ${folder.label}`} title="文件夹操作" aria-haspopup="menu" aria-controls={menuId} aria-expanded={open}>⋯</button>
    <div ref={menu} id={menuId} className="zt-folder-menu" role="menu" aria-label={`文件夹操作 ${folder.label}`} onKeyDown={navigate}>
      <button role="menuitem" onClick={() => choose(onEdit)}>更名</button><button role="menuitem" onClick={() => choose(onDelete)}>删除</button>
    </div></>
}
export function FolderTree({ folders, selected, onSelect, onEdit, onDelete }: { folders: HostFolder[]; selected: string; onSelect: (id: string) => void; onEdit: (folder: HostFolder) => void; onDelete: (folder: HostFolder) => void }) {
  const [collapsed, setCollapsed] = useState(new Set<string>())
  const rows = folderRows(folders), hidden = new Set<string>(), parents = new Set(folders.map((f) => f.parentId))
  return <nav className="zt-folder-tree" aria-label="主机文件夹">
    <button className={selected === '' ? 'active' : ''} onClick={() => onSelect('')}>▱ 根目录(全部主机)</button>
    {rows.map((folder) => {
      if (folder.parentId && (collapsed.has(folder.parentId) || hidden.has(folder.parentId))) { hidden.add(folder.id); return null }
      return <div key={folder.id} style={{ paddingLeft: `min(${Math.min(8, folder.depth) * 12}px, 25%)` }}><button className="zt-folder-toggle" aria-label={`${collapsed.has(folder.id) ? '展开' : '收起'}文件夹 ${folder.label}`} disabled={!parents.has(folder.id)} onClick={() => setCollapsed((previous) => { const next = new Set(previous); next.has(folder.id) ? next.delete(folder.id) : next.add(folder.id); return next })}>{parents.has(folder.id) ? collapsed.has(folder.id) ? '▸' : '▾' : '·'}</button>
        <button className={`zt-folder-name${selected === folder.id ? ' active' : ''}`} onClick={() => onSelect(folder.id)} title={folder.label}>▱ {folder.label}</button>
        <FolderActions folder={folder} onEdit={onEdit} onDelete={onDelete} /></div>
    })}
  </nav>
}
