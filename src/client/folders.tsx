import React, { useState } from 'react'
import type { HostFolder } from '../shared/types'

export function folderRows(folders: HostFolder[]): Array<HostFolder & { depth: number }> {
  const children = new Map<string, HostFolder[]>()
  for (const folder of folders) { const key = folder.parentId ?? ''; children.set(key, [...(children.get(key) ?? []), folder]) }
  const stack = (children.get('') ?? []).slice().reverse().map((folder) => ({ ...folder, depth: 0 })), result = [], seen = new Set<string>()
  while (stack.length) { const folder = stack.pop()!; if (seen.has(folder.id)) continue; seen.add(folder.id); result.push(folder)
    for (const child of (children.get(folder.id) ?? []).slice().reverse()) stack.push({ ...child, depth: folder.depth + 1 }) }
  return result
}
export function FolderTree({ folders, selected, onSelect }: { folders: HostFolder[]; selected: string; onSelect: (id: string) => void }) {
  const [collapsed, setCollapsed] = useState(new Set<string>())
  const rows = folderRows(folders), hidden = new Set<string>(), parents = new Set(folders.map((f) => f.parentId))
  return <nav className="zt-folder-tree" aria-label="主机文件夹">
    {['', 'root'].map((id) => <button key={id} className={selected === id ? 'active' : ''} onClick={() => onSelect(id)}>{id ? '▱ 根目录' : '▤ 全部主机'}</button>)}
    {rows.map((folder) => {
      if (folder.parentId && (collapsed.has(folder.parentId) || hidden.has(folder.parentId))) { hidden.add(folder.id); return null }
      return <div key={folder.id} style={{ paddingLeft: Math.min(8, folder.depth) * 12 }}><button className="zt-folder-toggle" aria-label={`${collapsed.has(folder.id) ? '展开' : '收起'}文件夹 ${folder.label}`} disabled={!parents.has(folder.id)} onClick={() => setCollapsed((previous) => { const next = new Set(previous); next.has(folder.id) ? next.delete(folder.id) : next.add(folder.id); return next })}>{parents.has(folder.id) ? collapsed.has(folder.id) ? '▸' : '▾' : '·'}</button>
        <button className={selected === folder.id ? 'active' : ''} onClick={() => onSelect(folder.id)} title={folder.label}>▱ {folder.label}</button></div>
    })}
  </nav>
}
