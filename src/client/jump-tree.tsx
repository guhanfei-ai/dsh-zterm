import React, { useState, useRef, useEffect } from 'react'
import type { ClientContext } from '../shared/types'
import { rpc } from './api'

interface Node { nodeId: string; key: string; name: string; hasChildren: boolean; assetCount: number }
export function JumpTree({ ctx, instanceId, nodes, selected, onSelect, onError }: { ctx: ClientContext; instanceId: string; nodes: Node[]; selected: string; onSelect: (id: string) => void; onError: (message: string) => void }) {
  const [children, setChildren] = useState(new Map<string, Node[]>()), [expanded, setExpanded] = useState(new Set<string>()), [loading, setLoading] = useState(new Set<string>())
  const alive = useRef(true), controller = useRef(new AbortController())
  useEffect(() => () => { alive.current = false; controller.current.abort() }, [])
  const expand = async (node: Node) => {
    if (expanded.has(node.nodeId)) { setExpanded((previous) => { const next = new Set(previous); next.delete(node.nodeId); return next }); return }
    if (!children.has(node.nodeId)) {
      setLoading((previous) => new Set(previous).add(node.nodeId))
      try { const result = await rpc(ctx, 'jump/query', { instanceId, operation: 'nodes', parentKey: node.key || node.nodeId }, controller.current.signal)
        if (!alive.current) return; setChildren((previous) => new Map(previous).set(node.nodeId, result.nodes ?? []))
      } catch (error) { if (alive.current) onError((error as Error).message); return }
      finally { if (alive.current) setLoading((previous) => { const next = new Set(previous); next.delete(node.nodeId); return next }) }
    }
    setExpanded((previous) => new Set(previous).add(node.nodeId))
  }
  const stack = nodes.slice().reverse().map((node) => ({ node, depth: 0 })), rows = [], seen = new Set<string>()
  while (stack.length && rows.length < 500) { const item = stack.pop()!; if (seen.has(item.node.nodeId)) continue; seen.add(item.node.nodeId); rows.push(item)
    if (expanded.has(item.node.nodeId)) for (const node of (children.get(item.node.nodeId) ?? []).slice().reverse()) stack.push({ node, depth: item.depth + 1 }) }
  return <nav className="zt-folder-tree" aria-label="JumpServer 资产节点"><button className={!selected ? 'active' : ''} onClick={() => onSelect('')}>▤ 全部资产</button>
    {rows.map(({ node, depth }) => <div key={node.nodeId} style={{ paddingLeft: Math.min(8, depth) * 12 }}><button className="zt-folder-toggle" disabled={!node.hasChildren || loading.has(node.nodeId)} aria-label={`展开资产节点 ${node.name}`} onClick={() => void expand(node)}>{loading.has(node.nodeId) ? '…' : node.hasChildren ? expanded.has(node.nodeId) ? '▾' : '▸' : '·'}</button>
      <button className={selected === node.nodeId ? 'active' : ''} onClick={() => onSelect(node.nodeId)} title={node.name}>{node.name} ({node.assetCount})</button></div>)}
    {stack.length > 0 && <p className="zt-hint">节点显示已达 500 项，请收起部分节点。</p>}
  </nav>
}
