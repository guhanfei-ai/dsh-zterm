import React from 'react'
import type { ClientContext } from '../shared/types'
import { rpc } from './api'
import { AssetTreeState, uniqueItems, visibleTree } from './asset-tree-state'
import { DirectoryRow, PageControls, PageFeedback, TreeScroll, treeIndent, useTreePage, useTreeState } from './tree-browser'

interface Node { nodeId: string; key: string; name: string; hasChildren: boolean; assetCount: number }
interface Asset { assetId: string; name: string; address: string; platform: string }
interface JumpTreeProps { ctx: ClientContext; instanceId: string; state: AssetTreeState; query: string; onChoose: (asset: Asset) => void }
const ALL: Node = { nodeId: '', key: '', name: '全部资产', hasChildren: false, assetCount: 0 }
function JumpContent({ props, node, depth }: { props: JumpTreeProps; node?: Node; depth: number }) {
  const { ctx, instanceId, state, query, onChoose } = props
  const children = useTreePage<Node>(state, `children:${node?.nodeId}`, async (_offset, signal) => {
    const result = await rpc(ctx, 'jump/query', { instanceId, operation: 'nodes', parentKey: node!.key || node!.nodeId }, signal)
    return { items: uniqueItems<Node>(result.nodes ?? [], (item) => item.nodeId), total: result.nodes?.length ?? 0, hasMore: false, truncated: result.truncated }
  }, Boolean(node?.hasChildren))
  const { page, load } = useTreePage<Asset>(state, node ? `assets:${node.nodeId}` : `search:${query}`, async (offset, signal) => {
    const result = await rpc(ctx, 'jump/query', { instanceId, operation: 'assets', nodeId: node?.nodeId || undefined, query: node ? undefined : query, offset, limit: 100 }, signal)
    return { items: uniqueItems<Asset>(result.assets ?? [], (item) => item.assetId), total: result.total, hasMore: result.hasMore }
  }, true, !node)
  const label = node?.name ?? '搜索结果'
  return <div className="zt-tree-content" style={treeIndent(depth)} data-asset-node={node?.nodeId ?? 'search'}>
    {node?.hasChildren && <><PageFeedback page={children.page} label={`${label}子目录`} retry={() => children.load()} />{children.page?.data?.truncated && <p className="zt-tree-message">子目录超过读取上限，可通过搜索查找资产。</p>}</>}
    <PageFeedback page={page} label={label} retry={() => load()} />
    {page?.status === 'ready' && <>{page.data?.items.map((item) => <button className="zt-asset-row" key={item.assetId} onClick={() => onChoose(item)} title={`${item.name} · ${item.address}`}><strong>▤ {item.name}</strong><small>{item.address} · {item.platform}</small></button>)}
      {!page.data?.items.length && (!node?.hasChildren || (children.page?.status === 'ready' && !children.page.data?.items.length)) && <p className="zt-tree-message">{node ? '此目录为空' : '没有匹配的资产'}</p>}</>}
    <PageControls page={page} size={100} label={label} load={load} />
  </div>
}
export function JumpTree(props: JumpTreeProps) {
  const { ctx, instanceId, state, query } = props
  useTreeState(state)
  const { page, load } = useTreePage<Node>(state, 'nodes', async (_offset, signal) => {
    const result = await rpc(ctx, 'jump/query', { instanceId, operation: 'nodes' }, signal)
    return { items: uniqueItems<Node>(result.nodes ?? [], (item) => item.nodeId), total: result.nodes?.length ?? 0, hasMore: false, truncated: result.truncated }
  }, !query)
  const { rows, truncated } = visibleTree(page?.data?.items ?? [], (node) => node.nodeId,
    (node) => node.hasChildren ? state.page<Node>(`children:${node.nodeId}`)?.data?.items ?? [] : [], state.expanded)
  return <TreeScroll state={state} view={query ? `search:${query}` : 'tree'} label={query ? 'JumpServer 搜索结果' : 'JumpServer 资产目录'}>
    {query ? <JumpContent key={`search:${query}`} props={props} depth={0} /> : <>
      <PageFeedback page={page} label="资产目录" retry={() => load()} />
      {rows.map(({ node, depth, content }) => content ? <JumpContent key={`content:${node.nodeId}`} props={props} node={node} depth={depth + 1} />
        : <DirectoryRow key={`directory:${node.nodeId}`} label={node.name} depth={depth} expanded={state.expanded.has(node.nodeId)} onToggle={() => state.toggle(node.nodeId)} />)}
      {(truncated || page?.data?.truncated) && <p className="zt-tree-message">目录显示已达 500 项，请收起部分目录或搜索资产。</p>}
      {/* 汇总入口放在真实目录之后，且不占用目录显示额度，避免大量机器把目录挤到下方。 */}
      <DirectoryRow label={ALL.name} depth={0} expanded={state.expanded.has(ALL.nodeId)} onToggle={() => state.toggle(ALL.nodeId)} />
      {state.expanded.has(ALL.nodeId) && <JumpContent props={props} node={ALL} depth={1} />}
    </>}
  </TreeScroll>
}
