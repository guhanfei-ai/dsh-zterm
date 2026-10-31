import React from 'react'
import * as jsx from 'react/jsx-runtime'
import { createRoot } from 'react-dom/client'

// 仅用于离线 UI 验证：加载正式客户端产物，宿主接口使用虚构数据。
const w = window as any, listeners = new Set<() => void>(), slots = new Map<string, any>()
const withSidebar = new URLSearchParams(location.search).get('sidebar') !== '0'
const localEnabled = new URLSearchParams(location.search).get('local') !== '0'
const connecting = new URLSearchParams(location.search).get('connecting') === '1', resizes: any[] = []
const legacyTab = new URLSearchParams(location.search).get('legacy') === '1', calls = new Map<string, number>()
const largeTree = new URLSearchParams(location.search).get('tree') === 'large'
const treeMode = new URLSearchParams(location.search).get('tree'), treeRequests: any[] = [], treeDelays = new Map<string, number>(), treeFailures = new Set<string>()
let jumpChildrenRemoved = false
let tab: any, open = false, activeType = 'zterm'
let openedTab: any, titleUpdates = 0, openCalls = 0, headerKey = 0, sessionId = 'fixture-session'
const history = new URLSearchParams(location.search).get('history') === '1'
const legacyHook = new URLSearchParams(location.search).get('hook') === 'session'
let chatSnapshot = { legacy: { nodes: history ? [{ children: [{ id: 'historical-connect', name: 'zterm_connect' }, { calls: [{ id: 'historical-bind', name: 'zterm_bind' }] }] }] as any[] : [] as any[] } }
const notify = () => listeners.forEach((listener) => listener())
function useChatSnapshot(selector: (snapshot: any) => any) {
  return selector(React.useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener) }, () => chatSnapshot))
}
let revision = 1, seq = 1, terminalSequence = 1, output = '$ uname -a\r\nLinux test-machine 6.8.0 x86_64 GNU/Linux\r\n$ '
const target = { source: 'ssh', assetId: 'app-01', label: '应用服务 01', host: '192.0.2.21', port: 22, username: 'operator' }
const state: any = { terminals: [{ id: 'terminal-01', generation: 1, target, state: connecting ? 'connecting' : 'ready', busy: false, uncertain: false, agentReady: !connecting, createdAt: new Date().toISOString() }], binding: undefined, operations: [], revision: 1, capabilities: { local: localEnabled, external: false }, hostPlatform: 'linux' }
w.__ztermFixture = { resizes, snapshot: () => ({ terminals: state.terminals.map((t: any) => ({ id: t.id, source: t.target.source })), binding: state.binding }), setOutput: (text: string) => { output = text; seq++ }, finishConnect: () => { state.terminals[0].state = 'ready'; state.terminals[0].agentReady = true } }
const catalog: any = { hosts: Array.from({ length: 8 }, (_, i) => ({ id: `host-${i}`, label: i < 3 ? `应用服务 0${i + 1}` : i < 5 ? `数据库 0${i - 2}` : `缓存节点 0${i - 4}`, kind: 'ssh', host: `192.0.2.${21 + i}`, port: 22, username: 'operator', authType: 'password', credentialRef: `DSH_ZTERM_TEST_${i}`, folderId: i < 3 ? 'apps' : undefined })), folders: [{ id: 'apps', label: '应用服务' }], jumpservers: [{ id: 'jump-1', label: '测试堡垒机', baseUrl: 'https://jump.example.invalid', authMode: 'token', credentialRef: 'DSH_ZTERM_TEST_JUMP', verifyTls: true }], total: 8, revision: 1,
  credentials: [], defaultCredentialId: '', allowLocalTerminal: localEnabled, allowExternalTargets: false, temporarilyDisabled: false, defaultPanelWidth: 60, maxSessions: 12, maxWriteCalls: 100, commandTimeoutMs: 30000, credentialsConfigured: {} }
if (largeTree) catalog.folders.push(...Array.from({ length: 30 }, (_, i) => ({ id: `folder-${i}`, label: `测试文件夹 ${i + 1}` })))
if (treeMode === 'root') { catalog.folders = []; catalog.hosts = catalog.hosts.slice(0, 4).map((host: any, index: number) => ({ ...host, label: `根目录机器 ${index + 1}`, folderId: undefined })) }
if (treeMode === 'unified' || largeTree) {
  catalog.folders = [{ id: 'prod', label: '生产环境' }, { id: 'apps', label: '应用服务', parentId: 'prod' }, { id: 'db', label: '数据库', parentId: 'prod' }, { id: 'empty', label: '空目录' }, ...catalog.folders.filter((folder: any) => folder.id !== 'apps')]
  catalog.hosts = largeTree ? Array.from({ length: 20000 }, (_, i) => ({ ...catalog.hosts[0], id: `host-${i}`, label: i < 450 ? `应用服务 ${i + 1}` : i < 800 ? `数据库 ${i - 449}` : `根目录机器 ${i - 799}`, host: `192.0.2.${i % 200 + 1}`, folderId: i < 450 ? 'apps' : i < 800 ? 'db' : undefined }))
    : catalog.hosts.map((host: any, index: number) => ({ ...host, folderId: index < 3 ? 'apps' : index < 5 ? 'db' : undefined }))
  catalog.jumpservers.push({ ...catalog.jumpservers[0], id: 'jump-2', label: '第二测试堡垒机' })
}
const jumpAsset = (id: string, name: string) => ({ assetId: id, name, address: '192.0.2.31', platform: 'Linux' })
const jumpGroups: Record<string, any[]> = {
  'n-prod': [jumpAsset('shared', '共享资产')],
  'n-app': Array.from({ length: largeTree ? 205 : 3 }, (_, index) => jumpAsset(`app-${index}`, `应用资产 ${index + 1}`)),
  'n-leaf': [jumpAsset('shared', '共享资产'), ...Array.from({ length: largeTree ? 120 : 2 }, (_, index) => jumpAsset(`leaf-${index}`, `叶子资产 ${index + 1}`))],
  'n-empty': [], 'n-deep': [jumpAsset('deep', '深层资产')],
}
const allJumpAssets = [...new Map(Object.values(jumpGroups).flat().map((item) => [item.assetId, item])).values(), ...(largeTree ? Array.from({ length: 20000 }, (_, i) => jumpAsset(`global-${i}`, `全局资产 ${i + 1}`)) : [])]
const jumpQuery = (payload: any) => {
  const prefix = payload.instanceId === 'jump-2' ? '第二实例 · ' : ''
  if (payload.operation === 'accounts') return { accounts: [{ accountId: 'a', name: '运维账号', username: 'operator', canConnect: true }] }
  if (payload.operation === 'nodes') return { nodes: (payload.parentKey === '1:0' ? [{ nodeId: 'n-app', key: '1:0:0', name: '应用资产目录', hasChildren: true, assetCount: jumpGroups['n-app'].length }]
    : payload.parentKey === '1:0:0' ? [{ nodeId: 'n-deep', key: '1:0:0:0', name: '深层目录', hasChildren: false, assetCount: 1 }]
    : payload.parentKey ? [] : [{ nodeId: 'n-prod', key: '1:0', name: '生产资产', hasChildren: !jumpChildrenRemoved, assetCount: 1 }, { nodeId: 'n-leaf', key: '1:1', name: '叶子目录', hasChildren: false, assetCount: jumpGroups['n-leaf'].length }, { nodeId: 'n-empty', key: '1:2', name: '空资产目录', hasChildren: false, assetCount: 0 }]).filter(() => !payload.parentKey || !jumpChildrenRemoved).map((node) => ({ ...node, name: prefix + node.name })) }
  const assets = (payload.nodeId ? jumpGroups[payload.nodeId] ?? [] : allJumpAssets).map((item) => ({ ...item, name: prefix + item.name })).filter((item) => `${item.name} ${item.address}`.toLowerCase().includes((payload.query ?? '').toLowerCase()))
  const offset = payload.offset ?? 0, limit = payload.limit ?? 100, slice = assets.slice(offset, offset + limit)
  return { assets: payload.nodeId === 'n-app' && slice.length ? [...slice, slice[0]] : slice, total: assets.length, hasMore: offset + limit < assets.length }
}
Object.assign(w.__ztermFixture, { treeRequests, delay: (key: string, ms: number) => treeDelays.set(key, ms), failNext: (key: string) => treeFailures.add(key),
  removeJumpChildren: () => { jumpChildrenRemoved = true },
  closeWorkbench: () => { open = false; notify() },
  uiSnapshot: () => ({ sessionId, open, openCalls, calls: Object.fromEntries(calls) }),
  setChatNodes: (nodes: any[]) => { chatSnapshot = { legacy: { nodes } }; notify() },
  switchSession: (id: string, nodes: any[] = []) => { sessionId = id; open = false; chatSnapshot = { legacy: { nodes } }; notify() },
  remountHeader: () => { headerKey++; notify() },
  renameHost: (id: string, label: string) => { catalog.hosts.find((host: any) => host.id === id).label = label; revision++ },
  renameAsset: (id: string, name: string) => { allJumpAssets.find((asset) => asset.assetId === id).name = name },
  catalog: () => ({ folders: catalog.folders, hosts: catalog.hosts.map((host: any) => ({ id: host.id, label: host.label, folderId: host.folderId })), revision }),
  moveHost: (id: string, folderId?: string) => { catalog.hosts.find((host: any) => host.id === id).folderId = folderId; revision++; state.catalogRevision = revision },
})
catalog.temporarilyDisabled = new URLSearchParams(location.search).get('disabled') === '1'
const ctx: any = { effect: (body: any) => body(), inject: (names: string[], body: any) => { if (!names.includes('betterSidebar') || withSidebar) return body(ctx) }, slots: { inject: (_name: any, body: any) => body(), register: (descriptor: any, component: any) => { slots.set(descriptor.name, component); return () => {} } },
  betterSidebar: withSidebar ? { registerTab: (descriptor: any) => { tab = descriptor; return () => {} }, openTab: (seed: any) => { openCalls++; openedTab ??= { id: 'fixture-tab', title: legacyTab ? '终端工作台' : seed.title }; open = true; activeType = 'zterm'; notify() },
    updateTab: (id: string, patch: any) => { if (openedTab?.id === id) { openedTab = { ...openedTab, ...patch }; titleUpdates++; notify() } } } : undefined,
  connection: { rpc: { call: async (_channel: string, endpoint: string, payload: any) => {
    let value: any = {}; const method = endpoint.slice(6)
    calls.set(method, (calls.get(method) ?? 0) + 1)
    if (method === 'catalog' || method === 'jump/query') {
      const key = method === 'catalog' ? `catalog:${payload.folderId ?? 'search'}` : `jump:${payload.instanceId}:${payload.operation}:${payload.nodeId ?? payload.parentKey ?? 'root'}`
      treeRequests.push({ key, payload: { ...payload } })
      if (treeDelays.get(key)) await new Promise((resolve) => setTimeout(resolve, treeDelays.get(key)))
      if (treeFailures.delete(key)) return { ok: false, error: { message: '虚构目录读取失败' } }
    }
    if (method === 'catalog') { const hosts = catalog.hosts.filter((h: any) => (!payload.targetId || h.id === payload.targetId) && `${h.label} ${h.host}`.toLowerCase().includes((payload?.query ?? '').toLowerCase()) && (!payload?.folderId || (payload.folderId === 'root' ? !h.folderId : h.folderId === payload.folderId))); const offset = payload.offset ?? 0; value = { ...catalog, hosts: hosts.slice(offset, offset + 200), total: hosts.length, revision } }
    else if (method === 'poll') value = { workspace: state, reset: true, cursor: seq, output: [], snapshots: state.terminals.map((t: any) => ({ terminalId: t.id, generation: t.generation, text: output })) }
    else if (method === 'status') value = { temporarilyDisabled: Boolean(catalog.temporarilyDisabled) }
    else if (method === 'bind') state.binding = { terminalId: payload.terminalId, generation: payload.generation, mode: 'read', writeCalls: 0, maxWriteCalls: 100 }
    else if (method === 'mode') state.binding.mode = payload.mode
    else if (method === 'input') { output += payload.data; seq++; state.terminals.find((t: any) => t.id === payload.terminalId).agentReady = false; if (state.binding) state.binding.mode = 'read' }
    else if (method === 'resize') { resizes.push({ ...payload }); notify() }
    else if (method === 'shell-ready') state.terminals.find((t: any) => t.id === payload.terminalId).agentReady = true
    else if (method === 'connect') {
      const local = payload.target.kind === 'local'
      if (local && !catalog.allowLocalTerminal) throw new Error('本地终端尚未启用')
      if (state.terminals.length >= catalog.maxSessions) throw new Error('当前会话终端数量已达上限，请关闭不用的标签')
      const host = catalog.hosts.find((h: any) => h.id === payload.target.targetId), t = { id: `terminal-${++terminalSequence}`, generation: 1, state: 'ready', busy: false, uncertain: false, agentReady: true, createdAt: new Date().toISOString(),
        target: local ? { source: 'local', assetId: 'dsh-host', label: 'DSH 宿主 (linux)', username: '当前宿主用户' } : { ...target, label: host?.label ?? target.label, host: host?.host ?? target.host } }
      state.terminals.push(t); value = t
    }
    else if (method === 'close') { state.terminals = state.terminals.filter((t: any) => t.id !== payload.terminalId); if (state.binding?.terminalId === payload.terminalId) state.binding = undefined }
    else if (method === 'host/save') { const host = { ...payload.host, id: payload.host.id ?? `host-${Date.now()}` }; catalog.hosts = [...catalog.hosts.filter((h: any) => h.id !== host.id), host]; revision++; value = { id: host.id } }
    else if (method === 'host/delete') { catalog.hosts = catalog.hosts.filter((host: any) => host.id !== payload.id); revision++; value = { deleted: true } }
    else if (method === 'credential/save') {
      const credential = { ...payload.credential, id: payload.credential.id ?? `credential-${Date.now()}`, ...(payload.credential.authType === 'key-file' ? { privateKeyPath: payload.content } : { credentialRef: 'DSH_ZTERM_FIXTURE_CREDENTIAL' }) }
      catalog.credentials = [...catalog.credentials.filter((c: any) => c.id !== credential.id), credential]; revision++; value = { id: credential.id }
    }
    else if (method === 'folder/save') { const folder = { ...payload.folder, id: payload.folder.id ?? `folder-${Date.now()}` }; catalog.folders = [...catalog.folders.filter((f: any) => f.id !== folder.id), folder]; revision++; value = { id: folder.id } }
    else if (method === 'folder/delete') {
      if (catalog.folders.some((f: any) => f.parentId === payload.id) || catalog.hosts.some((h: any) => h.folderId === payload.id)) throw new Error('请先移出主机和子文件夹')
      catalog.folders = catalog.folders.filter((f: any) => f.id !== payload.id); revision++; value = { deleted: true }
    }
    else if (method === 'jump/save') { const profile = { ...payload.profile, id: payload.profile.id ?? `jump-${Date.now()}` }; catalog.jumpservers = [...catalog.jumpservers.filter((p: any) => p.id !== profile.id), profile]; revision++; value = { id: profile.id } }
    else if (method === 'config') { Object.assign(catalog, payload.patch); state.capabilities.local = catalog.allowLocalTerminal; revision++ }
    else if (method === 'results') value = state.operations
    else if (method === 'saved-workspace') value = []
    else if (method === 'terminal/export') value = output
    else if (method === 'jump/query') value = jumpQuery(payload)
    return { ok: true, value: structuredClone(value) }
  } } } }
w.__ModuleLoader__ = { load: (bundle: any) => { const plugin = bundle.factory((name: string) => name === 'react' ? React : name === 'react/jsx-runtime' ? jsx : {}); plugin.apply(ctx); render() } }
const root = createRoot(document.getElementById('fixture')!)
function App() {
  React.useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener) }, () => `${open}:${activeType}:${resizes.length}:${openedTab?.title}:${titleUpdates}:${sessionId}:${headerKey}`)
  const [settingsOpen, setSettingsOpen] = React.useState(false), Header = slots.get('conversation.session.header.actions'), Settings = slots.get('settings.section'), NativeTitle = slots.get('sidebar.right.pane.tab.title')
  return <div className="fixture-app"><div id="root" className="fixture-chat"><header><strong>DSH 对话</strong>{Header && <Header key={headerKey} sessionId={sessionId} {...(legacyHook ? { useSession: useChatSnapshot } : { useChat: useChatSnapshot })} />}<button onClick={() => setSettingsOpen(true)}>设置</button></header><section><div className="fixture-user">帮忙检查应用服务的机器状态。</div><div className="fixture-ai">已找到对应资产。可以在右侧 zTerm 查看连接和操作过程。<p>当前模式：默认只读。需要修改时，由人类在终端工具栏开启读写。</p></div></section><footer><textarea placeholder="继续与 AI 对话…" /><span>同一对话中的资产、证据和操作结果</span><output data-testid="fixture-diagnostics">{JSON.stringify({ resizes: resizes.slice(-8), calls: Object.fromEntries(calls), titleUpdates, tabTitle: openedTab?.title })}</output></footer></div>
    {open && <aside className="fixture-side"><nav><button onClick={() => { activeType = 'mindmap'; notify() }}>思维脑图</button><button onClick={() => { activeType = 'zterm'; notify() }}>{NativeTitle ? <NativeTitle /> : openedTab?.title ?? 'zTerm'}</button><button aria-label="关闭 zTerm 面板" onClick={() => { open = false; notify() }}>×</button></nav>
      <div className="fixture-content" style={{ display: activeType === 'zterm' ? 'block' : 'none' }}>{tab && <tab.component ctx={ctx} tab={openedTab} scope={{ sessionId }} visible={activeType === 'zterm'} />}</div>
      {activeType === 'mindmap' && <div className="fixture-mindmap">脑图与终端共享右侧面板，通过 Tab 切换。</div>}</aside>}
    {settingsOpen && <div role="dialog" aria-label="zTerm 设置" style={{ position: 'absolute', left: '5%', top: '8%', width: 'min(600px,90%)', height: '84%', zIndex: 70, background: '#fff', border: '1px solid #dfe3e9' }}><button aria-label="关闭设置" style={{ position: 'absolute', right: 5, top: 5, zIndex: 1 }} onClick={() => setSettingsOpen(false)}>×</button>{Settings && <Settings />}</div>}
  </div>
}
function render() { root.render(<App />) }
render()
