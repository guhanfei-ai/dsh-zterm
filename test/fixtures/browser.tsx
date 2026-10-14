import React from 'react'
import * as jsx from 'react/jsx-runtime'
import { createRoot } from 'react-dom/client'

// 仅用于离线 UI 验证：加载正式客户端产物，宿主接口使用虚构数据。
const w = window as any, listeners = new Set<() => void>(), slots = new Map<string, any>()
const withSidebar = new URLSearchParams(location.search).get('sidebar') !== '0'
const localEnabled = new URLSearchParams(location.search).get('local') !== '0'
const connecting = new URLSearchParams(location.search).get('connecting') === '1', resizes: any[] = []
const legacyTab = new URLSearchParams(location.search).get('legacy') === '1', calls = new Map<string, number>()
let tab: any, open = false, activeType = 'zterm'
let openedTab: any, titleUpdates = 0
const notify = () => listeners.forEach((listener) => listener())
let revision = 1, seq = 1, terminalSequence = 1, output = '$ uname -a\r\nLinux test-machine 6.8.0 x86_64 GNU/Linux\r\n$ '
const target = { source: 'ssh', assetId: 'app-01', label: '应用服务 01', host: '192.0.2.21', port: 22, username: 'operator' }
const state: any = { terminals: [{ id: 'terminal-01', generation: 1, target, state: connecting ? 'connecting' : 'ready', busy: false, uncertain: false, agentReady: !connecting, createdAt: new Date().toISOString() }], binding: undefined, operations: [], revision: 1, capabilities: { local: localEnabled, external: false }, hostPlatform: 'linux' }
w.__ztermFixture = { resizes, snapshot: () => ({ terminals: state.terminals.map((t: any) => ({ id: t.id, source: t.target.source })), binding: state.binding }), setOutput: (text: string) => { output = text; seq++ }, finishConnect: () => { state.terminals[0].state = 'ready'; state.terminals[0].agentReady = true } }
const catalog: any = { hosts: Array.from({ length: 8 }, (_, i) => ({ id: `host-${i}`, label: i < 3 ? `应用服务 0${i + 1}` : i < 5 ? `数据库 0${i - 2}` : `缓存节点 0${i - 4}`, kind: 'ssh', host: `192.0.2.${21 + i}`, port: 22, username: 'operator', authType: 'password', credentialRef: `DSH_ZTERM_TEST_${i}`, folderId: i < 3 ? 'apps' : undefined })), folders: [{ id: 'apps', label: '应用服务' }], jumpservers: [{ id: 'jump-1', label: '测试堡垒机', baseUrl: 'https://jump.example.invalid', authMode: 'token', credentialRef: 'DSH_ZTERM_TEST_JUMP', verifyTls: true }], total: 8, revision: 1,
  credentials: [], defaultCredentialId: '', allowLocalTerminal: localEnabled, allowExternalTargets: false, defaultPanelWidth: 60, maxSessions: 12, maxWriteCalls: 100, commandTimeoutMs: 30000, credentialsConfigured: {} }
const ctx: any = { effect: (body: any) => body(), inject: (names: string[], body: any) => { if (!names.includes('betterSidebar') || withSidebar) return body(ctx) }, slots: { inject: (_name: any, body: any) => body(), register: (descriptor: any, component: any) => { slots.set(descriptor.name, component); return () => {} } },
  betterSidebar: withSidebar ? { registerTab: (descriptor: any) => { tab = descriptor; return () => {} }, openTab: (seed: any) => { openedTab ??= { id: 'fixture-tab', title: legacyTab ? '终端工作台' : seed.title }; open = true; activeType = 'zterm'; notify() },
    updateTab: (id: string, patch: any) => { if (openedTab?.id === id) { openedTab = { ...openedTab, ...patch }; titleUpdates++; notify() } } } : undefined,
  connection: { rpc: { call: async (_channel: string, endpoint: string, payload: any) => {
    let value: any = {}; const method = endpoint.slice(6)
    calls.set(method, (calls.get(method) ?? 0) + 1)
    if (method === 'catalog') { const hosts = catalog.hosts.filter((h: any) => `${h.label} ${h.host}`.includes(payload?.query ?? '') && (!payload?.folderId || (payload.folderId === 'root' ? !h.folderId : h.folderId === payload.folderId))); value = { ...catalog, hosts, total: hosts.length, revision } }
    else if (method === 'poll') value = { workspace: state, reset: true, cursor: seq, output: [], snapshots: state.terminals.map((t: any) => ({ terminalId: t.id, generation: t.generation, text: output })) }
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
    else if (method === 'credential/save') {
      const credential = { ...payload.credential, id: payload.credential.id ?? `credential-${Date.now()}`, ...(payload.credential.authType === 'key-file' ? { privateKeyPath: payload.content } : { credentialRef: 'DSH_ZTERM_FIXTURE_CREDENTIAL' }) }
      catalog.credentials = [...catalog.credentials.filter((c: any) => c.id !== credential.id), credential]; revision++; value = { id: credential.id }
    }
    else if (method === 'folder/save') { const folder = { ...payload.folder, id: payload.folder.id ?? `folder-${Date.now()}` }; catalog.folders = [...catalog.folders.filter((f: any) => f.id !== folder.id), folder]; revision++; value = { id: folder.id } }
    else if (method === 'jump/save') { const profile = { ...payload.profile, id: payload.profile.id ?? `jump-${Date.now()}` }; catalog.jumpservers = [...catalog.jumpservers.filter((p: any) => p.id !== profile.id), profile]; revision++; value = { id: profile.id } }
    else if (method === 'config') { Object.assign(catalog, payload.patch); state.capabilities.local = catalog.allowLocalTerminal; revision++ }
    else if (method === 'results') value = state.operations
    else if (method === 'saved-workspace') value = []
    else if (method === 'terminal/export') value = output
    else if (method === 'jump/query') value = payload.operation === 'nodes' ? { nodes: [{ nodeId: 'n', name: '测试资产', assetCount: 2 }] } : payload.operation === 'accounts' ? { accounts: [{ accountId: 'a', name: '运维账号', username: 'operator', canConnect: true }] } : { assets: [{ assetId: 'a1', name: '测试应用主机', address: '192.0.2.31', platform: 'Linux' }], total: 1, hasMore: false }
    return { ok: true, value }
  } } } }
w.__ModuleLoader__ = { load: (bundle: any) => { const plugin = bundle.factory((name: string) => name === 'react' ? React : name === 'react/jsx-runtime' ? jsx : {}); plugin.apply(ctx); render() } }
const root = createRoot(document.getElementById('fixture')!)
function App() {
  React.useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener) }, () => `${open}:${activeType}:${resizes.length}:${openedTab?.title}:${titleUpdates}`)
  const [settingsOpen, setSettingsOpen] = React.useState(false), Header = slots.get('conversation.session.header.actions'), Settings = slots.get('settings.section'), NativeTitle = slots.get('sidebar.right.pane.tab.title')
  return <div className="fixture-app"><div id="root" className="fixture-chat"><header><strong>DSH 对话</strong>{Header && <Header sessionId="fixture-session" />}<button onClick={() => setSettingsOpen(true)}>设置</button></header><section><div className="fixture-user">帮忙检查应用服务的机器状态。</div><div className="fixture-ai">已找到对应资产。可以在右侧 zTerm 查看连接和操作过程。<p>当前模式：默认只读。需要修改时，由人类在终端工具栏开启读写。</p></div></section><footer><textarea placeholder="继续与 AI 对话…" /><span>同一对话中的资产、证据和操作结果</span><output data-testid="fixture-diagnostics">{JSON.stringify({ resizes: resizes.slice(-8), calls: Object.fromEntries(calls), titleUpdates, tabTitle: openedTab?.title })}</output></footer></div>
    {open && <aside className="fixture-side"><nav><button onClick={() => { activeType = 'mindmap'; notify() }}>思维脑图</button><button onClick={() => { activeType = 'zterm'; notify() }}>{NativeTitle ? <NativeTitle /> : openedTab?.title ?? 'zTerm'}</button></nav>
      <div className="fixture-content" style={{ display: activeType === 'zterm' ? 'block' : 'none' }}>{tab && <tab.component ctx={ctx} tab={openedTab} scope={{ sessionId: 'fixture-session' }} visible={activeType === 'zterm'} />}</div>
      {activeType === 'mindmap' && <div className="fixture-mindmap">脑图与终端共享右侧面板，通过 Tab 切换。</div>}</aside>}
    {settingsOpen && <div role="dialog" aria-label="zTerm 设置" style={{ position: 'absolute', left: '5%', top: '8%', width: 'min(600px,90%)', height: '84%', zIndex: 70, background: '#fff', border: '1px solid #dfe3e9' }}><button aria-label="关闭设置" style={{ position: 'absolute', right: 5, top: 5, zIndex: 1 }} onClick={() => setSettingsOpen(false)}>×</button>{Settings && <Settings />}</div>}
  </div>
}
function render() { root.render(<App />) }
render()
