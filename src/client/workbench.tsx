import React, { useState, useEffect, useCallback, useRef } from 'react'
import type { ClientContext, WorkspaceView, TerminalView, HostTarget, HostFolder, JumpProfile, PollResult } from '../shared/types'
import { rpc, download, timestamp, mergeFrames, progressElapsed } from './api'
import { TerminalScreen } from './terminal'
import { HostEditor, JumpEditor, FolderEditor, Modal } from './forms'
import { FolderTree } from './folders'
import { JumpTree } from './jump-tree'
import { TreePane } from './tree-pane'
import { savedNumber, saveNumber, useDrag } from './preferences'
import { PRODUCT_NAME } from '../shared/branding'

const EMPTY: WorkspaceView = { terminals: [], operations: [], revision: 0, capabilities: { local: false, external: false }, hostPlatform: '' }
const status: Record<string, string> = { connecting: '连接中', ready: '已连接', disconnected: '已断开', error: '连接失败', executing: '执行中', completed: '完成', failed: '失败', unknown: '结果不明', blocked: '已拒绝', not_sent: '未下发' }
export const pageId = typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : `page-${Date.now()}-${Math.random()}`
export function Workbench({ ctx, sessionId, visible = true, onClose }: { ctx: ClientContext; sessionId: string; visible?: boolean; onClose?: () => void }) {
  const [workspace, setWorkspace] = useState<WorkspaceView>(EMPTY), [buffers, setBuffers] = useState<Map<string, any>>(new Map()), [active, setActive] = useState('')
  const [error, setError] = useState(''), [catalog, setCatalog] = useState<any>(), [query, setQuery] = useState(''), [offset, setOffset] = useState(0), [folder, setFolder] = useState('')
  const [source, setSource] = useState<'ssh' | 'jumpserver'>('ssh'), [hostEditor, setHostEditor] = useState<HostTarget | null | false>(false), [jumpEditor, setJumpEditor] = useState<JumpProfile | null | false>(false), [folderEditor, setFolderEditor] = useState<HostFolder | null | false>(false)
  const [instanceId, setInstanceId] = useState(''), [nodeId, setNodeId] = useState(''), [nodes, setNodes] = useState<any[]>([]), [assets, setAssets] = useState<any>(), [accounts, setAccounts] = useState<any>(), [asset, setAsset] = useState<any>()
  const [showRecords, setShowRecords] = useState(false), [listHidden, setListHidden] = useState(false), [listWidth, setListWidth] = useState(() => savedNumber('dsh-zterm.list-width', 240, 180, 440))
  const [actionBusy, setActionBusy] = useState(false), [saved, setSaved] = useState(false), [confirm, setConfirm] = useState<{ text: string; act: () => void }>()
  const alive = useRef(true), visibleRef = useRef(visible), cursor = useRef(-1), pollRefresh = useRef<() => Promise<void>>(async () => {}), activeRef = useRef(active), catalogRequest = useRef(0), accountRequest = useRef(0)
  const tabsRef = useRef<HTMLElement>(null), activeTabRef = useRef<HTMLDivElement>(null)
  const startDrag = useDrag()
  visibleRef.current = visible; activeRef.current = active
  const fail = useCallback((message: string) => setError(message), [])
  useEffect(() => {
    alive.current = true; setWorkspace(EMPTY); setBuffers(new Map()); cursor.current = -1
    let cancelled = false, attached = false, timer: ReturnType<typeof setTimeout>, inFlight: Promise<void> | undefined; const controller = new AbortController()
    const fetchPoll = async () => {
      try {
        if (!attached) { await rpc(ctx, 'client/attach', { sessionId, pageId }, controller.signal); attached = true }
        const result = await rpc<PollResult>(ctx, 'poll', { sessionId, cursor: cursor.current }, controller.signal)
        if (cancelled) return
        cursor.current = result.cursor; setWorkspace(result.workspace); setBuffers((previous) => mergeFrames(previous, result))
        if (!result.workspace.terminals.some((t) => t.id === activeRef.current)) setActive(result.workspace.terminals[0]?.id ?? '')
      } catch (e) { if (!cancelled) setError(e instanceof Error ? e.message : '无法读取终端状态') }
    }
    const poll = () => { if (inFlight) return inFlight; inFlight = fetchPoll().finally(() => { inFlight = undefined }); return inFlight }
    const loop = async () => { await poll(); if (!cancelled) timer = setTimeout(loop, visibleRef.current ? 200 : 1000) }
    pollRefresh.current = poll; void loop(); void rpc<any[]>(ctx, 'saved-workspace', { sessionId }).then((targets) => { if (!cancelled) setSaved(targets.length > 0) }).catch(() => {})
    return () => { cancelled = true; alive.current = false; clearTimeout(timer); controller.abort() }
  }, [ctx, sessionId])
  const loadCatalog = useCallback(async (signal?: AbortSignal) => {
    const request = ++catalogRequest.current
    const result = await rpc(ctx, 'catalog', { query, offset, folderId: folder || undefined }, signal)
    if (signal?.aborted || request !== catalogRequest.current || !alive.current) return
    setCatalog(result); if (!instanceId && result.jumpservers.length) setInstanceId(result.jumpservers[0].id)
  }, [ctx, query, offset, folder, instanceId])
  useEffect(() => { const controller = new AbortController(); const timer = setTimeout(() => { void loadCatalog(controller.signal).catch((e) => { if (!controller.signal.aborted) fail(e.message) }) }, 150)
    return () => { clearTimeout(timer); controller.abort() } }, [loadCatalog, fail, workspace.catalogRevision])
  const action = useCallback(async (method: string, payload: any = {}) => {
    setActionBusy(true); setError('')
    try { const value = await rpc(ctx, method, { sessionId, pageId, ...payload }); if (alive.current) { await pollRefresh.current(); return value } }
    catch (e) { if (alive.current) fail(e instanceof Error ? e.message : '操作失败') }
    finally { if (alive.current) setActionBusy(false) }
  }, [ctx, sessionId, fail])
  const connect = async (target: unknown) => { const view = await action('connect', { target }); if (view?.id) setActive(view.id) }
  useEffect(() => {
    if (!visible || !tabsRef.current) return
    const reveal = () => activeTabRef.current?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
    reveal(); const observer = new ResizeObserver(reveal); observer.observe(tabsRef.current)
    return () => observer.disconnect()
  }, [active, visible, workspace.terminals.length])
  const current = workspace.terminals.find((t) => t.id === active), bound = workspace.binding, currentBound = current && bound?.terminalId === current.id && bound.generation === current.generation
  const trustTerminal = workspace.terminals.find((t) => t.trust), trustParameters = trustTerminal ? { terminalId: trustTerminal.id, generation: trustTerminal.generation } : {}
  const targetText = (terminal: TerminalView) => terminal.target.source === 'local' ? terminal.target.label : `${terminal.target.username ?? ''}@${terminal.target.host ?? terminal.target.label}${terminal.target.port ? `:${terminal.target.port}` : ''}`
  const parameters = current ? { terminalId: current.id, generation: current.generation } : {}
  // 执行中的操作记录或连接起点给出已用时；超过 2 秒才显示（issue #3 期望 2）。
  const startedAt = current ? workspace.operations.filter((record) => record.status === 'executing' && record.terminalId === current.id).at(-1)?.startedAt
    ?? (current.state === 'connecting' ? current.createdAt : undefined) : undefined
  const progress = progressElapsed(startedAt)
  const profile = catalog?.jumpservers?.find((p: any) => p.id === instanceId)
  useEffect(() => {
    if (source !== 'jumpserver' || !instanceId) return
    let active = true; setNodes([])
    void rpc(ctx, 'jump/query', { instanceId, operation: 'nodes' }).then((value) => { if (active) setNodes(value.nodes ?? []) }).catch((e) => { if (active) fail(e.message) })
    return () => { active = false }
  }, [ctx, instanceId, source, fail])
  useEffect(() => {
    if (source !== 'jumpserver' || !instanceId) return
    let active = true; setAssets(undefined); const timer = setTimeout(() => {
      void rpc(ctx, 'jump/query', { instanceId, operation: 'assets', nodeId: nodeId || undefined, query, offset, limit: 100 })
        .then((value) => { if (active) setAssets(value) }).catch((e) => { if (active) fail(e.message) })
    }, 200)
    return () => { active = false; clearTimeout(timer) }
  }, [ctx, instanceId, nodeId, query, offset, source, fail])
  useEffect(() => { accountRequest.current++; setAccounts(undefined) }, [instanceId, source])
  const chooseAsset = async (value: any) => { const request = ++accountRequest.current; setAsset(value); setAccounts(undefined); try { const result = await rpc(ctx, 'jump/query', { instanceId, operation: 'accounts', assetId: value.assetId }); if (request === accountRequest.current && alive.current) setAccounts(result.accounts) } catch (e) { if (request === accountRequest.current && alive.current) fail((e as Error).message) } }
  const resizeList = (event: React.MouseEvent) => {
    const start = event.clientX, width = listWidth
    startDrag(event, (e) => { const value = Math.max(180, Math.min(440, width + start - e.clientX)); setListWidth(value); saveNumber('dsh-zterm.list-width', value) })
  }
  return <div className="zt-workbench">
    {catalog?.temporarilyDisabled && <div className="zt-workbench-notice" role="status">zTerm 已临时禁用：AI 不会收到本插件提示，也不能调用 zterm_* 工具；手工连接、终端和配置管理仍可使用。可在「设置 → zTerm」恢复。</div>}
    {error && <div className="zt-error-banner" role="alert"><span>{error}</span><button aria-label="关闭错误提示" onClick={() => setError('')}>×</button></div>}
    <div className="zt-workbench-body">
      <main className="zt-terminal-area">
        <div className="zt-terminal-topbar"><nav ref={tabsRef} className="zt-terminal-tabs" aria-label="终端标签">{workspace.terminals.map((terminal) => <div key={terminal.id} ref={terminal.id === active ? activeTabRef : undefined} className={`zt-tab ${terminal.id === active ? 'active' : ''}`}>
          <button onClick={() => setActive(terminal.id)} title={targetText(terminal)}><i className={`zt-state-dot ${terminal.state}`} />{terminal.target.label}</button>
          <button aria-label={`关闭终端 ${terminal.target.label}`} onClick={() => setConfirm({ text: `关闭「${terminal.target.label}」的终端连接？`, act: () => { void action('close', { terminalId: terminal.id }); setConfirm(undefined) } })}>×</button></div>)}
          </nav>
          <div className="zt-terminal-controls"><button disabled={!workspace.capabilities.local || actionBusy} title={workspace.capabilities.local ? '每次点击新开一个终端，运行在 DSH 所在的机器上' : `请在 ${PRODUCT_NAME} 设置中启用本地终端并保存`} onClick={() => void connect({ kind: 'local' })}>打开本机终端</button><button title="操作记录" onClick={() => setShowRecords(!showRecords)}>记录</button>{listHidden && <button title="显示机器列表" aria-expanded={false} onClick={() => setListHidden(false)}>机器列表</button>}{onClose && <button aria-label={`收起 ${PRODUCT_NAME}`} onClick={onClose}>×</button>}</div></div>
        {current ? <><div className="zt-terminal-toolbar"><div className="zt-target" title={targetText(current)}>{targetText(current)}<span>{status[current.state]}{current.busy ? ' · AI 执行中' : ''}{progress ? ` · ${progress}` : ''}</span></div>
          <div className="zt-actions"><button disabled={actionBusy || current.state !== 'ready' || !current.agentReady || current.uncertain} onClick={() => void action('bind', parameters)}>{currentBound ? '已绑定 AI' : '绑定 AI'}</button>
            <label className={`zt-mode ${currentBound && bound.mode === 'readwrite' ? 'write' : ''}`} title="未勾选：读模式，AI 仅可使用内置查询工具；勾选：读写模式，AI 可执行已授权的命令。"><input type="checkbox" aria-label="允许AI写操作" checked={Boolean(currentBound && bound.mode === 'readwrite')}
              disabled={!currentBound || actionBusy || !current.agentReady || current.uncertain} onChange={(e) => void action('mode', { ...parameters, mode: e.target.checked ? 'readwrite' : 'read' })} />允许AI写操作</label>
            <button disabled={!current.busy} onClick={() => void action('stop', parameters)}>停止</button>
            <button disabled={actionBusy || current.busy} onClick={() => void action(current.state === 'ready' ? 'disconnect' : 'reconnect', parameters)}>{current.state === 'ready' ? '断开' : '重连'}</button></div></div>
          {!current.agentReady && current.state === 'ready' && !current.uncertain && <div className="zt-notice">手工输入后，AI 已暂停操作。确认终端回到空闲 Shell 后：<button onClick={() => void action('shell-ready', parameters)}>确认空闲 Shell</button></div>}
          {current.uncertain && <div className="zt-notice danger">前次操作结果不明，已停止自动下发。核实机器状态后重新建立连接。</div>}
          {current.error && <div className="zt-notice danger">{current.error}</div>}
        </> : <div className="zt-empty"><div className="zt-terminal-mark">&gt;_</div><h3>连接一台机器</h3><p>从右侧选择主机或 JumpServer 资产。<br />连接后可手工操作，或绑定给当前 DSH 对话中的 AI。</p>
          {workspace.capabilities.automatic && <p>也可在对话中指定主机名或 IP，AI 会先查远程主机，再查 JumpServer，最后使用默认 SSH 私钥。</p>}
          <button className="zt-primary" onClick={() => setHostEditor(null)}>添加远程主机</button>{saved && <button onClick={() => void action('restore')}>恢复上次终端列表（默认只读）</button>}</div>}
        <div className="zt-screens">{workspace.terminals.map((terminal) => <TerminalScreen key={`${terminal.id}:${terminal.generation}`} ctx={ctx} sessionId={sessionId} terminal={terminal} buffer={buffers.get(terminal.id)} visible={visible && terminal.id === active} onError={fail} />)}</div>
        <footer className="zt-statusbar"><div className="zt-status-info"><span>{bound ? `AI 绑定：${workspace.terminals.find((t) => t.id === bound.terminalId)?.target.label ?? bound.terminalId} · ${bound.mode === 'readwrite' ? `读写 ${bound.writeCalls}/${bound.maxWriteCalls}` : '只读'}` : 'AI 尚未绑定终端'}</span>
          <span className="zt-host-platform" title="终端连接与命令从 DSH 宿主发起">DSH 宿主 · {workspace.hostPlatform || '正在连接'}</span></div>
          {current && <button onClick={() => { void rpc(ctx, 'terminal/export', { sessionId, terminalId: current.id }).then((text) => download(`zterm-${timestamp()}-终端.txt`, `终端：${targetText(current)}\n说明：仅包含有界历史缓冲，可能已截断。\n\n${text}`)).catch((e) => fail(e.message)) }}>导出终端</button>}</footer>
        {showRecords && <div className="zt-records"><header><strong>实际操作记录</strong><button onClick={() => { void rpc(ctx, 'results', { sessionId, limit: 200 }).then((records) => download(`zterm-${timestamp()}-操作记录.json`, JSON.stringify({ version: 1, sessionId, historyLimited: true, records }, null, 2), 'application/json')).catch((e) => fail(e.message)) }}>导出 JSON</button></header>
          {!workspace.operations.length && <p className="zt-hint">绑定终端并调用工具后，实际操作记录会显示在这里。</p>}
          {workspace.operations.slice().reverse().map((record) => <details key={record.id}><summary><span className={`zt-record-status ${record.status}`}>{status[record.status]}</span><span>{record.label}</span><time>{new Date(record.startedAt).toLocaleTimeString('zh-CN')}</time></summary>
            <p className="zt-hint">{record.target.label} · 退出码 {record.exitCode ?? '未知'} · {record.completion ?? '未核验'}{record.truncated ? ' · 记录已截断' : ''}</p><pre>{record.error || record.output || '（无输出）'}</pre></details>)}</div>}
      </main>
      {!listHidden && <><div className="zt-list-handle" role="separator" aria-label="调整机器列表宽度" aria-orientation="vertical" onMouseDown={resizeList} />
        <aside className="zt-hosts" style={{ width: listWidth }}><div className="zt-list-header"><strong>主机与资产</strong><div className="zt-list-header-actions"><button aria-label="刷新机器列表" title="刷新机器列表" onClick={() => void loadCatalog().catch((e) => fail(e.message))}>↻</button><button title="收起机器列表" aria-expanded={true} onClick={() => setListHidden(true)}>收起列表</button></div></div>
          <div className="zt-source-tabs"><button className={source === 'ssh' ? 'active' : ''} onClick={() => { setSource('ssh'); setOffset(0); setQuery('') }}>远程主机</button><button className={source === 'jumpserver' ? 'active' : ''} onClick={() => { setSource('jumpserver'); setOffset(0); setQuery('') }}>JumpServer</button></div>
          <input className="zt-list-search" aria-label="搜索主机或资产" placeholder="搜索名称或地址" value={query} onChange={(e) => { setQuery(e.target.value); setOffset(0) }} />
          {source === 'ssh' ? <><div className="zt-list-actions"><button onClick={() => setHostEditor(null)}>＋ 主机</button><button onClick={() => setFolderEditor(null)}>＋ 文件夹</button>
            <button onClick={() => void rpc(ctx, 'hosts/export').then((text) => download(`zterm-${timestamp()}-ssh-config`, text)).catch((e) => fail(e.message))}>导出</button></div>
            <div className="zt-host-browser"><TreePane key="folders" label="调整主机文件夹高度" storageKey="dsh-zterm.folder-tree-height"><FolderTree folders={catalog?.folders ?? []} selected={folder} onSelect={(id) => { setFolder(id); setOffset(0) }} onEdit={setFolderEditor}
              onDelete={(target) => setConfirm({ text: `删除文件夹「${target.label}」？文件夹必须为空。`, act: () => { void rpc(ctx, 'folder/delete', { id: target.id, revision: catalog?.revision }).then(() => { if (folder === target.id) setFolder(''); return loadCatalog() }).catch((e) => fail(e.message)); setConfirm(undefined) } })} /></TreePane>
            <div className="zt-host-list">{catalog?.hosts.map((host: HostTarget) => <div className="zt-host-row" key={host.id}><button className="zt-host-connect" disabled={actionBusy} onClick={() => void connect({ targetId: host.id })} title={`连接 ${host.username}@${host.host}:${host.port}`}><span className="zt-host-glyph">▤</span><span><strong>{host.label}</strong><small>{host.username}@{host.host}</small></span></button>
              <button title="编辑主机" onClick={() => setHostEditor(host)}>⋯</button><button title="移除主机配置" onClick={() => setConfirm({ text: `移除「${host.label}」的配置？已有终端连接保持原目标。`, act: () => { void rpc(ctx, 'host/delete', { id: host.id, revision: catalog.revision }).then(() => loadCatalog()).catch((e) => fail(e.message)); setConfirm(undefined) } })}>×</button></div>)}
              {!catalog?.hosts.length && <p className="zt-list-empty">{query ? '没有匹配的主机' : '添加主机后从这里连接'}</p>}</div></div>
            <div className="zt-pagination"><span>{catalog?.total ?? 0} 台{catalog?.total ? ` · 当前 ${offset + 1}–${Math.min(offset + 200, catalog.total)}` : ''}</span><button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 200))}>‹</button><button disabled={offset + 200 >= (catalog?.total ?? 0)} onClick={() => setOffset(offset + 200)}>›</button></div>
          </> : <><div className="zt-list-actions"><button onClick={() => setJumpEditor(null)}>＋ 实例</button>{profile && <button onClick={() => setJumpEditor(profile)}>编辑</button>}{profile && <button onClick={() => setConfirm({ text: `移除「${profile.label}」的配置？`, act: () => { void rpc(ctx, 'jump/delete', { id: instanceId, revision: catalog.revision }).then(() => { setInstanceId(''); void loadCatalog() }).catch((e) => fail(e.message)); setConfirm(undefined) } })}>移除</button>}</div>
            <select aria-label="JumpServer 实例" value={instanceId} onChange={(e) => { setInstanceId(e.target.value); setNodeId(''); setOffset(0) }}><option value="">选择实例</option>{catalog?.jumpservers.map((p: any) => <option key={p.id} value={p.id}>{p.label}</option>)}</select>
            <div className="zt-host-browser">{instanceId && <TreePane key="jumpserver" label="调整 JumpServer 资产节点高度" storageKey="dsh-zterm.jump-tree-height"><JumpTree key={instanceId} ctx={ctx} instanceId={instanceId} nodes={nodes} selected={nodeId} onSelect={(id) => { setNodeId(id); setOffset(0) }} onError={fail} /></TreePane>}
            <div className="zt-host-list">{assets?.assets?.map((item: any) => <button className="zt-asset-row" key={item.assetId} onClick={() => void chooseAsset(item)}><strong>{item.name}</strong><small>{item.address} · {item.platform}</small></button>)}
              {!instanceId && <p className="zt-list-empty">先添加 JumpServer 实例</p>}</div></div>
            <div className="zt-pagination"><span>{assets?.total ?? 0} 台</span><button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 100))}>‹</button><button disabled={!assets?.hasMore} onClick={() => setOffset(offset + 100)}>›</button></div>
          </>}
        </aside></>}
    </div>
    {hostEditor !== false && <HostEditor ctx={ctx} host={hostEditor ?? undefined} folders={catalog?.folders ?? []} credentials={catalog?.credentials ?? []} defaultCredentialId={catalog?.defaultCredentialId} revision={catalog?.revision} onClose={() => setHostEditor(false)} onSaved={() => void loadCatalog()} />}
    {jumpEditor !== false && <JumpEditor ctx={ctx} profile={jumpEditor ?? undefined} revision={catalog?.revision} onClose={() => setJumpEditor(false)} onSaved={() => void loadCatalog()} />}
    {folderEditor !== false && <FolderEditor ctx={ctx} folder={folderEditor ?? undefined} folders={catalog?.folders ?? []} revision={catalog?.revision} onClose={() => setFolderEditor(false)} onSaved={() => void loadCatalog()} />}
    {accounts && <Modal title={`选择账号 · ${asset?.name ?? ''}`} onClose={() => setAccounts(undefined)}><div className="zt-account-list">{accounts.map((account: any) => <button key={account.accountId} disabled={!account.canConnect || actionBusy} onClick={() => { void connect({ kind: 'jumpserver', instanceId, assetId: asset.assetId, accountId: account.accountId, label: asset.name, accountName: account.name || account.username }); setAccounts(undefined) }}><strong>{account.name}</strong><span>{account.username}{!account.canConnect ? ' · 无连接权限' : ''}</span></button>)}{!accounts.length && <p>没有可用账号</p>}</div></Modal>}
    {visible && trustTerminal?.trust && <Modal title={trustTerminal.trust.kind === 'changed' ? 'SSH 主机指纹已变更' : '核实 SSH 主机身份'} onClose={() => { void action('disconnect', trustParameters) }}>
      <div className="zt-trust"><p>{trustTerminal.target.label} · {trustTerminal.trust.username}@{trustTerminal.trust.host}:{trustTerminal.trust.port}</p><pre>{trustTerminal.trust.algorithm}{'\n'}{trustTerminal.trust.fingerprint}</pre>{trustTerminal.trust.trustedFingerprint && <p>原指纹：{trustTerminal.trust.trustedFingerprint}</p>}
        <p className="zt-hint">通过独立可信渠道核实指纹后再继续。</p><footer>{trustTerminal.trust.kind === 'changed' ? <><button onClick={() => void action('disconnect', trustParameters)}>取消连接</button><button onClick={() => { void action('trust/reset', trustParameters) }}>已核实变更，清除旧记录</button></> : <><button onClick={() => void action('trust', { ...trustParameters, requestId: trustTerminal.trust!.requestId, decision: 'reject' })}>拒绝</button>
          <button onClick={() => void action('trust', { ...trustParameters, requestId: trustTerminal.trust!.requestId, decision: 'trust-once' })}>仅信任此次连接</button><button className="zt-primary" onClick={() => void action('trust', { ...trustParameters, requestId: trustTerminal.trust!.requestId, decision: 'trust-always' })}>信任并保存</button></>}</footer></div>
    </Modal>}
    {confirm && <Modal title="确认操作" onClose={() => setConfirm(undefined)}><p>{confirm.text}</p><footer><button onClick={() => setConfirm(undefined)}>取消</button><button className="zt-primary" onClick={confirm.act}>确认</button></footer></Modal>}
  </div>
}
