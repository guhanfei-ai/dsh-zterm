import React, { useState, useEffect, useRef, useCallback } from 'react'
import type { ClientContext } from '../shared/types'
import { rpc } from './api'
import { PRODUCT_NAME } from '../shared/branding'
import { CredentialManager } from './credential-manager'
import { CREDENTIAL_LABELS } from '../shared/credentialLabels'
const CONFIG_KEYS = ['allowLocalTerminal', 'defaultSshUsername', 'defaultPrivateKeyPath', 'defaultCredentialId', 'defaultPanelWidth', 'maxSessions', 'maxWriteCalls', 'commandTimeoutMs']
import { useTerminalFontSize, setTerminalFontSize, DEFAULT_TERMINAL_FONT_SIZE, MIN_TERMINAL_FONT_SIZE, MAX_TERMINAL_FONT_SIZE } from './preferences'
export function SettingsPanel({ ctx }: { ctx: ClientContext }) {
  const [config, setConfig] = useState<any>(), [error, setError] = useState(''), [saving, setSaving] = useState(false), [message, setMessage] = useState('')
  const fontSize = useTerminalFontSize(), [fontDraft, setFontDraft] = useState(String(fontSize))
  const baseline = useRef<any>(), alive = useRef(true)
  const loadConfig = useCallback(async () => {
    const value = await rpc(ctx, 'catalog'); if (!alive.current) return
    const previousBaseline = baseline.current; baseline.current = value
    // 新增凭证只刷新列表和修订号，保留尚未保存的其它设置。
    setConfig((previous: any) => ({ ...value, ...Object.fromEntries(CONFIG_KEYS.filter((k) => previousBaseline && previous?.[k] !== previousBaseline[k]).map((k) => [k, previous[k]])) }))
  }, [ctx])
  useEffect(() => setFontDraft(String(fontSize)), [fontSize])
  useEffect(() => { alive.current = true; void loadConfig().catch((e) => { if (alive.current) setError(e.message) }); return () => { alive.current = false } }, [loadConfig])
  const patch = (key: string, value: unknown) => { setConfig({ ...config, [key]: value }); setMessage('') }
  return <section className="zt-settings"><h2>{PRODUCT_NAME}</h2><p>在 DSH 对话右侧连接真实机器。默认读模式，由人类在已绑定终端的工具栏开启读写。</p>
    <div className="zt-settings-card"><strong>终端外观</strong>
      <label className="zt-field"><span>终端字体大小（px）</span><input type="number" min={MIN_TERMINAL_FONT_SIZE} max={MAX_TERMINAL_FONT_SIZE} step={1} value={fontDraft}
        onChange={(e) => { setFontDraft(e.target.value); setTerminalFontSize(Number(e.target.value)) }} onBlur={() => setFontDraft(String(fontSize))} /></label>
      <p className="zt-hint">默认 {DEFAULT_TERMINAL_FONT_SIZE}px，可调 {MIN_TERMINAL_FONT_SIZE}–{MAX_TERMINAL_FONT_SIZE}px。修改立即应用到已打开的终端，保存在当前浏览器。</p>
    </div>
    {error && <p className="zt-error" role="alert">{error}</p>}{message && <p className="zt-success" role="status">{message}</p>}
    {!config ? <p className="zt-hint">正在读取配置…</p> : <><form onSubmit={(event) => { event.preventDefault(); setSaving(true); setError(''); setMessage('')
      void rpc(ctx, 'config', { patch: Object.fromEntries(CONFIG_KEYS.map((k) => [k, config[k]])), revision: config.revision })
        .then(() => rpc(ctx, 'catalog')).then((value) => { baseline.current = value; setConfig(value); setMessage(value.allowLocalTerminal ? `配置已保存。本地终端已启用：打开 ${PRODUCT_NAME}，点击「打开本机终端」。` : '配置已保存，本地终端未启用。') }).catch((e) => setError(e.message)).finally(() => setSaving(false))
    }}>
      <div className="zt-settings-card"><strong>本地终端</strong>
        <label className="zt-check"><input type="checkbox" checked={config.allowLocalTerminal} onChange={(e) => patch('allowLocalTerminal', e.target.checked)} />允许打开运行 DSH 的机器上的终端</label>
        <p className="zt-hint">DSH 在你的电脑上运行，就打开这台电脑的终端；DSH 在服务器上运行，就打开服务器的终端。</p>
        <p className="zt-hint">勾选后点击下方的「保存设置」才会生效。然后从聊天顶部打开「{PRODUCT_NAME}」，点击面板右上方的「打开本机终端」。每次点击都会新开一个终端标签。</p>
      </div>
      <div className="zt-settings-card"><strong>通过对话连接远程机器</strong>
        <p>告诉 AI 要连接的主机名或 IP，例如「连接 192.0.2.21」。AI 会按以下顺序查找：</p>
        <ol className="zt-hint"><li>先找主机列表里已保存的机器。</li><li>没找到，再查 JumpServer（堡垒机）里你有权限访问的机器。</li><li>都没找到，就保存为新主机，并尝试用下方的账号和 SSH 私钥连接。</li></ol>
        <label className="zt-field"><span>新主机默认登录账号</span><input value={config.defaultSshUsername ?? ''} placeholder="留空使用运行 DSH 的账号" onChange={(e) => patch('defaultSshUsername', e.target.value)} /></label>
        <p className="zt-hint">对话里指定了登录账号时，优先使用你指定的账号。</p>
        <label className="zt-field"><span>默认 SSH 凭证</span><select value={config.defaultCredentialId ?? ''} onChange={(e) => patch('defaultCredentialId', e.target.value)}><option value="">自动查找宿主默认私钥文件</option>
          {(config.credentials ?? []).filter((c: any) => c.authType !== 'password').map((c: any) => <option key={c.id} value={c.id}>{c.label} · {CREDENTIAL_LABELS[c.authType as keyof typeof CREDENTIAL_LABELS]}</option>)}</select></label>
        <p className="zt-hint">在下方「管理凭证」保存私钥后，按名称选择默认凭证。私钥内容不会发送给 AI。</p>
        {!config.defaultCredentialId && <details><summary>指定已有的宿主私钥文件（可选）</summary><label className="zt-field"><span>默认 SSH 私钥文件</span><input value={config.defaultPrivateKeyPath ?? ''} placeholder="留空自动查找 ~/.ssh 下的默认私钥" onChange={(e) => patch('defaultPrivateKeyPath', e.target.value)} /></label>
          <p className="zt-hint">使用运行 DSH 的机器上的路径；远端部署时使用远端路径。</p></details>}
      </div>
      <div className="zt-settings-card"><strong>执行与布局</strong>{[
        ['defaultPanelWidth', '独立面板默认宽度（百分比）', 30, 80], ['maxSessions', '每会话终端上限', 1, 32],
        ['maxWriteCalls', '每次读写授权的命令上限', 1, 1000], ['commandTimeoutMs', '单次命令超时（毫秒）', 1000, 120000],
      ].map(([key, title, min, max]) => <label className="zt-field" key={key}><span>{title}</span><input type="number" min={min} max={max} required value={config[key]} onChange={(e) => patch(String(key), Number(e.target.value))} /></label>)}
      </div>
      <div className="zt-settings-card"><strong>主机与凭据</strong><p>主机、文件夹、JumpServer 实例和账号从会话中的「{PRODUCT_NAME}」入口管理。密码、私钥内容和口令写入 DSH 凭据库；私钥文件直接从宿主读取，工具结果不包含凭据值。</p><p className="zt-hint">已配置 {config.total} 台主机、{config.jumpservers.length} 个 JumpServer 实例。</p></div>
      <button className="zt-primary" disabled={saving}>{saving ? '保存中…' : '保存设置'}</button>
    </form><CredentialManager ctx={ctx} credentials={config.credentials ?? []} revision={config.revision} onSaved={loadConfig} /></>}
  </section>
}
