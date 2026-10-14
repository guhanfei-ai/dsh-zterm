import React, { useState, useEffect } from 'react'
import type { ClientContext } from '../shared/types'
import { rpc } from './api'
import { PRODUCT_NAME } from '../shared/branding'
import { useTerminalFontSize, setTerminalFontSize, DEFAULT_TERMINAL_FONT_SIZE, MIN_TERMINAL_FONT_SIZE, MAX_TERMINAL_FONT_SIZE } from './preferences'
export function SettingsPanel({ ctx }: { ctx: ClientContext }) {
  const [config, setConfig] = useState<any>(), [error, setError] = useState(''), [saving, setSaving] = useState(false), [message, setMessage] = useState('')
  const fontSize = useTerminalFontSize(), [fontDraft, setFontDraft] = useState(String(fontSize))
  useEffect(() => setFontDraft(String(fontSize)), [fontSize])
  useEffect(() => { let alive = true; void rpc(ctx, 'catalog').then((value) => { if (alive) setConfig(value) }).catch((e) => { if (alive) setError(e.message) }); return () => { alive = false } }, [ctx])
  const patch = (key: string, value: unknown) => setConfig({ ...config, [key]: value })
  return <section className="zt-settings"><h2>{PRODUCT_NAME}</h2><p>在 DSH 对话右侧连接真实机器。默认读模式，由人类在已绑定终端的工具栏开启读写。</p>
    <div className="zt-settings-card"><strong>终端外观</strong>
      <label className="zt-field"><span>终端字体大小（px）</span><input type="number" min={MIN_TERMINAL_FONT_SIZE} max={MAX_TERMINAL_FONT_SIZE} step={1} value={fontDraft}
        onChange={(e) => { setFontDraft(e.target.value); setTerminalFontSize(Number(e.target.value)) }} onBlur={() => setFontDraft(String(fontSize))} /></label>
      <p className="zt-hint">默认 {DEFAULT_TERMINAL_FONT_SIZE}px，可调 {MIN_TERMINAL_FONT_SIZE}–{MAX_TERMINAL_FONT_SIZE}px。修改立即应用到已打开的终端，保存在当前浏览器。</p>
    </div>
    {error && <p className="zt-error" role="alert">{error}</p>}{message && <p className="zt-success" role="status">{message}</p>}
    {!config ? <p className="zt-hint">正在读取配置…</p> : <form onSubmit={(event) => { event.preventDefault(); setSaving(true); setError(''); setMessage('')
      const keys = ['allowLocalTerminal', 'defaultSshUsername', 'defaultPrivateKeyPath', 'defaultPanelWidth', 'maxSessions', 'maxWriteCalls', 'commandTimeoutMs']
      void rpc(ctx, 'config', { patch: Object.fromEntries(keys.map((k) => [k, config[k]])), revision: config.revision })
        .then(() => rpc(ctx, 'catalog')).then((value) => { setConfig(value); setMessage('配置已保存，下一次操作生效。') }).catch((e) => setError(e.message)).finally(() => setSaving(false))
    }}>
      <div className="zt-settings-card"><strong>连接能力</strong>
        <label className="zt-check"><input type="checkbox" checked={config.allowLocalTerminal} onChange={(e) => patch('allowLocalTerminal', e.target.checked)} />允许 DSH 宿主本地终端</label><p className="zt-hint">本地终端运行在 DSH 宿主机器。浏览器所在的电脑可能是另一台。</p>
        <p>对话中指定目标后，先查远程主机，再查 JumpServer 授权；都没有时，自动新增远程主机并使用默认 SSH 私钥连接。</p>
        <label className="zt-field"><span>新主机默认登录账号</span><input value={config.defaultSshUsername ?? ''} placeholder="留空使用 DSH 宿主当前用户" onChange={(e) => patch('defaultSshUsername', e.target.value)} /></label>
        <p className="zt-hint">对话中明确给出登录账号时，优先使用该账号。</p>
        <label className="zt-field"><span>默认 SSH 私钥文件</span><input value={config.defaultPrivateKeyPath ?? ''} placeholder="自动查找 ~/.ssh 下的默认私钥" onChange={(e) => patch('defaultPrivateKeyPath', e.target.value)} /></label>
        <p className="zt-hint">留空依次查找 ~/.ssh/id_ed25519、id_rsa、id_ecdsa。私钥文件位于 DSH 宿主，内容不会发送给 AI。</p>
      </div>
      <div className="zt-settings-card"><strong>执行与布局</strong>{[
        ['defaultPanelWidth', '独立面板默认宽度（百分比）', 30, 80], ['maxSessions', '每会话终端上限', 1, 32],
        ['maxWriteCalls', '每次读写授权的命令上限', 1, 1000], ['commandTimeoutMs', '单次命令超时（毫秒）', 1000, 120000],
      ].map(([key, title, min, max]) => <label className="zt-field" key={key}><span>{title}</span><input type="number" min={min} max={max} required value={config[key]} onChange={(e) => patch(String(key), Number(e.target.value))} /></label>)}
      </div>
      <div className="zt-settings-card"><strong>主机与凭据</strong><p>主机、文件夹、JumpServer 实例和账号从会话中的「{PRODUCT_NAME}」入口管理。密码、私钥内容和口令写入 DSH 凭据库；私钥文件直接从宿主读取，工具结果不包含凭据值。</p><p className="zt-hint">已配置 {config.total} 台主机、{config.jumpservers.length} 个 JumpServer 实例。</p></div>
      <button className="zt-primary" disabled={saving}>{saving ? '保存中…' : '保存设置'}</button>
    </form>}
  </section>
}
