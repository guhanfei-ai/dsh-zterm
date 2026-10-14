import React, { useState, useRef, useEffect } from 'react'
import type { HostTarget, JumpProfile, HostFolder, ClientContext, SavedCredential } from '../shared/types'
import { CREDENTIAL_LABELS } from '../shared/credentialLabels'
import { rpc } from './api'
import { folderRows } from './folders'

export function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  const root = useRef<HTMLElement>(null), close = useRef(onClose); close.current = onClose
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null, dialog = root.current
    ;(dialog?.querySelector('input,select,textarea') as HTMLElement | null ?? dialog?.querySelector('button') ?? dialog)?.focus()
    const key = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close.current(); return }
      if (event.key !== 'Tab') return
      const items = [...(dialog?.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]') ?? [])].filter((item) => item.offsetParent !== null)
      const first = items[0], last = items.at(-1)
      if (!first) { event.preventDefault(); dialog?.focus() }
      else if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) { event.preventDefault(); last?.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }
    dialog?.addEventListener('keydown', key)
    return () => { dialog?.removeEventListener('keydown', key); if (previous?.isConnected) previous.focus() }
  }, [])
  return <div className="zt-modal-shade" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
    <section ref={root} tabIndex={-1} className="zt-modal" role="dialog" aria-modal="true" aria-label={title}><header><strong>{title}</strong><button aria-label="关闭对话框" onClick={onClose}>×</button></header>{children}</section>
  </div>
}
function Field({ title, children }: { title: string; children: React.ReactNode }) { return <label className="zt-field"><span>{title}</span>{children}</label> }
export function HostEditor({ ctx, host, folders, credentials = [], defaultCredentialId, revision, onClose, onSaved }: {
  ctx: ClientContext; host?: HostTarget; folders: HostFolder[]; credentials?: SavedCredential[]; defaultCredentialId?: string; revision?: number; onClose: () => void; onSaved: () => void
}) {
  const [form, setForm] = useState({ label: host?.label ?? '', host: host?.host ?? '', port: String(host?.port ?? 22), username: host?.username ?? '', authType: host?.authType ?? 'key-file', privateKeyPath: host?.privateKeyPath ?? '', folderId: host?.folderId ?? '' })
  const [secret, setSecret] = useState(''), [phrase, setPhrase] = useState(''), [clearPhrase, setClearPhrase] = useState(false), [error, setError] = useState(''), [busy, setBusy] = useState(false)
  const [authChoice, setAuthChoice] = useState(host?.credentialId || (!host && credentials.length) ? 'saved' : host?.authType ?? 'key-file')
  const [credentialId, setCredentialId] = useState(host?.credentialId || defaultCredentialId || credentials[0]?.id || '')
  const retainsSecret = host && !host.credentialId && host.authType === authChoice
  const patch = (key: string, value: string) => setForm((previous) => ({ ...previous, [key]: value }))
  return <Modal title={host ? '编辑远程主机' : '添加远程主机'} onClose={onClose}><form onSubmit={(e) => {
    e.preventDefault(); setBusy(true); setError('')
    void rpc(ctx, 'host/save', { host: { ...host, ...form, credentialId: authChoice === 'saved' ? credentialId : undefined, folderId: form.folderId || undefined, port: Number(form.port), kind: 'ssh' }, secret: authChoice === 'saved' ? '' : secret, passphrase: authChoice === 'saved' ? '' : phrase, clearPassphrase: clearPhrase, revision })
      .then(() => { setSecret(''); setPhrase(''); onSaved(); onClose() }).catch((e) => setError(e.message)).finally(() => setBusy(false))
  }}>
    <Field title="名称"><input required value={form.label} onChange={(e) => patch('label', e.target.value)} /></Field>
    <div className="zt-form-row"><Field title="主机地址"><input required value={form.host} placeholder="主机名或 IP" onChange={(e) => patch('host', e.target.value)} /></Field>
      <Field title="端口"><input type="number" required min="1" max="65535" value={form.port} onChange={(e) => patch('port', e.target.value)} /></Field></div>
    <Field title="登录账号"><input required value={form.username} onChange={(e) => patch('username', e.target.value)} /></Field>
    <Field title="文件夹"><select value={form.folderId} onChange={(e) => patch('folderId', e.target.value)}><option value="">根目录</option>{folderRows(folders).map((f) => <option key={f.id} value={f.id}>{'　'.repeat(Math.min(8, f.depth))}{f.label}</option>)}</select></Field>
    <Field title="认证方式"><select value={authChoice} onChange={(e) => { setAuthChoice(e.target.value); if (e.target.value !== 'saved') patch('authType', e.target.value); setSecret(''); setPhrase(''); setClearPhrase(false) }}><option value="saved">选择已保存凭证</option><option value="password">密码</option><option value="key">私钥内容</option><option value="key-file">私钥文件</option></select></Field>
    {authChoice === 'saved' && <><Field title="登录凭证"><select required value={credentialId} onChange={(e) => setCredentialId(e.target.value)}><option value="">请选择凭证</option>{credentials.map((c) => <option key={c.id} value={c.id}>{c.label} · {CREDENTIAL_LABELS[c.authType]}</option>)}</select></Field>
      <p className="zt-hint">凭证在「设置 → zTerm → 管理凭证」中保存，此处无需再填内容或路径。</p></>}
    {['password', 'key'].includes(authChoice) && <Field title={form.authType === 'key' ? '私钥内容' : '密码'}>{form.authType === 'key'
      ? <textarea rows={5} value={secret} placeholder={retainsSecret ? '留空保留现有私钥' : '粘贴私钥内容'} onChange={(e) => setSecret(e.target.value)} spellCheck={false} required={!retainsSecret} />
      : <input type="password" value={secret} autoComplete="new-password" placeholder={retainsSecret ? '留空保留现有密码' : '输入密码'} onChange={(e) => setSecret(e.target.value)} required={!retainsSecret} />}</Field>}
    {authChoice === 'key-file' && <><Field title="私钥文件路径"><input value={form.privateKeyPath} placeholder="留空使用默认 SSH 私钥文件" onChange={(e) => patch('privateKeyPath', e.target.value)} /></Field>
      <p className="zt-hint">填写 DSH 宿主上的绝对路径或 ~/ 路径。DSH 部署在远端时，填写远端的文件路径。</p></>}
    {['key', 'key-file'].includes(authChoice) && <><Field title="私钥口令（可选）"><input type="password" disabled={clearPhrase} value={phrase} placeholder="留空保留现有口令" onChange={(e) => setPhrase(e.target.value)} /></Field>{host?.passphraseRef && <label className="zt-check"><input type="checkbox" checked={clearPhrase} onChange={(e) => setClearPhrase(e.target.checked)} />移除此主机的私钥口令引用</label>}</>}
    <p className="zt-hint">密码、私钥内容和口令保存在 DSH 凭据库；私钥文件由宿主读取。所有新连接默认读模式。</p>{error && <p className="zt-error" role="alert">{error}</p>}
    <footer><button type="button" onClick={onClose}>取消</button><button className="zt-primary" disabled={busy}>{busy ? '保存中…' : '保存主机'}</button></footer>
  </form></Modal>
}
export function JumpEditor({ ctx, profile, revision, onClose, onSaved }: { ctx: ClientContext; profile?: JumpProfile; revision?: number; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({ label: profile?.label ?? '', baseUrl: profile?.baseUrl ?? '', authMode: profile?.authMode ?? 'access_key', username: profile?.username ?? '', verifyTls: profile?.verifyTls ?? true })
  const [secret, setSecret] = useState(''), [keyId, setKeyId] = useState(''), [error, setError] = useState(''), [busy, setBusy] = useState(false)
  return <Modal title={profile ? '编辑 JumpServer' : '添加 JumpServer'} onClose={onClose}><form onSubmit={(e) => { e.preventDefault(); setBusy(true); setError('')
    void rpc(ctx, 'jump/save', { profile: { ...profile, ...form }, secret, accessKeyId: keyId, revision }).then(() => { setSecret(''); setKeyId(''); onSaved(); onClose() }).catch((e) => setError(e.message)).finally(() => setBusy(false))
  }}>
    <Field title="名称"><input required value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} /></Field>
    <Field title="服务地址"><input required type="url" value={form.baseUrl} placeholder="https://jump.example.com" onChange={(e) => setForm({ ...form, baseUrl: e.target.value })} /></Field>
    <Field title="认证方式"><select value={form.authMode} onChange={(e) => setForm({ ...form, authMode: e.target.value as any })}><option value="access_key">Access Key</option><option value="token">Token</option><option value="password">账号密码</option></select></Field>
    {form.authMode === 'access_key' && <Field title="Access Key ID"><input type="password" value={keyId} placeholder={profile ? '留空保留现有值' : ''} onChange={(e) => setKeyId(e.target.value)} /></Field>}
    {form.authMode === 'password' && <Field title="账号"><input required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></Field>}
    <Field title={form.authMode === 'access_key' ? 'Access Key Secret' : form.authMode === 'token' ? 'Token' : '密码'}><input type="password" value={secret} placeholder={profile ? '留空保留现有值' : ''} onChange={(e) => setSecret(e.target.value)} /></Field>
    <label className="zt-check"><input type="checkbox" checked={form.verifyTls} onChange={(e) => setForm({ ...form, verifyTls: e.target.checked })} />验证 TLS 证书</label>
    <p className="zt-hint">连接使用资产与账号的稳定 ID，令牌仅在宿主内部处理。</p>{error && <p className="zt-error" role="alert">{error}</p>}
    <footer><button type="button" onClick={onClose}>取消</button><button className="zt-primary" disabled={busy}>{busy ? '保存中…' : '保存实例'}</button></footer>
  </form></Modal>
}
export function FolderEditor({ ctx, folder, folders, revision, onClose, onSaved }: { ctx: ClientContext; folder?: HostFolder; folders: HostFolder[]; revision?: number; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(folder?.label ?? ''), [parentId, setParentId] = useState(folder?.parentId ?? ''), [error, setError] = useState(''), [busy, setBusy] = useState(false)
  const excluded = new Set<string>(); if (folder) { excluded.add(folder.id); for (const row of folderRows(folders)) if (row.parentId && excluded.has(row.parentId)) excluded.add(row.id) }
  return <Modal title={folder ? '编辑主机文件夹' : '新建主机文件夹'} onClose={onClose}><form onSubmit={(e) => { e.preventDefault(); setBusy(true); void rpc(ctx, 'folder/save', { folder: { id: folder?.id, label: name, parentId: parentId || undefined }, revision })
    .then(() => { onSaved(); onClose() }).catch((e) => setError(e.message)).finally(() => setBusy(false)) }}>
    <Field title="名称"><input required value={name} onChange={(e) => setName(e.target.value)} /></Field>
    <Field title="父文件夹"><select value={parentId} onChange={(e) => setParentId(e.target.value)}><option value="">根目录</option>{folderRows(folders).filter((f) => !excluded.has(f.id)).map((f) => <option value={f.id} key={f.id}>{'　'.repeat(Math.min(8, f.depth))}{f.label}</option>)}</select></Field>
    {error && <p className="zt-error" role="alert">{error}</p>}<footer><button type="button" onClick={onClose}>取消</button><button disabled={busy} className="zt-primary">{busy ? '保存中…' : folder ? '保存' : '创建'}</button></footer>
  </form></Modal>
}
