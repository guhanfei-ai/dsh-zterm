import React, { useEffect, useRef, useState } from 'react'
import type { ClientContext, SavedCredential } from '../shared/types'
import { CREDENTIAL_LABELS } from '../shared/credentialLabels'
import { rpc } from './api'

export function CredentialManager({ ctx, credentials, revision, onSaved }: {
  ctx: ClientContext; credentials: SavedCredential[]; revision?: number; onSaved: () => Promise<void>
}) {
  const [editing, setEditing] = useState<SavedCredential>(), [name, setName] = useState(''), [type, setType] = useState<SavedCredential['authType']>('key')
  const [content, setContent] = useState(''), [phrase, setPhrase] = useState(''), [clearPhrase, setClearPhrase] = useState(false)
  const [busy, setBusy] = useState(false), [readingFile, setReadingFile] = useState(false), [error, setError] = useState(''), [message, setMessage] = useState('')
  const fileRead = useRef(0)
  useEffect(() => () => { fileRead.current++ }, [])
  const reset = (credential?: SavedCredential) => {
    fileRead.current++; setReadingFile(false); setEditing(credential); setName(credential?.label ?? ''); setType(credential?.authType ?? 'key')
    setContent(credential?.privateKeyPath ?? ''); setPhrase(''); setClearPhrase(false); setError(''); setMessage('')
  }
  return <section className="zt-settings-card zt-credential-manager" aria-label="管理凭证"><div className="zt-credential-header"><strong>管理凭证</strong>
    <button type="button" disabled={busy} onClick={() => { void onSaved().then(() => setError('')).catch((e) => setError(e.message)) }}>刷新凭证列表</button></div>
    <p className="zt-hint">保存一次，主机按名称选用。</p>
    <div className="zt-credential-list" role="list" aria-label="凭证列表">{credentials.length ? credentials.map((credential) => <div className="zt-credential-row" role="listitem" key={credential.id}>
      <span><b>{credential.label}</b><small>{CREDENTIAL_LABELS[credential.authType]}</small></span>
      <button type="button" disabled={busy} aria-label={`编辑凭证 ${credential.label}`} onClick={() => reset(credential)}>编辑</button>
    </div>) : <p className="zt-hint">暂无凭证，在下方新增。</p>}</div>
    <form onSubmit={(event) => { event.preventDefault(); if (busy || readingFile) return; setBusy(true); setError(''); setMessage(''); fileRead.current++
      void rpc(ctx, 'credential/save', { credential: { id: editing?.id, label: name, authType: type }, content, passphrase: phrase, clearPassphrase: clearPhrase, revision })
        .then(async () => { reset(); await onSaved(); setMessage('凭证已保存，可在主机中按名称选择。') }).catch((e) => setError(e.message)).finally(() => setBusy(false))
    }}><fieldset disabled={busy} className="zt-credential-fields"><h3>{editing ? '编辑凭证' : '新增凭证'}</h3>
      <div className="zt-credential-meta"><label className="zt-field"><span>凭证名称</span><input required maxLength={200} value={name} placeholder="例如：运维私钥" onChange={(e) => setName(e.target.value)} /></label>
      <label className="zt-field"><span>凭证类型</span><select value={type} onChange={(e) => { fileRead.current++; setReadingFile(false); setType(e.target.value as SavedCredential['authType']); setContent(''); setPhrase(''); setClearPhrase(false); setError('') }}>
        {Object.entries(CREDENTIAL_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label></div>
      <label className="zt-field"><span>凭证内容</span>{type === 'key' ? <textarea rows={3} value={content} spellCheck={false} autoComplete="off" required={!editing || editing.authType !== type}
        placeholder={editing?.authType === type ? '留空保留现有私钥；也可选择文件导入' : '粘贴私钥内容，或在下方选择私钥文件'} onChange={(e) => { fileRead.current++; setReadingFile(false); setContent(e.target.value) }} />
        : <input type={type === 'password' ? 'password' : 'text'} value={content} autoComplete="new-password" required={type === 'key-file' || !editing || editing.authType !== type}
          placeholder={type === 'key-file' ? '宿主文件路径，例如 ~/.ssh/id_ed25519' : editing?.authType === type ? '留空保留现有密码' : '输入密码'} onChange={(e) => setContent(e.target.value)} />}</label>
      {type === 'key' && <label className="zt-field"><span>选择私钥文件</span><input type="file" aria-label="选择私钥文件" disabled={busy} onChange={(e) => {
        const file = e.target.files?.[0], request = ++fileRead.current; e.target.value = ''; setReadingFile(false); if (!file) return
        if (file.size > 100000) { setError('私钥文件不能超过 100 KB'); return }
        setReadingFile(true)
        void file.text().then((value) => { if (fileRead.current !== request) return; setContent(value); setName((previous) => previous || file.name.slice(0, 200)); setError('') }).catch(() => { if (fileRead.current === request) setError('读取私钥文件失败，请重新选择') }).finally(() => { if (fileRead.current === request) setReadingFile(false) })
      }} /><small className="zt-hint">直接导入文件，无需填写路径。</small></label>}
      {type === 'key-file' && <p className="zt-hint">填写运行 DSH 的机器上的私钥路径，仅在这里填写一次。远端部署时使用远端路径。</p>}
      {type !== 'password' && <><label className="zt-field"><span>私钥口令（可选）</span><input type="password" autoComplete="new-password" disabled={clearPhrase} value={phrase} onChange={(e) => setPhrase(e.target.value)} placeholder={editing ? '留空保留现有口令' : '私钥有口令时填写'} /></label>
        {editing?.passphraseRef && <label className="zt-check"><input type="checkbox" checked={clearPhrase} onChange={(e) => setClearPhrase(e.target.checked)} />清除私钥口令</label>}</>}
      {error && <p role="alert" className="zt-error">{error}</p>}{message && <p role="status" className="zt-success">{message}</p>}
      <div className="zt-actions">{editing && <button type="button" disabled={busy} onClick={() => reset()}>取消编辑</button>}<button className="zt-primary" disabled={busy || readingFile}>{busy ? '保存中…' : readingFile ? '读取文件…' : '保存凭证'}</button></div>
    </fieldset></form>
  </section>
}
