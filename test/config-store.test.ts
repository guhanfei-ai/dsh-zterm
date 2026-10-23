import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { validateConfig, DEFAULT_CONFIG } from '../src/host/config'
import { RecordStore } from '../src/host/store'
import { mergeFrames } from '../src/client/api'
import type { Operation } from '../src/shared/types'
const dirs: string[] = []
afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })))
describe('配置与持久记录', () => {
  it('默认不启用本地或外部地址能力，默认命令预算为 100', () => {
    expect(validateConfig({})).toMatchObject({ allowLocalTerminal: false, allowExternalTargets: false, temporarilyDisabled: false, maxWriteCalls: 100 })
    expect(() => validateConfig({ temporarilyDisabled: 'yes' })).toThrow('开关')
  })
  it('拒绝循环目录、明文秘密、非插件凭据引用及畸形地址', () => {
    expect(() => validateConfig({ folders: [{ id: 'a', label: 'A', parentId: 'b' }, { id: 'b', label: 'B', parentId: 'a' }] })).toThrow('循环')
    const host = { id: 'h1', label: 'H', kind: 'ssh', host: 'host.example.invalid', username: 'operator', port: 22, authType: 'password', credentialRef: 'DSH_ZTERM_PASSWORD' }
    expect(() => validateConfig({ hosts: [{ ...host, password: 'not-for-model' }] })).toThrow('凭据')
    expect(() => validateConfig({ hosts: [{ ...host, credentialRef: 'OPENAI_API_KEY' }] })).toThrow('前缀')
    expect(() => validateConfig({ hosts: [{ ...host, host: 'https://example.invalid/path' }] })).toThrow('地址')
  })
  it('宿主私钥文件支持绝对路径和 ~/，旧 Agent 配置转为文件认证且保留主机', () => {
    const host = { id: 'h1', label: 'H', kind: 'ssh', host: 'host.example.invalid', username: 'operator', port: 22, authType: 'key-file', privateKeyPath: '/srv/dsh/.ssh/fixture_key' }
    expect(validateConfig({ hosts: [host] }).hosts[0]).toMatchObject({ authType: 'key-file', privateKeyPath: host.privateKeyPath })
    expect(validateConfig({ hosts: [{ ...host, authType: 'agent', privateKeyPath: undefined }] }).hosts[0]).toMatchObject({ id: 'h1', authType: 'key-file' })
    expect(() => validateConfig({ hosts: [{ ...host, privateKeyPath: 'relative/key' }] })).toThrow('绝对路径')
    expect(() => validateConfig({ defaultPrivateKeyPath: 'relative/key' })).toThrow('绝对路径')
  })
  it('重复记录按操作 ID 合并，宿主崩溃的 executing 恢复为 unknown', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-zterm-store-')); dirs.push(dir); const store = new RecordStore(dir)
    const record: Operation = { version: 1, id: 'r1', callId: 'c1', tool: 'zterm_execute', sessionId: 's1', terminalId: 't1', generation: 1, target: { source: 'ssh', assetId: 'h1', label: 'H' }, startedAt: new Date().toISOString(), status: 'executing', label: 'test', exitCode: null, output: '', truncated: false }
    store.append(record); expect(store.history('s1')[0].status).toBe('unknown')
    store.append({ ...record, status: 'completed', exitCode: 0, output: 'real output' }); expect(store.history('s1')).toHaveLength(1)
    expect(store.history('s1')[0].status).toBe('completed'); expect(store.history('s2')).toEqual([])
  })
  it('重连快照替换输出，重复帧不重复显示，旧代次不混入新终端', () => {
    const previous = new Map([['t', { generation: 1, text: 'old', seq: 2 }]])
    const next = mergeFrames(previous, { reset: false, output: [{ seq: 2, terminalId: 't', generation: 1, text: 'duplicate' }, { seq: 3, terminalId: 't', generation: 2, text: 'new' }], workspace: { terminals: [{ id: 't' }] } })
    expect(next.get('t')?.text).toBe('new')
    const reset = mergeFrames(next, { reset: true, cursor: 5, snapshots: [{ terminalId: 't', generation: 2, text: 'snapshot' }], workspace: { terminals: [{ id: 't' }] } })
    expect(reset.get('t')?.text).toBe('snapshot')
  })
  it('命名凭证配置拒绝明文内容、悬空引用和默认密码凭证', () => {
    const credential = { id: 'cred-1', label: 'Shared', authType: 'password', credentialRef: 'DSH_ZTERM_SHARED' }
    expect(() => validateConfig({ credentials: [{ ...credential, content: 'raw-secret' }] })).toThrow('秘密')
    expect(() => validateConfig({ credentials: [credential], defaultCredentialId: credential.id })).toThrow('私钥')
    expect(() => validateConfig({ hosts: [{ id: 'h', label: 'H', kind: 'ssh', host: '192.0.2.21', username: 'operator', authType: 'password', credentialId: 'missing' }] })).toThrow('不存在')
  })
})
