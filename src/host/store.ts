import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, appendFileSync, openSync, readSync, closeSync, statSync } from 'node:fs'
import { createHash, randomUUID } from 'node:crypto'
import { join } from 'node:path'
import type { HostTrustStore } from '../core/sshHostTrust'
import { createSshHostTrustCandidate, normalizeSshEndpoint, parseSshHostTrustRecords } from '../core/sshHostTrust'
import type { Operation, ConnectTarget } from '../shared/types'

/** 插件私有记录；授权不落盘，目录在确实需要写入时建立。 */
export class RecordStore implements HostTrustStore {
  constructor(readonly root: string) {}
  private ensure(): void { mkdirSync(this.root, { recursive: true, mode: 0o700 }) }
  private path(name: string): string { return join(this.root, name) }
  private read(name: string, fallback: any): any {
    const path = this.path(name)
    if (!existsSync(path)) return fallback
    if (statSync(path).size > 4 * 1024 * 1024) throw new Error('插件状态文件超过读取上限')
    return JSON.parse(readFileSync(path, 'utf8'))
  }
  private write(name: string, data: unknown): void {
    this.ensure(); const path = this.path(name), temp = `${path}.${randomUUID()}.tmp`
    writeFileSync(temp, JSON.stringify(data), { mode: 0o600, flag: 'wx' }); renameSync(temp, path)
  }
  get(host: unknown, port: unknown) {
    const ep = normalizeSshEndpoint(host, port)
    return ep ? parseSshHostTrustRecords(this.read('host-trust.json', [])).find((record) => record.endpoint === ep.endpoint) ?? null : null
  }
  save(candidate: Parameters<HostTrustStore['save']>[0]) {
    const value = createSshHostTrustCandidate(candidate)
    if (!value) throw new Error('SSH 主机信任记录无效')
    const records = parseSshHostTrustRecords(this.read('host-trust.json', [])), previous = records.find((r) => r.endpoint === value.endpoint)
    const now = new Date().toISOString(), record = { ...value, createdAt: previous?.createdAt ?? now, updatedAt: now }
    this.write('host-trust.json', [...records.filter((r) => r.endpoint !== value.endpoint), record]); return record
  }
  resetTrust(host: unknown, port: unknown): void {
    const ep = normalizeSshEndpoint(host, port)
    if (!ep) throw new Error('SSH endpoint 无效')
    this.write('host-trust.json', parseSshHostTrustRecords(this.read('host-trust.json', [])).filter((r) => r.endpoint !== ep.endpoint))
  }
  private sessionFile(sessionId: string, suffix: string): string { return `${createHash('sha256').update(sessionId).digest('hex')}.${suffix}` }
  append(record: Operation): void { this.ensure(); appendFileSync(this.path(this.sessionFile(record.sessionId, 'jsonl')), JSON.stringify(record) + '\n', { mode: 0o600 }) }
  history(sessionId: string, limit = 100): Operation[] {
    const path = this.path(this.sessionFile(sessionId, 'jsonl'))
    if (!existsSync(path)) return []
    const size = statSync(path).size, start = Math.max(0, size - 2 * 1024 * 1024), fd = openSync(path, 'r')
    try {
      const bytes = Buffer.alloc(Math.min(size, 2 * 1024 * 1024)); const count = readSync(fd, bytes, 0, bytes.length, start)
      const lines = bytes.subarray(0, count).toString('utf8').split('\n'); if (start) lines.shift()
      const records = new Map<string, Operation>()
      for (const line of lines) { if (!line) continue; try { const record = JSON.parse(line) as Operation; if (record.sessionId === sessionId && record.version === 1) records.set(record.id, record) } catch { /* 末尾不完整行不冒充成功。 */ } }
      return [...records.values()].map((r) => r.status === 'executing' ? { ...r, status: 'unknown' as const, error: '宿主恢复后无法确认前次操作结果' } : r).slice(-Math.min(200, limit))
    } finally { closeSync(fd) }
  }
  saveWorkspace(sessionId: string, targets: ConnectTarget[]): void { this.write(this.sessionFile(sessionId, 'workspace.json'), { version: 1, targets }) }
  workspace(sessionId: string): ConnectTarget[] { const value = this.read(this.sessionFile(sessionId, 'workspace.json'), { targets: [] }); return Array.isArray(value.targets) ? value.targets.slice(0, 32) : [] }
  calls(sessionId: string): Set<string> { const value = this.read(this.sessionFile(sessionId, 'calls.json'), []); if (!Array.isArray(value)) throw new Error('执行标识记录无效'); return new Set(value.filter((id) => typeof id === 'string' && id.length <= 256)) }
  saveCalls(sessionId: string, calls: Set<string>): void { this.write(this.sessionFile(sessionId, 'calls.json'), [...calls]) }
}
