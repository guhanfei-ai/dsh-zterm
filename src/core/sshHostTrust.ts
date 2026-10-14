/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
import { createHash } from 'node:crypto'
import { isIP } from 'node:net'
import { domainToASCII, URL } from 'node:url'
import ssh2 from 'ssh2'
import {
  SSH_HOST_TRUST_STORE_KEY,
  type SshHostTrustCandidate,
  type SshHostTrustRecord
} from './sshHostTrustTypes'


const CONTROL_CHARACTER = /[\u0000-\u001F\u007F]/
const SHA256_FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/

function canonicalizeIp(host: string): string | null {
  const unbracketed = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
  if (!isIP(unbracketed)) return null

  if (isIP(unbracketed) === 4) return unbracketed

  try {
    return new URL(`http://[${unbracketed}]/`).hostname.slice(1, -1).toLowerCase()
  } catch {
    return null
  }
}

export function normalizeSshHost(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const host = value.trim()
  if (!host || CONTROL_CHARACTER.test(host)) return null

  const ip = canonicalizeIp(host)
  if (ip) return ip

  if (host.startsWith('[') || host.endsWith(']')) return null
  const ascii = domainToASCII(host.endsWith('.') ? host.slice(0, -1) : host)
  if (!ascii || CONTROL_CHARACTER.test(ascii)) return null
  return ascii.toLowerCase()
}

export function normalizeSshPort(value: unknown): number | null {
  const port =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && /^(?:[1-9]\d*)$/.test(value)
        ? Number(value)
        : Number.NaN
  return Number.isSafeInteger(port) && port >= 1 && port <= 65535 ? port : null
}

export function normalizeSshUsername(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const username = value.trim()
  return username && !CONTROL_CHARACTER.test(username) ? username : null
}

export function normalizeSshFingerprint(value: unknown): string | null {
  if (typeof value !== 'string') return null
  return SHA256_FINGERPRINT.test(value) ? value : null
}

export function normalizeSshEndpoint(host: unknown, port: unknown): { host: string; port: number; endpoint: string } | null {
  const normalizedHost = normalizeSshHost(host)
  const normalizedPort = normalizeSshPort(port)
  if (!normalizedHost || !normalizedPort) return null
  return {
    host: normalizedHost,
    port: normalizedPort,
    endpoint: isIP(normalizedHost) === 6 ? `[${normalizedHost}]:${normalizedPort}` : `${normalizedHost}:${normalizedPort}`
  }
}

export function createSshHostFingerprint(rawHostKey: Buffer): string | null {
  if (!Buffer.isBuffer(rawHostKey) || rawHostKey.length === 0) return null
  return `SHA256:${createHash('sha256').update(rawHostKey).digest('base64').replace(/=+$/u, '')}`
}

export function createSshHostTrustCandidate(input: {
  host: unknown
  port: unknown
  username: unknown
  algorithm: unknown
  fingerprint: unknown
}): SshHostTrustCandidate | null {
  const endpoint = normalizeSshEndpoint(input.host, input.port)
  const username = normalizeSshUsername(input.username)
  const fingerprint = normalizeSshFingerprint(input.fingerprint)
  const algorithm = typeof input.algorithm === 'string' && input.algorithm.trim() && !CONTROL_CHARACTER.test(input.algorithm)
    ? input.algorithm.trim()
    : null
  if (!endpoint || !username || !fingerprint || !algorithm) return null

  return {
    ...endpoint,
    username,
    algorithm,
    fingerprint
  }
}

export function inspectSshHostKey(
  rawHostKey: Buffer,
  connection: { host: unknown; port: unknown; username: unknown }
): SshHostTrustCandidate | null {
  const parsedKey = ssh2.utils.parseKey(rawHostKey)
  if (parsedKey instanceof Error || Array.isArray(parsedKey) || !parsedKey.type) return null
  const fingerprint = createSshHostFingerprint(rawHostKey)
  if (!fingerprint) return null
  return createSshHostTrustCandidate({ ...connection, algorithm: parsedKey.type, fingerprint })
}

export function isSshHostTrustRecord(value: unknown): value is SshHostTrustRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  const allowedKeys = new Set([
    'endpoint',
    'host',
    'port',
    'username',
    'algorithm',
    'fingerprint',
    'createdAt',
    'updatedAt'
  ])
  if (Object.keys(record).some((key) => !allowedKeys.has(key))) return false
  const candidate = createSshHostTrustCandidate({
    host: record.host,
    port: record.port,
    username: record.username,
    algorithm: record.algorithm,
    fingerprint: record.fingerprint
  })
  if (
    !candidate ||
    candidate.endpoint !== record.endpoint ||
    candidate.host !== record.host ||
    candidate.port !== record.port ||
    candidate.username !== record.username ||
    candidate.algorithm !== record.algorithm ||
    candidate.fingerprint !== record.fingerprint
  ) {
    return false
  }
  return (
    typeof record.createdAt === 'string' &&
    Number.isFinite(Date.parse(record.createdAt)) &&
    typeof record.updatedAt === 'string' &&
    Number.isFinite(Date.parse(record.updatedAt))
  )
}

export function parseSshHostTrustRecords(value: unknown): SshHostTrustRecord[] {
  if (!Array.isArray(value)) return []
  const records = value.filter(isSshHostTrustRecord)
  const endpointCounts = new Map<string, number>()
  for (const record of records) {
    endpointCounts.set(record.endpoint, (endpointCounts.get(record.endpoint) || 0) + 1)
  }
  return records.filter((record) => endpointCounts.get(record.endpoint) === 1)
}


export interface HostTrustStore {
  get(host: unknown, port: unknown): SshHostTrustRecord | null
  save(candidate: SshHostTrustCandidate): SshHostTrustRecord
}

export function memoryHostTrustStore(): HostTrustStore {
  const records = new Map<string, SshHostTrustRecord>()
  return {
    get(host, port) { const ep = normalizeSshEndpoint(host, port); return ep ? records.get(ep.endpoint) ?? null : null },
    save(candidate) { const verified = createSshHostTrustCandidate(candidate); if (!verified) throw new Error("SSH 主机信任记录无效"); const now = new Date().toISOString(); const record = { ...verified, createdAt: records.get(verified.endpoint)?.createdAt ?? now, updatedAt: now }; records.set(record.endpoint, record); return record },
  }
}
