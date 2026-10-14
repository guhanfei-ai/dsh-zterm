export const SSH_HOST_TRUST_STORE_KEY = 'ssh_host_trust_v1'

export type SshHostTrustDecision = 'trust-once' | 'trust-always' | 'reject'
export type SshHostTrustKind = 'unknown' | 'changed'

export interface SshHostTrustCandidate {
  endpoint: string
  host: string
  port: number
  username: string
  algorithm: string
  fingerprint: string
}

export interface SshHostTrustRecord extends SshHostTrustCandidate {
  createdAt: string
  updatedAt: string
}

export interface SshHostTrustRequiredEvent {
  tabId: string
  generation: number
  requestId: string
  kind: SshHostTrustKind
  host: string
  port: number
  username: string
  algorithm: string
  fingerprint: string
  trustedAlgorithm?: string
  trustedFingerprint?: string
}

export interface SshHostTrustResponse {
  tabId: string
  generation: number
  requestId: string
  decision: SshHostTrustDecision
}

export type SshHostTrustResponseResult =
  | { success: true }
  | { success: false; error: string }
