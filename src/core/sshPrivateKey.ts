import { createPrivateKey, randomBytes, type KeyObject } from 'node:crypto'
import ssh2 from 'ssh2'

function uint32(value: number): Buffer { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes }
function sshString(value: string | Buffer): Buffer {
  const bytes = typeof value === 'string' ? Buffer.from(value) : value
  return Buffer.concat([uint32(bytes.length), bytes])
}

// Node only exports Ed25519 as PKCS#8/JWK; ssh2 needs the OpenSSH envelope.
// Encode the same key, without encryption, solely for the in-memory SSH client.
function ed25519OpenSsh(key: KeyObject): string {
  const jwk = key.export({ format: 'jwk' })
  if (!jwk.x || !jwk.d) throw new Error('Invalid Ed25519 key')
  const publicKey = Buffer.from(jwk.x, 'base64url'), seed = Buffer.from(jwk.d, 'base64url')
  if (publicKey.length !== 32 || seed.length !== 32) throw new Error('Invalid Ed25519 key')
  const algorithm = sshString('ssh-ed25519'), check = randomBytes(4)
  const publicBlock = Buffer.concat([algorithm, sshString(publicKey)])
  const privateBlock = Buffer.concat([check, check, algorithm, sshString(publicKey), sshString(Buffer.concat([seed, publicKey])), sshString('')])
  const padding = Buffer.from(Array.from({ length: 8 - privateBlock.length % 8 }, (_, i) => i + 1))
  const encoded = Buffer.concat([Buffer.from('openssh-key-v1\0'), sshString('none'), sshString('none'), sshString(''), uint32(1), sshString(publicBlock), sshString(Buffer.concat([privateBlock, padding]))])
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${encoded.toString('base64').match(/.{1,70}/g)!.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`
}

/** Validate every private-key entry point; preserve native formats and convert PKCS#8 only in memory. */
export function normalizeSshPrivateKey(value: string, passphrase?: string): string {
  try {
    let compatible = value
    const text = value.trim()
    if (/^-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/.test(text)) {
      // OpenSSL otherwise silently selects the first PEM block and ignores trailing text.
      if (!/^-----BEGIN ((?:ENCRYPTED )?PRIVATE KEY)-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END \1-----$/.test(text)) throw new Error('Invalid PKCS#8 envelope')
      const key = createPrivateKey({ key: text, format: 'pem', passphrase })
      switch (key.asymmetricKeyType) {
        case 'rsa': compatible = key.export({ type: 'pkcs1', format: 'pem' }).toString(); break
        case 'ec': compatible = key.export({ type: 'sec1', format: 'pem' }).toString(); break
        case 'ed25519': compatible = ed25519OpenSsh(key); break
        default: throw new Error('Unsupported SSH key algorithm')
      }
    }
    const parsed = ssh2.utils.parseKey(compatible, passphrase)
    if (parsed instanceof Error || !(Array.isArray(parsed) ? parsed : [parsed]).some((key) => key.getPrivatePEM())) throw new Error('Not a private SSH key')
    return compatible
  } catch {
    // Never forward OpenSSL/parser diagnostics or input material to RPC/UI errors.
    throw new Error('私钥无法解析，请检查完整内容、私钥算法和口令')
  }
}
