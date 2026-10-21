import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { utils } from 'ssh2'
import { normalizeSshPrivateKey } from '../../src/core/sshPrivateKey'
import { TerminalSession } from '../../src/core/terminalSessionManager'

const algorithms = [
  { name: 'RSA', generate: () => generateKeyPairSync('rsa', { modulusLength: 2048 }), hash: 'sha256' },
  { name: 'ECDSA P-256', generate: () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' }), hash: 'sha256' },
  { name: 'ECDSA P-384', generate: () => generateKeyPairSync('ec', { namedCurve: 'secp384r1' }), hash: 'sha384' },
  { name: 'ECDSA P-521', generate: () => generateKeyPairSync('ec', { namedCurve: 'secp521r1' }), hash: 'sha512' },
  { name: 'Ed25519', generate: () => generateKeyPairSync('ed25519'), hash: null },
]
function parsedKey(pem: string) {
  const parsed = utils.parseKey(pem)
  if (parsed instanceof Error) throw parsed
  const keys = Array.isArray(parsed) ? parsed : [parsed]
  expect(keys).toHaveLength(1)
  expect(keys[0].getPrivatePEM()).toBeTruthy()
  return keys[0]
}

describe('SSH 私钥统一兼容层', () => {
  it.each(algorithms.flatMap((algorithm) => [false, true].map((encrypted) => ({ ...algorithm, encrypted }))))('$name PKCS#8（加密：$encrypted）转换后身份和签名保持不变', ({ generate, hash, encrypted }) => {
    const { privateKey, publicKey } = generate(), passphrase = encrypted ? 'fixture-pkcs8-passphrase' : undefined
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem', ...(passphrase ? { cipher: 'aes-256-cbc', passphrase } : {}) }).toString()
    const normalized = normalizeSshPrivateKey(pem, passphrase), parsed = parsedKey(normalized)
    expect(normalized).not.toBe(pem)
    expect(createPublicKey(parsed.getPublicPEM()).export({ type: 'spki', format: 'der' })).toEqual(publicKey.export({ type: 'spki', format: 'der' }))
    const data = Buffer.from('fixture SSH authentication challenge'), signature = parsed.sign(data, hash ?? undefined)
    expect(Buffer.isBuffer(signature)).toBe(true)
    expect(verify(hash, data, publicKey, signature)).toBe(true)
  })

  it.each(['\n', '\r\n'])('支持外围空白、BOM 与换行 %j', (newline) => {
    const { privateKey } = generateKeyPairSync('ed25519')
    const pem = '\uFEFF \n' + privateKey.export({ type: 'pkcs8', format: 'pem' }).toString().replaceAll('\n', newline) + '\n  '
    expect(parsedKey(normalizeSshPrivateKey(pem)).type).toBe('ssh-ed25519')
  })

  it.each([false, true])('原有 RSA PKCS#1 与 EC SEC1 原文及口令行为保持不变（加密：%s）', (encrypted) => {
    const passphrase = encrypted ? 'fixture-legacy-passphrase' : undefined
    for (const type of ['rsa', 'ec'] as const) {
      const { privateKey } = type === 'rsa' ? generateKeyPairSync('rsa', { modulusLength: 2048 }) : generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      const pem = privateKey.export({ type: type === 'rsa' ? 'pkcs1' : 'sec1', format: 'pem', ...(passphrase ? { cipher: 'aes-256-cbc', passphrase } : {}) }).toString()
      expect(normalizeSshPrivateKey(pem, passphrase)).toBe(pem)
      if (encrypted) expect(() => normalizeSshPrivateKey(pem, 'fixture-wrong-passphrase')).toThrow('口令')
    }
  })

  it.each([false, true])('原有 OpenSSH RSA、ECDSA 和 Ed25519 保留原文（加密：%s）', (encrypted) => {
    const encryption: utils.KeyPairOptions = encrypted ? { cipher: 'aes256-ctr', passphrase: 'fixture-openssh-passphrase', rounds: 1 } : {}
    const pairs = [utils.generateKeyPairSync('rsa', { bits: 2048, ...encryption }), utils.generateKeyPairSync('ecdsa', { bits: 256, ...encryption }), utils.generateKeyPairSync('ed25519', encryption)]
    for (const pair of pairs) {
      expect(normalizeSshPrivateKey(pair.private, encrypted ? 'fixture-openssh-passphrase' : undefined)).toBe(pair.private)
      if (encrypted) expect(() => normalizeSshPrivateKey(pair.private, 'fixture-wrong-passphrase')).toThrow('口令')
      expect(() => normalizeSshPrivateKey(pair.public)).toThrow('私钥')
    }
  })

  it.each([undefined, 'fixture-wrong-passphrase'])('加密 PKCS#8 缺少或错误口令均拒绝：%s', (passphrase) => {
    const { privateKey } = generateKeyPairSync('ed25519')
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'fixture-correct-passphrase' }).toString()
    expect(() => normalizeSshPrivateKey(pem, passphrase)).toThrow('口令')
  })

  it('口令中的首尾空格和中文按原文处理，不隐式 trim', () => {
    const { privateKey } = generateKeyPairSync('ed25519'), passphrase = '  虚构测试口令 with spaces  '
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }).toString()
    expect(parsedKey(normalizeSshPrivateKey(pem, passphrase)).type).toBe('ssh-ed25519')
    expect(() => normalizeSshPrivateKey(pem, passphrase.trim())).toThrow('口令')
  })

  it('拒绝公钥、空内容、损坏和截断的 PKCS#8，错误不包含输入或解析器细节', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), lines = pem.trim().split('\n')
    const invalid = ['', 'fixture-private-secret-must-not-leak', publicKey.export({ type: 'spki', format: 'pem' }).toString(), pem.slice(0, -40), pem + 'fixture-trailing-text', pem + pem, pem.replace('-----END PRIVATE KEY-----', '-----END ENCRYPTED PRIVATE KEY-----'), [lines[0], ...lines.slice(2)].join('\n'), '-----BEGIN PRIVATE KEY-----\ninvalid!fixture-secret\n-----END PRIVATE KEY-----']
    for (const value of invalid) {
      expect(() => normalizeSshPrivateKey(value)).toThrow('私钥无法解析，请检查完整内容、私钥算法和口令')
    }
  })

  it('拒绝 SSH 不支持的 PKCS#8 算法和曲线，而不是按 RSA 或 Ed25519 误用', () => {
    const keys = [generateKeyPairSync('ed448').privateKey, generateKeyPairSync('x25519').privateKey, generateKeyPairSync('rsa-pss', { modulusLength: 2048 }).privateKey, generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).privateKey]
    for (const key of keys) expect(() => normalizeSshPrivateKey(key.export({ type: 'pkcs8', format: 'pem' }).toString())).toThrow('私钥')
  })

  it('连接层在创建 SSH 客户端前拒绝坏私钥，不开始网络连接', async () => {
    const factory = vi.fn(), session = new TerminalSession('invalid-key', 1, factory)
    await expect(session.connect({ host: 'fixture.invalid', port: 22, username: 'operator', privateKey: 'fixture-private-secret-must-not-leak', password: 'fixture-no-fallback-password' })).rejects.toThrow('私钥无法解析')
    expect(factory).not.toHaveBeenCalled()
    expect(session.connected).toBe(false)
  })
})
