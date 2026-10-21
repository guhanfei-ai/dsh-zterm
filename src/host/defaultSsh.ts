import { open } from 'node:fs/promises'
import { homedir, userInfo } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { normalizeSshPrivateKey } from '../core/sshPrivateKey'
import { checkCancelled, ZtermError } from './errors'

export const DEFAULT_KEY_FILES = ['id_ed25519', 'id_rsa', 'id_ecdsa']
export function defaultSshUsername(configured: string): string { return configured || userInfo().username }
export async function readDefaultPrivateKey(configured: string, passphrase?: string, signal?: AbortSignal, home = homedir()): Promise<string> {
  const paths = configured ? [configured.startsWith('~/') ? join(home, configured.slice(2)) : configured] : DEFAULT_KEY_FILES.map((file) => join(home, '.ssh', file))
  for (const path of paths) {
    checkCancelled(signal)
    if (!isAbsolute(path)) throw new ZtermError('invalid_key_path', '默认 SSH 私钥请填写 DSH 宿主的绝对路径或 ~/ 路径')
    let file
    try { file = await open(path, 'r') }
    catch (error: any) {
      if (!configured && error.code === 'ENOENT') continue
      throw new ZtermError('default_key_unavailable', '无法读取默认 SSH 私钥文件，请检查 zTerm 设置中的路径与文件权限')
    }
    try {
      const stat = await file.stat()
      if (!stat.isFile() || stat.size > 1024 * 1024) throw new ZtermError('invalid_private_key', '默认 SSH 私钥文件无效或过大')
      const value = await file.readFile({ encoding: 'utf8' }); checkCancelled(signal)
      if (Buffer.byteLength(value) > 1024 * 1024) throw new ZtermError('invalid_private_key', '默认 SSH 私钥文件过大')
      try { normalizeSshPrivateKey(value, passphrase) }
      catch { throw new ZtermError('invalid_private_key', '默认 SSH 私钥无法解析；请检查完整私钥和算法，若文件已加密，请填写正确的私钥口令') }
      return value
    } finally { await file.close() }
  }
  throw new ZtermError('default_key_missing', '未找到默认 SSH 私钥。主机已保存在远程主机列表；请在 zTerm 设置填写私钥路径，或编辑该主机的认证方式')
}
