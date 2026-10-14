import { createRequire } from 'node:module'
import { dirname, join, relative, isAbsolute } from 'node:path'
import { existsSync, realpathSync, lstatSync, chmodSync } from 'node:fs'
// node-pty 1.1.0 的 macOS 预编译辅助程序可能以 0644 分发；只修复该依赖内的辅助程序。
if (process.platform === 'darwin') {
  const require = createRequire(import.meta.url)
  let packagePath
  try { packagePath = require.resolve('node-pty/package.json') } catch { process.exit(0) }
  const root = realpathSync(dirname(packagePath))
  for (const candidate of [join(root, 'prebuilds', `darwin-${process.arch}`, 'spawn-helper'), join(root, 'build', 'Release', 'spawn-helper')]) {
    if (!existsSync(candidate)) continue
    const info = lstatSync(candidate), resolved = realpathSync(candidate), inside = relative(root, resolved)
    if (!info.isFile() || info.isSymbolicLink() || inside.startsWith('..') || isAbsolute(inside)) throw new Error('node-pty 辅助程序路径无效')
    if (!(info.mode & 0o111)) { chmodSync(candidate, info.mode | 0o111); console.log('Prepared node-pty macOS spawn-helper executable permission.') }
  }
}
