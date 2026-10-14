// 仅供隔离检查：真实 node-pty 通过 default 导出，Shell 使用测试拥有的 /bin/sh。
const fixtureUrl = 'zterm-fixture:node-pty'
export function resolve(specifier, context, nextResolve) {
  return specifier === 'node-pty' ? { url: fixtureUrl, shortCircuit: true } : nextResolve(specifier, context)
}
export function load(url, context, nextLoad) {
  if (url !== fixtureUrl) return nextLoad(url, context)
  return { format: 'module', shortCircuit: true, source: `
    import { createRequire } from 'node:module'
    const nativePty = createRequire(${JSON.stringify(import.meta.url)})('node-pty')
    export default { spawn(_shell, args, options) {
      return nativePty.spawn('/bin/sh', args, { ...options, env: { PATH: process.env.PATH, TERM: 'xterm-256color' } })
    } }
  ` }
}
