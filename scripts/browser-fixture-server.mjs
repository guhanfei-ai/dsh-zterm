import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
// 隔离界面检查拥有的临时服务器，仅提供两个虚构测试资源，自动结束。
const assets = new Map([['/workbench.html', ['workbench.html', 'text/html;charset=utf-8']], ['/fixture.js', ['fixture.js', 'application/javascript;charset=utf-8']]])
const server = createServer(async (req, res) => {
  const asset = assets.get(new URL(req.url ?? '/', 'http://localhost').pathname)
  if (!asset) { res.writeHead(404); res.end(); return }
  try { const body = await readFile(join('output/playwright', asset[0])); res.writeHead(200, { 'content-type': asset[1], 'cache-control': 'no-store' }); res.end(body) }
  catch { res.writeHead(404); res.end() }
})
const timer = setTimeout(() => server.close(), 15 * 60 * 1000)
server.on('close', () => { clearTimeout(timer); process.exit(0) })
process.stdin.on('data', () => server.close())
server.listen(0, '127.0.0.1', () => console.log(`Isolated UI fixture: http://127.0.0.1:${server.address().port}/workbench.html`))
