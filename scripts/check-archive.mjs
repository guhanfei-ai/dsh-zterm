import { mkdtemp, readFile, rm, mkdir } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { resolve, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { Script } from 'node:vm'
import assert from 'node:assert/strict'

const version = JSON.parse(await readFile('package.json', 'utf8')).version
const archive = resolve(process.argv[2] ?? `out/dsh-zterm-${version}.tgz`)
const files = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' }).trim().split('\n')
assert(files.length === 10 && files.every((name) => /^package\/[\w./-]+$/.test(name) && !name.includes('..')), 'unexpected archive members')
await mkdir('.cache', { recursive: true })
const root = await mkdtemp(resolve('.cache/archive-'))
try {
  execFileSync('tar', ['-xzf', archive, '-C', root])
  const manifest = JSON.parse(await readFile(join(root, 'package/package.json'), 'utf8'))
  const host = await import(pathToFileURL(join(root, 'package', manifest.main)).href)
  const tools = [], disposers = []
  host.apply({ tools: { register: (tool) => tools.push(tool) }, systemPrompt: { section() {} }, credentials: {}, sessions: { get() {} },
    connection: { fetch: { register() { return () => {} } } }, on() {}, effect: (body) => disposers.push(body()) }, {}, { dataRoot: join(root, 'data') })
  assert.equal(tools.length, 14)
  for (const dispose of disposers.reverse()) if (typeof dispose === 'function') await dispose()
  new Script(await readFile(join(root, 'package/lib/client.js'), 'utf8'))
  console.log(`Packed archive loaded: ${manifest.name}@${manifest.version}, ${tools.length} tools, browser bundle parsed. Dependencies resolved from this project; no DSH service started.`)
} finally { await rm(root, { recursive: true, force: true }) }
