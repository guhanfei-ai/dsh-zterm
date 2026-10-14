import { readFile, stat } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { Script } from 'node:vm'
import assert from 'node:assert/strict'
import { resolve } from 'node:path'

const manifest = JSON.parse(await readFile('package.json', 'utf8'))
const expected = ['lib/index.js', 'lib/client.js', 'cordis.patch.yml', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'README.md', 'USERGUIDE.zh-CN.md', 'scripts/prepare-native.mjs']
const result = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--ignore-scripts', '--json'], { encoding: 'utf8', env: { ...process.env, npm_config_cache: resolve('.cache/npm') } }))[0]
const entries = result.files.map((file) => file.path)
for (const name of expected) assert(entries.includes(name), `missing package entry: ${name}`)
for (const name of entries) {
  assert(!/^\.(?:git|env)|^(?:src|test|node_modules|_docs|_tacp|output|\.cache)\//.test(name), `unexpected private/build content: ${name}`)
  assert(expected.includes(name) || ['package.json', 'lib/index.js.map'].includes(name), `unexpected package file: ${name}`)
}
for (const name of Object.keys({ ...manifest.dependencies, ...manifest.optionalDependencies })) assert(!/electron|pi-coding-agent|openai/.test(name), `unexpected desktop/model runtime: ${name}`)
const host = await import('../lib/index.js')
assert.equal(typeof host.apply, 'function'); assert.equal(host.name, 'zterm')
const client = await readFile('lib/client.js', 'utf8'); new Script(client)
assert(client.includes('__ModuleLoader__')); assert(client.includes('dsh-zterm'))
assert((await stat('lib/client.js')).size < 1024 * 1024, 'client bundle over 1 MiB')
console.log(JSON.stringify({ name: manifest.name, version: manifest.version, fileCount: entries.length, packedBytes: result.size, unpackedBytes: result.unpackedSize, files: entries }, null, 2))
