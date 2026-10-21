import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, existsSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createBuiltinReadTools, prepareBuiltinRead, readResultText, ReadParameterError } from '../src/core/agentReadTools'
const directories: string[] = []
afterEach(() => { for (const dir of directories.splice(0)) rmSync(dir, { recursive: true, force: true }) })
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-zterm-read-')); directories.push(dir)
  const tools = createBuiltinReadTools(async (_id, prepare) => {
    const prepared = prepare(), result = spawnSync('/bin/sh', ['-c', prepared.command], { encoding: 'utf8', timeout: 5000, cwd: dir })
    return { content: [{ type: 'text', text: result.stdout ?? '' }], details: { output: result.stdout ?? '', exitCode: result.status ?? undefined, fidelity: 'verified' } }
  })
  const run = async (name: string, args: any) => JSON.parse((await tools.find((t) => t.name === name)!.execute('read-call', args)).content[0].text)
  return { dir, read: (args: any) => run('read_bound_file', args), search: (args: any) => run('search_bound_text', args) }
}
describe('实际 POSIX 内置读工具', () => {
  it('路径带空格与引号时，真实文件读取保留行号和正文', async () => {
    const { dir, read } = fixture(), path = join(dir, "quoted ' file.txt"); writeFileSync(path, 'first\nsecond\nthird\n')
    const result = await read({ path, start_line: 2, max_lines: 1 })
    expect(result.status).toBe('ok'); expect(JSON.stringify(result.data)).toContain('second'); expect(result.truncated).toBe(true)
  })
  it('空文件和行号越界分开返回，不伪造成功正文', async () => {
    const { dir, read } = fixture(), path = join(dir, 'empty.txt'); writeFileSync(path, '')
    const empty = await read({ path }); expect(empty.status).toBe('ok')
    writeFileSync(path, 'one\n'); const beyond = await read({ path, start_line: 9 }); expect(beyond.status).toBe('error'); expect(beyond.exitCode).not.toBe(0)
  })
  it('二进制文本读取拒绝，并清除成功退出码', async () => {
    const { dir, read } = fixture(), path = join(dir, 'binary.dat'); writeFileSync(path, Buffer.from([1, 0, 2]))
    const result = await read({ path }); expect(result.status).toBe('error'); expect(result.error.code).toBe('binary_not_supported'); expect(result.exitCode).not.toBe(0)
  })
  it('大文件结果有明确截断，不报告完整总行数', async () => {
    const { dir, read } = fixture(), path = join(dir, 'large.txt'); writeFileSync(path, '数据abc\n'.repeat(30000))
    const result = await read({ path, max_lines: 500 }); expect(result.status).toBe('ok'); expect(result.truncated).toBe(true); expect(result.truncationReasons.length).toBeGreaterThan(0)
  })
  it('失败信封不会带成功退出码或正文截断声明', () => {
    const result = JSON.parse(readResultText('read_bound_file', '/example', { text: '失败' }, { status: 'error', exitCode: 0, truncationReasons: ['output_bytes'] }))
    expect(result.exitCode).toBeNull(); expect(result.truncated).toBe(false)
  })
  it('拒绝凭据路径，并把命令替换字符串作为字面文件名读取', async () => {
    expect(() => prepareBuiltinRead('read_bound_file', { path: '/etc/shadow' })).toThrow()
    const { dir, read } = fixture(), path = join(dir, '$(touch should-not-run)'); writeFileSync(path, 'literal path\n')
    const result = await read({ path }); expect(JSON.stringify(result.data)).toContain('literal path')
    expect(existsSync(join(dir, 'should-not-run'))).toBe(false)
  })
  it('凭据封禁同时覆盖目录位置与文件类型（issue #1）', () => {
    const deniedPaths = [
      '/root/.ssh/id_ed25519', '/root/.aws/credentials', '/root/.kube/config',
      '/root/.docker/config.json', '/root/.gnupg/secring.gpg',
      '/home/op/.azure/service_principal.json', '/home/op/.gcloud/credentials.db',
      '/home/op/.config/gcloud/access_tokens.db', '/home/op/.aliyun/config.json',
      '/tmp/id_rsa', '/tmp/id_ed25519', '/tmp/site.ppk',
      '/srv/certs/server.p12', '/srv/certs/client.pfx', '/srv/app.keystore.jks',
      '/srv/vault.kdbx', '/root/cluster.kubeconfig', '/tmp/kubeconfig', '/tmp/kubeconfig.backup',
      '/root/.netrc', '/var/lib/postgresql/.pgpass', '/root/.git-credentials', '/etc/nginx/.htpasswd',
      '/app/.env.production', '/app/credentials.json', '/srv/LEAK.PEM',
    ]
    for (const name of ['read_bound_file', 'search_bound_text', 'read_bound_directory']) {
      const leaks = deniedPaths.filter((path) => {
        try { prepareBuiltinRead(name, { path, ...(name === 'search_bound_text' ? { query: 'fixture' } : {}) }); return true } catch { return false }
      })
      expect(leaks, name).toEqual([])
    }
    expect(() => prepareBuiltinRead('read_bound_file', { path: '/tmp/id_rsa' })).toThrow(ReadParameterError)
    try { prepareBuiltinRead('read_bound_file', { path: '/tmp/id_rsa' }) } catch (error) {
      expect((error as ReadParameterError).code).toBe('path_denied')
    }
  })
  it('公钥与普通配置文件不受凭据封禁影响', async () => {
    const { dir, read } = fixture(), path = join(dir, 'id_ed25519.pub')
    writeFileSync(path, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey zterm-test\n')
    const result = await read({ path })
    expect(result.status).toBe('ok'); expect(JSON.stringify(result.data)).toContain('ssh-ed25519')
    const notes = join(dir, 'kubeconfig-notes.md'); writeFileSync(notes, 'fixture documentation\n')
    const document = await read({ path: notes })
    expect(document.status).toBe('ok'); expect(JSON.stringify(document.data)).toContain('fixture documentation')
  })
  it.each(['leak.pem', 'kubeconfig', 'kubeconfig.backup'])('远端 realpath 复查拒绝符号链接绕过凭据封禁：%s', async (name) => {
    const { dir, read, search } = fixture()
    writeFileSync(join(dir, name), 'fixture-sensitive-marker\n')
    symlinkSync(join(dir, name), join(dir, 'innocent.txt'))
    for (const result of [await read({ path: join(dir, 'innocent.txt') }), await search({ path: join(dir, 'innocent.txt'), query: 'fixture-sensitive-marker' })]) {
      expect(result.status).toBe('error'); expect(result.error.code).toBe('path_denied')
      expect(JSON.stringify(result)).not.toContain('fixture-sensitive-marker')
    }
  })
  it('目录搜索跳过凭据命名的文件，其余文件正常返回', async () => {
    const { dir, search } = fixture()
    writeFileSync(join(dir, 'readme.md'), 'needle in readme\n')
    writeFileSync(join(dir, 'token.pem'), 'needle in secret\n')
    writeFileSync(join(dir, 'kubeconfig'), 'needle in kube credentials\n')
    writeFileSync(join(dir, 'kubeconfig.backup'), 'needle in kube credentials backup\n')
    const result = await search({ path: dir, query: 'needle' })
    expect(JSON.stringify(result.data)).toContain('readme.md')
    expect(JSON.stringify(result.data)).not.toContain('token.pem')
    expect(JSON.stringify(result.data)).not.toContain('kubeconfig')
    expect(JSON.stringify(result.data)).not.toContain('kube credentials')
    expect(JSON.stringify(result.data)).toContain('已检查 1 个文件')
  })
})
