import { describe, it, expect, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createBuiltinReadTools, prepareBuiltinRead, readResultText } from '../src/core/agentReadTools'
const directories: string[] = []
afterEach(() => { for (const dir of directories.splice(0)) rmSync(dir, { recursive: true, force: true }) })
function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-zterm-read-')); directories.push(dir)
  const tools = createBuiltinReadTools(async (_id, prepare) => {
    const prepared = prepare(), result = spawnSync('/bin/sh', ['-c', prepared.command], { encoding: 'utf8', timeout: 5000, cwd: dir })
    return { content: [{ type: 'text', text: result.stdout ?? '' }], details: { output: result.stdout ?? '', exitCode: result.status ?? undefined, fidelity: 'verified' } }
  })
  const read = async (args: any) => JSON.parse((await tools.find((t) => t.name === 'read_bound_file')!.execute('read-call', args)).content[0].text)
  return { dir, read }
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
})
