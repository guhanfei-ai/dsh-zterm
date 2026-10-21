import { afterEach, describe, expect, it } from 'vitest'
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createBuiltinReadTools, prepareBuiltinRead, ReadParameterError } from '../src/core/agentReadTools'
import type { AgentToolResult } from '../src/core/toolTypes'

const SOURCE_BYTES = 65_536
const temporaryParent = realpathSync(tmpdir())
const directoryPrefix = 'dsh-zterm-credential-content-'
const temporaryPrefix = join(temporaryParent, directoryPrefix)
const ownedDirectories = new Set<string>()

// Only remove the exact directories this fixture created, never an unchecked computed path.
afterEach(() => {
  for (const directory of [...ownedDirectories]) {
    const absolute = resolve(directory)
    expect(isAbsolute(directory)).toBe(true)
    expect(absolute).toBe(directory)
    expect(dirname(absolute)).toBe(temporaryParent)
    expect(absolute.startsWith(temporaryPrefix)).toBe(true)
    expect(basename(absolute)).toMatch(/^dsh-zterm-credential-content-[A-Za-z0-9]{6}$/)
    expect(realpathSync(absolute)).toBe(absolute)
    rmSync(absolute, { recursive: true, force: true })
    ownedDirectories.delete(directory)
  }
})

interface RawCapture {
  stdout: string
  stderr: string
  status: number | null
  error?: Error
  signal: NodeJS.Signals | null
}
interface ReadEnvelope {
  status: 'ok' | 'error'
  exitCode: number | null
  error: { code: string; phase: string; message: string } | null
  data: { text?: string; [key: string]: unknown }
  truncated: boolean
}
interface Observation {
  raw: RawCapture
  result: AgentToolResult<any>
  envelope: ReadEnvelope
}

function fixture() {
  const root = mkdtempSync(temporaryPrefix)
  ownedDirectories.add(root)
  const dir = join(root, 'arbitrary location', 'uploads')
  mkdirSync(dir, { recursive: true })
  const captures: RawCapture[] = []
  const tools = createBuiltinReadTools(async (_id, prepare) => {
    const prepared = prepare()
    const shell = spawnSync('/bin/sh', ['-c', prepared.command], {
      encoding: 'utf8', timeout: 5000, cwd: dir,
      // No login shell, real HOME, or application credentials are needed by this fixture.
      env: { PATH: process.env.PATH, HOME: root, TMPDIR: root, LC_ALL: 'C' },
    })
    const capture = {
      stdout: shell.stdout ?? '', stderr: shell.stderr ?? '', status: shell.status,
      error: shell.error, signal: shell.signal,
    }
    captures.push(capture)
    return {
      content: [{ type: 'text', text: capture.stdout }],
      details: { output: capture.stdout, exitCode: capture.status ?? undefined, fidelity: 'verified' },
    }
  })
  const run = async (name: string, args: Record<string, unknown>): Promise<Observation> => {
    const before = captures.length
    const tool = tools.find((candidate) => candidate.name === name)!
    const result = await tool.execute('credential-content-fixture', args)
    expect(captures).toHaveLength(before + 1)
    const raw = captures[before]
    expect(raw.error).toBeUndefined()
    expect(raw.signal).toBeNull()
    return { raw, result, envelope: JSON.parse(result.content[0].text) }
  }
  return {
    dir,
    read: (args: Record<string, unknown>) => run('read_bound_file', args),
    search: (args: Record<string, unknown>) => run('search_bound_text', args),
  }
}

function assertNoLeaks(observation: Observation, markers: string[]) {
  for (const marker of markers) {
    // Check before tool serialization: masking the final JSON would be too late for terminal/history.
    expect.soft(observation.raw.stdout, 'marker reached raw shell stdout').not.toContain(marker)
    expect.soft(observation.raw.stderr, 'marker reached raw shell stderr').not.toContain(marker)
    expect.soft(JSON.stringify(observation.result), 'marker reached the complete tool result').not.toContain(marker)
  }
}

function assertContentDenied(observation: Observation, markers: string[]) {
  assertNoLeaks(observation, markers)
  const { raw, result, envelope } = observation
  expect(raw.status).toBeTypeOf('number')
  expect(raw.status).not.toBe(0)
  expect(envelope.status).toBe('error')
  expect(envelope.error?.code).toBe('credential_content_denied')
  expect(envelope.error?.phase).toBe('content')
  expect(envelope.exitCode).toBeTypeOf('number')
  expect(envelope.exitCode).not.toBe(0)
  expect(envelope.truncated).toBe(false)
  expect(envelope.error?.message).toMatch(/凭据.*拒绝|拒绝.*凭据/)
  expect(raw.stdout.trim()).toBe(envelope.error?.message)
  expect(raw.stdout.trim().split(/\r?\n/)).toHaveLength(1)
  expect(raw.stderr).toBe('')
  expect(envelope.data.text).toBe(envelope.error?.message)
  expect(result.details.displayOutput).toBe(envelope.error?.message)
  expect(raw.stdout).not.toContain('__ZTERM_FILE_V1__')
}

interface CredentialFormat {
  label: string
  render: (marker: string) => string
}

// Deliberately fictitious structures, not real keys or an assertion that every secret is detectable.
const credentialFormats: CredentialFormat[] = [
  ...['PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY', 'OPENSSH PRIVATE KEY']
    .map((label) => ({ label: `PEM ${label}`, render: (marker: string) => `-----BEGIN ${label}-----\n${marker}\n-----END ${label}-----\n` })),
  { label: 'PGP private key', render: (marker) => `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${marker}\n-----END PGP PRIVATE KEY BLOCK-----\n` },
  { label: 'PEM BOM + CRLF', render: (marker) => `\ufeff-----BEGIN PRIVATE KEY-----\r\n${marker}\r\n-----END PRIVATE KEY-----\r\n` },
  ...['private_key', 'privateKey'].map((field) => ({ label: `JSON 私钥 ${field}`, render: (marker: string) => JSON.stringify({ [field]: `-----BEGIN PRIVATE KEY-----\n${marker}\n-----END PRIVATE KEY-----\n` }) + '\n' })),
  ...[2, 3].map((version) => ({ label: `PuTTY v${version}`, render: (marker: string) => `PuTTY-User-Key-File-${version}: ssh-ed25519\nEncryption: none\nComment: fixture only\nPublic-Lines: 1\nPUBLIC_FIXTURE\nPrivate-Lines: 1\n${marker}\nPrivate-MAC: fixture-only\n` })),
  ...['aws_access_key_id', 'aws_secret_access_key', 'aws_session_token'].flatMap((key) => [
    { label: `AWS ini ${key}`, render: (marker: string) => `[fixture-profile]\n${key} = ${marker}\n` },
    { label: `AWS JSON ${key}`, render: (marker: string) => JSON.stringify({ [key]: marker }) + '\n' },
  ]),
  { label: 'AWS export', render: (marker) => `export AWS_SECRET_ACCESS_KEY='${marker}'\n` },
  ...['auth', 'identitytoken'].map((key) => ({
    label: `Docker ${key}`,
    render: (marker: string) => JSON.stringify({ auths: { 'registry.fixture.invalid': { [key]: marker } } }) + '\n',
  })),
  { label: 'kubeconfig YAML users', render: (marker) => `apiVersion: v1\nkind: Config\nusers:\n  - name: fixture\n    user:\n      token: ${marker}\n` },
  { label: 'kubeconfig YAML clusters', render: (marker) => `apiVersion: v1\nkind: Config\nclusters:\n  - name: fixture\n    cluster:\n      certificate-authority-data: ${marker}\n` },
  { label: 'kubeconfig YAML 注释', render: (marker) => `apiVersion: v1\nkind: Config # generated\nusers: # auth entries\n  - name: fixture\n    user:\n      token: ${marker}\n` },
  { label: 'kubeconfig YAML 独立列表标记', render: (marker) => `apiVersion: v1\nkind: Config\nusers:\n  -\n    name: fixture\n    user:\n      token: ${marker}\n` },
  { label: 'kubeconfig YAML 引号与注释', render: (marker) => `"apiVersion": v1\n"kind": "Config" # generated\n"users": # auth entries\n  - name: fixture\n    user:\n      token: ${marker}\n` },
  ...['current-context: fixture', 'preferences: {}'].map((first) => ({ label: `kubeconfig YAML 首键 ${first}`, render: (marker: string) => `${first}\nkind: Config\nusers:\n  - name: fixture\n    user:\n      token: ${marker}\n` })),
  { label: 'kubeconfig JSON users（缺省 apiVersion）', render: (marker) => JSON.stringify({ kind: 'Config', users: [{ name: 'fixture', user: { token: marker } }] }) + '\n' },
  { label: 'kubeconfig JSON clusters', render: (marker) => JSON.stringify({ apiVersion: 'v1', kind: 'Config', clusters: [{ name: 'fixture', cluster: { 'certificate-authority-data': marker } }] }) + '\n' },
  { label: 'GCP service_account', render: (marker) => JSON.stringify({ type: 'service_account', project_id: 'fixture-project', private_key: marker }) + '\n' },
  { label: 'GCP authorized_user', render: (marker) => JSON.stringify({ type: 'authorized_user', client_id: 'fixture-client', refresh_token: marker }) + '\n' },
]
const smallCredentials = credentialFormats.map((format, index) => ({
  ...format,
  filename: index % 2 ? 'renamed' : 'safe-looking.txt',
  marker: `ZTERM_FAKE_SENSITIVE_BODY_${index}_DO_NOT_USE`,
}))

describe('凭据内容类型封条：在远端 POSIX 输出前拒绝', () => {
  it.each(smallCredentials)('任意目录中改名的 $label（$filename）仍被拒绝', async ({ filename, marker, render }) => {
    const { dir, read } = fixture()
    const path = join(dir, filename)
    writeFileSync(path, render(marker))
    assertContentDenied(await read({ path }), [marker])
  })

  it('直接/按行/末尾读取和仅匹配正文的单文件搜索都只返回同一固定拒绝文字', async () => {
    const { dir, read, search } = fixture()
    const marker = 'ZTERM_FAKE_PRIVATE_BODY_WITHOUT_HEADER_DO_NOT_USE'
    const path = join(dir, 'safe-looking.txt')
    writeFileSync(path, `-----BEGIN PRIVATE KEY-----\nfixture padding\n${marker}\n-----END PRIVATE KEY-----\n`)
    const observations = [
      await read({ path }),
      await read({ path, start_line: 3, max_lines: 1 }),
      await read({ path, from_end: true, max_lines: 2 }),
      await search({ path, query: marker }),
    ]
    // A different format must not produce a revealing format-specific refusal, either.
    const other = join(dir, 'renamed')
    const otherMarker = 'ZTERM_FAKE_AWS_BODY_DO_NOT_USE'
    writeFileSync(other, `[fixture]\naws_session_token = ${otherMarker}\n`)
    observations.push(await search({ path: other, query: otherMarker }))
    for (const observation of observations) assertContentDenied(observation, [marker, otherMarker])
    expect(new Set(observations.map(({ raw }) => raw.stdout.trim())).size).toBe(1)
  })

  it.each([
    { label: 'PEM private key', signature: '-----BEGIN PRIVATE KEY-----', prefix: '-----BEGIN PRIVATE KEY-----\n', suffix: '\n-----END PRIVATE KEY-----\n' },
    { label: 'kubeconfig structure', signature: 'kind: Config', prefix: 'apiVersion: v1\nkind: Config\nusers:\n  - name: fixture\n    user:\n', suffix: '\n' },
  ])('大文件末尾只有正文而 $label 头在前 64 KiB 时仍拒绝', async ({ signature, prefix, suffix }) => {
    const { dir, read } = fixture()
    const path = join(dir, 'renamed')
    const marker = 'ZTERM_FAKE_TAIL_CREDENTIAL_BODY_DO_NOT_USE'
    const body = signature.startsWith('-----') ? marker : `      token: ${marker}`
    const bytes = Buffer.from(prefix + '# harmless fixture padding\n'.repeat(6000) + body + suffix)
    expect(bytes.length).toBeGreaterThan(2 * SOURCE_BYTES)
    expect(bytes.subarray(0, SOURCE_BYTES).toString()).toContain(signature)
    expect(bytes.subarray(-SOURCE_BYTES).toString()).not.toContain(signature)
    expect(bytes.subarray(-SOURCE_BYTES).toString()).toContain(marker)
    writeFileSync(path, bytes)
    assertContentDenied(await read({ path, from_end: true, max_lines: 2 }), [marker])
  })

  it.each([
    { label: 'Docker', prefix: '{"auths":{"registry.fixture.invalid":{"auth":"', suffix: '"}}}' },
    { label: 'GCP', prefix: '{"type":"authorized_user","refresh_token":"', suffix: '"}' },
    { label: 'AWS', prefix: 'aws_secret_access_key="', suffix: '"' },
  ])('$label 非空凭据值被 64 KiB 窗口截断仍拒绝', async ({ prefix, suffix }) => {
    const { dir, read, search } = fixture(), path = join(dir, 'renamed')
    const marker = 'ZTERM_FAKE_TRUNCATED_CREDENTIAL_BODY_DO_NOT_USE'
    writeFileSync(path, prefix + marker + 'A'.repeat(SOURCE_BYTES) + suffix)
    assertContentDenied(await read({ path, max_lines: 1 }), [marker])
    assertContentDenied(await search({ path, query: marker }), [marker])
  })

  it('符号链接指向无敏感文件名的凭据仍按内容拒绝读取与搜索', async () => {
    const { dir, read, search } = fixture()
    const marker = 'ZTERM_FAKE_RENAMED_LINK_BODY_DO_NOT_USE'
    const target = join(dir, 'renamed')
    const path = join(dir, 'safe-looking.txt')
    writeFileSync(target, JSON.stringify({ type: 'authorized_user', refresh_token: marker }) + '\n')
    symlinkSync(target, path)
    assertContentDenied(await read({ path }), [marker])
    assertContentDenied(await search({ path, query: marker }), [marker])
  })

  it('目录先有普通命中也不输出后续凭据正文，并跳过凭据后继续普通文件', async () => {
    const { dir, search } = fixture()
    const markers = ['ZTERM_FAKE_DIR_needle_FIRST_DO_NOT_USE', 'ZTERM_FAKE_DIR_needle_SECOND_DO_NOT_USE']
    writeFileSync(join(dir, '00-public.txt'), 'needle public first match\n')
    writeFileSync(join(dir, '10-safe-looking.txt'), JSON.stringify({ auths: { 'registry.fixture.invalid': { auth: markers[0] } } }) + '\n')
    writeFileSync(join(dir, '20-renamed'), `[fixture]\naws_secret_access_key = ${markers[1]}\n`)
    writeFileSync(join(dir, '30-public.log'), 'needle public final match\n')
    const observation = await search({ path: dir, query: 'needle' })
    assertNoLeaks(observation, markers)
    expect(observation.raw.status).toBe(0)
    expect(observation.envelope.status).toBe('ok')
    expect(observation.envelope.exitCode).toBe(0)
    for (const output of [observation.raw.stdout, JSON.stringify(observation.result)]) {
      expect(output).toContain('public first match')
      expect(output).toContain('public final match')
      expect(output).not.toContain('10-safe-looking.txt')
      expect(output).not.toContain('20-renamed')
      expect(output).toMatch(/跳过\s*2\s*个凭据内容文件/)
    }
  })

  it('内容识别不放宽已有的目录、basename、扩展名及 realpath 封禁', async () => {
    const { dir, read, search } = fixture()
    for (const path of [join(dir, '.aws', 'notes.txt'), join(dir, '.netrc'), join(dir, 'client.PEM'), join(dir, 'id_ed25519')]) {
      for (const tool of ['read_bound_file', 'search_bound_text', 'read_bound_directory']) {
        expect(() => prepareBuiltinRead(tool, { path, ...(tool === 'search_bound_text' ? { query: 'public' } : {}) })).toThrow(ReadParameterError)
      }
    }
    const target = join(dir, 'client.PEM')
    const path = join(dir, 'plain-link.txt')
    writeFileSync(target, 'public fixture text\n')
    symlinkSync(target, path)
    for (const observation of [await read({ path }), await search({ path, query: 'public' })]) {
      expect(observation.envelope.status).toBe('error')
      expect(observation.envelope.error?.code).toBe('path_denied')
      expect(observation.raw.status).not.toBe(0)
      expect(observation.raw.stdout).not.toContain('public fixture text')
    }
  })
})

const publicContent = [
  { label: 'SSH 公钥', marker: 'PUBLIC_SSH_FIXTURE', text: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnly PUBLIC_SSH_FIXTURE\n' },
  { label: 'PEM 公钥', marker: 'PUBLIC_KEY_FIXTURE', text: '-----BEGIN PUBLIC KEY-----\nPUBLIC_KEY_FIXTURE\n-----END PUBLIC KEY-----\n' },
  { label: '公开证书', marker: 'PUBLIC_CERTIFICATE_FIXTURE', text: '-----BEGIN CERTIFICATE-----\nPUBLIC_CERTIFICATE_FIXTURE\n-----END CERTIFICATE-----\n' },
  { label: '常规日志', marker: 'PUBLIC_LOG_FIXTURE', text: 'PUBLIC_LOG_FIXTURE level=info token=not-set password=not-set auth=anonymous\n' },
  { label: '日志中带引号提及私钥头', marker: 'PUBLIC_QUOTED_HEADER_FIXTURE', text: 'PUBLIC_QUOTED_HEADER_FIXTURE documented header="-----BEGIN PRIVATE KEY-----" without key material\n' },
  { label: 'Docker 空 auths', marker: 'PUBLIC_EMPTY_AUTHS_FIXTURE', text: JSON.stringify({ auths: {}, note: 'PUBLIC_EMPTY_AUTHS_FIXTURE' }) + '\n' },
  { label: 'Docker 空 auths 与无关 auth 字段', marker: 'PUBLIC_UNRELATED_AUTH_FIXTURE', text: JSON.stringify({ auths: {}, auth: 'anonymous', note: 'PUBLIC_UNRELATED_AUTH_FIXTURE' }) + '\n' },
  { label: 'YAML Config 的 users 是换行标量', marker: 'PUBLIC_YAML_SCALAR_FIXTURE', text: 'kind: Config\nusers:\n  PUBLIC_YAML_SCALAR_FIXTURE\n' },
  { label: 'JSON 私钥字段只是头文案而无密钥正文', marker: 'PUBLIC_JSON_HEADER_FIXTURE', text: JSON.stringify({ private_key: '-----BEGIN PRIVATE KEY-----', note: 'PUBLIC_JSON_HEADER_FIXTURE' }) + '\n' },
  { label: 'Config 的 users 是普通标量', marker: 'PUBLIC_SCALAR_USERS_FIXTURE', text: JSON.stringify({ apiVersion: 'v1', kind: 'Config', users: 'PUBLIC_SCALAR_USERS_FIXTURE' }) + '\n' },
  { label: 'GCP 只有类型没有敏感字段', marker: 'PUBLIC_GCP_TYPE_ONLY_FIXTURE', text: JSON.stringify({ type: 'service_account', project_id: 'PUBLIC_GCP_TYPE_ONLY_FIXTURE' }) + '\n' },
  { label: 'Deployment YAML', marker: 'PUBLIC_DEPLOYMENT_FIXTURE', text: 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: PUBLIC_DEPLOYMENT_FIXTURE\nspec:\n  replicas: 1\n' },
  { label: 'Deployment JSON', marker: 'PUBLIC_DEPLOYMENT_JSON_FIXTURE', text: JSON.stringify({ kind: 'Deployment', metadata: { name: 'PUBLIC_DEPLOYMENT_JSON_FIXTURE' } }) + '\n' },
  { label: '非凭据结构里的通用 token/password 字段', marker: 'PUBLIC_DOCUMENTATION_FIXTURE', text: JSON.stringify({ token: 'PUBLIC_DOCUMENTATION_FIXTURE', password: 'EXAMPLE_ONLY_NOT_A_REAL_SECRET' }) + '\n' },
]

describe('凭据内容类型识别的非敏感边界', () => {
  it.each(publicContent)('$label 仍能读取和做字面搜索', async ({ marker, text }) => {
    const { dir, read, search } = fixture()
    const path = join(dir, 'safe-looking.txt')
    writeFileSync(path, text)
    for (const observation of [await read({ path }), await search({ path, query: marker })]) {
      expect(observation.raw.status).toBe(0)
      expect(observation.raw.stderr).toBe('')
      expect(observation.envelope.status).toBe('ok')
      expect(observation.envelope.error).toBeNull()
      expect(observation.envelope.exitCode).toBe(0)
      expect(observation.raw.stdout).toContain(marker)
      expect(JSON.stringify(observation.envelope.data)).toContain(marker)
    }
  })
})
