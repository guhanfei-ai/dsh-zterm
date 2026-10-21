/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
/**
 * 内置观察工具：模型只填写查询参数，宿主生成固定的只读操作。
 * 经现有绑定终端执行，不安装远端组件，不开放额外命令或主机参数。
 */
import { posix } from 'node:path'
import { Type } from '@sinclair/typebox'
import { defineTool, type ToolDefinition } from './toolTypes'
import type { AgentToolResult } from './toolTypes'

export interface ReadExecutionDetails {
  skipped?: boolean
  command?: string
  displayOutput?: string
  blocked?: boolean
  error?: string
  reason?: string
  stepNumber?: number
  fidelity?: string
  exitCode?: number
  duration?: number
  truncated?: boolean
  output?: string
  truncationReasons?: ReadTruncationReason[]
  readErrorCode?: string
}

export type ReadTruncationReason = 'source_bytes' | 'max_lines' | 'output_bytes' | 'output_chars' | 'capture_buffer' | 'history_limit'
interface ReadError { code: string; phase: 'validation' | 'execution' | 'content' | 'protocol' | 'context'; message: string }

export class ReadParameterError extends Error {
  constructor(public readonly code: string, message: string) { super(message) }
}

export interface PreparedRead {
  toolName: string
  label: string
  command: string
  scope: string
  fileWindow?: { startLine: number; fromEnd: boolean }
  summarizeOutput?: (output: string) => { text: string; truncated: boolean }
}

export type ReadExecutor = (
  toolCallId: string,
  prepare: () => PreparedRead,
  signal?: AbortSignal,
) => Promise<AgentToolResult<ReadExecutionDetails>>

const SOURCE_BYTES = 65_536
const OUTPUT_CHARS = 8_000
const FILE_OUTPUT_BYTES = 7_000
const pathParam = Type.String({ description: '绑定目标上的绝对路径，不是本地模型运行目录；不展开 ~、变量或通配符', maxLength: 2048 })
const objectOptions = { additionalProperties: false }

const definitions = [
  {
    name: 'read_bound_directory',
    label: '查看目录',
    description: '查看已绑定目标的目录直接子项和文件属性，不递归。省略 path 时查询绑定终端当前目录，结果中返回解析后的目标路径。数量与输出有上限。',
    parameters: Type.Object({
      path: Type.Optional(pathParam),
      limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 200, default: 50 })),
    }, objectOptions),
  },
  {
    name: 'read_bound_file',
    label: '读取文件',
    description: '读取绑定目标的文本文件或已支持的 /proc 信息。开头/末尾返回窗口最多 64 KiB（另读一个边界字节），末尾读取另检查前 64 KiB 的凭据类型，文本输出最多 7000 字节。返回实际行区间、截断原因和可用的 nextStartLine。只有完整观察文件时 totalLines 才有值；末尾窗口的绝对行号可能未知。超出文件与超出窗口分别报错。拒绝设备、管道、凭据路径及样本中识别出的常见凭据内容。',
    parameters: Type.Object({
      path: pathParam,
      start_line: Type.Optional(Type.Integer({ minimum: 1, maximum: 10000, default: 1 })),
      max_lines: Type.Optional(Type.Integer({ minimum: 1, maximum: 500, default: 100 })),
      from_end: Type.Optional(Type.Boolean({ default: false })),
    }, objectOptions),
  },
  {
    name: 'search_bound_text',
    label: '搜索文本',
    description: '在已绑定目标的一个文本文件或目录直接子文件中做字面关键词搜索，不执行正则或脚本，不递归。目录最多检查 100 个文件，每个文件最多检查前 64 KiB；单文件识别到常见凭据内容时拒绝，目录搜索跳过符号链接、凭据路径及识别到的凭据内容并报告数量。',
    parameters: Type.Object({
      path: pathParam,
      query: Type.String({ minLength: 1, maxLength: 256 }),
      max_matches: Type.Optional(Type.Integer({ description: '每个文件最多返回的匹配行数', minimum: 1, maximum: 100, default: 30 })),
    }, objectOptions),
  },
  {
    name: 'read_bound_system',
    label: '查看系统概况',
    description: '读取已绑定目标的系统版本、运行时间、负载、内存和磁盘信息。支持 Linux，macOS 使用已有系统查询。缺失能力如实返回，不安装软件。',
    parameters: Type.Object({}, objectOptions),
  },
  {
    name: 'list_bound_processes',
    label: '查看进程',
    description: '读取已绑定目标的进程 PID、父进程、用户、状态、CPU、内存和名称；不读取环境变量或完整启动参数。可按 PID 或名称过滤。',
    parameters: Type.Object({
      pid: Type.Optional(Type.Integer({ minimum: 1, maximum: 2147483647 })),
      name: Type.Optional(Type.String({ minLength: 1, maxLength: 128 })),
      limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 200, default: 50 })),
    }, objectOptions),
  },
  {
    name: 'list_bound_sockets',
    label: '查看端口和连接',
    description: '使用目标现有的 ss 查询 TCP/UDP socket，缺少 ss 时使用已有 lsof。默认只看监听或未连接绑定项。返回当前网络命名空间可见的信息；进程信息可能受权限限制。不探测外部可达性，不安装软件。',
    parameters: Type.Object({
      protocol: Type.Optional(Type.Union([Type.Literal('all'), Type.Literal('tcp'), Type.Literal('udp')])),
      local_port: Type.Optional(Type.Integer({ minimum: 1, maximum: 65535 })),
      listening_only: Type.Optional(Type.Boolean({ default: true })),
      limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 200, default: 50 })),
    }, objectOptions),
  },
] as const

export const BUILTIN_READ_TOOL_NAMES: readonly string[] = definitions.map((definition) => definition.name)

export function activeTerminalToolNames(allowWrite: boolean): string[] {
  return [
    'read_bound_terminal_context',
    ...BUILTIN_READ_TOOL_NAMES,
    ...(allowWrite ? ['execute_bound_terminal'] : []),
  ]
}

function quote(value: string): string {
  return "'" + value.replace(/'/g, "'\\''") + "'"
}

function text(value: unknown, field: string, max: number): string {
  if (typeof value !== 'string' || !value.length || value.length > max || /[\x00-\x1f\x7f]/.test(value)) {
    throw new Error(field + ' 必须是长度受限且不包含控制字符的文本')
  }
  return value
}

function integer(value: unknown, fallback: number, min: number, max: number): number {
  const number = value === undefined ? fallback : value
  if (typeof number !== 'number' || !Number.isInteger(number) || number < min || number > max) {
    throw new Error('数值参数超出允许范围')
  }
  return number
}

function boolean(value: unknown, fallback: boolean): boolean {
  if (value === undefined) return fallback
  if (typeof value !== 'boolean') throw new Error('布尔参数格式无效')
  return value
}

/** 凭据封禁唯一事实源：JS 参数校验与远端 realpath 复查共用，防止两层清单漂移。 */
const credentialDirectories = [
  '.ssh', '.aws', '.kube', '.docker', '.gnupg', '.azure', '.gcloud', '.config/gcloud', '.aliyun',
]
const credentialBasenames = ['.env', 'credentials', 'secrets', '.netrc', '.pgpass', '.git-credentials', '.htpasswd', 'kubeconfig']
const credentialNameSuffixes = ['.kubeconfig']
const credentialExtensions = ['pem', 'key', 'p12', 'pfx', 'ppk', 'jks', 'kdbx']
const sshKeyBasenames = ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519']
const CREDENTIAL_CONTENT_EXIT = 77
const CREDENTIAL_CONTENT_MESSAGE = '检测到凭据文件内容，读取被拒绝。'

/** 在远端的有界样本上识别常见凭据类型；先检查再输出，秘密不能进入终端流或操作记录。 */
const credentialContentAwk = String.raw`
  function jsonObjectField(value, field, start, pos, depth, quoted, escaped, ch) {
    if (!match(value, "\"" field "\"[[:space:]]*:[[:space:]]*[{]")) return "";
    start = RSTART + RLENGTH - 1;
    for (pos = start; pos <= length(value); pos++) {
      ch = substr(value, pos, 1);
      if (quoted) {
        if (escaped) escaped = 0;
        else if (ch == "\\") escaped = 1;
        else if (ch == "\"") quoted = 0;
      } else if (ch == "\"") quoted = 1;
      else if (ch == "{") depth++;
      else if (ch == "}") { depth--; if (depth == 0) return substr(value, start, pos - start + 1); }
    }
    return substr(value, start);
  }
  function credentialContent(value, lower, root, auths) {
    lower = tolower(value);
    sub(/^\357\273\277/, "", lower);
    if (lower ~ /(^|\n)[[:blank:]]*-----[[:blank:]]*(begin|end)[[:blank:]]+((rsa|ec|dsa|openssh|encrypted)[[:blank:]]+)?private key[[:blank:]]*-----[[:blank:]]*(\r?\n|$)/) return 1;
    if (lower ~ /(^|\n)[[:blank:]]*-----[[:blank:]]*(begin|end)[[:blank:]]+pgp private key block[[:blank:]]*-----[[:blank:]]*(\r?\n|$)/) return 1;
    if (lower ~ /(^|\n)[[:blank:]]*----[[:blank:]]*(begin|end)[[:blank:]]+ssh2[[:blank:]]+(encrypted[[:blank:]]+)?private key[[:blank:]]*----[[:blank:]]*(\r?\n|$)/) return 1;
    if (lower ~ /(^|\n)[[:blank:]]*putty-user-key-file-[123]:/) return 1;
    if (lower ~ /(^|\n)[[:blank:]]*(export[[:blank:]]+)?aws_(access_key_id|secret_access_key|session_token)[[:blank:]]*=[[:blank:]]*("[^"]|'[^']|[^[:space:]"'#;])/) return 1;
    root = lower;
    sub(/^[[:space:]]+/, "", root);
    while (root ~ /^(#[^\n]*|---[[:blank:]]*(#[^\n]*)?)\r?\n/) { sub(/^[^\n]*\n/, "", root); sub(/^[[:space:]]+/, "", root); }
    if (root ~ /^\{/) {
      if (root ~ /"aws_(access_key_id|secret_access_key|session_token)"[[:space:]]*:[[:space:]]*"[^"]/) return 1;
      if (root ~ /"(private_key|privatekey)"[[:space:]]*:[[:space:]]*"-----begin[[:blank:]]+((rsa|ec|dsa|openssh|encrypted)[[:blank:]]+)?private key-----(\\r)?\\n[a-z0-9+]/) return 1;
      auths = jsonObjectField(root, "auths");
      if (auths ~ /"(auth|identitytoken)"[[:space:]]*:[[:space:]]*"[^"]/) return 1;
      if (root ~ /"kind"[[:space:]]*:[[:space:]]*"config"/ && root ~ /"(users|clusters)"[[:space:]]*:[[:space:]]*\[/) return 1;
      if (root ~ /"type"[[:space:]]*:[[:space:]]*"(service_account|authorized_user)"/ && root ~ /"(private_key|refresh_token|client_secret)"[[:space:]]*:[[:space:]]*"[^"]/) return 1;
    }
    if (root ~ /^["']?(apiversion|kind|users|clusters|contexts|current-context|preferences|extensions)["']?[[:blank:]]*:/ && lower ~ /(^|\n)["']?kind["']?[[:blank:]]*:[[:blank:]]*["']?config["']?[[:blank:]]*(#[^\n]*)?(\r?\n|$)/ && lower ~ /(^|\n)["']?(users|clusters)["']?[[:blank:]]*:[[:blank:]]*(\[|(#[^\n]*)?\r?\n([[:blank:]]*(#[^\n]*)?\r?\n)*[[:blank:]]*-[[:space:]])/) return 1;
    return 0;
  }`
const denyCredentialContentAwk = `if (credentialContent(sample)) { printf "%s", "${CREDENTIAL_CONTENT_MESSAGE}"; exit ${CREDENTIAL_CONTENT_EXIT}; }`

const escaped = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const globCharClass = (character: string) => {
  const lower = character.toLowerCase(), upper = character.toUpperCase()
  return lower === upper ? character : `[${lower}${upper}]`
}
/** 路径解析后的远端目标还会检查同一边界，避免符号链接绕过。 */
const deniedPathCases = [
  '/dev|/dev/*|/sys|/sys/*',
  '/etc/shadow|/etc/gshadow|/etc/shadow-*|/etc/gshadow-*',
  ...credentialDirectories.flatMap((directory) => [`*/${directory}`, `*/${directory}/*`]),
  ...credentialBasenames.flatMap((name) => [`*/${name}`, `*/${name}.*`]),
  ...credentialNameSuffixes.map((suffix) => `*${suffix}`),
  ...credentialExtensions.map((extension) => '*.' + [...extension].map(globCharClass).join('')),
  ...sshKeyBasenames.map((name) => `*/${name}`),
].join('|')
const allowedProcCases = '/proc/meminfo|/proc/loadavg|/proc/uptime|/proc/cpuinfo|/proc/version|/proc/net/tcp|/proc/net/tcp6|/proc/net/udp|/proc/net/udp6'
const credentialPatterns = [
  new RegExp(`(?:^|/)(${credentialDirectories.map(escaped).join('|')})(?:/|$)`),
  new RegExp(`/(?:${credentialBasenames.map(escaped).join('|')})(?:\\..*)?$`),
  new RegExp(`(?:${credentialNameSuffixes.map(escaped).join('|')})$`),
  new RegExp(`\\.(?:${credentialExtensions.join('|')})$`, 'i'),
  new RegExp(`/(?:${sshKeyBasenames.join('|')})$`),
]

function filePath(value: unknown): string {
  const path = text(value, 'path', 2048)
  if (!path.startsWith('/')) throw new ReadParameterError('relative_path', '请使用目标上的绝对路径')
  const normalized = posix.normalize(path)
  if (/^\/(?:dev|sys)(?:\/|$)/.test(normalized)
    || /^\/etc\/(?:shadow|gshadow)(?:-|$)/.test(normalized)
    || credentialPatterns.some((pattern) => pattern.test(normalized))) {
    throw new ReadParameterError('path_denied', '该路径属于设备或凭据范围，内置读工具不开放')
  }
  return normalized
}

function pathPrelude(path: string): string {
  const failed = '{ printf "%s\\n" "目标路径不存在或无法解析，请使用绑定终端上的路径"; exit 2; }'
  return 'p=' + quote(path)
    + '; if command -v realpath >/dev/null 2>&1; then p=$(command realpath "$p" 2>/dev/null) || ' + failed
    + '; elif command -v readlink >/dev/null 2>&1; then p=$(command readlink -f "$p" 2>/dev/null) || ' + failed
    + '; else printf "%s\\n" "路径解析能力不可用"; exit 2; fi'
    + '; case "$p" in /*) ;; *) ' + failed + ';; esac'
    + '; case "$p" in ' + deniedPathCases + ') printf "%s\\n" "该路径属于设备或凭据范围，读取被拒绝"; exit 2;; esac'
    + '; case "$p" in ' + allowedProcCases + ') ;; /proc|/proc/*) printf "%s\\n" "该 /proc 接口尚未开放"; exit 2;; esac; '
}

/** 消费完整查询流但只保存限量行；最后一行携带源状态，避免 head/SIGPIPE 掩盖失败。 */
function checkedQuery(command: string, options: {
  limit: number; header?: string; filter?: string; record?: string; environment?: string
  emptyExit1?: 'header' | 'empty'
}): string {
  const script = String.raw`
    function collect(line) {
      if (!length(line)) return;
      nonempty++;
      ${options.header ? 'if (line ~ ' + options.header + ') { headers++; if (!header) header = line; return; }' : ''}
      ${options.filter ? 'if (' + (options.record ? 'line ~ ' + options.record : '1') + ') { split(line, fields); if (!(' + options.filter + ')) return; }' : ''}
      if (count < limit) rows[++count] = line;
    }
    { if (NR > 1) collect(previous); previous = $0; }
    END {
      ec = 3;
      if (previous ~ /^__ZTERM_QUERY_EXIT_[0-9]+__$/) {
        gsub(/[^0-9]/, "", previous); ec = previous + 0;
        ${options.emptyExit1 ? 'if (ec == 1 && ' + (options.emptyExit1 === 'header' ? 'headers > 0 && nonempty == headers' : 'nonempty == 0') + ') ec = 0;' : ''}
      }
      if (header) print header;
      for (i = 1; i <= count; i++) print rows[i];
      if (ec != 0) printf "查询执行失败（源退出码 %d）。\n", ec;
      exit ec;
    }`.trim().replace(/\s*\n\s*/g, ' ')
  return 'if ! command -v awk >/dev/null 2>&1; then printf "%s\\n" "查询能力不可用：需要 awk"; exit 127; fi; '
    + '{ ' + command + ' 2>&1; zterm_query_ec=$?; printf "\\n__ZTERM_QUERY_EXIT_%d__\\n" "$zterm_query_ec"; } | '
    + (options.environment ? options.environment + ' ' : '')
    + 'LC_ALL=C command awk -v limit=' + options.limit + ' ' + quote(script)
}

const sourceExitAwk = String.raw`
  ec = 3;
  if (match(trailer, /\n__ZTERM_SOURCE_EXIT_[0-9]+__\n$/)) {
    status = substr(trailer, RSTART, RLENGTH); size -= RLENGTH;
    gsub(/[^0-9]/, "", status); ec = status + 0;
  }`

function fileSample(reader: 'head' | 'tail', pathVariable: 'p' | 'f', bytes: number): string {
  return '{ command ' + reader + ' -c ' + bytes + ' "$' + pathVariable + '" 2>/dev/null; '
    + 'zterm_read_ec=$?; printf "\\n__ZTERM_SOURCE_EXIT_%d__\\n" "$zterm_read_ec"; } '
    + '| LC_ALL=C command od -An -v -tu1 | '
}

/** 在同一份样本上先分类再输出；NUL 保留为标志，不能经 Shell 变量静默丢失。 */
function inspectedTextSample(action: string): string {
  return String.raw`
    ${credentialContentAwk}
    BEGIN { for (i = 1; i < 256; i++) characters[i] = sprintf("%c", i); }
    {
      for (i = 1; i <= NF; i++) {
        value = $i + 0; size++;
        if (value == 0) binary = 1;
        chunk = chunk (value == 0 ? " " : characters[value]);
        if (size % 1024 == 0) { sample = sample chunk; chunk = ""; }
      }
    }
    END {
      sample = sample chunk;
      trailer = substr(sample, length(sample) > 48 ? length(sample) - 47 : 1);
      ${sourceExitAwk}
      sample = substr(sample, 1, size);
      ${action}
    }`.trim().replace(/\s*\n\s*/g, ' ')
}

/** 尾窗可能看不到文件头；额外有界检查前缀，只输出固定失败文字，不返回样本。 */
function credentialPrefixGuard(): string {
  const script = inspectedTextSample(String.raw`
    if (ec != 0) { printf "凭据类型检查读取失败（源退出码 %d）。\n", ec; exit ec; }
    ${denyCredentialContentAwk}
    exit 0;`)
  return fileSample('head', 'p', SOURCE_BYTES)
    + 'LC_ALL=C command awk ' + quote(script)
    + '; zterm_check_ec=$?; if [ "$zterm_check_ec" -ne 0 ]; then exit "$zterm_check_ec"; fi; '
}

/** 样本通过 od 保留 NUL；完整检查样本后才返回字面命中及源读取状态。 */
function checkedTextSearch(matches: number): string {
  const script = inspectedTextSample(String.raw`
    if (ec != 0) { printf "文本搜索读取失败（源退出码 %d）。\n", ec; exit ec; }
    ${denyCredentialContentAwk}
    if (!binary) {
      lines = split(sample, rows, "\n");
      for (i = 1; i <= lines && count < limit; i++) {
        if (index(rows[i], ENVIRON["ZTERM_READ_QUERY"])) { print i ":" rows[i]; count++; }
      }
    }
    exit 0;`)
  return fileSample('head', 'f', SOURCE_BYTES)
    + 'ZTERM_READ_QUERY="$q" LC_ALL=C command awk -v limit=' + matches + ' ' + quote(script)
}

/** od 保留 NUL 和换行；只在有界样本中统计行数，不扫描完整大文件、不写远端临时文件。 */
function fileWindowCommand(start: number, lines: number, fromEnd: boolean): string {
  const script = String.raw`
    ${credentialContentAwk}
    function prefix(s, cap) {
      while (cap > 0 && substr(s, cap + 1, 1) ~ /[\200-\277]/) cap--;
      return substr(s, 1, cap);
    }
    function suffix(s, cap, pos) {
      pos = length(s) - cap + 1;
      while (pos <= length(s) && substr(s, pos, 1) ~ /[\200-\277]/) pos++;
      return substr(s, pos);
    }
    { for (i = 1; i <= NF; i++) bytes[++size] = $i + 0; }
    END {
      for (i = (size > 48 ? size - 48 : 1); i <= size; i++) trailer = trailer sprintf("%c", bytes[i]);
      ${sourceExitAwk}
      for (i = 1; i <= size; i++) {
        chunk = chunk (bytes[i] == 0 ? " " : sprintf("%c", bytes[i]));
        if (i % 1024 == 0) { sample = sample chunk; chunk = ""; }
      }
      sample = sample chunk;
      if (ec == 0) { ${denyCredentialContentAwk} }
      limited = size > sourceLimit; observed = limited ? sourceLimit : size;
      lo = tail && limited ? size - sourceLimit + 1 : 1;
      hi = tail ? size : observed;
      for (i = lo; i <= hi; i++) if (bytes[i] == 0) binary = 1;
      if (!tail && limited) {
        pos = hi;
        while (pos >= lo && bytes[pos] >= 128 && bytes[pos] < 192) pos--;
        width = bytes[pos] >= 240 && bytes[pos] < 245 ? 4 : bytes[pos] >= 224 && bytes[pos] < 240 ? 3 : bytes[pos] >= 194 && bytes[pos] < 224 ? 2 : 1;
        if (hi - pos + 1 < width) hi = pos - 1;
      }
      if (tail && limited && bytes[lo - 1] != 10) {
        partialFirst = 1;
        for (i = lo; i < hi; i++) if (bytes[i] == 10) { lo = i + 1; partialFirst = 0; break; }
      }
      if (!binary && ec == 0) {
        for (i = lo; i <= hi; i++) {
          if (bytes[i] == 10) { row[++n] = line; line = ""; }
          else line = line sprintf("%c", bytes[i]);
        }
        if (length(line)) { row[++n] = line; if (!tail && limited) partialLast = 1; }
        first = tail ? (n > maxLines ? n - maxLines + 1 : 1) : startLine;
        last = tail ? n : (n < first + maxLines - 1 ? n : first + maxLines - 1);
        lineLimited = tail ? first > 1 : last < n;
        for (i = tail ? last : first; tail ? i >= first : i <= last; i += tail ? -1 : 1) {
          value = (tail ? "" : i ":") row[i] "\n"; room = outputLimit - length(out);
          if (length(value) > room) {
            outputLimited = 1;
            if (returned == 0) {
              value = tail ? suffix(value, room) : prefix(value, room);
              out = value; returned = 1; firstOut = lastOut = i;
              if (tail) partialOutputFirst = 1; else partialOutputLast = 1;
            }
            break;
          }
          out = tail ? value out : out value; returned++;
          if (!firstOut || i < firstOut) firstOut = i;
          if (i > lastOut) lastOut = i;
        }
        if (firstOut > 1) partialFirst = 0;
        if (lastOut < n) partialLast = 0;
        partialFirst = partialFirst || partialOutputFirst;
        partialLast = partialLast || partialOutputLast;
      }
      printf "__ZTERM_FILE_V1__|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d\n", observed, n, limited, binary, ec, firstOut, lastOut, returned, partialFirst, partialLast, lineLimited, outputLimited, size;
      printf "%s", out;
      exit ec;
    }`.trim().replace(/\s*\n\s*/g, ' ')
  const reader = fromEnd ? 'tail' : 'head'
  return 'if ! command -v od >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1; then printf "%s\\n" "文件查询能力不可用：需要 od 和 awk"; exit 127; fi; '
    + (fromEnd ? credentialPrefixGuard() : '')
    + fileSample(reader, 'p', SOURCE_BYTES + 1) + 'LC_ALL=C command awk '
    + '-v sourceLimit=' + SOURCE_BYTES + ' -v outputLimit=' + FILE_OUTPUT_BYTES
    + ' -v startLine=' + start + ' -v maxLines=' + lines + ' -v tail=' + Number(fromEnd) + ' ' + quote(script)
}

/** 仅由六个固定操作生成命令，未知字段和非枚举参数无法进入执行链路。 */
export function prepareBuiltinRead(name: string, params: Record<string, unknown>): PreparedRead {
  const definition = definitions.find((item) => item.name === name)
  if (!definition) throw new Error('未知内置读工具')
  if (!params || typeof params !== 'object' || Array.isArray(params)) throw new Error('查询参数格式无效')
  const allowed = Object.keys(definition.parameters.properties)
  if (Object.keys(params).some((key) => !allowed.includes(key))) throw new Error('查询包含未支持的参数')
  let command: string
  let scope = '当前绑定目标'
  let fileWindow: PreparedRead['fileWindow']

  switch (name) {
    case 'read_bound_directory': {
      const path = params.path === undefined ? '.' : filePath(params.path)
      const limit = integer(params.limit, 50, 1, 200)
      command = pathPrelude(path)
        + 'if [ ! -d "$p" ]; then printf "%s\\n" "路径不是目录"; exit 2; fi; '
        + 'printf "目录：%s\\n" "$p"; '
        + checkedQuery('LC_ALL=C command ls -lna "$p"', { limit: limit + 3 })
      scope += '，目录直接子项，最多 ' + limit + ' 项'
      break
    }
    case 'read_bound_file': {
      const path = filePath(params.path)
      const start = integer(params.start_line, 1, 1, 10000)
      const lines = integer(params.max_lines, 100, 1, 500)
      const fromEnd = boolean(params.from_end, false)
      if (fromEnd && start !== 1) throw new Error('读取末尾时不能同时指定 start_line')
      fileWindow = { startLine: start, fromEnd }
      command = pathPrelude(path)
        + 'if [ ! -f "$p" ] || [ ! -r "$p" ]; then printf "%s\\n" "路径不是可读普通文件"; exit 2; fi; '
        + fileWindowCommand(start, lines, fromEnd)
      scope += fromEnd ? '，文件末尾窗口，最多 64 KiB；另检查前 64 KiB 的凭据类型' : '，文件开头 64 KiB 内的行窗口'
      break
    }
    case 'search_bound_text': {
      const path = filePath(params.path)
      const query = text(params.query, 'query', 256)
      const matches = integer(params.max_matches, 30, 1, 100)
      command = pathPrelude(path) + 'q=' + quote(query) + '; count=0; unread=0; credentials=0; directory=0; '
        + 'if [ ! -r "$p" ] || { [ -d "$p" ] && [ ! -x "$p" ]; }; then printf "%s\\n" "搜索路径不可读或目录不可访问"; exit 2; fi; '
        + 'if ! command -v od >/dev/null 2>&1 || ! command -v awk >/dev/null 2>&1; then printf "%s\\n" "文本搜索能力不可用：需要 od 和 awk"; exit 127; fi; '
        + 'if [ -f "$p" ]; then set -- "$p"; elif [ -d "$p" ]; then directory=1; set -- "$p"/* "$p"/.[!.]* "$p"/..?*'
        + '; else printf "%s\\n" "路径不是普通文件或目录"; exit 2; fi; '
        + 'for f do [ -f "$f" ] && [ ! -L "$f" ] || continue; '
        + 'case "$f" in ' + deniedPathCases + ') continue;; esac; '
        + 'if [ ! -r "$f" ]; then unread=$((unread+1)); continue; fi; '
        + '[ "$count" -lt 100 ] || break; count=$((count+1)); '
        + 'hits=$(' + checkedTextSearch(matches) + '); ec=$?; '
        + 'if [ "$ec" -eq ' + CREDENTIAL_CONTENT_EXIT + ' ] && [ "$hits" = ' + quote(CREDENTIAL_CONTENT_MESSAGE) + ' ] && [ "$directory" -eq 1 ]; then credentials=$((credentials+1)); continue; fi; '
        + 'if [ "$ec" -ne 0 ]; then printf "%s" "$hits"; exit "$ec"; fi; '
        + 'if [ -n "$hits" ]; then printf "\\nFILE %s\\n%s\\n" "$f" "$hits"; fi; '
        + 'done; printf "\\n搜索范围：已检查 %s 个文件，跳过 %s 个不可读文件，跳过 %s 个凭据内容文件。\\n" "$count" "$unread" "$credentials"; exit 0'
      scope += '，非递归字面搜索，最多 100 个文件，每文件前 64 KiB'
      break
    }
    case 'read_bound_system':
      command = 'printf "%s\\n" "=== 目标当前目录 ==="; command pwd -P; '
        + 'printf "%s\\n" "=== 系统 ==="; command uname -s; command uname -r; '
        + 'if [ -r /etc/os-release ]; then command head -n 12 /etc/os-release; fi; '
        + 'printf "%s\\n" "=== CPU ==="; printf "%s" "在线逻辑 CPU："; '
        + 'command getconf _NPROCESSORS_ONLN 2>/dev/null || printf "%s\\n" "未知"; '
        + 'if [ -r /proc/cpuinfo ]; then command head -c 65536 /proc/cpuinfo | LC_ALL=C command awk -F: '
        + quote('!found && /^(model name|Hardware|Processor)[[:space:]]*:/ { print "CPU 型号：" $2; found=1 }') + '; '
        + 'elif command -v sysctl >/dev/null 2>&1; then command sysctl -n hw.model 2>/dev/null || :; fi; '
        + 'printf "%s\\n" "=== 运行时间与负载 ==="; command uptime; '
        + 'printf "%s\\n" "=== 内存 ==="; '
        + 'if [ -r /proc/meminfo ]; then command head -n 8 /proc/meminfo; '
        + 'elif command -v vm_stat >/dev/null 2>&1; then command vm_stat; '
        + 'else printf "%s\\n" "内存查询能力不可用"; fi; '
        + 'printf "%s\\n" "=== 磁盘 ==="; ' + checkedQuery('command df -Pk', { limit: 40 })
      break
    case 'list_bound_processes': {
      const limit = integer(params.limit, 50, 1, 200)
      const pid = params.pid === undefined ? undefined : integer(params.pid, 1, 1, 2147483647)
      const nameFilter = params.name === undefined ? undefined : text(params.name, 'name', 128)
      command = checkedQuery('LC_ALL=C command ps ' + (pid ? '-p ' + pid : '-e')
        + ' -o pid,ppid,user,stat,pcpu,pmem,comm', {
        limit, header: '/^[[:space:]]*PID[[:space:]]+PPID[[:space:]]+USER[[:space:]]/',
        ...(pid ? { emptyExit1: 'header' as const } : {}),
        ...(nameFilter ? { environment: 'ZTERM_QUERY_NAME=' + quote(nameFilter),
          record: '/^[[:space:]]*[0-9]+[[:space:]]/', filter: 'index(line, ENVIRON["ZTERM_QUERY_NAME"]) > 0' } : {}),
      })
      scope += '，当前账号可见进程，最多 ' + limit + ' 项'
      break
    }
    case 'list_bound_sockets': {
      const protocol = params.protocol ?? 'all'
      if (!['all', 'tcp', 'udp'].includes(protocol as string)) throw new Error('protocol 必须是 all、tcp 或 udp')
      const port = params.local_port === undefined ? undefined : integer(params.local_port, 1, 1, 65535)
      const listening = boolean(params.listening_only, true)
      const limit = integer(params.limit, 50, 1, 200)
      const ssQuery = checkedQuery('LC_ALL=C command ss -H -n -t -u -p' + (listening ? ' -l' : ' -a')
        + (port ? ' ' + quote('sport = :' + port) : ''), { limit,
        ...(protocol !== 'all' ? { record: '/^(tcp|udp)[[:space:]]/', filter: 'fields[1] == "' + protocol + '"' } : {}),
      })
      const lsofQueries = (['tcp', 'udp'] as const).filter((kind) => protocol === 'all' || protocol === kind)
        .map((kind) => checkedQuery('LC_ALL=C command lsof -nP +c 0 -i' + kind.toUpperCase()
          + (port ? ':' + port : '') + (kind === 'tcp' && listening ? ' -sTCP:LISTEN' : ''), {
            limit, header: '/^COMMAND[[:space:]]/', emptyExit1: 'empty',
            ...(port || kind === 'udp' && listening ? { record: '/^[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]/',
              filter: (port ? 'fields[9] ~ /^[^>]*:' + port + '(->|$)/' : '1')
                + (kind === 'udp' && listening ? ' && fields[9] !~ /->/' : '') } : {}),
          }) + '; zterm_socket_ec=$?; if [ "$zterm_socket_ec" -ne 0 ]; then exit "$zterm_socket_ec"; fi')
        .join('; ')
      command = 'if command -v ss >/dev/null 2>&1; then ' + ssQuery
        + '; elif command -v lsof >/dev/null 2>&1; then ' + lsofQueries
        + '; else printf "%s\\n" "ss/lsof: command not found；本环境暂不支持端口查询"; exit 127; fi'
      scope += '，当前网络命名空间，进程信息受账号权限限制'
      break
    }
    default: throw new Error('未知内置读工具')
  }
  const label = definition.label + (params.path ? '：' + String(params.path)
    : params.local_port ? '：' + String(params.local_port) : '')
  const request = fileWindow
  return { toolName: name, label, command, scope, fileWindow,
    summarizeOutput: request ? (output) => {
      const parsed = fileResult(output, request)
      return { text: parsed?.displayOutput ?? output, truncated: !!parsed?.reasons.length }
    } : undefined,
  }
}

function socketRecords(output: string): Array<Record<string, unknown>> | undefined {
  const records: Array<Record<string, unknown>> = []
  for (const line of output.split('\n')) {
    const words = line.trim().split(/\s+/)
    if (!line.trim() || words[0] === 'COMMAND') continue
    if (words[0] === 'tcp' || words[0] === 'udp') {
      if (words.length < 6) return undefined
      const process = words.slice(6).join(' ')
      const pid = process.match(/pid=(\d+)/)?.[1]
      const endpoint = words[4]
      const separator = endpoint.lastIndexOf(':')
      records.push({
        protocol: words[0], state: words[1],
        localAddress: separator < 0 ? endpoint : endpoint.slice(0, separator),
        localPort: separator < 0 || !/^\d+$/.test(endpoint.slice(separator + 1))
          ? null : Number(endpoint.slice(separator + 1)),
        peer: words[5],
        pid: pid ? Number(pid) : null,
        processInfo: process || null,
      })
    } else if (/^\d+$/.test(words[1] ?? '') && ['TCP', 'UDP'].includes(words[7])) {
      const endpoint = words[8]?.split('->')[0] ?? ''
      const separator = endpoint.lastIndexOf(':')
      records.push({
        protocol: words[7].toLowerCase(), state: line.match(/\(([^)]+)\)$/)?.[1] ?? 'BOUND',
        localAddress: endpoint.slice(0, separator),
        localPort: /^\d+$/.test(endpoint.slice(separator + 1)) ? Number(endpoint.slice(separator + 1)) : null,
        pid: Number(words[1]), processInfo: words[0],
        peer: words[8]?.split('->')[1] ?? null,
      })
    } else return undefined
  }
  // 未识别行已在上方回退为文本；仅有表头或空输出可明确表示没有记录。
  return records
}

/** 所有读工具使用一个返回信封；界面使用 displayOutput，无需解析 shell 文本。 */
export function readResultText(
  tool: string,
  scope: string,
  data: Record<string, unknown>,
  metadata: { status: 'ok' | 'error'; exitCode?: number | null; truncated?: boolean; warnings?: string[];
    error?: ReadError | null; truncationReasons?: ReadTruncationReason[] },
): string {
  const failed = metadata.status === 'error'
  // 内容/协议失败没有可用正文：不把成功的底层采样退出码或丢弃的样本表述为读取成功。
  // 原始命令退出码由执行记录保留；此信封中失败只能带非零退出码或 null。
  const reasons = failed ? [] : [...new Set(metadata.truncationReasons ?? (metadata.truncated ? ['output_chars'] : []))]
  return JSON.stringify({ version: 1, tool, scope, observedAt: new Date().toISOString(),
    status: metadata.status, exitCode: failed && metadata.exitCode === 0 ? null : metadata.exitCode ?? null,
    error: metadata.status === 'ok' ? null : metadata.error ?? { code: 'read_failed', phase: 'execution', message: '读取失败' },
    truncated: reasons.length > 0, truncationReasons: reasons, warnings: metadata.warnings ?? [], data })
}

function executionError(message: string): ReadError {
  const codes: Array<[RegExp, string]> = [
    [/设备或凭据/, 'path_denied'], [/不存在或无法解析/, 'path_not_found'],
    [/路径不是目录/, 'not_a_directory'], [/路径不是可读普通文件/, 'not_a_readable_file'],
    [/\/proc 接口尚未开放/, 'unsupported_path'], [/能力不可用|command not found|暂不支持/, 'capability_unavailable'],
  ]
  return { code: codes.find(([pattern]) => pattern.test(message))?.[1] ?? 'command_failed', phase: 'execution', message }
}

function fileResult(output: string, request: NonNullable<PreparedRead['fileWindow']>) {
  const boundary = output.indexOf('\n')
  const fields = output.slice(0, boundary).split('|')
  if (boundary < 0 || fields[0] !== '__ZTERM_FILE_V1__' || fields.length !== 14
    || fields.slice(1).some((value) => !/^\d+$/.test(value))) return null
  const [bytesRead, windowLines, sourceLimited, binary, sourceExit, first, last, count, partialFirst, partialLast, lineLimited, outputLimited] = fields.slice(1).map(Number)
  const reasons: ReadTruncationReason[] = []
  if (sourceLimited) reasons.push('source_bytes')
  if (lineLimited) reasons.push('max_lines')
  if (outputLimited) reasons.push('output_bytes')
  const totalLines = sourceLimited || binary || sourceExit ? null : windowLines
  let error: ReadError | null = null
  let emptyReason: string | null = null
  if (sourceExit) error = { code: 'file_read_failed', phase: 'execution', message: '文件读取失败，目标可能已变化或无法访问。' }
  else if (binary) error = { code: 'binary_not_supported', phase: 'content', message: '文件样本包含 NUL 字节，当前文本读取不支持二进制数据。' }
  else if (bytesRead === 0) emptyReason = 'empty_file'
  else if (!count) error = sourceLimited
    ? { code: 'outside_source_window', phase: 'content', message: '请求行号 ' + request.startLine + ' 超出本次 64 KiB 读取窗口，文件总行数未知。' }
    : { code: 'line_out_of_range', phase: 'content', message: '行号 ' + request.startLine + ' 超出文件总行数 ' + totalLines + '。' }
  const absolute = !request.fromEnd || !sourceLimited
  const nextStartLine = !error && !request.fromEnd && !partialLast && count && last < windowLines && last < 10000 ? last + 1 : null
  const text = error?.message ?? output.slice(boundary + 1)
  return { error, reasons: binary ? [] : reasons,
    data: { format: 'file', text, emptyReason, bytesRead, sourceByteLimit: SOURCE_BYTES,
      outputByteLimit: FILE_OUTPUT_BYTES, linesReturned: count, totalLines,
      firstLine: absolute && count ? first : null, lastLine: absolute && count ? last : null,
      lineNumberBasis: absolute ? 'file' : 'window', windowFirstLine: count ? first : null,
      windowLastLine: count ? last : null, windowLines, direction: request.fromEnd ? 'end' : 'start',
      partialFirstLine: !!partialFirst, partialLastLine: !!partialLast,
      hasMore: binary || sourceExit ? null : reasons.length > 0,
      nextStartLine, canContinue: nextStartLine !== null,
      binaryDetection: binary ? { method: 'nul_in_sample', sampleBytes: bytesRead, sampleLimited: !!sourceLimited } : null },
    displayOutput: error?.message ?? (emptyReason ? '文件为空。' : text),
  }
}

export function createBuiltinReadTools(execute: ReadExecutor): ToolDefinition[] {
  return definitions.map((definition) => defineTool({
    ...definition,
    executionMode: 'sequential',
    async execute(toolCallId, params, signal) {
      let prepared: PreparedRead | undefined
      const result = await execute(toolCallId, () => {
        prepared = prepareBuiltinRead(definition.name, params as Record<string, unknown>)
        return prepared
      }, signal)
      const output = result.details.output
      if (output === undefined || result.details.fidelity !== 'verified') {
        const message = result.content.filter((item) => item.type === 'text').map((item) => item.text).join('\n')
        const displayOutput = prepared ? message.replaceAll(prepared.command, prepared.label) : message
        const error: ReadError = { code: result.details.readErrorCode ?? result.details.error ?? result.details.reason
          ?? (result.details.fidelity ? 'execution_unverified' : 'read_failed'),
          phase: result.details.error === 'invalid_read_parameters' ? 'validation' : result.details.fidelity ? 'protocol' : 'execution',
          message: displayOutput }
        return { ...result,
          content: [{ type: 'text', text: readResultText(definition.name, prepared?.scope ?? '当前绑定目标',
            { format: 'text', text: displayOutput }, { status: 'error', exitCode: result.details.fidelity === 'verified' ? result.details.exitCode : null,
              error, truncationReasons: result.details.truncationReasons }) }],
          details: { ...result.details, displayOutput, command: prepared?.label ?? definition.label },
        }
      }
      if (result.details.exitCode === CREDENTIAL_CONTENT_EXIT && output.trim() === CREDENTIAL_CONTENT_MESSAGE) {
        const error: ReadError = { code: 'credential_content_denied', phase: 'content', message: CREDENTIAL_CONTENT_MESSAGE }
        return { ...result,
          content: [{ type: 'text', text: readResultText(definition.name, prepared?.scope ?? '当前绑定目标',
            { format: prepared?.fileWindow ? 'file' : 'text', text: CREDENTIAL_CONTENT_MESSAGE },
            { status: 'error', exitCode: CREDENTIAL_CONTENT_EXIT, error }) }],
          details: { ...result.details, output: undefined, command: prepared?.label ?? definition.label,
            displayOutput: CREDENTIAL_CONTENT_MESSAGE, truncated: false, truncationReasons: [], readErrorCode: error.code },
        }
      }
      if (prepared?.fileWindow && (result.details.exitCode === 0 || output.startsWith('__ZTERM_FILE_V1__|'))) {
        const parsed = fileResult(output, prepared.fileWindow)
        const error: ReadError | null = parsed?.error ?? (parsed ? null : { code: 'file_metadata_unavailable', phase: 'protocol',
          message: '文件读取元数据缺失或被截断，不能确认文件内容和读取区间。' })
        const reasons = [...new Set([...(result.details.truncationReasons ?? []), ...(parsed?.reasons ?? [])])]
        const displayOutput = parsed?.displayOutput ?? error!.message
        return { ...result,
          content: [{ type: 'text', text: readResultText(definition.name, prepared.scope,
            parsed?.data ?? { format: 'file', text: displayOutput },
            { status: error ? 'error' : 'ok', exitCode: result.details.exitCode, error, truncationReasons: reasons }) }],
          details: { ...result.details, output: undefined, command: prepared.label, displayOutput,
            truncated: reasons.length > 0, truncationReasons: reasons, binary: error?.code === 'binary_not_supported' },
        }
      }
      const binary = output.includes('\x00')
      const noProcesses = definition.name === 'list_bound_processes'
        && !output.split('\n').some((line) => line.trim() && !/^\s*PID\s+PPID\s+USER\s+/.test(line))
      const displayOutput = binary ? '文件包含二进制数据，当前文本读取不支持。'
        : noProcesses ? '未找到匹配进程。' : output || '(当前范围内没有结果)'
      const records = definition.name === 'list_bound_sockets' && !binary ? socketRecords(output) : undefined
      const details = { ...result.details, command: prepared?.label ?? definition.label,
        displayOutput, output: undefined, toolName: definition.name, scope: prepared?.scope,
        observedAt: new Date().toISOString(), binary, sourceByteLimit: SOURCE_BYTES,
        warnings: definition.name === 'list_bound_sockets' ? ['所属进程信息可能受权限限制；查询范围是当前网络命名空间'] : [] }
      return {
        ...result,
        content: [{ type: 'text', text: readResultText(definition.name, prepared?.scope ?? '当前绑定目标',
          records === undefined ? { format: 'text', text: binary ? displayOutput : output.slice(0, OUTPUT_CHARS),
            noMatches: noProcesses }
            : { format: 'sockets', records, noMatches: records.length === 0 },
          { status: binary || details.exitCode !== 0 ? 'error' : 'ok', exitCode: details.exitCode,
            error: binary ? { code: 'binary_not_supported', phase: 'content', message: displayOutput }
              : details.exitCode !== 0 ? executionError(displayOutput) : null,
            truncationReasons: binary ? [] : details.truncationReasons, truncated: !binary && details.truncated, warnings: details.warnings }) }],
        details,
      }
    },
  }))
}
