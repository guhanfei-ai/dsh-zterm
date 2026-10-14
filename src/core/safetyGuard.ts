/** 移植自 zterm 0.4.1，MIT；来源见 THIRD_PARTY_NOTICES.md。 */
import { posix } from 'node:path'

// Agent 命令是受限的 shell 语言，不是任意脚本执行入口。
// 保留参数与重定向语义；无法证明安全的展开、解释器和语法一律拒绝。
export interface SafetyCheck {
  safe: boolean
  blocked: boolean
  isWrite: boolean
  isUnknown: boolean
  reason?: string
  category?: string
}

interface Word { value: string; dynamic: boolean }
interface Segment { words: Word[]; redirects: Array<{ op: string; target: Word }> }

function denied(reason: string, category = '权限控制', isWrite = false, isUnknown = false): SafetyCheck {
  return { safe: false, blocked: true, isWrite, isUnknown, reason, category }
}

function isProtectedWritePath(value: string): boolean {
  const path = posix.normalize(value)
  return /^\/(?:etc|proc|sys)(?:\/|$)/.test(path) || /^\/dev\/(?!null$)/.test(path)
}

/** 只解析普通参数、管道和串联；不模拟完整 shell，也不执行任何展开。 */
function parseCommands(command: string): Segment[] | null {
  const segments: Segment[] = []
  let segment: Segment = { words: [], redirects: [] }
  let word = ''
  let active = false
  let dynamic = false
  let quote = ''
  let redirect: string | null = null
  const pushWord = (): boolean => {
    if (!active) return true
    const token = { value: word, dynamic }
    if (redirect) { segment.redirects.push({ op: redirect, target: token }); redirect = null }
    else segment.words.push(token)
    word = ''; active = false; dynamic = false
    return true
  }
  const pushSegment = (): boolean => {
    pushWord()
    if (redirect || !segment.words.length) return false
    segments.push(segment)
    segment = { words: [], redirects: [] }
    return true
  }
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]
    if (quote === "'") {
      if (ch === "'") quote = ''
      else word += ch
      continue
    }
    if (ch === '\\') {
      if (++i >= command.length) return null
      const next = command[i]
      // 双引号内只有这些字符可由反斜杠转义；其余反斜杠属于参数。
      if (quote === '"' && !['$', '`', '"', '\\'].includes(next)) word += '\\'
      word += next; active = true
      continue
    }
    if (quote === '"' && ch === '"') { quote = ''; continue }
    if (!quote && (ch === "'" || ch === '"')) { quote = ch; active = true; continue }
    if (ch === '`' || ch === '$') {
      // 仅保留简单环境变量作为只读路径参数；拒绝命令替换与参数运算。
      const variable = command.slice(i).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})/)
      if (ch !== '$' || !variable) return null
      word += variable[0]; i += variable[0].length - 1; dynamic = true; active = true
      continue
    }
    if (quote) { word += ch; continue }
    if (ch !== '\n' && /\s/.test(ch)) { pushWord(); continue }
    if (ch === '#' && !active) break
    if (ch === '(' || ch === ')' || ch === '{' || ch === '}') return null
    if (ch === '>' || ch === '<') {
      // fd 前缀属于重定向，而不是普通参数。
      if (active && /^\d+$/.test(word)) { word = ''; active = false }
      else pushWord()
      if (redirect) return null
      let op = ch
      if (command[i + 1] === ch || command[i + 1] === '&' || command[i + 1] === '|') op += command[++i]
      if (op === '<<' || op === '<>' || op === '>|') return null
      redirect = op
      continue
    }
    if (ch === ';' || ch === '|' || ch === '&' || ch === '\n') {
      if (redirect || !pushSegment()) return null
      if ((ch === '|' || ch === '&') && command[i + 1] === ch) i++
      // 后台执行不能由前台结束标记证明其副作用已结束。
      else if (ch === '&') return null
      continue
    }
    if ('*?[]~'.includes(ch)) dynamic = true
    word += ch; active = true
  }
  if (quote) return null
  pushWord()
  if (redirect) return null
  if (segment.words.length) segments.push(segment)
  return segments.length ? segments : null
}

const READ_COMMANDS = new Set([
  'ls', 'cat', 'head', 'tail', 'wc', 'file', 'stat', 'md5sum', 'sha256sum',
  'grep', 'egrep', 'fgrep', 'rg', 'which', 'whereis', 'locate', 'ps', 'free',
  'df', 'du', 'uname', 'uptime', 'w', 'who', 'whoami', 'id', 'cal', 'lscpu',
  'lsmem', 'lspci', 'lsusb', 'lsblk', 'netstat', 'ss', 'ping', 'traceroute',
  'dig', 'nslookup', 'host', 'printenv', 'echo', 'printf', 'type', 'apropos',
  'cut', 'tr', 'paste', 'test', '[', 'true', 'false', 'lsof', 'readelf',
  'objdump', 'nm', 'strings', 'od', 'hexdump', 'pwd', 'realpath', 'readlink',
])
const WRITE_COMMANDS = new Set([
  'rm', 'mkdir', 'cp', 'mv', 'touch', 'ln', 'install', 'chmod', 'chown', 'chgrp',
  'useradd', 'usermod', 'userdel', 'groupadd', 'groupdel', 'passwd', 'kill',
  'killall', 'pkill', 'vgcreate', 'lvcreate', 'mount', 'tee', 'export', 'unset',
  'iptables', 'crontab',
])
const CODE_COMMANDS = new Set(['awk', 'gawk', 'mawk', 'sed', 'xargs', 'sh', 'bash', 'zsh', 'dash', 'fish', 'perl', 'python', 'python3', 'node', 'eval', 'exec', 'source', '.', 'export', 'unset'])

function commandKind(words: Word[]): 'read' | 'write' | 'unknown' {
  const [head, ...args] = words.map((w) => w.value)
  if (!head || words[0].dynamic || head.includes('/')) return 'unknown'
  if (CODE_COMMANDS.has(head)) return 'unknown'
  if (head === 'cd') return args.length <= 1 ? 'read' : 'unknown'
  if (head === 'env') return args.every((a) => ['-0', '--null'].includes(a)) ? 'read' : 'unknown'
  if (head === 'command') return args[0] === '-v' && args.slice(1).every((a) => !a.startsWith('-')) ? 'read' : 'unknown'
  if (head === 'find') {
    if (args.some((a) => /^-(?:exec|execdir|ok|okdir)$/.test(a))) return 'unknown'
    if (args.some((a) => /^-(?:delete|fprint|fprint0|fprintf|fls)$/.test(a))) return 'write'
    return 'read'
  }
  if (head === 'git') {
    const [verb, ...rest] = args
    if (['status', 'log', 'diff', 'show', 'blame', 'describe', 'shortlog'].includes(verb)) {
      return rest.some((a) => /^(?:--output(?:=|$)|--ext-diff|--textconv|--exec-path)/.test(a)) ? 'unknown' : 'read'
    }
    if (verb === 'reflog') return !rest.length || rest[0] === 'show' ? 'read' : 'write'
    if (verb === 'stash') return rest[0] === 'list' ? 'read' : 'write'
    if (verb === 'config') return ['--get', '--get-all', '--get-regexp', '--list', '-l'].includes(rest[0]) ? 'read' : 'write'
    if (verb === 'branch' || verb === 'tag') {
      return rest.every((a) => /^(?:-a|-r|-v|-vv|-l|--all|--list|--show-current)$/.test(a)) ? 'read' : 'write'
    }
    if (verb === 'remote') return rest.every((a) => a === '-v' || a === '--verbose') ? 'read' : 'write'
    if (verb === 'clean') return rest.some((a) => a === '--dry-run' || /^-[a-z]*n[a-z]*$/.test(a)) ? 'read' : 'write'
    return ['add', 'commit', 'push', 'merge', 'rebase', 'reset', 'checkout', 'switch', 'cherry-pick', 'restore', 'fetch', 'pull', 'rm', 'mv', 'init', 'clone'].includes(verb) ? 'write' : 'unknown'
  }
  if (head === 'docker') {
    const [verb, sub] = args
    if (['ps', 'images', 'logs', 'inspect', 'top', 'stats', 'version', 'info', 'history', 'diff', 'port'].includes(verb)) return 'read'
    if (verb === 'compose') return ['ps', 'logs'].includes(sub) ? 'read' : 'unknown'
    return ['rm', 'rmi', 'run', 'exec', 'start', 'stop', 'restart', 'pause', 'unpause', 'kill', 'build', 'push', 'pull', 'tag', 'save', 'load'].includes(verb) ? 'write' : 'unknown'
  }
  if (head === 'systemctl') return /^(?:status|list-[a-z-]+|is-active|is-enabled|is-failed|show)$/.test(args[0]) ? 'read' : /^(?:start|stop|restart|enable|disable|mask|unmask)$/.test(args[0]) ? 'write' : 'unknown'
  if (head === 'service') return args[1] === 'status' ? 'read' : ['start', 'stop', 'restart'].includes(args[1]) ? 'write' : 'unknown'
  if (head === 'ip') return ['addr', 'address', 'link', 'route', 'neigh'].includes(args[0]) && args[1] === 'show' ? 'read' : ['add', 'del', 'set', 'replace', 'change', 'flush'].includes(args[1]) ? 'write' : 'unknown'
  if (head === 'ifconfig') return args.length <= 1 ? 'read' : 'write'
  if (head === 'hostname') return args.every((a) => ['-f', '-s', '-d', '-i', '-I', '-a', '-A', '--fqdn'].includes(a)) ? 'read' : 'write'
  if (head === 'date') return args.some((a) => a === '-s' || a.startsWith('--set') || /^\d/.test(a)) ? 'write' : 'read'
  if (head === 'journalctl') return args.some((a) => /^--(?:rotate|vacuum|flush|sync|relinquish|setup-keys|update-catalog)/.test(a)) ? 'write' : 'read'
  if (head === 'dmesg') return args.some((a) => /^--(?:clear|read-clear|console)/.test(a) || /^-[a-zA-Z]*[cCnD][a-zA-Z]*$/.test(a)) ? 'write' : 'read'
  if (head === 'ss' && args.some((a) => a === '--kill' || /^-[a-zA-Z]*K/.test(a))) return 'write'
  if (head === 'sort') return args.some((a) => /^-o|^--output/.test(a)) ? 'write' : 'read'
  if (head === 'uniq' || head === 'xxd') return args.some((a) => a === '-r') || args.filter((a) => !a.startsWith('-')).length > 1 ? 'write' : 'read'
  if (head === 'fdisk' || head === 'parted') return args[0] === '-l' && args.length === 1 ? 'read' : 'unknown'
  if (head === 'blkid') return args.some((a) => a === '-w') ? 'write' : 'read'
  if (['rpm', 'dpkg', 'apt', 'apt-get', 'yum', 'dnf', 'pip', 'npm'].includes(head)) {
    if (/^(?:-q[a-zA-Z]*|-l|-s|-L|list|show|search|info|provides)$/.test(args[0])) return 'read'
    return ['install', 'uninstall', 'remove', 'purge', 'upgrade', 'dist-upgrade', 'update'].includes(args[0]) ? 'write' : 'unknown'
  }
  if (head === 'mount' && !args.length) return 'read'
  if (READ_COMMANDS.has(head)) return head === 'file' && args.some((a) => a === '-C' || a === '--compile') ? 'write' : 'read'
  return WRITE_COMMANDS.has(head) ? 'write' : 'unknown'
}

export function checkCommand(command: string, allowWrite = false): SafetyCheck {
  if (typeof command !== 'string' || command.length > 16_000) return denied('命令无效或过长', '终端协议', false, true)
  if (!command.trim()) return { safe: true, blocked: false, isWrite: false, isUnknown: false }
  if (/[\x00-\x08\x0b-\x1f\x7f]/.test(command)) return denied('命令包含终端控制字符', '终端协议', false, true)
  const segments = parseCommands(command)
  if (!segments) return denied('不支持的 shell 语法或命令展开，请使用直接命令', '命令注入', false, true)
  let write = false
  let unknown = false
  for (const { words, redirects } of segments) {
    const [head, ...args] = words.map((w) => w.value)
    if (/^mkfs(?:\.|$)/.test(head) || ['shutdown', 'reboot', 'halt', 'poweroff', 'dd'].includes(head) || head === 'init' && args.some((a) => a === '0' || a === '6')) return denied('禁止执行危险系统命令', '系统控制')
    if (head === 'rm') {
      const options = args.slice(0, args.indexOf('--') < 0 ? args.length : args.indexOf('--')).filter((a) => a.startsWith('-'))
      const recursive = options.some((a) => /^-[^-]*[rR]/.test(a) || a.startsWith('--rec'))
      const force = options.some((a) => /^-[^-]*f/.test(a) || a.startsWith('--for'))
      if (recursive && force) return denied('禁止执行 rm -rf', '数据删除')
      if (recursive && args.some((a) => a.startsWith('/'))) return denied('禁止递归删除绝对路径', '数据删除')
      if (options.some((a) => a.startsWith('--') && !['--recursive', '--force', '--verbose', '--interactive'].includes(a))) unknown = true
    }
    if (head === 'chmod' && args[0] === '777' && args.some((a) => a.startsWith('/'))) return denied('禁止修改绝对路径为全开放权限', '权限操作')
    // 插件、外部 diff、pager 等参数可能在看似查询的命令中执行程序。
    if (args.some((a) => /^(?:--plugin|--pre(?:=|$)|--exec(?:=|$)|--pager|--use-pager|--compress-program)/.test(a))) unknown = true
    for (const { op, target } of redirects) {
      if (op.includes('>')) {
        if (target.dynamic) return denied('重定向目标必须是确定的路径', '文件写入', true, true)
        if (op === '>&' && /^\d+$/.test(target.value)) continue
        if (isProtectedWritePath(target.value)) return denied('禁止覆盖系统配置或设备', '系统配置')
        write = true
      }
    }
    const kind = commandKind(words)
    // tee/cp/mv 也能写入系统路径，不能只防 shell 重定向。
    if (kind === 'write' && ['tee', 'cp', 'mv', 'ln', 'touch', 'mkdir', 'rm'].includes(head)) {
      const targets = ['cp', 'mv', 'ln'].includes(head) ? [args.at(-1) ?? ''] : args
      const optionTargets = args.flatMap((a, i) => a === '-t' || a === '--target-directory' ? [args[i + 1] ?? ''] : a.startsWith('--target-directory=') ? [a.split('=').slice(1).join('=')] : a.startsWith('-t') ? [a.slice(2)] : [])
      if ([...targets, ...optionTargets].some(isProtectedWritePath)) return denied('禁止通过文件工具修改系统配置或设备', '系统配置', true)
    }
    if (kind === 'write') write = true
    if (kind === 'unknown') {
      unknown = true
      if (CODE_COMMANDS.has(head) && /\b(?:rm|touch|mkdir|mv|cp)\b/.test(args.join(' '))) write = true
    }
    // 动态参数不能改变结构化子命令、写目标或危险选项。
    if (words.some((w) => w.dynamic) && (kind !== 'read' || !READ_COMMANDS.has(head) && !['find', 'cd'].includes(head))) unknown = true
    if (['rg', 'file', 'nm', 'objdump'].includes(head) && words.some((w) => w.dynamic)) unknown = true
  }
  // 未识别段优先：不能用一条已识别写命令替任意脚本取得授权。
  if (unknown) return denied('未识别命令、解释器或可执行参数，当前不允许执行', '命令注入', write, true)
  if (write && !allowWrite) return denied('写操作需要开启读写模式', '文件写入', true)
  return { safe: true, blocked: false, isWrite: write, isUnknown: false }
}
