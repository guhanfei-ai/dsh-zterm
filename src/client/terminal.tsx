import React, { useLayoutEffect, useRef, useEffect, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import type { TerminalView, ClientContext } from '../shared/types'
import { rpc, type TerminalBuffer } from './api'
import { useTerminalFontSize } from './preferences'

const MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test((navigator as any).userAgentData?.platform || navigator.platform || '')
/** 终端内搜索：macOS 用 Cmd+F，其它平台用 Ctrl+Shift+F；Ctrl+F 留给终端程序（less/vim 翻页、readline 前移）。 */
function isFindShortcut(event: KeyboardEvent): boolean {
  // 拉丁布局按字符判断；非拉丁布局（key 不是字母）退回物理键位。
  const f = /^[a-z]$/i.test(event.key) ? event.key.toLowerCase() === 'f' : event.code === 'KeyF'
  return f && !event.altKey && (MAC ? event.metaKey && !event.ctrlKey && !event.shiftKey : event.ctrlKey && event.shiftKey && !event.metaKey)
}
/** xterm 对终端查询的自动应答（DA1/DA2、DSR/CPR、窗口尺寸、DECRQM、DECRQSS、OSC 颜色），见 @xterm/xterm 5.5 InputHandler。 */
const AUTO_REPLY = /^(?:\x1b\[[?>]?[\d;]*[cnRt]|\x1b\[\??\d+;\d+\$y|\x1bP[01]\$r[^\x1b]*\x1b\\|\x1b\][\d;]+;rgb:[\da-fA-F/]+(?:\x1b\\|\x07))+$/
type RenderedMark = { epoch: number; end: number; text: string }
const NOTHING_RENDERED: RenderedMark = { epoch: -1, end: 0, text: '' }

export function TerminalScreen({ ctx, sessionId, terminal, buffer, visible, onError }: {
  ctx: ClientContext; sessionId: string; terminal: TerminalView; buffer?: TerminalBuffer; visible: boolean; onError: (message: string) => void
}) {
  const root = useRef<HTMLDivElement>(null), instance = useRef<Terminal>(), search = useRef<SearchAddon>(), fit = useRef<FitAddon>()
  const rendered = useRef(NOTHING_RENDERED), state = useRef(terminal), error = useRef(onError), inputQueue = useRef(Promise.resolve())
  const syncSize = useRef<() => void>(() => {}), disposeHandlers = useRef<() => void>(() => {}), output = useRef<(data: string, replay: boolean) => void>(() => {})
  const catchUp = useRef(false)
  const [find, setFind] = useState(''), fontSize = useTerminalFontSize(), currentFontSize = useRef(fontSize), bufferRef = useRef(buffer)
  currentFontSize.current = fontSize; bufferRef.current = buffer
  state.current = terminal; error.current = onError
  // 隐藏终端（display:none）里 xterm 的字符宽度测量 offsetWidth 恒为 0，宽度缓存
  // 永不回填，每次渲染逐字符强制同步布局——这是 issue #3 整页冻结的根因（报告人
  // CDP 实测阻塞窗口 96.6% CPU 在 _measure）。隐藏期间只累积缓冲，不写 xterm。
  const flush = () => {
    // 显示后的第一次写入是积压回放，其中查询的应答已经过时，不能再发给远端。
    const term = instance.current, pending = bufferRef.current, replay = catchUp.current
    catchUp.current = false
    if (!term || !pending || pending.generation !== state.current.generation) return
    const mark = rendered.current
    if (mark.epoch === pending.epoch && mark.end === pending.end) return
    // 同一输出流按累计偏移续写：缓冲头部被截断后仍是增量，不整屏重写、不丢滚动位置。
    const offset = mark.epoch === pending.epoch ? mark.end - (pending.end - pending.text.length) : -1
    if (offset >= 0 && offset <= pending.text.length) output.current(pending.text.slice(offset), replay)
    // 换流（断流快照）且内容可接续时补写差额；有已渲染内容时差额属于补回的积压。
    else if (pending.text.startsWith(mark.text)) output.current(pending.text.slice(mark.text.length), replay || Boolean(mark.text))
    else { term.reset(); output.current(pending.text, true) }
    rendered.current = { epoch: pending.epoch, end: pending.end, text: pending.text }
  }
  // xterm 实例延迟到终端第一次可见时创建：从未可见过的终端不渲染、不测量。
  const create = () => {
    if (instance.current || !root.current) return
    const container = root.current
    const term = new Terminal({ cursorBlink: true, fontSize: currentFontSize.current, fontFamily: 'Menlo, Consolas, monospace', scrollback: 5000,
      allowProposedApi: false, convertEol: false, theme: { background: '#12161d', foreground: '#dce3ed', cursor: '#e4edf8', selectionBackground: '#334b66' } })
    const fitAddon = new FitAddon(), searchAddon = new SearchAddon()
    term.loadAddon(fitAddon); term.loadAddon(searchAddon); term.open(container)
    instance.current = term; fit.current = fitAddon; search.current = searchAddon; rendered.current = NOTHING_RENDERED
    let disposed = false, replaying = 0
    // 回放写入在 xterm 解析完成（write 回调）前计数；应答在解析中同步触发，因此落在计数区间内。
    output.current = (data, replay) => {
      if (!data) return
      if (!replay) { term.write(data); return }
      replaying++; term.write(data, () => { replaying-- })
    }
    const input = term.onData((data) => {
      const current = state.current
      if (current.state !== 'ready') return
      // 回放期间丢弃自动应答：迟到的应答会作为输入混进当时正在读输入的程序。
      if (replaying > 0 && AUTO_REPLY.test(data)) return
      inputQueue.current = inputQueue.current.catch(() => {}).then(async () => {
        if (disposed) return
        await rpc(ctx, 'input', { sessionId, terminalId: current.id, generation: current.generation, data })
      }).catch((e) => { if (!disposed) error.current(e.message) })
    })
    let timer: ReturnType<typeof setTimeout> | undefined
    syncSize.current = () => { if (disposed || !root.current?.clientWidth) return; fitAddon.fit(); const current = state.current
      if (current.state === 'ready') void rpc(ctx, 'resize', { sessionId, terminalId: current.id, generation: current.generation, cols: term.cols, rows: term.rows }).catch((e) => { if (!disposed) error.current(e.message) }) }
    const resize = () => { clearTimeout(timer); timer = setTimeout(() => syncSize.current(), 80) }
    const observer = new ResizeObserver(resize); observer.observe(container); resize()
    // 捕获阶段先于 xterm 处理，避免快捷键被当作终端输入。
    const key = (event: KeyboardEvent) => {
      if (!isFindShortcut(event)) return
      event.preventDefault(); event.stopPropagation()
      document.getElementById(`zterm-find-${terminal.id}`)?.focus()
    }
    container.addEventListener('keydown', key, true)
    disposeHandlers.current = () => { disposed = true; syncSize.current = () => {}; output.current = () => {}; clearTimeout(timer); observer.disconnect(); input.dispose(); container.removeEventListener('keydown', key, true); term.dispose(); instance.current = undefined }
  }
  // 身份变化或卸载才销毁实例；切换标签只停写，保留实例与滚动历史。
  useLayoutEffect(() => () => { disposeHandlers.current(); disposeHandlers.current = () => {} }, [ctx, sessionId, terminal.id, terminal.generation])
  useLayoutEffect(() => { if (!visible) return; create(); catchUp.current = true; flush() }, [visible, ctx, sessionId, terminal.id, terminal.generation])
  useEffect(() => { if (visible) flush() }, [buffer, terminal.generation])
  useLayoutEffect(() => {
    const term = instance.current
    // 隐藏实例不改字体：display:none 下重新测量同样逐字符强制布局，等可见时再应用。
    if (!visible || !term || term.options.fontSize === fontSize) return
    // 保留连接、终端实例与历史，只更新字体并同步新的行列数。
    term.options.fontSize = fontSize
    syncSize.current()
  }, [fontSize, visible])
  useEffect(() => { if (visible) { syncSize.current(); instance.current?.focus() } }, [visible, terminal.state, terminal.generation])
  return <div className="zt-terminal-screen" style={{ display: visible ? 'flex' : 'none' }}>
    <div className="zt-terminal-search"><input id={`zterm-find-${terminal.id}`} aria-label="搜索终端输出" placeholder="搜索终端输出" value={find}
      onChange={(e) => { setFind(e.target.value); search.current?.findNext(e.target.value) }} onKeyDown={(e) => { if (e.key === 'Enter') search.current?.findNext(find); if (e.key === 'Escape') { setFind(''); instance.current?.focus() } }} />
      <button title="上一个匹配" onClick={() => search.current?.findPrevious(find)}>↑</button><button title="下一个匹配" onClick={() => search.current?.findNext(find)}>↓</button>
      <span>终端输入直接操作当前机器</span></div>
    <div className="zt-terminal-canvas" ref={root} />
  </div>
}
