import React, { useLayoutEffect, useRef, useEffect, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import type { TerminalView, ClientContext } from '../shared/types'
import { rpc } from './api'
import { useTerminalFontSize } from './preferences'

export function TerminalScreen({ ctx, sessionId, terminal, buffer, visible, onError }: {
  ctx: ClientContext; sessionId: string; terminal: TerminalView; buffer?: { generation: number; text: string; seq: number }; visible: boolean; onError: (message: string) => void
}) {
  const root = useRef<HTMLDivElement>(null), instance = useRef<Terminal>(), search = useRef<SearchAddon>(), fit = useRef<FitAddon>()
  const rendered = useRef(''), state = useRef(terminal), error = useRef(onError), inputQueue = useRef(Promise.resolve())
  const syncSize = useRef<() => void>(() => {}), disposeHandlers = useRef<() => void>(() => {})
  const [find, setFind] = useState(''), fontSize = useTerminalFontSize(), currentFontSize = useRef(fontSize), bufferRef = useRef(buffer)
  currentFontSize.current = fontSize; bufferRef.current = buffer
  state.current = terminal; error.current = onError
  // 隐藏终端（display:none）里 xterm 的字符宽度测量 offsetWidth 恒为 0，宽度缓存
  // 永不回填，每次渲染逐字符强制同步布局——这是 issue #3 整页冻结的根因（报告人
  // CDP 实测阻塞窗口 96.6% CPU 在 _measure）。隐藏期间只累积缓冲，不写 xterm。
  const flush = () => {
    const term = instance.current, pending = bufferRef.current, generation = state.current.generation
    if (!term || !pending || pending.generation !== generation || pending.text === rendered.current) return
    if (pending.text.startsWith(rendered.current)) term.write(pending.text.slice(rendered.current.length))
    else { term.reset(); term.write(pending.text) }
    rendered.current = pending.text
  }
  // xterm 实例延迟到终端第一次可见时创建：从未可见过的终端不渲染、不测量。
  const create = () => {
    if (instance.current || !root.current) return
    const container = root.current
    const term = new Terminal({ cursorBlink: true, fontSize: currentFontSize.current, fontFamily: 'Menlo, Consolas, monospace', scrollback: 5000,
      allowProposedApi: false, convertEol: false, theme: { background: '#12161d', foreground: '#dce3ed', cursor: '#e4edf8', selectionBackground: '#334b66' } })
    const fitAddon = new FitAddon(), searchAddon = new SearchAddon()
    term.loadAddon(fitAddon); term.loadAddon(searchAddon); term.open(container)
    instance.current = term; fit.current = fitAddon; search.current = searchAddon; rendered.current = ''
    let disposed = false
    const input = term.onData((data) => {
      const current = state.current
      if (current.state !== 'ready') return
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
    // Ctrl+F 会被 xterm 当作控制字符输入吞掉，监听放捕获阶段先于 xterm 处理；Cmd+F 一并覆盖。
    const key = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === 'f') {
        event.preventDefault(); event.stopPropagation()
        document.getElementById(`zterm-find-${terminal.id}`)?.focus()
      }
    }
    container.addEventListener('keydown', key, true)
    disposeHandlers.current = () => { disposed = true; syncSize.current = () => {}; clearTimeout(timer); observer.disconnect(); input.dispose(); container.removeEventListener('keydown', key, true); term.dispose(); instance.current = undefined }
  }
  // 身份变化或卸载才销毁实例；切换标签只停写，保留实例与滚动历史。
  useLayoutEffect(() => () => { disposeHandlers.current(); disposeHandlers.current = () => {} }, [ctx, sessionId, terminal.id, terminal.generation])
  useLayoutEffect(() => { if (visible) create() }, [visible, ctx, sessionId, terminal.id, terminal.generation])
  useEffect(() => { if (visible) flush() }, [buffer, visible, terminal.generation])
  useLayoutEffect(() => {
    const term = instance.current
    if (!term || term.options.fontSize === fontSize) return
    // 保留连接、终端实例与历史，只更新字体并同步新的行列数。
    term.options.fontSize = fontSize
    if (visible) syncSize.current()
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
