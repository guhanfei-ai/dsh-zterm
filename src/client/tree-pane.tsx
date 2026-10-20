import React, { useLayoutEffect, useRef, useState } from 'react'
import { savedNumber, saveNumber, useDrag } from './preferences'

export function TreePane({ children, label, storageKey }: { children: React.ReactNode; label: string; storageKey: string }) {
  const pane = useRef<HTMLDivElement>(null), startDrag = useDrag()
  const [preferredHeight, setPreferredHeight] = useState(() => savedNumber(storageKey, 165, 56, Number.MAX_SAFE_INTEGER)), [maxHeight, setMaxHeight] = useState(165)
  useLayoutEffect(() => {
    const parent = pane.current?.parentElement
    if (!parent) return
    // 为下方列表及文件夹操作保留空间，窗口缩小时不覆盖主机。
    const measure = () => setMaxHeight(Math.max(8, parent.clientHeight - 120))
    measure(); const observer = new ResizeObserver(measure); observer.observe(parent)
    return () => observer.disconnect()
  }, [])
  const minHeight = Math.min(56, maxHeight), height = Math.max(minHeight, Math.min(maxHeight, preferredHeight))
  const resize = (value: number) => {
    const next = Math.max(minHeight, Math.min(maxHeight, Math.round(value)))
    setPreferredHeight(next); saveNumber(storageKey, next)
  }
  const drag = (event: React.MouseEvent) => {
    if (event.button !== 0) return
    const start = event.clientY, initial = pane.current?.getBoundingClientRect().height ?? height
    startDrag(event, (move) => resize(initial + move.clientY - start))
  }
  const keyResize = (event: React.KeyboardEvent) => {
    let value: number
    if (event.key === 'ArrowUp') value = height - 10
    else if (event.key === 'ArrowDown') value = height + 10
    else if (event.key === 'Home') value = minHeight
    else if (event.key === 'End') value = maxHeight
    else return
    event.preventDefault(); resize(value)
  }
  return <div ref={pane} className="zt-tree-pane" style={{ height }}>
    {children}
    <div className="zt-tree-handle" role="separator" aria-label={label} aria-orientation="horizontal" tabIndex={0}
      aria-valuemin={minHeight} aria-valuemax={maxHeight} aria-valuenow={height} onMouseDown={drag} onKeyDown={keyResize} />
  </div>
}
