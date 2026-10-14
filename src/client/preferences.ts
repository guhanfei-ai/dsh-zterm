import { useEffect, useRef, useSyncExternalStore } from 'react'
import type { MouseEvent as ReactMouseEvent } from 'react'

export function savedNumber(key: string, fallback: number, min: number, max: number): number {
  try { const raw = localStorage.getItem(key), value = raw === null ? fallback : Number(raw); return Number.isFinite(value) ? Math.max(min, Math.min(max, value)) : fallback }
  catch { return fallback }
}
export function saveNumber(key: string, value: number): void { try { localStorage.setItem(key, String(value)) } catch { /* 禁用浏览器存储时仍允许本次使用。 */ } }

export const DEFAULT_TERMINAL_FONT_SIZE = 12, MIN_TERMINAL_FONT_SIZE = 8, MAX_TERMINAL_FONT_SIZE = 32
const FONT_SIZE_KEY = 'dsh-zterm.terminal-font-size', fontListeners = new Set<() => void>()
let fontSize: number | undefined
function validFontSize(value: number): boolean { return Number.isInteger(value) && value >= MIN_TERMINAL_FONT_SIZE && value <= MAX_TERMINAL_FONT_SIZE }
function readFontSize(): number {
  try { const raw = localStorage.getItem(FONT_SIZE_KEY), value = raw === null ? DEFAULT_TERMINAL_FONT_SIZE : Number(raw); return validFontSize(value) ? value : DEFAULT_TERMINAL_FONT_SIZE }
  catch { return fontSize ?? DEFAULT_TERMINAL_FONT_SIZE }
}
export function terminalFontSizeSnapshot(): number { return fontSize ??= readFontSize() }
function publishFontSize(value: number) {
  if (value === terminalFontSizeSnapshot()) return
  fontSize = value; fontListeners.forEach((listener) => listener())
}
export function setTerminalFontSize(value: number): void {
  if (!validFontSize(value)) return
  publishFontSize(value); saveNumber(FONT_SIZE_KEY, value)
}
function fontStorageChanged(event: StorageEvent) {
  if (event.key === FONT_SIZE_KEY || event.key === null) publishFontSize(readFontSize())
}
export function subscribeTerminalFontSize(listener: () => void): () => void {
  if (!fontListeners.size && typeof window !== 'undefined') {
    // 面板重新挂载时也读取其它页面在此期间保存的字号。
    fontSize = readFontSize(); window.addEventListener('storage', fontStorageChanged)
  }
  fontListeners.add(listener)
  return () => { fontListeners.delete(listener); if (!fontListeners.size && typeof window !== 'undefined') window.removeEventListener('storage', fontStorageChanged) }
}
export function useTerminalFontSize(): number { return useSyncExternalStore(subscribeTerminalFontSize, terminalFontSizeSnapshot, () => DEFAULT_TERMINAL_FONT_SIZE) }

export function useDrag() {
  const cleanup = useRef<() => void>(() => {})
  useEffect(() => () => cleanup.current(), [])
  return (event: ReactMouseEvent, move: (event: MouseEvent) => void) => {
    event.preventDefault(); cleanup.current()
    const end = () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', end); cleanup.current = () => {} }
    cleanup.current = end
    window.addEventListener('mousemove', move); window.addEventListener('mouseup', end, { once: true })
  }
}
