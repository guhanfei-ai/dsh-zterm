export interface TreePage<T> { items: T[]; total: number; hasMore: boolean; truncated?: boolean }
export interface PageState<T> { offset: number; status: 'idle' | 'loading' | 'ready' | 'error'; data?: TreePage<T>; error?: string; stale?: boolean; refreshing?: boolean; updatedAt?: number }
export type PageLoader<T> = (offset: number, signal: AbortSignal) => Promise<TreePage<T>>
export interface TreeSnapshot { expanded: string[]; scroll: number; pages: Array<[string, { offset: number; data: TreePage<unknown> }]> }

/** 每个来源/实例独享，生命周期由工作台持有；折叠和卸载视图不会清除展开偏好。 */
export class AssetTreeState {
  readonly expanded: Set<string>
  readonly scroll = new Map<string, number>()
  private pages = new Map<string, PageState<unknown>>()
  private pending = new Map<string, AbortController>()
  private listeners = new Set<() => void>()
  private version = 0
  onChange?: () => void
  constructor(expanded: string[] = []) { this.expanded = new Set(expanded) }
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener) } }
  snapshot = () => this.version
  private changed() { this.version++; this.listeners.forEach((listener) => listener()); this.onChange?.() }
  setScroll(view: string, value: number) { this.scroll.set(view, value); if (view === 'tree') this.onChange?.() }
  restore(snapshot: TreeSnapshot) {
    this.expanded.clear(); snapshot.expanded.forEach((id) => this.expanded.add(id)); this.scroll.set('tree', snapshot.scroll)
    for (const [key, page] of snapshot.pages) this.pages.set(key, { ...page, status: 'ready', stale: true })
  }
  export(): TreeSnapshot {
    return { expanded: [...this.expanded], scroll: this.scroll.get('tree') ?? 0, pages: [...this.pages].flatMap(([key, page]) =>
      !key.startsWith('search:') && page.data ? [[key, { offset: page.offset, data: page.data }] as TreeSnapshot['pages'][number]] : []) }
  }
  page<T>(key: string): PageState<T> | undefined { return this.pages.get(key) as PageState<T> | undefined }
  toggle(id: string) { this.expanded.has(id) ? this.expanded.delete(id) : this.expanded.add(id); this.changed() }
  reveal(ids: string[]) { ids.forEach((id) => this.expanded.add(id)); this.changed() }
  retain(ids: Set<string>) { for (const id of this.expanded) if (!ids.has(id)) this.expanded.delete(id) }
  seed<T>(key: string, data: TreePage<T>) {
    if ((this.pages.get(key)?.offset ?? 0) !== 0) return
    this.cancel(key); this.pages.set(key, { offset: 0, status: 'ready', data, updatedAt: Date.now() }); this.changed()
  }
  async load<T>(key: string, loader: PageLoader<T>, offset = this.pages.get(key)?.offset ?? 0): Promise<void> {
    this.pending.get(key)?.abort()
    const previous = this.pages.get(key), data = previous?.offset === offset ? previous.data : undefined
    const controller = new AbortController()
    this.pending.set(key, controller); this.pages.set(key, { offset, status: data ? 'ready' : 'loading', data, refreshing: true }); this.changed()
    try {
      let data = await loader(offset, controller.signal)
      if (controller.signal.aborted || this.pending.get(key) !== controller) return
      // 删除/移动主机后当前页可能越界，回到首个有效页。
      if (offset > 0 && !data.items.length) { offset = 0; data = await loader(0, controller.signal) }
      if (controller.signal.aborted || this.pending.get(key) !== controller) return
      this.pages.set(key, { offset, status: 'ready', data, updatedAt: Date.now() })
    } catch (error) {
      if (controller.signal.aborted || this.pending.get(key) !== controller) return
      this.pages.set(key, { offset: data ? previous!.offset : offset, status: data ? 'ready' : 'error', data, error: error instanceof Error ? error.message : '读取失败' })
    } finally {
      if (this.pending.get(key) === controller) { this.pending.delete(key); this.changed() }
    }
  }
  ensure<T>(key: string, loader: PageLoader<T>, reopening = false) {
    const page = this.pages.get(key)
    if (!this.pending.has(key) && (!page || page.status === 'idle' || page.stale || (reopening && Date.now() - (page.updatedAt ?? 0) >= 3000))) void this.load(key, loader)
  }
  cancel(key: string) {
    const controller = this.pending.get(key)
    if (!controller) return
    controller.abort(); this.pending.delete(key)
    const page = this.pages.get(key)!
    this.pages.set(key, page.data ? { ...page, status: 'ready', refreshing: false, stale: true } : { offset: page.offset, status: 'idle' }); this.changed()
  }
  forget(key: string) { this.cancel(key); if (this.pages.delete(key)) this.changed() }
  invalidate(dropData = false) {
    this.pending.forEach((controller) => controller.abort()); this.pending.clear()
    for (const [key, page] of this.pages) this.pages.set(key, !dropData && page.data ? { ...page, stale: true, refreshing: false, error: undefined } : { offset: page.offset, status: 'idle' })
    this.changed()
  }
  dispose() { this.pending.forEach((controller) => controller.abort()); this.pending.clear(); this.listeners.clear() }
}

/** 迭代展开可见行，目录在前、所属机器在后；限制目录数量并防御远端重复/循环节点。 */
export function visibleTree<T>(roots: T[], id: (node: T) => string, children: (node: T) => T[], expanded: Set<string>, limit = 500) {
  const stack = roots.slice().reverse().map((node) => ({ node, depth: 0, content: false })), rows: typeof stack = [], seen = new Set<string>()
  let truncated = false
  while (stack.length) {
    const row = stack.pop()!, key = id(row.node)
    if (row.content) { rows.push(row); continue }
    if (seen.has(key)) continue
    if (seen.size >= limit) { truncated = true; continue }
    seen.add(key); rows.push(row)
    if (!expanded.has(key)) continue
    stack.push({ ...row, content: true })
    for (const node of children(row.node).slice().reverse()) stack.push({ node, depth: row.depth + 1, content: false })
  }
  return { rows, truncated }
}

export function uniqueItems<T>(items: T[], id: (item: T) => string): T[] {
  const seen = new Set<string>()
  return items.filter((item) => { const key = id(item); if (seen.has(key)) return false; seen.add(key); return true })
}
