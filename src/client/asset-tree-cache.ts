import { AssetTreeState, type TreeSnapshot } from './asset-tree-state'

const PREFIX = 'dsh-zterm.asset-tree-cache.v1:'
const MAX_AGE = 24 * 60 * 60 * 1000, MAX_CHARS = 600_000, MAX_PAGES = 64
type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'key' | 'length'>
interface Preferences { source: 'ssh' | 'jumpserver'; instanceId: string; folder: string }
const record = (value: any): value is Record<string, any> => Boolean(value && typeof value === 'object' && !Array.isArray(value))
const text = (value: any): value is string => typeof value === 'string' && value.length <= 4096
const number = (value: any): value is number => Number.isFinite(value) && value >= 0
const priority = (key: unknown) => key === 'nodes' ? 2 : typeof key === 'string' && key.startsWith('children:') ? 1 : 0
function pick(value: any, strings: string[], numbers: string[] = [], booleans: string[] = []) {
  if (!record(value)) return undefined
  const result: Record<string, any> = {}
  for (const key of strings) if (text(value[key])) result[key] = value[key]
  for (const key of numbers) if (number(value[key])) result[key] = value[key]
  for (const key of booleans) if (typeof value[key] === 'boolean') result[key] = value[key]
  return result
}
function list(value: any, limit: number, project: (item: any) => any): any[] {
  return Array.isArray(value) ? value.slice(0, limit).map(project).filter(Boolean) : []
}
function catalogDisplay(value: any) {
  if (!record(value) || !Array.isArray(value.folders) || !Array.isArray(value.jumpservers)) return undefined
  return { ...pick(value, [], ['revision'], ['temporarilyDisabled']),
    folders: list(value.folders, 2000, (item) => text(item?.id) && text(item?.label) ? pick(item, ['id', 'label', 'parentId']) : undefined),
    jumpservers: list(value.jumpservers, 32, (item) => text(item?.id) && text(item?.label) ? pick(item, ['id', 'label']) : undefined) }
}
function treeDisplay(value: any, ssh: boolean): TreeSnapshot | undefined {
  if (!record(value) || !Array.isArray(value.expanded) || !Array.isArray(value.pages)) return undefined
  const pages: TreeSnapshot['pages'] = []
  for (const entry of value.pages.slice().sort((a: any, b: any) => priority(b?.[0]) - priority(a?.[0])).slice(0, MAX_PAGES)) {
    if (!Array.isArray(entry) || entry.length !== 2) continue
    const [key, page] = entry
    if (!text(key) || !record(page) || !Number.isInteger(page.offset) || page.offset < 0 || !record(page.data) || !Array.isArray(page.data.items) || !number(page.data.total)) continue
    const nodes = !ssh && (key === 'nodes' || key.startsWith('children:'))
    if (ssh ? !key.startsWith('hosts:') : !nodes && !key.startsWith('assets:')) continue
    const items = list(page.data.items, nodes ? 500 : ssh ? 200 : 100, (item) => {
      if (ssh) return text(item?.id) && text(item?.label) && text(item?.host) && text(item?.username) && number(item?.port)
        ? pick(item, ['id', 'label', 'folderId', 'kind', 'host', 'username'], ['port']) : undefined
      if (nodes) return text(item?.nodeId) && text(item?.key) && text(item?.name)
        ? pick(item, ['nodeId', 'key', 'name'], ['assetCount'], ['hasChildren']) : undefined
      return text(item?.assetId) && text(item?.name) && text(item?.address) && text(item?.platform) ? pick(item, ['assetId', 'name', 'address', 'platform']) : undefined
    })
    // 损坏或不完整的分页不作为完整列表展示，交给正常请求恢复。
    if (items.length !== page.data.items.length) continue
    pages.push([key, { offset: page.offset, data: { items, total: page.data.total, hasMore: Boolean(page.data.hasMore), truncated: Boolean(page.data.truncated) } }])
  }
  return { expanded: value.expanded.filter(text).slice(0, 2001), scroll: number(value.scroll) ? value.scroll : 0, pages }
}
function browserStorage(): StorageLike | undefined { try { return localStorage } catch { return undefined } }

/** 同源、同工作台的展示快照；不保存凭据、账号授权、终端内容或搜索结果。 */
export class AssetTreeCache {
  readonly host = new AssetTreeState([''])
  readonly jumps = new Map<string, AssetTreeState>()
  readonly key: string
  catalog: any
  preferences: Preferences = { source: 'ssh', instanceId: '', folder: '' }
  private timer?: ReturnType<typeof setTimeout>
  constructor(sessionId: string, private storage = browserStorage(), private now = () => Date.now()) {
    this.key = PREFIX + encodeURIComponent(sessionId)
    try {
      const raw = storage?.getItem(this.key)
      if (raw && raw.length <= MAX_CHARS) {
        const value = JSON.parse(raw)
        if (value.schema === 1 && number(value.writtenAt) && this.now() - value.writtenAt >= 0 && this.now() - value.writtenAt < MAX_AGE) {
          this.catalog = catalogDisplay(value.catalog)
          if (this.catalog) {
            const host = treeDisplay(value.host, true); if (host) this.host.restore(host)
            for (const entry of Array.isArray(value.jumps) ? value.jumps.slice(0, 32) : []) {
              if (!Array.isArray(entry) || !this.catalog.jumpservers.some((item: any) => item.id === entry[0])) continue
              const snapshot = treeDisplay(entry[1], false); if (snapshot) this.jump(entry[0]).restore(snapshot)
            }
            const prefs = value.preferences
            if (record(prefs)) this.preferences = { source: prefs.source === 'jumpserver' ? 'jumpserver' : 'ssh',
              instanceId: this.catalog.jumpservers.some((item: any) => item.id === prefs.instanceId) ? prefs.instanceId : this.catalog.jumpservers[0]?.id ?? '',
              folder: this.catalog.folders.some((item: any) => item.id === prefs.folder) ? prefs.folder : '' }
          }
        }
      }
    } catch { /* 存储被禁用或快照损坏时，照常通过接口加载。 */ }
    this.host.onChange = this.schedule
  }
  jump(id: string) {
    let tree = this.jumps.get(id)
    if (!tree) { tree = new AssetTreeState(); tree.onChange = this.schedule; this.jumps.set(id, tree) }
    return tree
  }
  schedule = () => { if (!this.timer) this.timer = setTimeout(() => { this.timer = undefined; this.flush() }, 200) }
  flush() {
    if (!this.catalog || !this.storage) return
    try {
      const host = treeDisplay(this.host.export(), true)!, jumps = [...this.jumps].map(([id, tree]) => [id, treeDisplay(tree.export(), false)!] as const)
      const value = { schema: 1, writtenAt: this.now(), catalog: catalogDisplay(this.catalog), preferences: this.preferences, host, jumps }
      // 目录优先留下；资产分页有容量上限，未缓存的折叠分支仍按需加载。
      const all = [host, ...jumps.map(([, tree]) => tree)], pages = all.flatMap((tree) => tree.pages.map((page) => ({ tree, page })))
      all.forEach((tree) => { tree.pages = [] })
      let length = JSON.stringify(value).length, count = 0
      for (const { tree, page } of pages.sort((a, b) => priority(b.page[0]) - priority(a.page[0]))) {
        const size = JSON.stringify(page).length + 1
        if (count < MAX_PAGES && length + size < MAX_CHARS) { tree.pages.push(page); length += size; count++ }
      }
      const raw = JSON.stringify(value)
      if (raw.length > MAX_CHARS) return
      // 最多保存最近三个工作台，避免多个万级列表挤满同源存储。
      const keys: Array<{ key: string; time: number }> = []
      for (let i = 0; i < this.storage.length; i++) {
        const key = this.storage.key(i)
        if (key?.startsWith(PREFIX) && key !== this.key) {
          let time = 0; try { time = JSON.parse(this.storage.getItem(key) ?? '{}').writtenAt ?? 0 } catch { /* 清理损坏的旧快照。 */ }
          keys.push({ key, time })
        }
      }
      keys.sort((a, b) => b.time - a.time).slice(2).forEach(({ key }) => this.storage!.removeItem(key))
      this.storage.setItem(this.key, raw)
    } catch { /* 配额不足时保留本次内存缓存，不阻塞操作。 */ }
  }
  dispose() { clearTimeout(this.timer); this.flush(); this.host.onChange = undefined; this.host.dispose(); this.jumps.forEach((tree) => { tree.onChange = undefined; tree.dispose() }) }
}
