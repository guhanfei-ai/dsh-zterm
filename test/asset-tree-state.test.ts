import { describe, expect, it, vi } from 'vitest'
import { AssetTreeState, uniqueItems, visibleTree, type TreePage } from '../src/client/asset-tree-state'

const page = (items: string[], total = items.length): TreePage<string> => ({ items, total, hasMore: total > items.length })
function pending() { let resolve!: (value: TreePage<string>) => void; const promise = new Promise<TreePage<string>>((done) => { resolve = done }); return { promise, resolve } }

describe('统一资产树可见性', () => {
  const children = (id: string): string[] => ({ root: ['apps', 'empty'], apps: ['nested'], nested: [], empty: [] })[id] ?? []
  it('机器内容紧跟目录，父目录折叠隐藏全部后代并保留子目录偏好', () => {
    const state = new AssetTreeState(['root', 'apps', 'nested'])
    const rows = () => visibleTree(['root'], (id) => id, children, state.expanded).rows.map((row) => `${row.node}:${row.content ? 'hosts' : 'folder'}`)
    expect(rows()).toEqual(['root:folder', 'apps:folder', 'nested:folder', 'nested:hosts', 'apps:hosts', 'empty:folder', 'root:hosts'])
    state.toggle('apps'); expect(rows()).toEqual(['root:folder', 'apps:folder', 'empty:folder', 'root:hosts'])
    expect(state.expanded.has('nested')).toBe(true)
    state.toggle('apps'); expect(rows()).toContain('nested:hosts')
    state.toggle('root'); expect(rows()).toEqual(['root:folder'])
  })
  it('没有子目录的叶子仍能展开机器内容', () => {
    expect(visibleTree(['leaf'], (id) => id, () => [], new Set(['leaf'])).rows).toEqual([
      { node: 'leaf', depth: 0, content: false }, { node: 'leaf', depth: 0, content: true },
    ])
  })
  it('防御远端循环/重复节点，达到上限时仍保留已展开目录的机器内容', () => {
    const result = visibleTree(['a', 'b', 'a', 'c'], (id) => id, (id) => [id], new Set(['a', 'b']), 2)
    expect(result.truncated).toBe(true)
    expect(result.rows.map((row) => row.node)).toEqual(['a', 'a', 'b', 'b'])
  })
  it('深层目录迭代展开，不依赖递归调用栈', () => {
    const expanded = new Set(Array.from({ length: 10000 }, (_, index) => String(index)))
    const result = visibleTree(['0'], (id) => id, (id) => Number(id) < 9999 ? [String(Number(id) + 1)] : [], expanded, 10000)
    expect(result.rows).toHaveLength(20000); expect(result.truncated).toBe(false)
  })
  it('同一资产在同一节点去重，在不同授权节点可以分别出现', () => {
    const assets = [{ id: 'a', label: 'A' }, { id: 'a', label: '重复' }, { id: 'b', label: 'B' }]
    expect(uniqueItems(assets, (item) => item.id)).toEqual([assets[0], assets[2]])
    expect(uniqueItems([assets[0]], (item) => item.id)).toEqual([assets[0]])
  })
})

describe('目录独立分页与请求竞态', () => {
  it('并发目录各自接收结果和页码', async () => {
    const state = new AssetTreeState(), a = pending(), b = pending()
    const first = state.load('a', () => a.promise, 200), second = state.load('b', () => b.promise, 100)
    b.resolve(page(['B'])); await second; a.resolve(page(['A'])); await first
    expect(state.page('a')).toMatchObject({ offset: 200, data: { items: ['A'] } })
    expect(state.page('b')).toMatchObject({ offset: 100, data: { items: ['B'] } })
  })
  it('后一次翻页优先，忽略不响应 AbortSignal 的旧请求', async () => {
    const state = new AssetTreeState(), old = pending()
    const first = state.load('a', () => old.promise)
    await state.load('a', async () => page(['new']), 200)
    old.resolve(page(['old'])); await first
    expect(state.page('a')).toMatchObject({ offset: 200, data: { items: ['new'] } })
  })
  it('折叠时取消请求，迟到结果不重新展开；重新展开允许重试', async () => {
    const state = new AssetTreeState(['a']), old = pending(); let signal!: AbortSignal
    const first = state.load('a', (_offset, current) => { signal = current; return old.promise })
    state.toggle('a'); state.cancel('a'); expect(signal.aborted).toBe(true)
    old.resolve(page(['old'])); await first
    expect(state.expanded.has('a')).toBe(false); expect(state.page('a')?.status).toBe('idle')
    state.toggle('a'); await state.load('a', async () => page(['new']))
    expect(state.page('a')?.data?.items).toEqual(['new'])
  })
  it('刷新保留展开与页码，失效前的响应不能污染新版本', async () => {
    const state = new AssetTreeState(['a']), old = pending()
    const first = state.load('a', () => old.promise, 200)
    state.invalidate(); expect(state.page('a')).toEqual({ offset: 200, status: 'idle' })
    await state.load('a', async () => page(['fresh']))
    old.resolve(page(['old'])); await first
    expect(state.expanded.has('a')).toBe(true); expect(state.page('a')?.data?.items).toEqual(['fresh'])
  })
  it('每个实例隔离相同节点 ID，已卸载实例的旧响应不会写入另一实例', async () => {
    const a = new AssetTreeState(), b = new AssetTreeState(), old = pending()
    const first = a.load('node', () => old.promise); a.cancel('node')
    await b.load('node', async () => page(['instance-B']))
    old.resolve(page(['instance-A'])); await first
    expect(b.page('node')?.data?.items).toEqual(['instance-B']); expect(a.page('node')?.data).toBeUndefined()
  })
  it('失败局限当前目录，重复渲染不自动重试，显式重试恢复', async () => {
    const state = new AssetTreeState(), loader = vi.fn(async () => { throw new Error('fixture unavailable') })
    await state.load('a', loader); state.ensure('a', loader); state.ensure('a', loader)
    await state.load('b', async () => page(['B']))
    expect(loader).toHaveBeenCalledTimes(1); expect(state.page('a')?.error).toBe('fixture unavailable')
    expect(state.page('b')?.status).toBe('ready')
    await state.load('a', async () => page(['A'])); expect(state.page('a')?.error).toBeUndefined()
  })
  it('删除导致当前页越界时回首屏，不丢失剩余主机', async () => {
    const state = new AssetTreeState(), loader = vi.fn(async (offset: number) => offset ? page([], 2) : page(['a', 'b']))
    await state.load('a', loader, 200)
    expect(loader.mock.calls.map(([offset]) => offset)).toEqual([200, 0])
    expect(state.page('a')).toMatchObject({ offset: 0, data: { items: ['a', 'b'] } })
  })
  it('越界回首屏失败时保留旧页内容及其原页码，重试后才切换首屏', async () => {
    const state = new AssetTreeState()
    await state.load('a', async () => page(['second-page']), 100)
    await state.load('a', async (offset) => { if (offset) return page([], 1); throw new Error('first-page unavailable') })
    expect(state.page('a')).toMatchObject({ offset: 100, status: 'ready', data: { items: ['second-page'] }, error: 'first-page unavailable' })
    const retry = vi.fn(async (offset: number) => offset ? page([], 1) : page(['remaining']))
    await state.load('a', retry)
    expect(retry.mock.calls.map(([offset]) => offset)).toEqual([100, 0])
    expect(state.page('a')).toMatchObject({ offset: 0, status: 'ready', data: { items: ['remaining'] } })
  })
  it('同一目录合并重复加载，首屏不会自动读取万级资产的后续页', async () => {
    const state = new AssetTreeState(), first = pending(), loader = vi.fn(() => first.promise)
    state.ensure('a', loader); state.ensure('a', loader); expect(loader).toHaveBeenCalledTimes(1)
    first.resolve(page(Array.from({ length: 200 }, (_, index) => String(index)), 20000))
    await vi.waitFor(() => expect(state.page('a')?.status).toBe('ready'))
    state.ensure('a', loader); expect(loader).toHaveBeenCalledTimes(1)
  })
  it('刷新种入根目录首屏不会重置其它目录或根目录后续页', async () => {
    const state = new AssetTreeState()
    await state.load('root', async () => page(['later']), 200); state.invalidate()
    state.seed('root', page(['first'])); expect(state.page('root')).toMatchObject({ offset: 200, status: 'ready', stale: true, data: { items: ['later'] } })
    state.seed('other', page(['other'])); expect(state.page('other')?.data?.items).toEqual(['other'])
  })
  it('后台刷新期间与失败后都保留当前页，失败不重复请求，重试原位更新', async () => {
    const state = new AssetTreeState(['a']); await state.load('a', async () => page(['cached']), 200)
    const next = pending(); state.invalidate(); const task = state.load('a', () => next.promise)
    expect(state.page('a')).toMatchObject({ status: 'ready', offset: 200, refreshing: true, data: { items: ['cached'] } })
    next.resolve(page(['fresh'])); await task
    const fail = vi.fn(async () => { throw new Error('offline') }); await state.load('a', fail)
    state.ensure('a', fail); expect(fail).toHaveBeenCalledTimes(1)
    expect(state.page('a')).toMatchObject({ status: 'ready', offset: 200, error: 'offline', data: { items: ['fresh'] } })
    await state.load('a', async () => page(['recovered'])); expect(state.page('a')?.error).toBeUndefined()
  })
  it('缓存命中重新打开时合并后台请求，快速折叠后保留旧数据并忽略迟到结果', async () => {
    const state = new AssetTreeState(['a']); state.restore({ expanded: ['a'], scroll: 120, pages: [['a', { offset: 0, data: page(['cached']) }]] })
    const request = pending(), loader = vi.fn(() => request.promise)
    state.ensure('a', loader, true); state.ensure('a', loader); expect(loader).toHaveBeenCalledTimes(1)
    state.toggle('a'); state.cancel('a'); request.resolve(page(['late'])); await Promise.resolve()
    expect(state.page('a')).toMatchObject({ status: 'ready', stale: true, data: { items: ['cached'] } })
    expect(state.scroll.get('tree')).toBe(120); expect(state.expanded.has('a')).toBe(false)
  })
  it('翻页不把旧页冒充新页，配置失效可以主动丢弃旧权限数据', async () => {
    const state = new AssetTreeState(); state.seed('a', page(['first'], 400))
    const next = pending(), task = state.load('a', () => next.promise, 200)
    expect(state.page('a')?.data).toBeUndefined()
    next.resolve(page(['second'])); await task; state.invalidate(true)
    expect(state.page('a')).toEqual({ status: 'idle', offset: 200 })
  })
  it('刚完成的缓存不在三秒内重复请求，重新打开过期页时静默更新', async () => {
    const clock = vi.spyOn(Date, 'now'); clock.mockReturnValue(10000)
    try {
      const state = new AssetTreeState(), loader = vi.fn(async () => page(['ready']))
      await state.load('a', loader); clock.mockReturnValue(12000); state.ensure('a', loader, true)
      expect(loader).toHaveBeenCalledTimes(1)
      clock.mockReturnValue(14000); state.ensure('a', loader, true); expect(loader).toHaveBeenCalledTimes(2)
      await Promise.resolve()
    } finally { clock.mockRestore() }
  })
})
