# 更新日志

## 0.2.1

- 修复独立面板与 dsh-mindmap 布局样式冲突（[guhanfei-ai/dsh-mindmap#6](https://github.com/guhanfei-ai/dsh-mindmap/issues/6)，共享契约 v1）：独立面板改为注入同时计入 `--dsh-mindmap-width`、`--dsh-zterm-width`、`--dsh-sidebar-width` 的唯一 `#root` 布局规则，且不含 `transition`；删除 MutationObserver + `getComputedStyle` 轮询，改监听 `dsh:panel-layout` 布局事件，脑图展开时收起独立面板并提示；打开、拖宽、关闭后派发自身面板宽度事件，卸载时清理样式、宽度变量与监听。互斥提示、Better Sidebar Tab 模式与既有行为不变。
