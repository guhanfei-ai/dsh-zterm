# 更新日志

## 0.2.3

- 修复独立壳模式下面板空白（[guhanfei-ai/dsh-zterm#4](https://github.com/guhanfei-ai/dsh-zterm/issues/4)，对齐 [guhanfei-ai/dsh-mindmap#5](https://github.com/guhanfei-ai/dsh-mindmap/issues/5) 的 0.18.8 方案）：standalone 面板宿主层改为经 `react-dom` `createPortal` 挂到 `document.body`，逃出宿主壳 0.2.2-rc 线会话头部祖先链的 `overflow: clip` 裁剪；`document` 不可用（SSR/测试）时退回原位渲染。`zt-standalone-error` 提示条保持头部槽位原位；class、内联宽度、拖宽、`--dsh-zterm-width` 变量、`dsh:panel-layout` 事件与互斥监听（共享契约 v1）、Better Sidebar Tab 模式均不变；关闭即卸载，portal 随卸载移除，不残留 `document.body` 子节点。

## 0.2.1

- 修复独立面板与 dsh-mindmap 布局样式冲突（[guhanfei-ai/dsh-mindmap#6](https://github.com/guhanfei-ai/dsh-mindmap/issues/6)，共享契约 v1）：独立面板改为注入同时计入 `--dsh-mindmap-width`、`--dsh-zterm-width`、`--dsh-sidebar-width` 的唯一 `#root` 布局规则，且不含 `transition`；删除 MutationObserver + `getComputedStyle` 轮询，改监听 `dsh:panel-layout` 布局事件，脑图展开时收起独立面板并提示；打开、拖宽、关闭后派发自身面板宽度事件，卸载时清理样式、宽度变量与监听。互斥提示、Better Sidebar Tab 模式与既有行为不变。
