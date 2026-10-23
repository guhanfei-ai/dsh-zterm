# zTerm

把 [zterm](https://github.com/guhanfei-ai/zterm) 的真实机器终端能力移植到 DeepSeek Harness（DSH）。DSH 负责 AI、对话与跨工具流程，zTerm 提供机器连接、终端、受限读工具、人类开启的读写操作和实际结果记录。安装包名为 `dsh-zterm`。

```text
DSH 对话中指定主机，结合 Grafana / OpenSearch 等证据
    → 取得资产与证据
    → zTerm 连接、读取、操作和核验机器
    → DSH 使用其它插件复核并归档结果
```

右侧工作台中，终端在左，主机／文件夹／JumpServer 资产列表在右。有 Better Sidebar 时使用独立 Tab，与脑图切换；没有时使用可调宽的独立大面板。

## 当前交付

- SSH 密码、私钥内容、宿主私钥文件；设置中保存命名凭证，多台主机按名称选用，私钥可直接选文件导入。
- 对话指定目标：先查远程主机，再查 JumpServer 授权；均无匹配时自动保存主机，使用选定的默认私钥凭证或宿主默认私钥文件。
- JumpServer 实例、按需节点树、分页资产、授权账号、fresh token 与 Koko SSH 网关。
- 可选 DSH 宿主本地 PTY；多终端、尺寸同步、手工输入、终端搜索、断开和重连。
- 终端默认 12px；设置中可调 8–32px，即时应用并保存在当前浏览器。
- 14 个 `zterm_*` 工具；默认读模式，人类在已绑定终端工具栏开启读写。
- 设置页顶部的「临时禁用 zTerm」：插件保持启用，仅撤下 AI 侧工具与系统提示，让 AI 可改用其它方式操作服务器；人类工作台不受影响。
- 真正的退出码和完成边界；终端串行锁、取消、发送前授权复核、结果不明隔离、重复 callId 防重放。
- DSH 设置及凭据库、操作记录与导出、恢复上次目标列表。

本插件负责连接、操作与真实结果；外部系统的查询与归档由 DSH 的其它工具完成。

## 安装

基线为 DSH `0.2.0-rc.2`、Node.js 22 以上。Better Sidebar 可选，已核对 Web `0.24.1` 的 Tab 契约。真实模型与真实测试机上的验收请自行完成；离线检查和界面夹具不能替代该验收。

可以把已生成的本地包安装到目标 profile，例如 Web profile：

```sh
dsh plugin --profile web add "/path/to/dsh-zterm/out/dsh-zterm-0.1.10.tgz"
```

本地源码联调可使用：

```sh
dsh plugin --profile web add "link:/path/to/dsh-zterm"
```

`cordis.patch.yml` 使用插件 ID `zterm` 和包名 `dsh-zterm`。通过现有 DSH 界面／方式加载或重载插件，然后刷新页面。以上示例仅操作 Web profile，桌面 profile 不受影响。

包管理器须允许本插件的 `postinstall` 和需要的原生依赖构建脚本。`scripts/prepare-native.mjs` 仅修复本依赖目录中 macOS `node-pty` 的 `spawn-helper` 执行位；不会改系统文件。SSH 不需要本地 PTY 原生模块；开启宿主本地终端才需要可用的 `node-pty`。如果安装策略跳过了本插件脚本，应在本插件目录中执行该脚本后再验收本地 PTY。

日常检查与构建不执行 Git 写操作，也不启动或重启服务。维护者的发布入口见下方「发布」。

## 开始使用

1. 在「设置 → zTerm」的【保存设置】下方管理凭证：填写名称、类型和内容，私钥可选择文件导入。添加主机时选择已保存凭证的名称；同一凭证可以供多台主机使用。也可设置默认 SSH 私钥凭证，让 AI 自动新增主机时直接选用。
2. 直接在对话中指定要访问的主机名或 IP。AI 使用 `zterm_connect` 自动查找、保存并连接；也可以点击「zTerm」，从右侧选择已保存的目标。
3. 点击目标建立连接；通过可信渠道核实首次 SSH 指纹。连接完成后点「绑定 AI」，或由 AI 调用 `zterm_bind`。
4. 让 AI 用目录、文件、系统、进程或端口读工具检查机器。默认读模式下通用命令被拒绝。
5. 需要修改时，人类在当前已绑定终端手工勾选「允许AI写操作」开启读写模式；未勾选时保持读模式。AI 可连续执行策略允许的命令，默认每次授权最多 100 条。
6. 通过读工具、监控或日志复核实际效果，再使用 `zterm_results` 把记录交给其它插件归档。

手工输入后，AI 暂停并切回读模式。结束 vim／less 等交互程序、确认回到空闲 Shell 后，再点「确认空闲 Shell」。切换可见标签不会切换 AI 绑定目标。

完整流程、设置和常见问题见 [中文使用指南](USERGUIDE.zh-CN.md)。

## 检查与构建

在项目目录中执行：

```sh
npm ci --cache ".cache/npm"
npm run verify
npm run check:package
node "scripts/check-host.mjs" "<DSH 安装目录>/node_modules/@deepseek-ai/dsh"
npm pack --ignore-scripts --pack-destination "out"
```

`verify` 包含 TypeScript、Vitest、宿主与客户端构建。测试只使用虚构数据、独立临时目录以及测试拥有的回环 HTTP／SSH／PTY，不连接真实机器。SDK 检查使用已安装包创建临时 Cordis 上下文，不启动真实 DSH。

## 发布

[deploy.sh](deploy.sh) 沿用 dsh-grafana 的维护者手动发布流程：

```sh
./deploy.sh release   # 输入版本号，验证后提交、打标签并推送
./deploy.sh build     # 安装开发依赖、准备原生依赖、验证和编译，打包到 dist/
./deploy.sh publish   # 校验当前版本安装包，发布到 npm 与 GitHub Release
./deploy.sh all       # 依次执行上述三步
```

发布链路默认限 main 分支，凭证和确认提示与来源项目一致。构建保留已有版本产物；分发只使用当前包名与版本对应的归档，并核对包内版本、宿主及客户端 bundle。脚本可从任意目录调用，不安装到 DSH profile，也不重启 Web 或桌面服务。

`release` 和 `all` 包含 Git 写操作，`publish` 会上传安装包，由维护者本人执行；AI 在本项目的 Git 写禁令仍然有效。

## 执行和数据边界

AI 执行要求空闲 POSIX Shell。每次调用使用独立子 Shell，`cd`／`export` 不改变后续调用的环境。结果不明的操作不会自动重试；核实远端后重建连接。

终端在 DSH 宿主执行，本地终端对应宿主而非浏览器电脑。授权只在内存中，刷新页面、换绑定目标、重连或插件重载均不恢复旧读写权限。

配置存放在 DSH 设置，秘密存放在 DSH 凭据库；插件的指纹、调用标识、目标列表和操作记录在 `$DSH_HOME/zterm/`，未设置时为 `~/.dsh/zterm/`。记录和终端导出有明确上限，不能作为外部归档成功的回执。不要把任意远端输出都视为已完全去除秘密的内容；人工终端本身会显示机器实际输出。

MIT，保留 [zterm 原始许可](LICENSE)；来源及依赖许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
