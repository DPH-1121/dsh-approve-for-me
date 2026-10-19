# dsh-approve-for-me · 替我审批

给 DeepSeek Harness 加**第四种权限预设**。

harness 原本只有三种，每一种都在两个糟糕的极端之间选一个：

| 预设 | 沙箱 | 审批 | 实际体验 |
|---|---|---|---|
| `read-only` | 只读 | 问人 | 什么都干不了 |
| `workspace-write` | 工作区可写 | 问人 | 每一步都要点一下 |
| `danger-full-access` | 全权限 | 不问了 | 什么都不问，包括不该问的 |

第四种叫 **Approve for me（替我审批）**：留着「让它自己干」的速度，但把「问不问」这件事交给一套
**确定性的 Codex 式规则表**——规则说安全的直接放行，说危险的原样拒绝并给出理由，规则判不了的
才回来问你。

```
        ┌─ allow  ── 直接执行，不打扰你
规则表 ─┼─ prompt ── 交给人工（就是原来的行为）
        └─ deny   ── 拒绝，并把「为什么」写回给模型
```

---

## 一、为什么是第四个预设，而不是一个开关

预设不是界面上的一个 `if`，它由 harness 固定为两个旋钮的组合：

```ts
type SandboxMode   = 'read-only' | 'workspace-write' | 'danger-full-access'
type ApprovalPolicy = 'ask' | 'never'
```

而 `never` 在**应答器瀑布之前**就把所有审批一律拒掉（`dsh-user-approval` 的 `decide()`），
所以在 `never` 之下没有「让规则表看一眼」这个环节。三种官方预设已经占掉三个组合，剩下的
唯一一个能让规则表真正拿到决定权的组合是：

```
danger-full-access + ask      ← 四种组合里剩下的那一个
```

这不是权宜之计，而是这套设计的诚实读法：**这一档是拿沙箱换规则表**。

- 沙箱不再拦你，所以规则表就是唯一的边界；
- 唯一边界是规则表，所以**匹配不到的 shell 命令默认是 `prompt`（交给人）**，不是 `allow`。
  官方 Auto 用的是 `allow`，但 Auto 背后有一次完整的 LLM 复核；这里没有 LLM，默认放行就等于没有边界。

---

## 二、装上

### 官方桌面版

**设置 → 插件 → 添加插件**，填：

```
github:DPH-1121/dsh-approve-for-me
```

### 命令行

```bash
dsh plugin --profile web add github:DPH-1121/dsh-approve-for-me
```

装完重启一次。之后在权限选择器（输入框旁的下拉、或 `/permission`）里会多一项
**Approve for me**。

> ★ 这一行 patch **整块重述**了官方 `permission` 行的 `config`——包括原来那三个预设。
> 因为 Loader 的 patch 是替换而不是深合并，不重述就会把官方三个预设弄丢。
> 代价是：如果上游以后改了那三个预设的值，本插件会把它覆盖回去。升级 dsh 后请对照
> `cordis.patch.yml` 与 `@deepseek-ai/dsh-base/cordis.patch.yml` 里的 `permission` 行。

---

## 三、规则表

规则表是一个 JSON 文件，第一次启动时自动写到：

```
$DSH_HOME/approve-for-me/rules.json
```

也可以用环境变量指到别处（比如放进仓库里跟着版本走）：

```powershell
$env:DSH_APPROVE_FOR_ME_RULES = 'D:\me\rules.json'
```

改完重启（或用 `plugin_manager` 重载该行）生效。**规则表在激活时编译一次**：一个回合内
两次一模一样的调用永远不会得到不同答案。

### 结构

```jsonc
{
  "shellDefault": "prompt",   // 没匹配到的 shell 命令怎么办
  "toolDefault":  "prompt",   // 没匹配到的工具怎么办
  "readTools":  ["read", "glob", "grep"],        // 只读工具，永不打扰
  "pathTools":  ["write", "edit"],               // 按路径判定，而不是按工具名
  "denyPaths":  ["^[a-z]:\\\\windows(?:\\\\|$)"], // 永不放行的路径
  "tools":      { "pwsh": "command" },           // 工具 → 判定
  "commands": [
    { "id": "force-push", "decision": "deny", "match": "\\bgit\\s+push\\b[^\\n]*--force", "reason": "..." }
  ]
}
```

`decision` 只有三个值：`allow`、`prompt`、`deny`。`tools` 里多一个特殊值 `command`，意思是
「把 `arguments.command` 拿去用下面的命令表判定」。

### 三道结构性保证

**1. 一行命令不等于一个动作。** `npm test && rm -rf build` 是两个动作。命令会先按
`&&` `||` `;` `|` 换行切开，逐段判定，**取最严的那个**（deny > prompt > allow）。
只检查行首的规则表，追加半句就能绕过。

**2. 有「整行」规则。** 管道进 shell（`curl … | sh`）的**证据就是那根管道**，一旦切成段
就只剩一个 `sh` 了。这类规则标了 `wholeLine: true`，先对未切分的整行判一次。

**3. 文件工具按路径判，不按名字判。** `write` / `edit` 落在工作区内是普通开发工作（allow），
落在系统目录直接 deny，落在工作区外交给人。否则「写什么文件」这件事就完全没人看了。

### 默认表里有什么

| 判定 | 例子 |
|---|---|
| **deny** | `rm -rf /`、`Remove-Item -Recurse C:\`、`format-volume`、`shutdown`、`curl … \| sh`、`git push --force`、`reg add HKLM…`、关掉 Defender / 防火墙 |
| **prompt** | `npm publish`、`git push`、`pnpm add`、`docker run`、`ssh`、`curl -X POST`、`rm -rf node_modules`、`git reset --hard`、`crontab`、`cat .env`、写工作区外的路径 |
| **allow** | `git status/diff/log`、`ls` / `Get-ChildItem`、`node --version`、`pnpm test`、`cargo test`、`echo` |

匹配不到的 shell 命令 → `prompt`。这条是刻意的，别改成 `allow` 之后又抱怨它不问。

### 规则表坏了会怎样

不会静默按别的规则运行。加载时逐条校验（decision 词汇、正则能否编译、类型对不对）：

- 有问题 → 启动日志里 `logger.error` 逐条列出来，**并且这一档预设会退化成「全部问人」**；
- 规则文件读不出来 → 同上，退化成「全部问人」。

「一个说自己是按 A 判、实际按 B 判的审批器」比「没有审批器」更危险，所以宁可退化。

---

## 四、它到底挂在哪两个接缝上

只用了两个，没有第三个：

**`approval/request`（waterfall，权威接缝）**
每一次审批——工具自己发起的、沙箱升级发起的——都会先经过这里，再去界面的应答器。
返回 `'allowed-once'` 就是批准，`'rejected'` 就是拒绝，调 `next()` 就是交给你。
harness 无论如何都会把 `approval/asked` + `approval/decided` 这一对写进会话日志，
所以**规则表的批准和你的点击一样可审计**。

**`tools/pre-execute`（waterfall，派发前接缝）**
这一层**只拒绝，不批准**。原因有两个：从 pre-execute 里再去问审批服务会重入同一个瀑布；
而在这里直接放行会绕过上面那对审计事件。所以 `allow` 在这一层等价于「不打扰」，
`deny` 才是它能携带的唯一强判定。

沙箱升级的语义也单独处理了：`escalate sandbox to workspace-write` 放行（还在围栏里），
`escalate sandbox to danger-full-access` 一律交给你。

---

## 五、验证

```
node --test test/smoke.mjs
```

17 个用例，覆盖：分段与最严判定、追加半句不能提权、管道进 shell、按路径判文件工具、
只读工具不打扰、未知工具回落到询问、规则文档的合并与校验、规则文件的创建/覆盖/损坏降级。

---

## 六、卸载

```bash
dsh plugin --profile web remove dsh-approve-for-me
```

卸载时仍在 `Approve for me` 上的会话会被移回 `danger-full-access`（沙箱松但**不问**），
而不是 `workspace-write`（沙箱紧但会问）——因为这档预设的用户是明确选了「不要每步都问」的，
把卸载变成「突然什么都问」比留一个宽松预设更烦人。日志里会逐个会话记录这次迁移。

---

## License

MIT
