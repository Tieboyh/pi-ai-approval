# pi-ai-approval · pi AI 审批扩展

> AI-assisted tool-call approval policy for [pi](https://github.com/earendil-works/pi-coding-agent) · pi 工具调用安全审批扩展

[English](#english) · [中文](#中文)

---

## 中文

三层审批策略:白名单直放 → 黑名单询问 → AI 独立评审,为 pi 的 bash / edit / write 工具调用提供安全边界。

### 功能特性

- **白名单直放**:只读/可逆命令(ls、git status、brew list…)零延迟放行,不打扰
- **复合白名单**:引号感知拆分子命令,全部通过白名单的复合命令(`ls && git status`)整体直放
- **黑名单询问**:sudo、rm -rf /、git push -f、curl|sh 等命中后询问用户
- **AI 独立评审**:spawn 独立 pi 进程(无工具)评审未知命令,支持用户意图感知、引号拼接检测(`-e'xec'`)、禁止绕过指令
- **敏感路径保护**:edit/write 命中 .env、id_rsa 等路径直接询问;bash 中涉及敏感路径的命令强制走 AI
- **断路器**:一轮内连续 3 次拒绝 → 阻断后续 bash,防模型死循环重试
- **审计日志**:每次决策写入 `~/.pi/agent/ai-approval.log`(JSON lines,0600)

### 部署

```bash
git clone https://github.com/Tieboyh/pi-ai-approval.git
ln -s ~/pi-ai-approval/ai-approval.ts ~/.pi/agent/extensions/ai-approval.ts
# pi 内 /reload 生效
```

### 配置

复制 `ai-approval.json.example` 到 `~/.pi/agent/ai-approval.json` 按需修改;不配置则用内置默认(安全优先)。

### 架构

```
① 黑名单(整串结构规则 + 子命令规则;输出型命令参数视为惰性文本)
② 敏感路径 → AI(读放行、写拒绝)
③ 白名单(纯只读;无 find/awk/sed/cp/mv/touch/npm run/node -e/git 写操作)
④ 复合白名单(全子命令过白名单才直放;含 $()/重定向则跳过)
⑤ AI 审批(意图感知 + 引号拼接检测)→ 非 allow 一律拦截
⑥ 断路器(3 拒停本轮)+ 只缓存 deny(防 TOCTOU)
```

零外部运行时依赖,任何装有 pi 的设备即可运行。

---

## English

A tiered tool-call approval policy for [pi](https://github.com/earendil-works/pi-coding-agent): whitelist fast-path → blacklist prompt → AI review, policing `bash` / `edit` / `write` tool calls.

### Features

- **Whitelist fast-path**: read-only / reversible commands (`ls`, `git status`, `brew list`…) pass instantly with zero friction
- **Compound whitelist**: quote-aware sub-command splitting; a compound like `ls && git status` passes only if every fragment is whitelisted
- **Blacklist prompt**: `sudo`, `rm -rf /`, `git push -f`, `curl|sh`… ask the user before running
- **AI review**: a separate `pi` process (no tools) judges unknown commands — user-intent aware, detects quote concatenation (`-e'xec'` ≡ `-exec`), and instructs the model not to bypass
- **Sensitive-path guard**: `edit`/`write` targeting `.env`, `id_rsa`, etc. prompts the user; bash commands mentioning sensitive paths are forced through AI
- **Circuit breaker**: 3 consecutive denials in one run block further bash, preventing denial loops
- **Audit log**: every decision appended to `~/.pi/agent/ai-approval.log` (JSON lines, mode 0600)

### Install

```bash
git clone https://github.com/Tieboyh/pi-ai-approval.git
ln -s ~/pi-ai-approval/ai-approval.ts ~/.pi/agent/extensions/ai-approval.ts
# /reload inside pi to activate
```

### Configuration

Copy `ai-approval.json.example` to `~/.pi/agent/ai-approval.json` and adjust. Without a config file the built-in defaults apply (fail-closed: headless defaults to deny).

### Architecture

```
① Blacklist (full-command structure rules + per-sub-command rules; args of
   pure output filters are treated as inert text)
② Sensitive-path mention → AI (reads allowed, writes denied)
③ Whitelist (read-only only; no find/awk/sed/cp/mv/touch/npm run/node -e/
   git write commands)
④ Compound whitelist (all fragments whitelisted → allow; $()/redirection
   skips this tier)
⑤ AI approval (intent-aware + quote-concatenation detection) → anything
   that is not an explicit "allow" is blocked
⑥ Circuit breaker (3 denials stops the run) + deny-only caching (TOCTOU-safe)
```

Zero runtime dependencies outside Node built-ins — works on any machine with pi installed.
