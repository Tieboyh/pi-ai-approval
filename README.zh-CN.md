# pi-ai-approval · 中文文档

> pi 工具调用安全审批扩展([pi](https://github.com/earendil-works/pi-coding-agent))
>
> English: [README.md](README.md)

三层审批策略:白名单直放 → 黑名单询问 → AI 独立评审,为 pi 的 bash / edit / write 工具调用提供安全边界。

## 功能特性

- **白名单直放**:只读/可逆命令(ls、git status、brew list…)零延迟放行,不打扰
- **复合白名单**:引号感知拆分子命令,全部通过白名单的复合命令(`ls && git status`)整体直放
- **黑名单询问**:sudo、rm -rf /、git push -f、curl|sh 等命中后询问用户
- **AI 独立评审**:spawn 独立 pi 进程(无工具)评审未知命令,支持用户意图感知、引号拼接检测(`-e'xec'`)、禁止绕过指令
- **敏感路径保护**:edit/write 命中 .env、id_rsa 等路径直接询问;bash 中涉及敏感路径的命令强制走 AI
- **断路器**:一轮内连续 3 次拒绝 → 阻断后续 bash,防模型死循环重试
- **审计日志**:每次决策写入 `~/.pi/agent/ai-approval.log`(JSON lines,0600)

## 部署

```bash
git clone https://github.com/Tieboyh/pi-ai-approval.git
ln -s ~/pi-ai-approval/ai-approval.ts ~/.pi/agent/extensions/ai-approval.ts
# pi 内 /reload 生效
```

## 配置

复制 `ai-approval.json.example` 到 `~/.pi/agent/ai-approval.json` 按需修改;不配置则用内置默认(安全优先)。

## 架构

```
① 黑名单(整串结构规则 + 子命令规则;输出型命令参数视为惰性文本)
② 敏感路径 → AI(读放行、写拒绝)
③ 白名单(纯只读;无 find/awk/sed/cp/mv/touch/npm run/node -e/git 写操作)
④ 复合白名单(全子命令过白名单才直放;含 $()/重定向则跳过)
⑤ AI 审批(意图感知 + 引号拼接检测)→ 非 allow 一律拦截
⑥ 断路器(3 拒停本轮)+ 只缓存 deny(防 TOCTOU)
```

零外部运行时依赖,任何装有 pi 的设备即可运行。
