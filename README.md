# ai-approval — pi 工具审批扩展

三层审批策略:白名单直放 → 黑名单询问 → AI 独立评审(意图感知 + 引号拼接检测 + 断路器)。

## 部署

```bash
# 克隆后软链接到 pi 扩展目录(改仓库即生效,git pull 即更新)
ln -s ~/pi-extensions/ai-approval/ai-approval.ts ~/.pi/agent/extensions/ai-approval.ts
```

## 配置

复制 `ai-approval.json.example` 到 `~/.pi/agent/ai-approval.json` 后按需修改。
不配置则使用内置默认值(headless 默认拒绝,安全优先)。

## 审计

决策日志:`~/.pi/agent/ai-approval.log`(JSON lines,0600 权限)。

## 架构

```
① 黑名单(整串结构规则 + 子命令规则,输出型命令参数视为惰性文本)
② 敏感路径 → AI(读放行、写拒绝)
③ 白名单(纯只读:无 find/awk/sed/cp/mv/touch/npm run/node -e/git 写操作)
④ 复合白名单(引号感知拆子命令,全过白名单才直放;含 $()/重定向则跳过)
⑤ AI 审批(意图感知 + 引号拼接检测 + 禁止绕过)→ 非 allow 一律拦截
⑥ 断路器(3 拒停本轮)+ 只缓存 deny
```

零外部运行时依赖(node 内置模块 + pi 扩展 API),任何设备装上 pi 即可运行。
