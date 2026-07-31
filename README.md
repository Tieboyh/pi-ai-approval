# pi-ai-approval

> AI-assisted tool-call approval policy for [pi](https://github.com/earendil-works/pi-coding-agent)
>
> 中文版: [README.zh-CN.md](README.zh-CN.md)

A tiered tool-call approval policy policing `bash` / `edit` / `write` tool calls: whitelist fast-path → blacklist prompt → AI review.

## Features

- **Whitelist fast-path**: read-only / reversible commands (`ls`, `git status`, `brew list`…) pass instantly with zero friction
- **Compound whitelist**: quote-aware sub-command splitting; a compound like `ls && git status` passes only if every fragment is whitelisted
- **Blacklist prompt**: `sudo`, `rm -rf /`, `git push -f`, `curl|sh`… ask the user before running
- **AI review**: a separate `pi` process (no tools) judges unknown commands — user-intent aware, detects quote concatenation (`-e'xec'` ≡ `-exec`), and instructs the model not to bypass
- **Sensitive-path guard**: `edit`/`write` targeting `.env`, `id_rsa`, etc. prompts the user; bash commands mentioning sensitive paths are forced through AI
- **Circuit breaker**: 3 consecutive denials in one run block further bash, preventing denial loops
- **Audit log**: every decision appended to `~/.pi/agent/ai-approval.log` (JSON lines, mode 0600)

## Install

```bash
git clone https://github.com/Tieboyh/pi-ai-approval.git
ln -s ~/pi-ai-approval/ai-approval.ts ~/.pi/agent/extensions/ai-approval.ts
# /reload inside pi to activate
```

## Configuration

Copy `ai-approval.json.example` to `~/.pi/agent/ai-approval.json` and adjust. Without a config file the built-in defaults apply (fail-closed: headless defaults to deny).

## Architecture

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
