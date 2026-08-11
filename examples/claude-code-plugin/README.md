# Example: guardrail-core as a Claude Code plugin

1. From your `guardrail-core` checkout: `pip install -e .`
2. Copy `guardrails/policy.yaml` into your project (or point
   `GUARDRAIL_POLICY` at wherever you keep it) and edit the allowlist.
3. Copy `hooks.json` into your project's `.claude/hooks.json` (or merge
   the `PreToolUse`/`PostToolUse` entries into an existing one).
4. Start a Claude Code session in that project. Every tool call now
   goes through `guardrail_core.adapters.claude_code` before it runs.
5. `tail -f logs/guardrail-audit.jsonl` in another terminal to watch
   decisions land in real time.

Environment variables (both optional, shown with their defaults):

```bash
export GUARDRAIL_POLICY=guardrails/policy.yaml
export GUARDRAIL_AUDIT_LOG=logs/guardrail-audit.jsonl
```

To also enforce a network egress allowlist independent of which tool
the model uses (Bash curl, an MCP server's own HTTP client, etc.), run
the proxy alongside the session and point Claude Code's process at it:

```bash
python3 -m guardrail_core.egress --policy guardrails/policy.yaml --port 8899 &
export HTTP_PROXY=http://127.0.0.1:8899
export HTTPS_PROXY=http://127.0.0.1:8899
```
