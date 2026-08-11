# Integrating this into guardrail-core

Three new modules, verified against the real package (source pulled
from `github.com/KKallias/guardrail-core@main` via the GitHub API — the
sandbox this was built in can't `git clone` or `pip install` from a
fresh repo, so testing happened against a byte-for-byte local copy of
`__init__.py`, `guard.py`, `policy.py`, `audit.py`,
`adapters/{__init__,generic,mcp}.py`, reconstructed from the same
source. Only `detectors/pii.py` was a reduced stand-in — email + api_key
detectors only, enough to exercise redaction — since your real file
wasn't fully fetchable in one pull; nothing here depends on the parts
that were left out).

All 44 new tests pass against that reconstruction. Copy these paths
into your checkout and `pytest` should pass unchanged against your real
`detectors/pii.py`, which is a superset of the stand-in.

## What's new

```
guardrail_core/adapters/claude_code.py   Claude Code PreToolUse/PostToolUse hook adapter
guardrail_core/credentials.py            short-lived, scoped credential broker
guardrail_core/egress.py                 local HTTP/HTTPS forward proxy, allowlist-enforced
tests/test_claude_code_adapter.py        18 tests
tests/test_credentials.py                18 tests
tests/test_egress.py                     8 tests
```

## Drop-in steps

1. Copy the three `guardrail_core/*.py` files into your checkout at the
   same paths.
2. Copy the three `tests/*.py` files into your checkout's `tests/`.
3. One small diff to an existing file —
   `guardrail_core/adapters/__init__.py` — the docstring now mentions
   `claude_code` alongside `langchain`/`mcp`/`x402`/`mpp` as an
   on-demand import. No behavior change; diff is docstring-only. Compare
   against your current file before overwriting, in case you've since
   changed it.
4. `pip install -e ".[dev]"` and `pytest` — should be 44 new passes,
   zero changes to existing test results.
5. `examples/claude-code-plugin/` has a working `hooks.json` +
   `policy.yaml` + a short README to try it against a real Claude Code
   session.

## Design notes worth knowing before you merge

**`claude_code.py`** turns `tool_name` + `tool_input` into a `ToolCall`
the same way `adapters/mcp.py` turns a `tools/call` request into one.
The one new idea: `extract_recipient()` maps `WebFetch` URLs, `mcp__*`
tool names, and `Bash` commands containing curl/wget/gh/aws/etc. to a
hostname or MCP server name, so your existing `policy.allowlist` field
does double duty as a coarse network allowlist — no new policy schema
needed. It's documented as best-effort (regex over command text, not a
sandbox) in the module docstring.

Claude Code doesn't expose a real dollar cost per tool call at
`PreToolUse` time, so `spend_cap` only fires if the caller supplies
`amount_for=` with their own price estimate. Undocumented-until-you-
read-the-code costs would have been worse than an honest "opt-in
estimate, not metered usage."

**`credentials.py`** is new territory for this package — nothing here
answers "should this call run" (that's `Guard`); it answers "what
secret does an approved call authenticate with, and does the agent ever
see it." Base secrets go in once at broker construction; `mint()`
hands the *caller* an opaque token with its own TTL and use-count;
`resolve()` — called only by the code that makes the real outbound
request, never by anything a tool call's arguments can reach — is the
only place the real secret comes back out. Shares your `AuditLog`
format (reuses `AuditEntry`), with its own decision vocabulary (`ISSUE`,
`RESOLVE`, `EXPIRE`, `EXHAUST`, `REVOKE`) that's inert to `Guard`'s
replay logic (`REPLAYED_DECISIONS` only matches `ALLOW`/`REDACT`), so
sharing one audit log file between a `Guard` and a `CredentialBroker` is
safe and gives one merged, call-id-ordered trail.

**`egress.py`** is a real stdlib-only forward proxy (`CONNECT` tunnel
for HTTPS, `http.client` passthrough for plain HTTP), not a mock. It
found and fixed a real bug during testing worth flagging explicitly: an
early build didn't set `Content-Length: 0` on blocked/error responses,
which hangs a keep-alive `HTTP/1.1` client waiting for a body that never
arrives. Fixed via `_send_empty()`; the tests
(`test_rate_limit_applies_across_requests`,
`test_every_request_is_audited`) exercise the path that would have
caught it. Separately: testing this revealed that `urllib.request`'s
`ProxyHandler` silently bypasses the proxy for loopback-looking targets
on some platforms (`proxy_bypass()`), which will bite anyone else
writing tests or client code against a local proxy with `urllib` —
worth a line in your own docs if you point users at this. The tests use
`http.client` directly against the proxy's own host:port to sidestep
it.

Documented non-goals, both explicit in the module docstring: no TLS
interception (host-level allow/deny only, not content inspection inside
HTTPS — pair with `detectors.pii` at the tool-call layer for that), and
no enforcement against a process that ignores `HTTP_PROXY` outright
(this is a control for well-behaved HTTP clients, not a network
namespace — a real boundary needs a container/VM whose only route out
is through it).

## What's still open (didn't build this round)

- A `Scope`-to-Claude-Code wiring example showing `CredentialBroker`
  used from inside a `PreToolUse` hook (mint on approval, hand the
  token back via `updatedInput`, resolve inside the tool's actual
  execution) — the pieces compose, but there's no end-to-end example of
  it yet.
- `egress.py` has no config for a second, `NO_PROXY`-style bypass list
  of hosts that skip the allowlist check (useful for e.g. the package
  registry a `pip install` needs during setup, before the agent's
  session-scoped policy should apply).
