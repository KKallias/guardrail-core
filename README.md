# guardrail-core

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

![guardrail-core demo](assets/demo.gif)

Policy enforcement for AI agent tool-calls. Intercept a call **before** it
executes, enforce **spend caps**, **rate limits** and **PII/secret rules**
against a declarative policy, and append every decision to an
**append-only JSONL audit log**.

```python
from guardrail_core import Policy
from guardrail_core.adapters.generic import guarded

@guarded(Policy.from_yaml("policy.yaml"), amount=1.25)
def fetch_market_data(symbol: str) -> str:
    ...   # raises BlockedByPolicy once the cap is hit; never runs
```

`guardrail-core` generalizes two shipped tools —
[x402-spend-guard](https://github.com/KKallias/x402-spend-guard) (Python,
x402 micropayments on Base Sepolia) and
[mpp-spend-guard](https://github.com/KKallias/mpp-spend-guard) (JavaScript,
Machine Payments Protocol) — into one policy engine that is not tied to a
payment protocol. Both were pre-payment spend-check + audit-log tools tested
on real testnets; this is the reusable core underneath them.

## Quickstart

```bash
git clone https://github.com/KKallias/guardrail-core.git
cd guardrail-core
pip install -e .          # add "[dev]" for pytest
```

```python
from guardrail_core import Guard, Policy, ToolCall

guard = Guard(Policy.from_yaml("examples/policy.yaml"))
result = guard.check(ToolCall(tool="search", payload={"q": "hi"}, amount=0.25))
print(result.decision, "-", result.reason)
```

Then see it end to end:

```bash
python examples/unified_demo.py          # ~3s, all mocked
python examples/unified_demo.py --step   # pause between sections
```

Requires Python 3.10+. Runtime dependency: `pyyaml`. The LangChain adapter
is optional — it imports and works without LangChain installed.

## The model

Everything funnels through one call:

```python
from guardrail_core import Guard, Policy, ToolCall

guard = Guard(Policy.from_yaml("policy.yaml"), audit_log="logs/audit.jsonl")
result = guard.check(ToolCall(tool="search", payload={"q": "..."}, amount=0.25))

result.decision   # Decision.ALLOW | Decision.BLOCK | Decision.REDACT
result.reason     # human-readable: "rolling spend cap exceeded: 6.25 > 5.00 USD ..."
result.rule       # which rule fired: "spend_cap.window"
result.payload    # what to actually send (redacted when REDACT fired)
result.allowed    # True for ALLOW and REDACT
```

Rules are evaluated cheapest-refusal-first, and the **first failing rule
decides**. `result.rule` names the one that fired:

| order | rule name | fires when |
| --- | --- | --- |
| 1 | `allowlist.recipient_not_allowed` | the call names a counterparty that is not on the allowlist |
| 2 | `spend_cap.currency` | the call's currency differs from the policy's |
| 3 | `spend_cap.per_call` | a single charge exceeds the per-call cap |
| 4 | `spend_cap.window` | the rolling-window total would be exceeded |
| 5 | `rate_limit` | too many calls in the rolling window |
| 6 | `pii_rules.block` / `pii_rules.redact` | a detector matched the payload |

The allowlist runs first because "this counterparty is not allowed at all"
is a more useful reason than "this call is too expensive".

Every check writes exactly one audit entry, including allowed ones.

### Spend and rate state survives restarts

A fresh `Guard` rebuilds its rolling windows from the audit log. An agent
script that runs once per cron tick therefore shares one budget across runs
— without this, a per-run process would reset its own cap every time. (This
is the behaviour inherited from x402-spend-guard's `_load_history`.)

### Commit semantics

`guard.check(call)` consumes the budget for an allowed call, which is what a
wrapper about to execute the call wants. For a pre-flight "would this be
allowed?", use `guard.check(call, commit=False)` and call `guard.commit(call)`
yourself once the call really happens.

Blocked calls consume nothing — a refused call neither spent money nor used
rate-limit budget.

## Policy

```yaml
name: default

allowlist:
  recipients:             # who a call may be directed at
    - acct_trusted
    - "0xServerReceivingAddress"

spend_cap:
  per_call: 1.00          # largest single charge
  window_amount: 5.00     # rolling-window total...
  window_seconds: 3600    # ...over this window
  currency: USD

rate_limit:
  max_calls: 10
  window_seconds: 60

pii_rules:
  detectors: [email, api_key, crypto_wallet, card_number]
  action: redact          # redact | block
  fields: null            # null = scan everything; or a list of top-level keys
```

Every section is optional. Caps compare with `>`, so a call landing exactly
on the cap is allowed. A call with `amount=None` skips the spend rules; rate
and PII rules still apply. A call whose currency differs from the policy's is
blocked rather than silently converted.

The allowlist governs `ToolCall.recipient` — an MPP account id, an x402
`payTo` address, an API vendor. Two deliberate no-ops: a call with
`recipient=None` skips the rule (most tool-calls have no counterparty and
should not need one), and an **empty** `recipients` list means "no
restriction" rather than deny-all, so a policy file that loses its entries
does not silently block everything. Recipients are never fed to the PII
detectors — an address you mean to pay is not a leaked wallet.

## Detectors

`guardrail_core.detectors.pii` — local regex matching, no network, no model.

| detector | matches |
| --- | --- |
| `email` | RFC-ish addresses |
| `api_key` | `sk-`, `sk-proj-`, `sk-ant-`, `AKIA`/`ASIA`, `ghp_`/`github_pat_`, `xoxb-`, `AIza`, `glpat-`, `hf_`, Stripe `rk_live/test_` |
| `crypto_wallet` | EVM addresses (`0x` + 40 hex; 64-hex private keys/tx hashes deliberately excluded) |
| `card_number` | 13–19 digits, grouped or not, gated on a Luhn checksum |

Each `Finding` carries `start`/`end` positions, so callers redact precisely
rather than re-running the regex, and `masked()` for audit entries — enough
to recognize *which* secret leaked without writing the secret to disk.

```python
from guardrail_core.detectors import pii

findings = pii.scan_payload({"body": "mail ada@example.com"})
pii.redact_payload({"body": "mail ada@example.com"})
# {'body': 'mail [REDACTED:email]'}
```

These are conservative pattern matchers, not a classifier. A clean result
means "no obvious leak", never "provably safe".

## Audit log

One JSON object per line, opened in append mode only — nothing ever rewrites
or truncates an existing line.

```json
{"v": 1, "timestamp": "2026-08-07T14:05:16.726650+00:00", "call_id": "2df69f16690e",
 "tool": "market_data_api", "decision": "BLOCK",
 "reason": "rolling spend cap exceeded: 6.2500 > 5.0000 USD in 3600s window",
 "policy": "demo-agent", "rule": "spend_cap.window", "amount": 1.25, "currency": "USD"}
```

Raw payloads are never written — only the redacted version, when redaction
fired. Corrupted lines (a process killed mid-write) are skipped on read
rather than making the whole history unreadable.

## Adapters

**`generic`** — the `@guarded` decorator, for any callable:

```python
@guarded(policy, amount=0.75)                     # fixed price
@guarded(policy, amount_arg="price")              # price comes from an argument
@guarded(policy, amount=lambda tokens: tokens*1e-3)  # computed price
@guarded(guard=other_tool.guard)                  # share one budget
```

Works on async functions too. On `REDACT` it re-binds the function's
arguments to the redacted values before calling it (`apply_redaction=False`
makes redaction audit-only). On `BLOCK` it raises `BlockedByPolicy` and the
function never runs.

**`langchain`** — a `BaseCallbackHandler` checking `on_tool_start`:

```python
from guardrail_core.adapters.langchain import GuardrailCallbackHandler

handler = GuardrailCallbackHandler(policy, amount_for=lambda tool, text, kw: 0.01)
agent.invoke({"input": "..."}, config={"callbacks": [handler]})
```

A `BLOCK` raises out of the tool run, so the tool never executes.

`REDACT` also blocks here, by default. That is a deliberate fail-closed
choice forced by the callback surface: LangChain gives a callback no way to
rewrite tool input, so a handler can only allow or refuse. Letting the call
through would mean a payload the policy just flagged as containing a secret
reaches the tool unchanged while the audit log records `REDACT` — a log
claiming a protection that never happened.

For redaction that actually rewrites the payload, put `@guarded` on the tool
function. `redact_as_block=False` is available for that setup — handler for
audit and spend/rate enforcement, decorator for redaction — but on its own it
means the tool receives the **original, unredacted** input.

**`mcp`** — a proxy-side guard for Model Context Protocol `tools/call`:

```python
from guardrail_core.adapters.mcp import MCPGuard

guard = MCPGuard(policy, server="files-server")

def handle(request):
    decision = guard.inspect(request)
    if decision.response is not None:
        return decision.response            # refused, upstream never contacted
    return upstream.send(decision.request)  # forwarded, possibly redacted
```

This is the one adapter where `REDACT` works properly. A proxy sits in the
middle of the JSON-RPC stream and can rewrite `params.arguments` before
forwarding, so the upstream server receives the redacted values and the call
still succeeds — the thing a LangChain callback structurally cannot do.

Blocked calls come back as a tool result with `isError: true`, not a JSON-RPC
protocol error: a policy refusal is something the *model* should read and
adapt to, while a protocol error makes the client think the server is broken.
`server=` sets the call's recipient, so `allowlist.recipients` restricts which
upstream servers are reachable. Non-tool traffic (`initialize`, `tools/list`)
passes through unevaluated and unlogged. Plain dicts throughout — no MCP SDK
dependency.

**`x402` / `mpp`** — scaffolding, not yet wired into the two existing repos.
`X402Adapter` maps an endpoint + USDC amount to a `ToolCall` and keeps the
testnet-only settlement guard; `MppAdapter` maps an MPP Challenge, converting
minor units to major. Neither imports its protocol SDK — they take plain
dicts.

Both populate `ToolCall.recipient` and let the core allowlist enforce it:
`pay_to` (the resource server's receiving address from the 402 payment
requirements) for x402, `recipient` for MPP.

```python
adapter.check_payment("/weather", 0.01, requirements["payTo"])  # priced
adapter.check_free_request("/weather")                          # no money moves
```

`pay_to` is **required and has no default** — the allowlist is not
bypassable by omission. Forgetting it raises `TypeError` at the call site
(and an empty string raises `ValueError`) instead of quietly performing a
payment that skipped the recipient check. The unpriced case — the probe that
*discovers* a 402's payment requirements, where there is no counterparty
yet — is `check_free_request`, a separate method so that skipping the
allowlist is always deliberate and visible in the code. Rate-limit and PII
rules still apply to free requests.

Note that x402's settlement `payer` is **not** mapped to `recipient` — that
field is our own wallet, the sender, so treating it as the counterparty
would have the allowlist check our own address and pass whatever the money
actually went to. It stays in the audit metadata.

## CLI

```bash
guardrail policy --policy policy.yaml                    # validate and echo
guardrail check  --policy policy.yaml --tool search --amount 0.25 --payload '{"q":"hi"}'
guardrail scan   --file notes.txt --redact
guardrail audit  --log logs/audit.jsonl --tail 20 --summary
```

`check` exits **0** when allowed, **1** when blocked, **2** on a usage or
policy error — usable directly in a shell pipeline or CI step.

## Examples

```bash
python examples/unified_demo.py          # the three-section tour
python examples/unified_demo.py --step   # pause between sections
```

Three sections, all mocked and deterministic — no network, no testnet, no
wallet, so a recording of it looks the same every time. An x402 agent hits
its spend cap and then tries to pay an unapproved address; a decorated
function has an email and API key stripped out of its argument before it
runs; the audit trail is printed with the rule name that fired for each
decision.

```bash
python examples/generic_agent_demo.py
```

An agent whose paid tool costs $1.25 per call under a $5/hour cap: four calls
succeed, the fifth is blocked, then the audit log is printed.

## Tests

```bash
python -m pytest
```

134 tests, no network access, no live services — allowlist blocks, spend-cap
blocks, rate-limit blocks, PII redaction, allowed pass-through, adapter
behaviour, audit-log durability, and CLI exit codes.

## Comparison

Adjacent tools, and where each one sits. Descriptions are from each
project's own documentation, checked August 2026 — capabilities change, so
check the current docs before relying on this.

| | guardrail-core | [TokenFence](https://tokenfence.dev/) | [Bifrost](https://github.com/maximhq/bifrost) | [Aperion Shield](https://github.com/AperionAI/shield) |
| --- | --- | --- | --- |  --- |
| **Focus** | Policy engine for tool-calls: spend, rate, PII, audit | LLM token cost control; auto-downgrades to cheaper models at 80% of budget | Enterprise AI gateway: routing, failover, 1000+ models, governance | Blocking destructive coding-agent actions (`DROP TABLE`, `rm -rf`, force-push) |
| **Payment-protocol adapters (x402 / MPP)** | Yes — x402 `payTo` and MPP Challenge map to `ToolCall` | Documents OpenAI/Anthropic token spend | Documents LLM provider spend via virtual keys | Documents MCP tool-call rules |
| **Allowlist as first-class policy** | Yes — `allowlist.recipients` governs payment counterparties | Budget caps and kill switch | Yes — virtual keys carry model allowlists and MCP tool filters | Rule-based, incl. tool-definition pinning against "rug pull" swaps |
| **Deployment** | Library, in-process (SDK + decorator + CLI) | Library, in-process (wraps your client in 2 lines) | Self-hosted gateway (Go), open source | Local MCP proxy binary, open source, no hosted service |

The short version: guardrail-core is the only one of these built around
**agent payments** — an amount and a counterparty per call — rather than LLM
token spend or destructive-command blocking. If you want a multi-provider LLM
gateway, Bifrost is a gateway and this is not; if you want fast token-budget
caps on OpenAI/Anthropic clients, TokenFence is two lines; if you want to stop
a coding agent dropping a table, that is Shield's job. They compose fine —
this runs in-process, at the tool-call boundary.

## Status

v0.1.0, alpha. The core is stable enough to build on; the x402 and MPP
adapters are mappings awaiting wiring into their respective repos.

## License

Apache-2.0 — see [LICENSE](LICENSE).
