# Contributing

Thanks for taking a look. This is an early project — issues and small PRs
are both welcome.

## Running the tests

```bash
pip install -e ".[dev]"
python -m pytest
```

The suite is fully offline: no network, no testnet, no API keys. If a change
needs a live service to test, that is a sign the logic should move behind a
seam that can be tested locally.

## Filing an issue

Include the guardrail-core version, your Python version, the policy (YAML or
`Policy(...)`) you used, and what you expected versus what happened. For a
wrong decision, the audit-log line for the call is the single most useful
thing you can paste — **redact anything sensitive first**, and note that a
`BLOCK` on a real payment may include a real recipient address.

## Pull requests

- Open an issue first for anything that changes a policy schema, a rule
  name, or an adapter signature — those are visible in users' config files
  and audit logs.
- Add a test for the behaviour you are changing. Rules that block money or
  leak-prone payloads need a test for both the allow and the block path.
- Keep the default fail-closed. If a new option can weaken enforcement, it
  should be opt-in and its docstring should say what it gives up.
- Match the surrounding style: comments explain *why*, not *what*.
