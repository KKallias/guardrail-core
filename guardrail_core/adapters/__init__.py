"""
Adapters turn a framework's "a tool is about to run" event into a
`ToolCall`, hand it to `Guard.check`, and act on the result.

`generic` is imported eagerly (no third-party imports). `langchain`,
`mcp`, `x402` and `mpp` are imported on demand so that installing
guardrail-core never drags in a framework you do not use:

    from guardrail_core.adapters.langchain import GuardrailCallbackHandler
"""

from .generic import guarded

__all__ = ["guarded"]
