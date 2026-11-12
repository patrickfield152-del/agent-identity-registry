"""OpenAI Agents SDK integration for skjold.

Provides :class:`skjoldAuditHook`, a small helper that logs Agent
invocations and tool calls to the skjold audit chain. The OpenAI Agents
SDK already speaks MCP natively, so the canonical wiring is::

    from agents import Agent
    from agents.mcp import MCPServerStdio

    skjold_server = MCPServerStdio(params={"command": "skjold", "args": ["mcp-server"]})
    agent = Agent(..., mcp_servers=[skjold_server])

The :class:`skjoldAuditHook` complements that by emitting a structured
``log_action`` row for every guardrail decision so the audit chain reflects
the agent's decision boundary, not just its tool calls.

Install with the opt-in extra::

    pip install 'skjold[openai-agents]'
"""

from attestix.integrations.openai_agents.hook import skjoldAuditHook

__all__ = ["skjoldAuditHook"]
