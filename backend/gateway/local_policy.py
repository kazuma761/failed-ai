"""LOCAL POLICY (stand-in): evaluates prguard.policy.yaml in-process.

Exists so PRGuard can be built and tested without FailproofAI installed. Its
decisions are always labelled LOCAL_POLICY, never FAILPROOFAI.
"""

from __future__ import annotations

from typing import Any

from backend.config import settings
from backend.gateway.base import BaseGateway
from backend.gateway.policy_engine import PolicyEngine
from backend.gateway.upstream import Upstream
from backend.models import Denial, Enforcer, TaskContext, ToolResult


class LocalPolicyGateway(BaseGateway):
    enforcer = Enforcer.LOCAL_POLICY

    def __init__(self, upstream: Upstream, engine: PolicyEngine | None = None) -> None:
        self.upstream = upstream
        self.upstream_name = upstream.name
        self.engine = engine or PolicyEngine(settings.policy_path)

    async def _decide(self, agent_id: str, ctx: TaskContext, tool: str, args: dict[str, Any]) -> ToolResult | Denial:
        decision = self.engine.evaluate(agent_id, ctx, tool, args)
        if not decision.allowed:
            return Denial(tool=tool, reason=decision.reason, enforcer=self.enforcer, policy=decision.rule)
        return ToolResult(tool=tool, data=await self.upstream.call(tool, args))
