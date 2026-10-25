"""Gateway factory: one place decides which enforcer and upstream are in play."""

from __future__ import annotations

from functools import lru_cache

from backend.config import settings
from backend.gateway.base import ToolGateway
from backend.gateway.direct import DirectGateway
from backend.gateway.failproofai_gw import FailproofAIGateway
from backend.gateway.local_policy import LocalPolicyGateway
from backend.gateway.upstream import McpUpstream, MockUpstream, Upstream
from backend.models import Mode


@lru_cache
def mock_upstream() -> MockUpstream:
    return MockUpstream()


@lru_cache
def _unsafe_upstream() -> Upstream:
    if settings.upstream == "mock":
        return mock_upstream()
    return McpUpstream(settings.github_mcp_url)


@lru_cache
def _guarded_gateway() -> ToolGateway:
    upstream = mock_upstream() if settings.upstream == "mock" else McpUpstream(settings.github_mcp_url)
    if settings.enforcer == "FAILPROOFAI":
        return FailproofAIGateway(upstream)
    return LocalPolicyGateway(upstream)


@lru_cache
def _direct_gateway() -> ToolGateway:
    return DirectGateway(_unsafe_upstream())


def gateway_for(mode: Mode) -> ToolGateway:
    return _direct_gateway() if mode is Mode.UNSAFE else _guarded_gateway()


def enforcer_label(mode: Mode) -> str:
    """What the UI badge should say. Never claims FailproofAI unless FailproofAI decides."""
    if mode is Mode.UNSAFE:
        return "NONE"
    return "FAILPROOFAI" if settings.enforcer == "FAILPROOFAI" else "LOCAL POLICY (stand-in)"
