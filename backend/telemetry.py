"""FailproofAI SDK audit trail: each review is one FailproofAI session.

session_id = review_id, agent_id = PRGuard agent id. Events land in the local
spool ($FAILPROOFAI_HOME/custom-agents/events) and the failproofai daemon ships
them to FailproofAI Cloud. No-op if `failproofai_sdk` is not installed, and a
telemetry failure never breaks a review.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

try:
    import failproofai_sdk as _sdk
except ImportError:  # pragma: no cover - SDK is optional
    _sdk = None

log = logging.getLogger(__name__)
_configured = False


def _emit(method: str, **kwargs: Any) -> None:
    global _configured
    if _sdk is None:
        return
    try:
        if not _configured:
            _sdk.configure()
            _configured = True
        getattr(_sdk.event, method)(**kwargs)
    except Exception as exc:  # noqa: BLE001 - telemetry must never fail the review
        log.warning("failproofai telemetry %s dropped: %s", method, exc)


def flush() -> None:
    if _sdk is not None and _configured:
        _sdk._writer.flush_now()


def review_start(session_id: str, agent_id: str, goal: str) -> None:
    _emit("agent_start", session_id=session_id, agent_id=agent_id, goal=goal)


def review_end(session_id: str, agent_id: str, outcome: str, summary: str = "") -> None:
    """outcome is the SDK's vocabulary: "success", "failed" or "cancelled"."""
    _emit("agent_end", session_id=session_id, agent_id=agent_id, outcome=outcome, summary=summary or None)


def tool_use(session_id: str, agent_id: str, tool: str, args: dict[str, Any]) -> str:
    """Starts a tool call and its access decision; returns the per-session unique call id."""
    call_id = uuid.uuid4().hex
    _emit("tool_use", session_id=session_id, agent_id=agent_id, tool_name=tool, tool_call_id=call_id, input=args)
    _emit("hook_triggered", session_id=session_id, agent_id=agent_id, hook_name="prguard-policies",
          hook_id=call_id, trigger_event="PreToolUse", input={"tool": tool, "args": args})
    return call_id


def decision(session_id: str, agent_id: str, call_id: str, verdict: str, enforcer: str, reason: str,
             policy: str = "") -> None:
    """The gateway decided (ALLOW/DENY), or could not decide (verdict ERROR -> outcome failed)."""
    output = {"decision": verdict, "enforcer": enforcer, "reason": reason, "policy": policy}
    _emit("hook_completed", session_id=session_id, agent_id=agent_id, hook_name="prguard-policies",
          hook_id=call_id, outcome="failed" if verdict == "ERROR" else "success", output=output,
          error=reason if verdict == "ERROR" else None)


def tool_result(session_id: str, agent_id: str, tool: str, call_id: str, output: Any = None,
                error: str | None = None) -> None:
    _emit("tool_result", session_id=session_id, agent_id=agent_id, tool_name=tool, tool_call_id=call_id,
          output=output, error=error)
