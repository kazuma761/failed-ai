"""GUARDED path with FailproofAI: every call is put to the failproofai PreToolUse hook.

PRGuard's policy (failproofai/prguard-policies.mjs, a port of prguard.policy.yaml)
decides inside failproofai; this gateway only builds the hook payload from the
trusted TaskContext, reads the verdict and forwards allowed calls upstream.
Anything other than a clear verdict fails closed as an UpstreamError, never as
a FailproofAI decision. See team/CONTRACT.md for the wire contract.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from backend.config import ROOT, settings
from backend.gateway.base import BaseGateway
from backend.gateway.upstream import Upstream
from backend.models import Denial, Enforcer, TaskContext, ToolResult, UpstreamError

# failproofai wraps the reason: "Blocked <tool> by failproofai because: <ours>, as per the policy configured by the user"
# Lazy rule group: rule names such as roles.<agent>.allow[1] contain "]" themselves.
_REASON = re.compile(r"PRGuard policy \[(.+?)\]: (.*?)(?:, as per the policy configured by the user)?\s*$", re.DOTALL)
CONTEXT_KEYS = ("_prguard", "prguard_task", "prguard")
NOT_LOADED = "PRGuard's FailproofAI policy is not loaded: run scripts/failproofai_setup.sh"


def _agent_args(args: dict[str, Any]) -> dict[str, Any]:
    """The agent's own args, minus any key that could pass for PRGuard's trusted context."""
    return {k: v for k, v in args.items() if k not in CONTEXT_KEYS}


def parse_verdict(stdout: str) -> str | None:
    """Deny reason, or None for allow. Raises UpstreamError on anything unclear."""
    text = stdout.strip()
    if not text:
        return None
    try:
        out = json.loads(text)
    except ValueError as exc:
        raise UpstreamError(f"unreadable failproofai output: {text[:200]}") from exc
    if not isinstance(out, dict):
        raise UpstreamError(f"unreadable failproofai output: {text[:200]}")
    hook = out.get("hookSpecificOutput")
    if isinstance(hook, dict):
        if hook.get("permissionDecision") == "deny":
            return str(hook.get("permissionDecisionReason") or "denied by failproofai")
        if hook.get("permissionDecision") in (None, "allow") and set(hook) <= {"hookEventName", "permissionDecision", "additionalContext"}:
            return None  # allow or instruct-only: PRGuard's policy never instructs
    if out.get("decision") == "block" or out.get("permission") == "deny":
        return str(out.get("reason") or out.get("message") or "denied by failproofai")
    raise UpstreamError(f"unexpected failproofai output: {text[:200]}")


class FailproofAIGateway(BaseGateway):
    enforcer = Enforcer.FAILPROOFAI

    def __init__(self, upstream: Upstream, binary: str | None = None) -> None:
        self.upstream = upstream
        self.upstream_name = upstream.name
        self.binary = binary or settings.failproofai_bin
        self._probed: bool | None = None  # None = not yet probed; False = policy missing, refuse everything
        self._lock = asyncio.Lock()

    async def _hook(self, agent_id: str, ctx: TaskContext, tool: str, args: dict[str, Any]) -> str | None:
        tool_input = _agent_args(args)
        task = {"agent_id": agent_id, "repo": ctx.repo_full_name, "pr_number": ctx.pr_number,
                "head_sha": ctx.head_sha, "human_approved": ctx.human_approved}
        # The same trusted context under three names: the real hook path has been seen to drop `_prguard`.
        tool_input["_prguard"] = tool_input["prguard_task"] = task
        payload = {"hook_event_name": "PreToolUse", "session_id": ctx.review_id, "transcript_path": "/dev/null",
                   "cwd": str(ROOT), "tool_name": f"mcp__prguard__{tool}", "tool_input": tool_input, "prguard": task}
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary, "--hook", "PreToolUse", cwd=str(ROOT),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except OSError as exc:
            raise UpstreamError(f"cannot run failproofai ({self.binary}): {exc}") from exc
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(json.dumps(payload).encode()), 15)
        except asyncio.TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise UpstreamError("failproofai hook timed out after 15 s") from exc
        reason = parse_verdict(stdout.decode(errors="replace"))
        if reason is None and proc.returncode != 0:
            raise UpstreamError(f"failproofai exited {proc.returncode}: {stderr.decode(errors='replace')[:200]}")
        return reason

    async def _ensure_policy(self) -> None:
        """failproofai fails OPEN on a missing policy, so prove ours denies before trusting any allow."""
        async with self._lock:
            if self._probed is None:
                probe = TaskContext(review_id="prguard-probe", repo_full_name=settings.target_repo, pr_number=1, head_sha="0" * 40)  # a complete context, so only always_deny.tools can fire
                reason = await self._hook("prguard-security", probe, "merge_pull_request", {})
                self._probed = bool(reason and "[always_deny.tools]" in reason)
        if not self._probed:
            raise UpstreamError(NOT_LOADED)

    async def _decide(self, agent_id: str, ctx: TaskContext, tool: str, args: dict[str, Any]) -> ToolResult | Denial:
        await self._ensure_policy()
        reason = await self._hook(agent_id, ctx, tool, args)
        if reason is not None:
            hit = _REASON.search(reason)
            return Denial(tool=tool, reason=hit.group(2) if hit else reason, enforcer=self.enforcer,
                          policy=hit.group(1) if hit else "failproofai")
        return ToolResult(tool=tool, data=await self.upstream.call(tool, _agent_args(args)))
