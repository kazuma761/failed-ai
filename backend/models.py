"""Shared data contracts: TaskContext, Finding, Review, Event, gateway results."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Mode(str, Enum):
    UNSAFE = "UNSAFE"
    GUARDED = "GUARDED"


class Enforcer(str, Enum):
    FAILPROOFAI = "FAILPROOFAI"
    LOCAL_POLICY = "LOCAL_POLICY"
    NONE = "NONE"


class TaskContext(BaseModel):
    """Trusted description of one review.

    Built only from a verified webhook or an operator-supplied PR URL, never
    from LLM output or PR content. `human_approved` is flipped only by /approve.
    """

    review_id: str
    repo_full_name: str
    pr_number: int
    head_sha: str
    base_ref: str = "main"
    sender: str = "unknown"
    mode: Mode = Mode.GUARDED
    human_approved: bool = False


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
AgentType = Literal["security", "quality", "tests", "docs", "ci"]


class Finding(BaseModel):
    agent_type: AgentType
    severity: Severity
    category: str
    summary: str
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    suggestion: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    rationale: str = ""
    # Filled in after the specialists run.
    agreed_by: list[str] = Field(default_factory=list)
    checker_status: Literal["CONFIRMED", "DOWNGRADED", "REJECTED", "UNVERIFIED"] = "UNVERIFIED"
    checker_reason: str = ""


Verdict = Literal["COMMENT", "REQUEST_CHANGES", "NEEDS_HUMAN"]


class Review(BaseModel):
    review_id: str
    findings: list[Finding] = Field(default_factory=list)
    overall_confidence: float = 0.0
    verdict: Verdict = "COMMENT"
    checker_notes: str = ""
    summary_markdown: str = ""
    posted_url: str = ""
    triage: dict[str, Any] = Field(default_factory=dict)


EventType = Literal[
    "span.start",
    "span.end",
    "tool.call",
    "decision",
    "finding",
    "sandbox",
    "canary.received",
    "review.posted",
    "hitl.waiting",
    "hitl.approved",
    "review.ready",
    "triage",
    "mode.changed",
    "error",
]


class Event(BaseModel):
    ts: float = Field(default_factory=time.time)
    review_id: str = ""
    mode: Mode = Mode.GUARDED
    source: str = ""
    type: EventType
    tool: str | None = None
    args_redacted: dict[str, Any] | None = None
    decision: Literal["ALLOW", "DENY"] | None = None
    reason: str | None = None
    enforcer: Enforcer | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    ok: Literal[True] = True
    tool: str
    data: Any = None


class Denial(BaseModel):
    """A call the access-control layer refused. Falsy, so `if not res:` works."""

    ok: Literal[False] = False
    tool: str
    reason: str
    enforcer: Enforcer
    policy: str = ""

    def __bool__(self) -> bool:
        return False


class UpstreamError(Exception):
    """The call was allowed but the tool server (or GitHub) failed it."""
