"""LangGraph pipeline:

build_context -> [security | quality | tests | docs | ci_fixer] -> aggregate -> gemini_check -> hitl_gate -> post_review
"""

from __future__ import annotations

import asyncio
import operator
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from backend import telemetry
from backend.agents import aggregator, ci_fixer, gemini_checker, specialists, triage
from backend.config import settings
from backend.events import bus
from backend.gateway import enforcer_label, gateway_for
from backend.models import Denial, Event, Finding, Review, TaskContext, UpstreamError
from backend.sandbox.checkout import checkout_pr
from backend.sandbox.runner import run_checks

ORCHESTRATOR = "prguard-orchestrator"


class ReviewState(TypedDict, total=False):
    ctx: TaskContext
    diff: str
    files: list[dict[str, Any]]
    head_files: dict[str, str]
    check_results: dict[str, Any]
    triage: dict[str, Any]
    title: str
    findings_by_agent: Annotated[dict[str, list[Finding]], operator.or_]
    review: Review
    role: str  # only set on the per-specialist payload


def _span(ctx: TaskContext, source: str, kind: str, **payload: Any) -> None:
    bus.emit(Event(type=kind, review_id=ctx.review_id, mode=ctx.mode, source=source, payload=payload))


def _text(data: Any) -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        return str(data.get("content") or data.get("text") or "")
    return ""


async def build_context(state: ReviewState) -> dict[str, Any]:
    ctx = state["ctx"]
    gateway = gateway_for(ctx.mode)
    _span(ctx, ORCHESTRATOR, "span.start", node="build_context")
    scope = {"repo": ctx.repo_full_name, "pull_number": ctx.pr_number}

    files_res = await gateway.call(ORCHESTRATOR, ctx, "get_pull_request_files", scope)
    diff_res = await gateway.call(ORCHESTRATOR, ctx, "get_pull_request_diff", scope)
    files = files_res.data if not isinstance(files_res, Denial) and isinstance(files_res.data, list) else []
    diff = _text(diff_res.data) if not isinstance(diff_res, Denial) else ""
    if not diff:
        diff = "\n".join(f.get("patch", "") for f in files)

    head_files: dict[str, str] = {}
    for item in files[:25]:
        if item.get("status") == "removed":
            continue
        try:
            res = await gateway.call(ORCHESTRATOR, ctx, "get_file_contents",
                                     {"repo": ctx.repo_full_name, "path": item["filename"], "ref": ctx.head_sha})
        except UpstreamError:
            continue
        if not isinstance(res, Denial):
            head_files[item["filename"]] = _text(res.data)

    try:
        src = await asyncio.wait_for(checkout_pr(ctx), timeout=settings.node_timeout_s)
        check_results = await run_checks(src, ctx)
    except Exception as exc:  # a failed checkout must not sink the review
        check_results = {"ran": False, "reason": f"checkout failed: {exc}", "exit_codes": {}}
        bus.emit(Event(type="error", review_id=ctx.review_id, mode=ctx.mode, source="sandbox", reason=str(exc)))

    _span(ctx, ORCHESTRATOR, "span.end", node="build_context", files=len(files))
    return {"files": files, "diff": diff, "head_files": head_files, "check_results": check_results}


async def triage_node(state: ReviewState) -> dict[str, Any]:
    """Optional fast pre-screen (TypeSafe Jev). Skipped silently when not configured."""
    ctx = state["ctx"]
    result = await triage.triage(state.get("title", ""), state.get("diff", ""))
    if result is None:
        return {"triage": {}}
    bus.emit(Event(type="triage", review_id=ctx.review_id, mode=ctx.mode, source="jev-triage", payload=result))
    return {"triage": result}


def fan_out(state: ReviewState) -> list[Send]:
    return [Send("specialist", {**state, "role": role}) for role in specialists.ROLES] + [Send("ci_fixer", state)]


async def ci_fixer_node(state: ReviewState) -> dict[str, Any]:
    ctx = state["ctx"]
    source = ci_fixer.AGENT_ID
    _span(ctx, source, "span.start", node="ci", llm="MOCK LLM" if settings.llm_is_mock else settings.llm_model)
    info: dict[str, Any] = {}
    try:
        findings, info = await asyncio.wait_for(
            ci_fixer.run_ci_fixer(ctx, state, gateway_for(ctx.mode)), timeout=settings.node_timeout_s
        )
        note = info.pop("note", "")
    except asyncio.TimeoutError:
        findings, note = [], f"timed out after {settings.node_timeout_s:.0f}s"
    except Exception as exc:  # the CI fixer failing never blocks the join
        findings, note = [], f"{type(exc).__name__}: {exc}"[:300]
    for finding in findings:
        bus.emit(Event(type="finding", review_id=ctx.review_id, mode=ctx.mode, source=source, payload=finding.model_dump()))
    _span(ctx, source, "span.end", node="ci", findings=len(findings), note=note, usage=info)
    return {"findings_by_agent": {"ci": findings}}


async def specialist(state: ReviewState) -> dict[str, Any]:
    ctx, role = state["ctx"], state["role"]
    source = specialists.agent_id(role)
    _span(ctx, source, "span.start", node=role, llm="MOCK LLM" if settings.llm_is_mock else settings.llm_model)
    usage: dict[str, Any] = {}
    try:
        findings, usage = await asyncio.wait_for(
            specialists.run_specialist(role, ctx, state, gateway_for(ctx.mode)), timeout=settings.node_timeout_s
        )
        note = ""
    except asyncio.TimeoutError:
        findings, note = [], f"timed out after {settings.node_timeout_s:.0f}s"
    except Exception as exc:  # one specialist failing never blocks the join
        findings, note = [], f"{type(exc).__name__}: {exc}"[:300]
    for finding in findings:
        bus.emit(Event(type="finding", review_id=ctx.review_id, mode=ctx.mode, source=source, payload=finding.model_dump()))
    _span(ctx, source, "span.end", node=role, findings=len(findings), note=note, usage=usage)
    return {"findings_by_agent": {role: findings}}


async def aggregate(state: ReviewState) -> dict[str, Any]:
    ctx = state["ctx"]
    _span(ctx, aggregator.AGENT_ID, "span.start", node="aggregate")
    findings = aggregator.merge(state.get("findings_by_agent", {}))
    overall, verdict = aggregator.score(findings)
    tri = state.get("triage") or {}
    if tri.get("needs_human"):
        verdict = "NEEDS_HUMAN"
    review = Review(review_id=ctx.review_id, findings=findings, overall_confidence=overall, verdict=verdict, triage=tri)
    _span(ctx, aggregator.AGENT_ID, "span.end", node="aggregate", findings=len(findings), verdict=verdict)
    return {"review": review}


async def gemini_check(state: ReviewState) -> dict[str, Any]:
    ctx, review = state["ctx"], state["review"]
    _span(ctx, "gemini-checker", "span.start", node="gemini_check")
    usage: dict[str, Any] = {}
    try:
        findings, notes, usage = await asyncio.wait_for(
            gemini_checker.check(review.findings, state.get("diff", "")), timeout=settings.node_timeout_s
        )
    except asyncio.TimeoutError:
        findings, notes = review.findings, "independent checker timed out; findings are unverified"
    overall, verdict = aggregator.score(findings)
    if review.triage.get("needs_human"):
        verdict = "NEEDS_HUMAN"  # the checker can reject findings, but not overrule the injection screen
    review = review.model_copy(update={"findings": findings, "overall_confidence": overall, "verdict": verdict, "checker_notes": notes})
    _span(ctx, "gemini-checker", "span.end", node="gemini_check", kept=len(findings), notes=notes, usage=usage)
    return {"review": review}


async def hitl_gate(state: ReviewState) -> dict[str, Any]:
    ctx, review = state["ctx"], state["review"]
    _span(ctx, "hitl-gate", "span.start", node="hitl_gate")
    if review.verdict == "NEEDS_HUMAN":
        bus.emit(Event(type="hitl.waiting", review_id=ctx.review_id, mode=ctx.mode, source="hitl-gate",
                       reason="critical finding or low confidence; APPROVE stays locked until a human approves"))
    _span(ctx, "hitl-gate", "span.end", node="hitl_gate", verdict=review.verdict)
    return {}


def labels(ctx: TaskContext) -> list[str]:
    out = [f"mode: {ctx.mode.value}", f"access control: {enforcer_label(ctx.mode)}"]
    if settings.llm_is_mock:
        out.append("reviewers: MOCK LLM (no model configured)")
    else:
        out.append(f"reviewers: {settings.llm_model}")
    if settings.upstream == "mock":
        out.append("GitHub: MOCK upstream")
    return out


async def post_review(state: ReviewState) -> dict[str, Any]:
    """Post the findings. NEEDS_HUMAN still posts a COMMENT; only APPROVE waits for a human."""
    ctx, review = state["ctx"], state["review"]
    gateway = gateway_for(ctx.mode)
    _span(ctx, aggregator.AGENT_ID, "span.start", node="post_review")
    blocked = sum(1 for e in bus.history if e.review_id == ctx.review_id and e.type == "decision" and e.decision == "DENY")
    review = review.model_copy(update={"summary_markdown": aggregator.summary_markdown(review, blocked, labels(ctx))})

    event = "REQUEST_CHANGES" if review.verdict == "REQUEST_CHANGES" else "COMMENT"
    args = {"repo": ctx.repo_full_name, "pull_number": ctx.pr_number, "event": event, "body": review.summary_markdown}
    result: Any = None
    try:
        result = await gateway.call(aggregator.AGENT_ID, ctx, "create_pull_request_review", args)
    except UpstreamError:
        if event != "COMMENT":
            # GitHub refuses REQUEST_CHANGES on your own PR; fall back to a comment.
            try:
                result = await gateway.call(aggregator.AGENT_ID, ctx, "create_pull_request_review", {**args, "event": "COMMENT"})
            except UpstreamError:
                result = None
    if result is not None and not isinstance(result, Denial) and isinstance(result.data, dict) and result.data.get("html_url"):
        url = result.data["html_url"]
        review = review.model_copy(update={"posted_url": url})
        bus.emit(Event(type="review.posted", review_id=ctx.review_id, mode=ctx.mode, source=aggregator.AGENT_ID,
                       payload={"url": url, "event": event}))
    bus.emit(Event(type="review.ready", review_id=ctx.review_id, mode=ctx.mode, source=aggregator.AGENT_ID,
                   payload=review.model_dump()))
    _span(ctx, aggregator.AGENT_ID, "span.end", node="post_review", posted=bool(review.posted_url))
    return {"review": review}


def build_graph():
    graph = StateGraph(ReviewState)
    graph.add_node("build_context", build_context)
    graph.add_node("triage", triage_node)
    graph.add_node("specialist", specialist)
    graph.add_node("ci_fixer", ci_fixer_node)
    graph.add_node("aggregate", aggregate)
    graph.add_node("gemini_check", gemini_check)
    graph.add_node("hitl_gate", hitl_gate)
    graph.add_node("post_review", post_review)
    graph.add_edge(START, "build_context")
    graph.add_edge("build_context", "triage")
    graph.add_conditional_edges("triage", fan_out, ["specialist", "ci_fixer"])
    graph.add_edge("specialist", "aggregate")
    graph.add_edge("ci_fixer", "aggregate")
    graph.add_edge("aggregate", "gemini_check")
    graph.add_edge("gemini_check", "hitl_gate")
    graph.add_edge("hitl_gate", "post_review")
    graph.add_edge("post_review", END)
    return graph.compile()


pipeline = build_graph()


async def run_review(ctx: TaskContext) -> Review:
    _span(ctx, "pr", "span.start", repo=ctx.repo_full_name, pr=ctx.pr_number, head_sha=ctx.head_sha,
          enforcer=enforcer_label(ctx.mode))
    telemetry.review_start(ctx.review_id, ORCHESTRATOR,
                           f"Review {ctx.repo_full_name} PR #{ctx.pr_number} at {ctx.head_sha} ({ctx.mode.value})")
    outcome, summary = "failed", ""
    try:
        state = await pipeline.ainvoke({"ctx": ctx, "findings_by_agent": {}})
        outcome, summary = "success", f"verdict {state['review'].verdict}, {len(state['review'].findings)} findings"
        return state["review"]
    except asyncio.CancelledError:
        outcome = "cancelled"
        raise
    finally:
        telemetry.review_end(ctx.review_id, ORCHESTRATOR, outcome, summary)
        telemetry.flush()
        _span(ctx, "pr", "span.end")
