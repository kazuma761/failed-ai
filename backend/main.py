"""PRGuard backend.

Run:  uvicorn backend.main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx
from fastapi import (
    BackgroundTasks,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend import github_webhook
from backend.agents import aggregator
from backend.config import settings
from backend.events import bus
from backend.gateway import enforcer_label, gateway_for, mock_upstream
from backend.models import Denial, Event, Mode, Review, TaskContext, UpstreamError
from backend.orchestrator.graph import ORCHESTRATOR, run_review
from backend.replay.assume_breach import run_replay
from backend.sandbox.runner import docker_ready

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("prguard")

app = FastAPI(title="PRGuard")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

current_mode: Mode = Mode.GUARDED
contexts: dict[str, TaskContext] = {}
reviews: dict[str, Review] = {}
seen_deliveries: set[str] = set()


async def _review_task(ctx: TaskContext) -> None:
    contexts[ctx.review_id] = ctx
    try:
        reviews[ctx.review_id] = await run_review(ctx)
    except Exception as exc:
        log.exception("review %s failed", ctx.review_id)
        bus.emit(Event(type="error", review_id=ctx.review_id, mode=ctx.mode, source="pr", reason=f"review failed: {exc}"))


async def _context_for_pr(repo: str, number: int, mode: Mode, prefix: str = "") -> TaskContext:
    """Build a TaskContext for an operator-chosen PR. Head SHA and author come from GitHub."""
    if repo != settings.target_repo:
        raise HTTPException(400, f"PRGuard only reviews {settings.target_repo}")
    # A separate, short-lived task just to look the PR up: its head commit is not
    # known yet, and the review task should name the exact commit.
    gateway = gateway_for(mode)
    probe = TaskContext(review_id="lookup-" + github_webhook.new_review_id(), repo_full_name=repo, pr_number=number,
                        head_sha="", mode=mode)
    try:
        res = await gateway.call(ORCHESTRATOR, probe, "get_pull_request", {"repo": repo, "pull_number": number})
    except UpstreamError as exc:
        raise HTTPException(502, f"could not load the pull request: {exc}") from exc
    if isinstance(res, Denial):
        raise HTTPException(403, f"access control refused the pull request lookup: {res.reason}")
    if not isinstance(res.data, dict) or "head" not in res.data:
        raise HTTPException(502, "could not load the pull request")
    pr = res.data
    return probe.model_copy(update={
        "review_id": prefix + github_webhook.new_review_id(),
        "head_sha": pr["head"]["sha"],
        "base_ref": pr.get("base", {}).get("ref", "main"),
        "sender": pr.get("user", {}).get("login", "unknown"),
    })


_pr_cache: dict[str, Any] = {"at": 0.0, "prs": []}


async def _list_prs() -> list[dict[str, Any]]:
    """PRs for the selector. Mock fixtures offline; the public GitHub API otherwise (cached a minute)."""
    if settings.upstream == "mock":
        return [{"number": n, "title": m["title"]} for n, m in sorted(mock_upstream().prs.items())]
    if time.time() - _pr_cache["at"] > 60:
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                response = await client.get(f"https://api.github.com/repos/{settings.target_repo}/pulls",
                                            params={"state": "open", "per_page": 30, "sort": "created", "direction": "asc"})
            if response.status_code == 200:
                _pr_cache.update(at=time.time(), prs=[{"number": p["number"], "title": p["title"]} for p in response.json()])
        except httpx.HTTPError:
            pass
    return _pr_cache["prs"]


@app.get("/state")
async def state() -> dict[str, Any]:
    prs = await _list_prs()
    return {
        "mode": current_mode.value,
        "enforcer": enforcer_label(current_mode),
        "upstream": settings.upstream,
        "llm": "MOCK LLM" if settings.llm_is_mock else settings.llm_model,
        "checker": settings.checker[1] if settings.checker else "not configured",
        "target_repo": settings.target_repo,
        "prs": prs,
        "sandbox": await docker_ready() or "ready",
    }


class ModeBody(BaseModel):
    mode: Mode


@app.post("/mode")
async def set_mode(body: ModeBody) -> dict[str, Any]:
    global current_mode
    current_mode = body.mode
    bus.emit(Event(type="mode.changed", mode=current_mode, source="operator", payload={"enforcer": enforcer_label(current_mode)}))
    return {"mode": current_mode.value, "enforcer": enforcer_label(current_mode)}


class ReviewBody(BaseModel):
    pr_url: str | None = None
    pr_number: int | None = None


@app.post("/review")
async def review(body: ReviewBody, background: BackgroundTasks) -> dict[str, Any]:
    if body.pr_url:
        parsed = github_webhook.parse_pr_url(body.pr_url)
        if not parsed:
            raise HTTPException(400, "pr_url must look like https://github.com/owner/repo/pull/123")
        repo, number = parsed
    elif body.pr_number:
        repo, number = settings.target_repo, body.pr_number
    else:
        raise HTTPException(400, "give pr_url or pr_number")
    ctx = await _context_for_pr(repo, number, current_mode)
    background.add_task(_review_task, ctx)
    return {"review_id": ctx.review_id, "mode": ctx.mode.value}


@app.post("/webhook")
async def webhook(request: Request, background: BackgroundTasks) -> dict[str, Any]:
    body = await request.body()
    if not github_webhook.verify_signature(settings.github_webhook_secret, body, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(401, "bad signature")
    delivery = request.headers.get("X-GitHub-Delivery", "")
    if delivery in seen_deliveries:
        return {"status": "duplicate"}
    seen_deliveries.add(delivery)
    if request.headers.get("X-GitHub-Event") != "pull_request":
        return {"status": "ignored"}
    ctx = github_webhook.context_from_webhook(json.loads(body), current_mode)
    if ctx is None or ctx.repo_full_name != settings.target_repo:
        return {"status": "ignored"}
    background.add_task(_review_task, ctx)
    return {"status": "queued", "review_id": ctx.review_id}


@app.post("/approve/{review_id}")
async def approve(review_id: str) -> dict[str, Any]:
    ctx, rev = contexts.get(review_id), reviews.get(review_id)
    if ctx is None or rev is None:
        raise HTTPException(404, "unknown or unfinished review")
    if rev.verdict != "NEEDS_HUMAN":
        raise HTTPException(409, "this review is not waiting for a human")
    # Runtime permission change, scoped to this one task.
    ctx.human_approved = True
    bus.emit(Event(type="hitl.approved", review_id=review_id, mode=ctx.mode, source="operator",
                   reason=f"human approved; APPROVE unlocked for {ctx.repo_full_name}#{ctx.pr_number} only"))
    args = {"repo": ctx.repo_full_name, "pull_number": ctx.pr_number, "event": "APPROVE",
            "body": "Approved by a human reviewer via PRGuard.\n\n" + rev.summary_markdown}
    try:
        result = await gateway_for(ctx.mode).call(aggregator.AGENT_ID, ctx, "create_pull_request_review", args)
    except UpstreamError as exc:
        # e.g. GitHub does not let an account approve its own pull request.
        return {"approved": True, "posted": False, "reason": f"allowed by access control, refused by GitHub: {exc}"}
    if isinstance(result, Denial):
        return {"approved": True, "posted": False, "reason": result.reason}
    url = result.data.get("html_url", "") if isinstance(result.data, dict) else ""
    bus.emit(Event(type="review.posted", review_id=review_id, mode=ctx.mode, source=aggregator.AGENT_ID,
                   payload={"url": url, "event": "APPROVE"}))
    return {"approved": True, "posted": True, "url": url}


@app.post("/replay")
async def replay(agent: str = "prguard-security", pr: int = 2) -> dict[str, Any]:
    # Always a fresh task, so an approval given to a real review never carries over.
    ctx = await _context_for_pr(settings.target_repo, pr, current_mode, prefix="replay-")
    results = await run_replay(agent, ctx, gateway_for(ctx.mode))
    return {"review_id": ctx.review_id, "mode": ctx.mode.value, "enforcer": enforcer_label(ctx.mode), "results": results}


@app.post("/reset")
async def reset() -> dict[str, Any]:
    """Clear the event feed and, with the mock upstream, undo recorded writes."""
    bus.clear()
    contexts.clear()
    reviews.clear()
    mock_upstream().reset()
    return {"ok": True}


@app.post("/internal/canary")
async def canary(request: Request) -> dict[str, Any]:
    if request.client is None or request.client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(403, "localhost only")
    record = await request.json()
    latest = next((e for e in reversed(bus.history) if e.source == "sandbox" and e.review_id), None)
    bus.emit(Event(type="canary.received", review_id=latest.review_id if latest else "", mode=latest.mode if latest else current_mode,
                   source="canary-listener",
                   payload={"env_names": record.get("env_names", []), "canary": record.get("canary")}))
    return {"ok": True}


@app.websocket("/ws")
async def ws(socket: WebSocket) -> None:
    await socket.accept()
    queue = bus.subscribe()
    try:
        for event in list(bus.history):
            await socket.send_text(event.model_dump_json())
        while True:
            event = await queue.get()
            await socket.send_text(event.model_dump_json())
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        pass
    finally:
        bus.unsubscribe(queue)
