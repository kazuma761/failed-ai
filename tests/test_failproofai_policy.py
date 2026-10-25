"""Parity: failproofai/prguard-policies.mjs must decide exactly like PolicyEngine on the YAML."""

import json
import shutil
import subprocess

import pytest

from backend.config import ROOT, settings
from backend.gateway.policy_engine import PolicyEngine
from backend.gateway.upstream import MockUpstream
from backend.models import TaskContext
from backend.replay.assume_breach import steps

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not on PATH")

REPO = settings.target_repo
HEAD = MockUpstream().head_sha(2)
read = lambda path, ref=HEAD, **kw: {"repo": REPO, "path": path, "ref": ref, **kw}
review = lambda event, pr=2: {"repo": REPO, "pull_number": pr, "event": event, "body": "x"}

BYPASS_PATHS = ["./.env", "a/../.env", ".ENV", ".Env", "/.env", "//.env", ".env/", "a//.env", "app/Secrets/x",
                "x.PEM", "x.Key", "%2Eenv", ".en%76", "secr%65ts/x", "k.p%65m", ".env?x=1", "app.py?ref=main",
                "app.py#x", ".env/.", "x.pem/.", "config.key/.", ".env/./.", "./app.py", "", "\t.env", "a\\..\\.env", ".env\x00", "\x85.env"]
BYPASS_QUERIES = ["x repo:someone/other", "x REPO:someone/other", "x repo:a/b", "x　Org:a", "Repo:a/b", "x\trepo:a/b", "(org:other)", "user:other x",
                  "owner:other", "-repo:x", "érepo:x"]

# (agent, human_approved, tool, args)
CASES = [
    ("prguard-security", False, "get_pull_request", {"repo": REPO, "pull_number": 2}),
    ("prguard-security", False, "get_pull_request", {"repo": REPO, "pull_number": "2"}),
    ("prguard-security", False, "get_pull_request", {"repo": REPO}),                         # where near-miss
    ("prguard-security", False, "get_pull_request_diff", {"repo": settings.other_repo, "pull_number": 2}),
    ("prguard-security", False, "get_pull_request_files", {"repo": REPO, "pull_number": 1}),
    ("prguard-quality", False, "get_file_contents", read("app/payments.py")),
    ("prguard-quality", False, "get_file_contents", read("app/payments.py", ref="main")),
    ("prguard-quality", False, "get_file_contents", read("app/payments.py", ref=None)),
    *[("prguard-quality", False, "get_file_contents", read(p)) for p in [
        ".env", "/.env.local", " .env ", "config/.env.prod", "deploy/secrets/key.txt", "secrets/a",
        "certs/server.pem", "a/b/id.key", "../outside", "a/../.env", "src/environment.py", "README.md"]],
    ("prguard-quality", False, "get_file_contents", {"repo": REPO, "ref": HEAD, "path": None}),
    ("prguard-quality", False, "get_file_contents", {"repo": REPO, "ref": HEAD}),
    ("prguard-tests", False, "search_code", {"repo": REPO, "query": "refund"}),
    ("prguard-docs", False, "search_code", {"query": "refund"}),
    ("prguard-orchestrator", False, "list_workflow_runs", {"repo": REPO}),                    # role default
    *[("prguard-security", True, t, {"repo": REPO, "pull_number": 2}) for t in
      ["merge_pull_request", "push_files", "delete_file", "create_or_update_file"]],
    ("prguard-aggregator", False, "create_pull_request_review", review("COMMENT")),
    ("prguard-aggregator", False, "create_pull_request_review", review("REQUEST_CHANGES")),
    ("prguard-aggregator", False, "create_pull_request_review", review("APPROVE")),
    ("prguard-aggregator", True, "create_pull_request_review", review("APPROVE")),
    ("prguard-aggregator", True, "create_pull_request_review", review("APPROVE", pr=1)),
    ("prguard-aggregator", False, "create_pull_request_review", review("DISMISS")),
    ("prguard-aggregator", False, "create_pull_request_review", {"repo": REPO, "pull_number": 2}),
    ("prguard-security", True, "create_pull_request_review", review("APPROVE")),
    ("prguard-ci-fixer", False, "list_workflow_runs", {"repo": REPO, "head_sha": HEAD}),
    ("prguard-ci-fixer", False, "get_job_logs", {"repo": REPO, "run_id": 9003}),
    ("prguard-ci-fixer", False, "rerun_failed_jobs", {"repo": REPO, "run_id": 9003}),
    ("prguard-ci-fixer", False, "get_job_logs", {"repo": settings.other_repo, "run_id": 1}),
    ("prguard-ci-fixer", False, "get_file_contents", read("app/payments.py")),
    ("prguard-ci-fixer", False, "create_or_update_file", {"repo": REPO, "path": ".github/workflows/ci.yml"}),
    # Round 2 red team: every one of these must deny in both engines (see test_secret_and_scope_bypasses).
    *[("prguard-quality", False, "get_file_contents", read(p)) for p in BYPASS_PATHS],
    *[("prguard-security", False, "get_pull_request", {"repo": REPO, "pull_number": v}) for v in ["2 ", "02", "+2", True, [2]]],
    *[("prguard-security", False, "get_pull_request", {"repo": r, "pull_number": 2}) for r in
      [REPO.upper(), REPO + " ", REPO + "/"]],
    *[("prguard-tests", False, "search_code", {"repo": REPO, "query": q}) for q in BYPASS_QUERIES],
    ("prguard-tests", False, "search_code", {"repo": REPO, "query": "repository: refund user_id"}),  # allowed
    ("prguard-tests", False, "search_code", {"repo": REPO, "query": None}),
    ("prguard-security", True, "MERGE_PULL_REQUEST", {"repo": REPO, "pull_number": 2}),
    ("nobody", False, "get_pull_request", {"repo": REPO, "pull_number": 2}),
    ("constructor", False, "get_pull_request", {"repo": REPO, "pull_number": 2}),
]


def ctx_for(human_approved: bool) -> TaskContext:
    return TaskContext(review_id="parity", repo_full_name=REPO, pr_number=2, head_sha=HEAD, human_approved=human_approved)


def task(ctx: TaskContext, agent: str) -> dict:
    return {"agent_id": agent, "repo": ctx.repo_full_name, "pr_number": ctx.pr_number,
            "head_sha": ctx.head_sha, "human_approved": ctx.human_approved}


def run_js(cases: list[dict]) -> list[dict]:
    out = subprocess.run(["node", str(ROOT / "failproofai" / "harness.mjs")], input=json.dumps(cases),
                         capture_output=True, text=True, timeout=30, check=True)
    return json.loads(out.stdout)


def test_js_policy_matches_policy_engine():
    engine = PolicyEngine(settings.policy_path)
    replay = [("prguard-security", False, s["tool"], s["args"]) for s in steps(ctx_for(False))]
    table = CASES + replay
    js = run_js([{"tool": f"mcp__prguard__{tool}", "input": {**args, "_prguard": task(ctx_for(h), agent)}}
                 for agent, h, tool, args in table])
    for (agent, h, tool, args), got in zip(table, js, strict=True):
        want = engine.evaluate(agent, ctx_for(h), tool, args)
        expected = {"decision": "allow", "reason": ""} if want.allowed else \
            {"decision": "deny", "reason": f"PRGuard policy [{want.rule}]: {want.reason}"}
        assert got == expected, (agent, tool, args)
    # The replay itself still reads ALLOW then seven DENYs.
    assert [d["decision"] for d in js[-8:]] == ["allow"] + ["deny"] * 7


def test_secret_and_scope_bypasses():
    engine, ctx = PolicyEngine(settings.policy_path), ctx_for(False)
    reads = [p for p in BYPASS_PATHS if p != "\x85.env"]   # \x85.env is a different file, not .env
    assert not any(engine.evaluate("prguard-quality", ctx, "get_file_contents", read(p)).allowed for p in reads)
    assert not any(engine.evaluate("prguard-tests", ctx, "search_code", {"repo": REPO, "query": q}).allowed
                   for q in BYPASS_QUERIES)
    assert engine.evaluate("prguard-tests", ctx, "search_code", {"repo": REPO, "query": "refund"}).allowed
    assert engine.evaluate("prguard-quality", ctx, "get_file_contents", read("app/payments.py")).allowed


def test_contract_extras():
    no_context = {"decision": "deny", "reason": "PRGuard policy [default]: no PRGuard task context"}
    good = task(ctx_for(False), "prguard-security")
    # A broken task must not let ref="None" match a missing head_sha, or "true" pass as approval.
    broken = [{}, {"agent_id": "prguard-security"}, {**good, "head_sha": None},
              {k: v for k, v in good.items() if k != "head_sha"}, {**good, "pr_number": "2"},
              {**good, "human_approved": "true"}, {**good, "agent_id": None}, {**good, "repo": None}, []]
    file_read = {"repo": REPO, "path": "app/payments.py", "ref": "None"}
    *broken_out, no_task, upper_prefix, others = run_js(
        [{"tool": "mcp__prguard__get_file_contents", "input": {**file_read, "_prguard": t}} for t in broken] + [
        {"tool": "mcp__prguard__get_pull_request", "input": {"repo": REPO, "pull_number": 2}},
        {"tool": "MCP__PRGUARD__merge_pull_request", "input": {"repo": REPO, "pull_number": 2, "_prguard": good}},
        {"tool": "Bash", "input": {"command": "ls"}},
    ])
    for got in [*broken_out, no_task]:
        assert got["decision"] == "deny" and got["reason"].startswith(no_context["reason"] + " (tool_input keys: ")
    # The operator's next run must show what survives the real hook path: key names only, never values.
    assert no_task["reason"].endswith("tool_input keys: repo,pull_number; payload keys: hook_event_name,tool_name,tool_input)")
    assert REPO not in broken_out[2]["reason"] and "prguard-security" not in broken_out[1]["reason"]
    assert upper_prefix["decision"] == "deny" and "[always_deny.tools]" in upper_prefix["reason"]
    assert others["decision"] == "allow"


def test_task_context_survives_any_carrier():
    """The real hook may drop `_prguard`: the task also rides as tool_input.prguard_task and payload.prguard."""
    good = task(ctx_for(False), "prguard-security")
    read_env = {"repo": REPO, "path": ".env", "ref": HEAD}
    read_ok = {"repo": REPO, "path": "app/payments.py", "ref": HEAD}
    carriers = [({"_prguard": good}, None), ({"prguard_task": good}, None), ({}, {"prguard": good}),
                ({"_prguard": good, "prguard_task": good}, {"prguard": good})]   # all three, identical
    out = run_js([{"tool": "mcp__prguard__get_file_contents", "input": {**a, **inp}, "payload": extra}
                  for a in (read_env, read_ok) for inp, extra in carriers])
    assert [o["decision"] for o in out] == ["deny"] * 4 + ["allow"] * 4
    assert all("[roles.prguard-security.allow[1]]" in o["reason"] for o in out[:4])
    # The task key itself is not a tool argument: it must not reach the rules.
    assert out[1] == out[0]
    # Carriers that disagree, or one that is broken beside a good one, are tampering: deny even a harmless read.
    other = {**good, "agent_id": "prguard-aggregator"}
    for inp, extra in [({"_prguard": good, "prguard_task": other}, None), ({"prguard_task": good}, {"prguard": other}),
                       ({"_prguard": {"agent_id": "x"}, "prguard_task": good}, None)]:
        got, = run_js([{"tool": "mcp__prguard__get_file_contents", "input": {**read_ok, **inp}, "payload": extra}])
        assert got == {"decision": "deny", "reason": "PRGuard policy [default]: conflicting PRGuard task context"}
