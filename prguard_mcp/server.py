"""PRGuard's own GitHub MCP server: the dozen GitHub operations a PR reviewer
and CI fixer could ever want, and nothing else.

Why our own server instead of GitHub's ~90-tool one:
  - the GitHub token lives here, on the host, so neither the agents nor
    FailproofAI ever hold it;
  - a small, stable tool catalog that PRGuard's FailproofAI policy can name
    tool by tool.

It deliberately includes dangerous tools (merge, push, file write/delete):
those are what the "before" half of the demo abuses and what FailproofAI blocks in
the "after" half. The server itself enforces nothing.

    .venv/bin/python -m prguard_mcp.server        # http://127.0.0.1:8090/mcp
"""

from __future__ import annotations

import base64
import os
from typing import Any

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

API = "https://api.github.com"
mcp = FastMCP("prguard-github")


def _headers(accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "prguard"}
    token = os.environ.get("GITHUB_PAT_UNSAFE", "").strip()
    if token:  # public repos can be read without one
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _request(method: str, path: str, *, accept: str = "application/vnd.github+json", **kwargs: Any) -> httpx.Response:
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        response = await client.request(method, API + path, headers=_headers(accept), **kwargs)
    if response.status_code >= 400:
        try:
            message = response.json().get("message", response.text[:200])
        except ValueError:
            message = response.text[:200]
        raise ToolError(f"GitHub {response.status_code}: {message}")
    return response


async def _json(method: str, path: str, **kwargs: Any) -> Any:
    response = await _request(method, path, **kwargs)
    return response.json() if response.content else {}


# ------------------------------------------------------------------- read

@mcp.tool
async def get_pull_request(owner: str, repo: str, pull_number: int) -> dict:
    """Get one pull request: title, author, head commit and base branch."""
    pr = await _json("GET", f"/repos/{owner}/{repo}/pulls/{pull_number}")
    return {"number": pr["number"], "title": pr["title"], "body": pr.get("body") or "", "state": pr["state"],
            "merged": pr.get("merged", False), "head": {"sha": pr["head"]["sha"], "ref": pr["head"]["ref"]},
            "base": {"ref": pr["base"]["ref"]}, "user": {"login": pr["user"]["login"]}, "html_url": pr["html_url"]}


@mcp.tool
async def get_pull_request_files(owner: str, repo: str, pull_number: int) -> list[dict]:
    """List the files changed by a pull request, with their patches."""
    files = await _json("GET", f"/repos/{owner}/{repo}/pulls/{pull_number}/files", params={"per_page": 100})
    return [{"filename": f["filename"], "status": f["status"], "patch": f.get("patch", "")} for f in files]


@mcp.tool
async def get_pull_request_diff(owner: str, repo: str, pull_number: int) -> str:
    """Get the unified diff of a pull request."""
    response = await _request("GET", f"/repos/{owner}/{repo}/pulls/{pull_number}", accept="application/vnd.github.diff")
    return response.text


@mcp.tool
async def get_file_contents(owner: str, repo: str, path: str, ref: str = "") -> dict:
    """Read one file from a repository at a branch, tag or commit."""
    data = await _json("GET", f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}", params={"ref": ref} if ref else None)
    if isinstance(data, list):
        raise ToolError(f"{path} is a directory")
    return {"path": data["path"], "content": base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")}


@mcp.tool
async def search_code(owner: str, repo: str, query: str) -> dict:
    """Search one repository's code for a string."""
    data = await _json("GET", "/search/code", params={"q": f"{query} repo:{owner}/{repo}", "per_page": 20})
    return {"total_count": data.get("total_count", 0), "items": [{"path": i["path"]} for i in data.get("items", [])]}


@mcp.tool
async def list_workflow_runs(owner: str, repo: str) -> dict:
    """List recent GitHub Actions workflow runs for a repository."""
    data = await _json("GET", f"/repos/{owner}/{repo}/actions/runs", params={"per_page": 30})
    runs = [{"id": r["id"], "name": r["name"], "head_sha": r["head_sha"], "head_branch": r["head_branch"],
             "status": r["status"], "conclusion": r["conclusion"], "html_url": r["html_url"]} for r in data.get("workflow_runs", [])]
    return {"total_count": len(runs), "workflow_runs": runs}


@mcp.tool
async def get_job_logs(owner: str, repo: str, run_id: int) -> dict:
    """Get the logs of the failed jobs in one workflow run."""
    data = await _json("GET", f"/repos/{owner}/{repo}/actions/runs/{run_id}/jobs")
    jobs = []
    for job in data.get("jobs", []):
        entry = {"name": job["name"], "conclusion": job["conclusion"], "logs": ""}
        if job["conclusion"] == "failure":
            try:
                entry["logs"] = (await _request("GET", f"/repos/{owner}/{repo}/actions/jobs/{job['id']}/logs")).text[-12000:]
            except ToolError as exc:  # reading logs needs a token even on public repos
                failed = [s["name"] for s in job.get("steps", []) if s.get("conclusion") == "failure"]
                entry["logs"] = f"(logs unavailable: {exc}) failed steps: {failed}"
        jobs.append(entry)
    return {"run_id": run_id, "jobs": jobs}


# ------------------------------------------------------------------ write

@mcp.tool
async def create_pull_request_review(owner: str, repo: str, pull_number: int, event: str, body: str = "") -> dict:
    """Submit a pull request review. event is COMMENT, REQUEST_CHANGES or APPROVE."""
    review = await _json("POST", f"/repos/{owner}/{repo}/pulls/{pull_number}/reviews", json={"event": event, "body": body})
    return {"id": review["id"], "state": review["state"], "html_url": review["html_url"]}


@mcp.tool
async def rerun_failed_jobs(owner: str, repo: str, run_id: int) -> dict:
    """Re-run the failed jobs of one workflow run."""
    await _json("POST", f"/repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs")
    return {"ok": True, "message": f"re-running failed jobs of run {run_id}"}


@mcp.tool
async def merge_pull_request(owner: str, repo: str, pull_number: int) -> dict:
    """Merge a pull request into its base branch."""
    return await _json("PUT", f"/repos/{owner}/{repo}/pulls/{pull_number}/merge")


async def _put_file(owner: str, repo: str, path: str, content: str, message: str, branch: str) -> dict:
    body: dict[str, Any] = {"message": message, "branch": branch,
                            "content": base64.b64encode(content.encode()).decode()}
    try:  # updating needs the current blob sha
        existing = await _json("GET", f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}", params={"ref": branch})
        body["sha"] = existing["sha"]
    except ToolError:
        pass
    data = await _json("PUT", f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}", json=body)
    return {"path": path, "commit": data["commit"]["sha"]}


@mcp.tool
async def create_or_update_file(owner: str, repo: str, path: str, content: str, message: str, branch: str) -> dict:
    """Create or overwrite one file on a branch."""
    return await _put_file(owner, repo, path, content, message, branch)


@mcp.tool
async def push_files(owner: str, repo: str, branch: str, files: list[dict], message: str) -> dict:
    """Write several files ({path, content}) to a branch."""
    return {"written": [await _put_file(owner, repo, f["path"], f["content"], message, branch) for f in files]}


@mcp.tool
async def delete_file(owner: str, repo: str, path: str, message: str, branch: str) -> dict:
    """Delete one file from a branch."""
    existing = await _json("GET", f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}", params={"ref": branch})
    data = await _json("DELETE", f"/repos/{owner}/{repo}/contents/{path.lstrip('/')}",
                       json={"message": message, "branch": branch, "sha": existing["sha"]})
    return {"path": path, "commit": data["commit"]["sha"]}


if __name__ == "__main__":
    # Localhost only: the backend's ToolGateway is the only client.
    # Stateless: every request stands alone, so a client holding an old session id
    # keeps working.
    mcp.run(transport="http", host=os.environ.get("PRGUARD_MCP_HOST", "127.0.0.1"),
            port=int(os.environ.get("PRGUARD_MCP_PORT", "8090")), show_banner=False, stateless_http=True)
