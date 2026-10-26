# PRGuard: working notes for coding agents

PRGuard is an AI pull-request reviewer (a CodeRabbit-style product with a CI
fixer) built to stay safe when a pull request turns hostile. Every GitHub call
an agent makes is decided by PRGuard's policy running in FailproofAI's
PreToolUse hook. Read `README.md` for how it works and how to run it.

## The five judging criteria (most important; every decision serves these)

From the organizers' kickoff talk. Before adding or changing anything, ask
which of these it improves.

| # | Criterion | What the judges want | How PRGuard answers it |
|---|---|---|---|
| 1 | Real-world agent use case | A practical enterprise application, not a toy | AI code review is a real product category. The threat is a real incident: in January 2025 one crafted PR gave attackers CodeRabbit's GitHub App key, with write access to about a million repositories. |
| 2 | Real-world guardrail relevance | A clear reason the guardrails are needed | A reviewer bot reads untrusted text (the PR) and holds write access to the repository. The fix is just-for-task access: this review, this repo, this PR, this commit. |
| 3 | Depth of guardrail usage | Number and depth of controls used | See the control matrix below: default deny, per-role tools, argument pinning, secret paths, human approval, fail-closed probe, audit. |
| 4 | Before vs after | Off the rails without guardrails, contained with them | One toggle, same code. UNSAFE: PR code reads the reviewer's environment and the assume-breach replay merges, pushes and edits CI. GUARDED: canary stays at zero and seven of the eight replay calls are stopped, each with a reason. |
| 5 | Demo and communication | Clarity, presentation, recorded walkthrough | Mission Control UI shows every decision live; the demo is deterministic (cached model replies, fixed replay). Record a backup video. |

## Architecture

Pull Request → Orchestrator + Sandbox → 5 specialist agents → Aggregator →
Checker → Human Gate. Every GitHub call goes agent → `ToolGateway` →
`FailproofAIGateway` (`backend/gateway/failproofai_gw.py`) → the failproofai
binary as a PreToolUse hook, which runs PRGuard's six policies (`prguard-no-repo-writes`,
`prguard-repo-scope`, `prguard-pr-scope`, `prguard-secret-paths`, `prguard-search-scope`,
`prguard-role-tools`) from `failproofai/prguard-policies.mjs` → if allowed, PRGuard's own GitHub MCP
server (`prguard_mcp/server.py`), the only place the GitHub token lives.
`team/CONTRACT.md` has the exact hook input and output.

## FailproofAI control matrix (criterion 3)

Status key: VERIFIED LIVE = seen working through a real failproofai install.
BUILT+TESTED = built and covered by the offline tests. TODO = not built.
Live result (operator's machine, real hook): `scripts/failproofai_check.py`
printed READY and the hook decided all 8 replay steps as expected (1 allow,
7 deny with PRGuard's own reasons). The first run had failed because
`tool_input._prguard` did not survive the real hook path; the fix sends the
context three ways (`tool_input._prguard`, `tool_input.prguard_task`,
top-level `prguard`). Rows below are VERIFIED LIVE only for what those 8
steps exercise, run as the security role; default deny for unknown roles,
the approval allow path, the `ref` pin, SDK and Cloud rows were not. Never mark
something VERIFIED LIVE, or label a decision "FailproofAI", unless failproofai
returned that decision.

| Control | PRGuard use | Status |
|---|---|---|
| PreToolUse hook on every GitHub call | `FailproofAIGateway` runs the hook per call as `mcp__prguard__<tool>`; the task context (agent id, repo, PR, commit, human approval; sent as `_prguard`, `prguard_task` and top-level `prguard`) is built from the trusted `TaskContext`, any agent-supplied copy is dropped, and it is never forwarded upstream | VERIFIED LIVE (replay run, 2026-10-25); also tested offline |
| Default deny | A `mcp__prguard__*` call with no task context, an unknown role or an unlisted tool is denied (`[default]`); a policy exception is a deny too | BUILT+TESTED |
| Per-role tools | Each specialist (security, quality, tests, docs, ci-fixer, aggregator) gets only its own tool list (`roles.<agent>`) | VERIFIED LIVE for the security role only (replay run, 2026-10-25); other roles BUILT+TESTED |
| Argument pinning | Every call pinned to the task's repo (`always_deny.cross_repo`); PR tools and reviews to its PR (`task_scope.pull_number`); file reads to its head commit (`ref`) | VERIFIED LIVE for repo and PR pins (replay run, 2026-10-25); `ref` pin BUILT+TESTED |
| Secret paths | File reads may not match `.env*`, `**/secrets/**`, `**/*.pem`, `**/*.key` | VERIFIED LIVE (replay run, 2026-10-25); also tested offline |
| Destructive tools | Merge, push, file write and file delete always denied (`always_deny.tools`), so no role can edit `.github/workflows/**` | VERIFIED LIVE (replay run, 2026-10-25); also tested offline |
| Human approval | APPROVE only when a human approved in Mission Control, for that PR only | Deny without approval VERIFIED LIVE (replay run, 2026-10-25); allow after approval BUILT+TESTED |
| Fail-closed probe | failproofai fails open on a missing or throwing policy, so the gateway first sends a merge probe; unless PRGuard's `[always_deny.tools]` rule denies it, every call fails closed | VERIFIED LIVE (replay run, 2026-10-25); also tested offline |
| Parity with the Python engine | `tests/test_failproofai_policy.py` checks the JS policy decides exactly like `PolicyEngine` on `prguard.policy.yaml` | BUILT+TESTED |
| Audit: hook activity | Every allow and deny recorded by failproofai (local dashboard :8020, Policies → Activity; FailproofAI Cloud when connected) | TODO (needs the live run) |
| Audit: SDK sessions | `backend/telemetry.py`: one FailproofAI session per review (`session_id` = review id), tool and decision events per call; no-op without `failproofai_sdk` | BUILT+TESTED offline; Cloud view TODO |
| Cloud audits and evals | Run audits/evaluations over PRGuard sessions in FailproofAI Cloud | TODO |

Layers that are PRGuard's own, not FailproofAI's (say so in the demo): the
Docker sandbox for PR code, the prompt-injection handling in the reviewers,
the independent checker, and the optional Jev triage.

## Settings

- `ENFORCER=LOCAL_POLICY` (default, the in-process stand-in) or
  `ENFORCER=FAILPROOFAI`.
- `FAILPROOFAI_BIN`: the failproofai binary, default `failproofai`.
- `FAILPROOFAI_HOME`: optional SDK spool root (defaults to failproofai's home
  directory). Tests point it at a temp dir.

## Going live with FailproofAI: who does what

Secrets are entered by the human only. Agents never type a GitHub token,
Cloud token or model key into any screen, command or file.

1. Human: install the local half (`npm install -g failproofai`, Node 20.9+).
2. Human: `./scripts/failproofai_setup.sh` copies the policy to
   `.failproofai/policies/prguard-policies.mjs` (the filename must end in
   `policies.mjs` or failproofai skips it silently).
3. Human, optional: connect the machine to FailproofAI Cloud
   (app.befailproof.ai) with failproofai's interactive config wizard, which
   installs the daemon.
4. Human: paste the fine-grained GitHub token into `.env` after
   `GITHUB_PAT_UNSAFE=`. It is read only by PRGuard's GitHub MCP server
   (port 8090), never by the agents or the gateway.
5. `.venv/bin/python scripts/failproofai_check.py` until it prints READY, then
   set `ENFORCER=FAILPROOFAI` in `.env` and restart the backend.
6. Run the review and the replay in GUARDED mode; confirm the decisions in the
   local dashboard and in Cloud, then update the matrix above.

GitHub accounts: `kazuma761` is the main account and owns the demo repo.
`Shrirajas` is the alternate account that opens the pull requests, so the
reviewer is never reviewing its own PR.

## Rules for agents working here

- FailproofAI guards your own session: never run a failproofai CLI command and
  never write under any `.failproofai` path. Those are the operator's steps;
  list the exact commands for the human instead. A deny saying "Running
  failproofai CLI commands is blocked" is that guard: do not retry it in
  another spelling.
- The attack is a harmless simulation. The hostile PR only reports environment
  variable names and a planted fake marker to localhost. Never add anything
  that reads or sends real values, and never give PR code a real key.
- Be honest in code and UI. Stand-ins and mocks are labelled as such
  (`LOCAL POLICY (stand-in)`, `MOCK upstream`, `MOCK LLM`).
- A deterministic demo beats a clever one. Keep the LLM cache and the fixed
  replay working.
- Use the cheapest workable models; model names live in `.env`, never in code.
- Tests must stay offline (`tests/conftest.py` forces mocks). Run
  `.venv/bin/python -m pytest -q` before saying something works.
- Do not build: vector search, queues, user accounts, a GitHub App install
  flow, multi-repo support, cost dashboards.
- `agntid-docs/` is the old vendor's login-gated documentation. Do not commit
  or publish it.
