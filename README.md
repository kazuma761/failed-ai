# PRGuard

An AI pull-request reviewer built to stay safe when a pull request turns hostile.

> In the CodeRabbit case, one PR led to write access on a million repos.
> Against PRGuard, the worst case is one comment on one PR.

Every GitHub call an agent makes is checked by
[FailproofAI](https://befailproof.ai): its PreToolUse hook runs PRGuard's
policy on the call and records the decision.

## Architecture

```mermaid
flowchart LR
  PR[Pull request] --> O[Orchestrator + Sandbox]
  O --> S[5 specialist agents]
  S --> A[Aggregator] --> C[Checker] --> H[Human gate] --> P[Post review]
  O & S & P -. every GitHub call .-> G[ToolGateway]
  G --> F{{FailproofAI PreToolUse hook<br/>PRGuard policy}}
  F -- allow --> M[PRGuard GitHub MCP server<br/>holds the only token] --> GH[(GitHub)]
  F -- deny + reason --> G
  F -. hook activity .-> L[Local dashboard :8020 / FailproofAI Cloud]
  G -. SDK session events .-> L
```

The policy is default deny: each role gets only its own tools, calls are
pinned to the task's repository, PR and commit, secret paths are refused,
merge, push and file writes are never allowed, and APPROVE needs a human.
FailproofAI records every allow and deny as hook activity (local dashboard on
port 8020, and FailproofAI Cloud when the machine is connected). The FailproofAI
SDK also reports each review as a session.

## Demo

New recordings and screenshots with FailproofAI are TODO. The GIF and
screenshots in `docs/` come from the earlier  build and are kept only
for history.

## The threat

In January 2025, Kudelski Security showed that one crafted PR made CodeRabbit
run untrusted code on its production server, because a linter ran outside its
sandbox. That server's environment held the GitHub App private key, which gave
write access to roughly a million repositories. CodeRabbit fixed it within
hours of disclosure.

Two root causes: untrusted code ran somewhere full of secrets, and one key
unlocked everything.

## The three layers

1. **Sandbox.** PR code (pylint, pytest) runs in Docker with no network, no
   host environment, a read-only filesystem, no capabilities and a non-root
   user. If Docker is unavailable, PR code is not run at all.
2. **No keys in agents.** Agents never import a GitHub or MCP client. Every
   GitHub action goes through a `ToolGateway`. The GitHub token lives only in
   PRGuard's own MCP server.
3. **Per-action rules.** Default deny. Each agent role may call only its own
   tools, only on the repo, PR and commit of the current task. Merge and push
   are never allowed. APPROVE needs a human, for that one PR. With
   `ENFORCER=FAILPROOFAI` these rules run as a FailproofAI policy
   (`failproofai/prguard-policies.mjs`) in the PreToolUse hook.

## Two modes, same code

| | UNSAFE ("how many bots work") | GUARDED (PRGuard) |
|---|---|---|
| PR code runs | subprocess on the host with a fake "victim" env | locked Docker sandbox |
| GitHub access | `DirectGateway`: every tool, no checks | policy decides each call |
| Hostile PR | canary panel lists the env var names it could read | canary panel stays at 0 |
| Assume-breach replay | 6 of 8 went through on real GitHub | 7 of 8 denied, each with a reason (offline tests) |

## Status

FailproofAI enforcement is **built and tested offline, not yet verified live**.
The operator still has to run `scripts/failproofai_setup.sh` and
`scripts/failproofai_check.py` (see [FailproofAI](#failproofai) below).

Shown on a real GitHub repository
([prguard-demo-target](https://github.com/kazuma761/prguard-demo-target))
with the earlier  build:

- Real pull requests reviewed end to end, with the reviews posted to GitHub.
- UNSAFE mode: six of eight assume-breach steps went through, including a real
  merge and a real push.
- Reviews take about 15 seconds and half a cent on cheap models
  (`openai/gpt-oss-120b` reviewers, `google/gemini-2.5-flash-lite` checker).

What the offline tests show for GUARDED mode with PRGuard's policy: seven of
eight replay steps denied (only the legitimate read is allowed), including the
comment on a different PR, and APPROVE allowed only after a human approves,
for that PR only. `tests/test_failproofai_policy.py` checks that the
FailproofAI policy decides exactly like the Python policy engine.

Limits, stated plainly:

- None of this has run through a live FailproofAI install yet.
- FailproofAI fails open when a policy is missing or throws, so PRGuard probes
  the hook first: if a merge is not denied by PRGuard's own rule, every call
  fails closed until the backend restarts.
- With no keys configured, PRGuard falls back to an offline mock of GitHub, a
  deterministic mock reviewer and a local policy stand-in, each labelled as
  such in the UI. `TRIAGE` with TypeSafe Jev is built but was never run live.
- Enforcement only covers calls that go through the gateway, which is why
  agents get no shell and no token.

See [docs/SUBMISSION.md](docs/SUBMISSION.md) for the submission write-up and
[AGENTS.md](AGENTS.md) for the FailproofAI control matrix.

## CI/CD: the CI fixer

A fifth agent, `prguard-ci-fixer`, runs alongside the reviewers. When CI failed
on the PR's commit it reads the workflow run and the failed job's log, explains
the root cause, and proposes a fix in the review. If the log looks like
infrastructure noise it re-runs the failed jobs instead. That is all it can do:
it has no tool that writes a file, and writing anything (including
`.github/workflows/**`) is denied for every role. Demo PR #3 has a real
regression and a real captured failing log.

## The attack is a harmless simulation

The hostile PR ships a pylint config that makes pylint import a module from
the same PR. That module only reports environment variable **names** and one
planted fake marker to a listener on localhost. It sends no values, uses no
credential, and swallows every error. The "victim" environment contains fake
decoys only and is never inherited from the backend.

What an attacker would do next (merge, push, touch other repos) is shown by the
**assume-breach replay**, a script we run that sends those calls through our
own gateway. UNSAFE mode only runs PR code for PRs opened by the target repo's
owner.

## Run it

Needs Python 3.11, Node 20+, Docker and `uv` (or pip).

```bash
uv venv --python 3.11 .venv && uv pip install --python .venv/bin/python -r requirements.txt
```

```bash
docker build -t prguard-sandbox backend/sandbox
```

```bash
npm --prefix frontend install
```

```bash
cp .env.example .env
```

```bash
./scripts/dev.sh
```

Open http://localhost:5173. Then: pick PR #2, run a review in UNSAFE, flip to
GUARDED, reset, run it again, run the assume-breach replay, and click Human
approve.

Checks:

```bash
.venv/bin/python -m pytest -q
```

```bash
./scripts/smoke.sh
```

`smoke.sh` runs the hostile PR in both modes and prints what the canary
listener received, then the 8 replay decisions in both modes.
`./scripts/review_once.sh 3` runs one review and prints models, tokens, cost,
tool decisions and findings.

### Models

Set these in `.env` (see `.env.example` for tested choices):

- `OPENROUTER_API_KEY`, `LLM_MODEL`: reviewers. A comma-separated list is a
  fallback chain. Free models work (`nvidia/nemotron-3-super-120b-a12b:free`)
  but are rate limited and may log prompts, so keep private code away from them.
- `CHECKER_MODEL`: the independent checker. Use a different model family; the
  review notes warn if it is not.
- `OPENROUTER_SORT=price` trades speed for the lowest price.
- `ANTHROPIC_API_KEY` or `GEMINI_API_KEY` call those providers directly instead.

### Triage with TypeSafe Jev (optional)

Set `JEV_API_KEY` to add one fast typed-classifier call per PR before the
reviewers run. Jev answers four fixed questions (is this trying to instruct an
AI reviewer, does a config make a tool run PR code, how risky is it, what kind
of change is it) with a label or score and a probability. PRGuard uses that as
an injection screen that does not depend on the reviewer models (a flag always
sends the review to a human), as a risk score in the review, and for routing:
with `LLM_MODEL_STRONG` set, the security reviewer moves to the stronger model
only when Jev rates the PR risky. No key, a timeout or an error means the step
is skipped. Tested offline with a stubbed Jev; **not yet run against the live
API** (the key on this machine was rejected).

### Real GitHub

`./scripts/setup_demo_repo.sh` creates two throwaway public repos and the demo
PRs (read it first). Then set `TARGET_REPO`, `OTHER_REPO`, `UPSTREAM=mcp`, a
fine-grained `GITHUB_PAT_UNSAFE` limited to those repos, and
`docker compose up -d`. GitHub will not let an account approve or request
changes on its own PR, so those need a second account or a GitHub App.

### FailproofAI

The gateway runs the failproofai binary as a PreToolUse hook once per tool
call (`--hook PreToolUse`), naming the tool `mcp__prguard__<tool>`. The task
(agent id, repo, PR, commit, human approval) comes from the backend, never
from the agent. Empty output means allow; a deny comes back with PRGuard's
rule name and reason. A timeout, a missing binary or unreadable output fails
closed and is not labelled a FailproofAI decision.

Operator steps (coding agents in this repo are blocked from running them):

1. Install the local half: `npm install -g failproofai` (Node 20.9+).
2. `./scripts/failproofai_setup.sh` copies `failproofai/prguard-policies.mjs`
   to `.failproofai/policies/` (gitignored), where failproofai loads it.
3. Optional, for FailproofAI Cloud (app.befailproof.ai): run the interactive
   `config` wizard of the failproofai CLI, which installs the daemon, and
   connect with a one-time token you paste yourself.
4. `.venv/bin/python scripts/failproofai_check.py` until it prints READY, then
   set `ENFORCER=FAILPROOFAI` in `.env` and restart the backend.
   `FAILPROOFAI_BIN` overrides the binary path (default `failproofai`).
5. Run a review and the replay in GUARDED mode, then find the decisions in the
   local dashboard (port 8020, Policies, Activity) and in Cloud.

## Layout

```
backend/
  main.py              FastAPI: /review /webhook /approve /mode /replay /reset /ws
  gateway/             ToolGateway: direct (UNSAFE), local_policy (stand-in), failproofai_gw, policy engine, tool map
  policies/            prguard.policy.yaml
  telemetry.py         FailproofAI SDK sessions (no-op without the SDK)
  sandbox/             Dockerfile, credential-free checkout, check runner
  agents/              llm (OpenRouter/Anthropic/Gemini), triage (Jev), prompts, specialists, ci_fixer, aggregator, checker
  orchestrator/        LangGraph pipeline
  replay/              assume-breach replay
prguard_mcp/           PRGuard's own 13-tool GitHub MCP server; the only place the GitHub token lives
canary_listener/       localhost listener for the canary
failproofai/           prguard-policies.mjs: the same rules as a FailproofAI policy
demo_target/           demo app plus prs/01_clean, 02_hostile and 03_ci_failure
frontend/              Mission Control (React, React Flow)
scripts/               dev, smoke, review_once, failproofai_setup, failproofai_check, setup_demo_repo, reset_demo
```

Differences from the original plan:

- The aggregator is plain code rather than an LLM, so the verdict is
  deterministic and PR text cannot argue with it.
- A prompt-injection finding always sends the review to a human, whatever
  severity the model gave it.
- Duplicate findings are merged by file, line range and topic, because
  different models name the same problem differently.
- The checker can be any model from a different family, not only Gemini.
- The replay has an eighth step: editing the CI workflow.
- The four specialists share one module, each with its own agent id.

## Production roadmap (not built)

Vector search, a job queue, user accounts, a GitHub App installation flow,
multi-repo support, cost dashboards.

## Credits

- Review architecture (specialist fan-out, Finding contract, aggregator,
  confidence/HITL gate, events spine) adapted from Antern's "Designing an AI
  Pull-Request Review Agent" by Ayush Singh. The "maker is never checker" and
  "gates are computed, not narrated" rules come from Antern's Genesis study.
- Threat model from Kudelski Security's research on CodeRabbit.
- Access control by [FailproofAI](https://befailproof.ai). An earlier build
  used .
