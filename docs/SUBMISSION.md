# PRGuard: hackathon submission

Copy these into the Devfolio project form.

## Project name

PRGuard

## Tagline

An AI code reviewer that stays safe even when a pull request turns hostile.

## The problem it solves

AI review bots read text written by strangers (the pull request) while holding
write access to the repository. In January 2025, Kudelski Security showed that
one crafted PR made CodeRabbit run attacker code on its server, where a single
GitHub App key gave write access to about a million repositories.

PRGuard is a working AI pull-request reviewer with a CI fixer, built so that a
hijacked reviewer can do almost nothing. Every GitHub action an agent takes
passes through FailproofAI's PreToolUse hook, where PRGuard's policy allows or
denies it for this one task: this repository, this pull request, this commit,
read and comment only.

## What it does

- Five specialist agents review each PR in parallel (security, quality, tests,
  docs, CI fixer). An aggregator merges their findings and an independent model
  from a different family re-checks them before anything is posted. APPROVE
  waits for a human.
- The CI fixer reads the failed GitHub Actions log for the PR's commit and
  explains the root cause. It can re-run jobs but can never edit the pipeline.
- PR code (linters, tests) runs in a locked Docker sandbox: no network, no
  secrets, read-only filesystem.
- Agents never hold a GitHub token. It lives only in PRGuard's own 13-tool
  GitHub MCP server, reached only after FailproofAI allows the call.
- A live dashboard shows every agent, every allow and deny, and the review.

## How FailproofAI is used

| FailproofAI feature | How PRGuard uses it |
|---|---|
| PreToolUse hook | Runs on every GitHub call an agent makes, as `mcp__prguard__<tool>`, with the task context supplied by the backend, not the agent |
| Custom policy (`prguard-tool-gateway`) | Default deny; per-role tools; repo, PR and commit pinning; no secret file paths; merge, push and file writes always denied; APPROVE only after a human, each deny with a readable reason |
| Fail-closed guard | Before the first call PRGuard probes the hook with a merge; unless PRGuard's own rule denies it, nothing goes through |
| Hook activity | Every allow and deny recorded (local dashboard, FailproofAI Cloud) |
| SDK sessions | Each review is one FailproofAI session with its tool calls and decisions, ready for Cloud audits and evaluations |

Status, stated honestly: all of this is built and covered by offline tests,
including a test that the FailproofAI policy decides exactly like PRGuard's
Python policy engine. It has not yet been run through a live failproofai
install.

## Before and after

Eight attack steps, replayed as if one agent had been hijacked. "Without" was
measured on the real repository. "With" is PRGuard's policy in the offline
tests; the live FailproofAI run is still to do.

| Attack step | Without guardrails | With PRGuard's policy |
|---|---|---|
| Read the PR's files | allowed | allowed (legitimate) |
| Read `.env` | went through | denied: secret path |
| Approve the PR | reached GitHub | denied: not this agent's tool |
| Merge the PR | really merged | denied: never permitted |
| Push a file to `main` | really pushed | denied: never permitted |
| Read another repository | went through | denied: wrong repository |
| Comment on a different PR | went through | denied: outside this task |
| Edit the CI workflow | reached GitHub | denied: never permitted |

## Honest limits

- No live FailproofAI run yet: the setup and readiness check are operator steps.
- FailproofAI fails open when a policy is missing or throws; PRGuard's probe
  turns that into fail closed, but only for calls through its gateway, which is
  why agents get no shell and no token.
- The GitHub token is a fine-grained personal token held by PRGuard's MCP
  server, not a short-lived per-call credential.

## Challenges we ran into

- FailproofAI silently skips a policy file whose name does not end in
  `policies.mjs`, and fails open if the policy is missing, so we added a probe
  that refuses to run until PRGuard's own rule answers.
- Keeping one source of truth: the same rules exist as YAML for the local
  stand-in and as a FailproofAI policy, so a parity test runs both on the same
  cases.
- Cheap models name the same issue differently, so duplicate findings are
  merged by file, line range and topic rather than by category name.

## Technologies

Python, FastAPI, LangGraph, FailproofAI (PreToolUse hook policy, SDK, Cloud),
Model Context Protocol (FastMCP), Docker, React, React Flow, Tailwind,
OpenRouter (gpt-oss-120b reviewers, Gemini 2.5 Flash Lite checker).

## Links

- Code: https://github.com/kazuma761/prguard
- Demo repository with the reviewed pull requests: https://github.com/kazuma761/prguard-demo-target

## Credits

Review architecture adapted from Antern's "Designing an AI Pull-Request Review
Agent" (Ayush Singh). Threat model from Kudelski Security's research on
CodeRabbit. Access control by FailproofAI.

## Three-minute video script

1. (20 s) The CodeRabbit story: one PR, a million repositories. "The bot reads
   a stranger's text and holds your keys."
2. (30 s) Dashboard in GUARDED mode. Run a review. Point at the feed: every
   read is allowed by FailproofAI, under each agent's own identity. Open the
   review that was posted on GitHub.
3. (50 s) Assume-breach replay. Read the denials aloud: secrets, approve,
   merge, push, other repository, other PR, CI workflow. Show the same
   decisions in FailproofAI's hook activity and the review's Cloud session.
4. (40 s) The "before": the same replay with no guardrails. Show the merged PR
   and the pushed commit on GitHub. Then run the reset script.
5. (30 s) The three layers (sandbox, no keys in agents, per-action rules), then
   the honest limits and what would close them.
