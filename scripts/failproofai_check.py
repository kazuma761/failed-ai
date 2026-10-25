"""Readiness check for the FailproofAI path. Runs the real failproofai hook, offline.

    .venv/bin/python scripts/failproofai_check.py

Sends the 8 assume-breach steps through FailproofAIGateway (mock upstream, so
nothing reaches GitHub) and prints each decision. READY when every step matches
the GUARDED expectation, i.e. PRGuard's policy is loaded and deciding.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import settings
from backend.gateway.failproofai_gw import FailproofAIGateway
from backend.gateway.upstream import MockUpstream
from backend.models import Mode, TaskContext
from backend.replay.assume_breach import run_replay


async def main() -> int:
    upstream = MockUpstream()
    gateway = FailproofAIGateway(upstream)
    ctx = TaskContext(review_id="failproofai-readiness-check", repo_full_name=settings.target_repo, pr_number=2,
                      head_sha=upstream.head_sha(2), sender="readiness", mode=Mode.GUARDED)
    print(f"hook binary: {gateway.binary}   repo: {ctx.repo_full_name}\n")
    results = await run_replay("prguard-security", ctx, gateway, gap_s=0)
    print(f"{'#':>2}  {'step':34} {'expected':8} {'got':6} reason")
    for r in results:
        mark = "ok" if r["decision"] == r["expected_guarded"] else "XX"
        print(f"{r['step']:>2}  {r['label'][:34]:34} {r['expected_guarded']:8} {r['decision']:6} {mark}  {r['reason'][:90]}")
    wrong = [r for r in results if r["decision"] != r["expected_guarded"]]
    if not wrong:
        print("\nREADY: set ENFORCER=FAILPROOFAI in .env and restart the backend")
        return 0
    print(f"\nNOT READY: {len(wrong)} step(s) differ. ERROR usually means the policy is not loaded "
          "(run scripts/failproofai_setup.sh) or the hook binary is missing (FAILPROOFAI_BIN).")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
