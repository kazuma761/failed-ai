"""Settings, read once from the environment (.env is loaded if present)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass
class Settings:
    # Reviewers. LLM_PROVIDER empty = auto (openrouter, then anthropic, else mock).
    llm_provider: str = field(default_factory=lambda: _env("LLM_PROVIDER").lower())
    llm_model: str = field(default_factory=lambda: _env("LLM_MODEL"))
    openrouter_api_key: str = field(default_factory=lambda: _env("OPENROUTER_API_KEY"))
    # How OpenRouter picks a provider: throughput | latency | price | "" (its default).
    openrouter_sort: str = field(default_factory=lambda: _env("OPENROUTER_SORT", "throughput").lower())
    anthropic_api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY"))
    # Independent checker: a different model family from the reviewers.
    checker_provider: str = field(default_factory=lambda: _env("CHECKER_PROVIDER").lower())
    checker_model: str = field(default_factory=lambda: _env("CHECKER_MODEL") or _env("GEMINI_MODEL"))
    gemini_api_key: str = field(default_factory=lambda: _env("GEMINI_API_KEY"))
    # TypeSafe Jev: one fast typed-classifier call per PR (optional).
    jev_api_key: str = field(default_factory=lambda: _env("JEV_API_KEY"))
    jev_model: str = field(default_factory=lambda: _env("JEV_MODEL", "jev-latest"))
    llm_model_strong: str = field(default_factory=lambda: _env("LLM_MODEL_STRONG"))
    # Replay identical LLM requests from disk: deterministic demos, no repeat cost.
    llm_cache: bool = field(default_factory=lambda: _env("LLM_CACHE", "1") not in ("0", "false", "no"))

    # LOCAL_POLICY (stand-in) | FAILPROOFAI. Only used in GUARDED mode.
    enforcer: str = field(default_factory=lambda: _env("ENFORCER", "LOCAL_POLICY").upper())
    failproofai_bin: str = field(default_factory=lambda: _env("FAILPROOFAI_BIN", "failproofai"))

    # mcp = real GitHub MCP server, mock = offline fixtures from demo_target/.
    upstream: str = field(default_factory=lambda: _env("UPSTREAM", "mock").lower())
    github_mcp_url: str = field(default_factory=lambda: _env("GITHUB_MCP_URL", "http://localhost:8081/mcp"))
    github_pat_unsafe: str = field(default_factory=lambda: _env("GITHUB_PAT_UNSAFE"))
    github_webhook_secret: str = field(default_factory=lambda: _env("GITHUB_WEBHOOK_SECRET"))

    target_repo: str = field(default_factory=lambda: _env("TARGET_REPO", "you/prguard-demo-target"))
    other_repo: str = field(default_factory=lambda: _env("OTHER_REPO", "you/prguard-demo-other"))
    # UNSAFE mode runs PR code on this machine, so it only does that for PRs
    # opened by these logins. Defaults to the owner of TARGET_REPO.
    unsafe_allowed_authors: str = field(default_factory=lambda: _env("UNSAFE_ALLOWED_AUTHORS"))

    hitl_threshold: float = field(default_factory=lambda: float(_env("HITL_THRESHOLD", "0.7")))
    canary_url: str = field(default_factory=lambda: _env("CANARY_URL", "http://127.0.0.1:9999/canary"))
    sandbox_image: str = field(default_factory=lambda: _env("SANDBOX_IMAGE", "prguard-sandbox"))
    node_timeout_s: float = field(default_factory=lambda: float(_env("NODE_TIMEOUT_S", "45")))

    runs_dir: Path = ROOT / "runs"
    policy_path: Path = ROOT / "backend" / "policies" / "prguard.policy.yaml"
    demo_target_dir: Path = ROOT / "demo_target"

    @property
    def provider(self) -> str:
        """Which backend the reviewers use: openrouter | anthropic | mock."""
        if self.llm_provider in ("openrouter", "anthropic", "mock"):
            wanted = self.llm_provider
        elif self.openrouter_api_key:
            wanted = "openrouter"
        elif self.anthropic_api_key:
            wanted = "anthropic"
        else:
            wanted = "mock"
        key = {"openrouter": self.openrouter_api_key, "anthropic": self.anthropic_api_key}.get(wanted, "x")
        return wanted if key and (self.llm_model or wanted == "mock") else "mock"

    @property
    def llm_is_mock(self) -> bool:
        return self.provider == "mock"

    @property
    def checker(self) -> tuple[str, str] | None:
        """(provider, model) for the independent checker, or None if not configured."""
        if not self.checker_model or self.checker_provider == "none":
            return None
        if self.checker_provider == "gemini" or (not self.checker_provider and self.gemini_api_key):
            return ("gemini", self.checker_model) if self.gemini_api_key else None
        if self.openrouter_api_key:
            return ("openrouter", self.checker_model)
        return None

    @property
    def checker_available(self) -> bool:
        return self.checker is not None

    @property
    def allowed_unsafe_authors(self) -> set[str]:
        names = {n.strip().lower() for n in self.unsafe_allowed_authors.split(",") if n.strip()}
        return names or {self.target_repo.split("/")[0].lower()}


settings = Settings()
