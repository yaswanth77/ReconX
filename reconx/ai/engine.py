"""
AI Engine — the brain that makes ReconX dynamic instead of hardcoded.

Wraps the provider and exposes high-level methods that stages call.
Gracefully degrades: if no AI configured, returns None and stages use defaults.
"""

import hashlib
import json
import logging
from pathlib import Path
from rich.console import Console

from .providers import AIProvider, create_provider
from . import prompts

console = Console()
_log = logging.getLogger(__name__)

# Rough char→token heuristic; only used for budget accounting when the
# provider doesn't return usage data.
_CHARS_PER_TOKEN = 4


def _sanitize_for_prompt(value) -> str:
    """
    Strip ASCII control chars from untrusted strings before embedding them
    in a prompt. Keeps the content visible to the model without letting
    targets smuggle in escape sequences or multi-line instruction overrides.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = json.dumps(value, default=str, ensure_ascii=False)
        except Exception:
            value = str(value)
    return "".join(ch for ch in value if ch == "\n" or ch == "\t" or ord(ch) >= 32)


class AIEngine:
    """
    High-level AI interface for all pipeline stages.

    Features:
    - response cache keyed by sha256(system+user), persisted under run_dir
    - token budget: warn + disable further calls once exceeded
    - generic error messages (no provider internals leaked)

    Usage:
        engine = AIEngine(provider="ollama", model="llama3")
        result = engine.analyze_target(tech_stack, headers, title)
    """

    def __init__(
        self,
        provider_name: str = "ollama",
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        enabled: bool = True,
        cache_path: str | Path | None = None,
        token_budget: int | None = None,
    ):
        self.enabled = enabled
        self.provider: AIProvider | None = None
        self.cache_path: Path | None = Path(cache_path) if cache_path else None
        self._cache: dict[str, str] = self._load_cache()
        self.token_budget = token_budget
        self.tokens_used = 0

        if enabled:
            self.provider = create_provider(
                provider_name=provider_name,
                api_key=api_key,
                model=model,
                base_url=base_url,
            )
            if self.provider:
                console.print(
                    f"  [cyan]🤖 AI Engine: {provider_name}"
                    f" ({model or 'default model'})[/cyan]"
                )
                if self.token_budget:
                    console.print(
                        f"  [dim]AI token budget: {self.token_budget:,}[/dim]"
                    )
            else:
                console.print("  [yellow]⚠ AI provider not configured, running without AI[/yellow]")
                self.enabled = False

    # --- cache -----------------------------------------------------------

    def _load_cache(self) -> dict[str, str]:
        if not self.cache_path or not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception as e:
            _log.debug("AI cache load failed: %s", e)
            return {}

    def _save_cache(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(
                json.dumps(self._cache, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as e:
            _log.debug("AI cache save failed: %s", e)

    @staticmethod
    def _cache_key(system: str, user: str, json_mode: bool) -> str:
        h = hashlib.sha256()
        h.update(b"json:" if json_mode else b"text:")
        h.update(system.encode("utf-8"))
        h.update(b"\x00")
        h.update(user.encode("utf-8"))
        return h.hexdigest()

    # --- budget ----------------------------------------------------------

    def _budget_allows(self, system: str, user: str) -> bool:
        if not self.token_budget:
            return True
        estimate = (len(system) + len(user)) // _CHARS_PER_TOKEN
        if self.tokens_used + estimate > self.token_budget:
            console.print(
                f"  [yellow]⚠ AI token budget exhausted "
                f"({self.tokens_used:,}/{self.token_budget:,}); skipping further calls.[/yellow]"
            )
            self.enabled = False
            return False
        return True

    def _record_usage(self, system: str, user: str, response: str) -> None:
        self.tokens_used += (len(system) + len(user) + len(response)) // _CHARS_PER_TOKEN

    # --- core call -------------------------------------------------------

    def _call(self, system: str, user: str, json_mode: bool = True) -> dict | None:
        """Internal: call provider (with cache) and parse JSON response."""
        if not self.enabled or not self.provider:
            return None

        cache_key = self._cache_key(system, user, json_mode)
        cached = self._cache.get(cache_key)
        if cached is not None:
            response = cached
        else:
            if not self._budget_allows(system, user):
                return None
            try:
                response = self.provider.complete(
                    prompt=user,
                    system_prompt=system,
                    json_mode=json_mode,
                )
            except Exception as e:
                _log.debug("AI provider raised: %s", e)
                console.print("  [dim red]AI call failed (see debug log)[/dim red]")
                return None

            if response.startswith("[AI Error"):
                console.print(f"  [dim red]{response}[/dim red]")
                return None

            self._record_usage(system, user, response)
            self._cache[cache_key] = response
            self._save_cache()

        if json_mode:
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                if "```" in response:
                    try:
                        fenced = response.split("```")[1]
                        if fenced.startswith("json"):
                            fenced = fenced[4:]
                        return json.loads(fenced.strip())
                    except (IndexError, json.JSONDecodeError):
                        return None
                return None
        return {"text": response}

    # --- high-level helpers ---------------------------------------------

    def analyze_target(self, tech_stack: dict, headers: dict, title: str) -> dict | None:
        """Post-fingerprint: analyze tech and suggest attack vectors."""
        system, user = prompts.target_analysis_prompt(
            _sanitize_for_prompt(tech_stack),
            _sanitize_for_prompt(headers),
            _sanitize_for_prompt(title),
        )
        result = self._call(system, user)
        if result:
            console.print("  [cyan]🤖 AI target analysis complete[/cyan]")
        return result

    def generate_wordlist(self, tech_stack: list[str], existing_paths: list[str]) -> list[str]:
        """Generate dynamic paths based on detected tech."""
        system, user = prompts.dynamic_wordlist_prompt(
            [_sanitize_for_prompt(t) for t in tech_stack],
            [_sanitize_for_prompt(p) for p in existing_paths],
        )
        result = self._call(system, user)
        if result and "paths" in result:
            paths = result["paths"]
            console.print(f"  [cyan]🤖 AI generated {len(paths)} dynamic paths[/cyan]")
            return paths
        return []

    def score_params(self, params: list[dict]) -> list[dict]:
        """Score parameters by injection risk."""
        if not params:
            return []
        system, user = prompts.param_risk_scoring_prompt(params)
        result = self._call(system, user)
        if result and "scored_params" in result:
            scored = result["scored_params"]
            console.print(f"  [cyan]🤖 AI scored {len(scored)} parameters[/cyan]")
            return scored
        return []

    def triage_findings(self, findings: list[dict]) -> list[dict]:
        """Triage raw findings for severity and false-positive likelihood."""
        if not findings:
            return []
        system, user = prompts.finding_triage_prompt(findings)
        result = self._call(system, user)
        if result and "triaged" in result:
            triaged = result["triaged"]
            console.print(f"  [cyan]🤖 AI triaged {len(triaged)} findings[/cyan]")
            return triaged
        return []

    def select_nuclei_templates(self, tech_stack: list[str], services: list[dict]) -> list[str]:
        """Select relevant Nuclei template tags based on fingerprint."""
        system, user = prompts.nuclei_template_selection_prompt(tech_stack, services)
        result = self._call(system, user)
        if result and "selected_tags" in result:
            tags = result["selected_tags"]
            # Allowlist to prevent injection into the nuclei argv via AI hallucination.
            valid = {"exposure", "misconfig", "cve", "iot", "intrusive",
                     "malware", "vulnerability", "default-login", "token-spray",
                     "takeover", "panel", "config", "exposed-panels",
                     "file", "dns", "network", "tech", "ssl", "generic"}
            tags = [t for t in tags if isinstance(t, str) and t in valid]
            if tags:
                console.print(f"  [cyan]🤖 AI selected Nuclei tags: {', '.join(tags)}[/cyan]")
            return tags
        return []

    def generate_summary(self, data_summary: dict, key_findings: list[dict]) -> str | None:
        """Generate AI-written attack narrative for the report."""
        system, user = prompts.recon_summary_prompt(data_summary, key_findings)
        result = self._call(system, user, json_mode=False)
        if result and "text" in result:
            console.print("  [cyan]🤖 AI generated recon summary[/cyan]")
            return result["text"]
        return None

    def generate_subdomains(self, domain: str, known_subs: list[str]) -> list[str]:
        """Generate context-aware subdomain candidates."""
        system, user = prompts.subdomain_generation_prompt(
            _sanitize_for_prompt(domain),
            [_sanitize_for_prompt(s) for s in known_subs],
        )
        result = self._call(system, user)
        if result and "candidates" in result:
            candidates = result["candidates"]
            console.print(f"  [cyan]🤖 AI generated {len(candidates)} subdomain candidates[/cyan]")
            return candidates
        return []
