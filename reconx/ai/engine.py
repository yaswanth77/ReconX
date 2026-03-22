"""
AI Engine — the brain that makes ReconX dynamic instead of hardcoded.

Wraps the provider and exposes high-level methods that stages call.
Gracefully degrades: if no AI configured, returns None and stages use defaults.
"""

import json
from typing import Optional, Any
from rich.console import Console

from .providers import AIProvider, create_provider
from . import prompts

console = Console()


class AIEngine:
    """
    High-level AI interface for all pipeline stages.

    Usage:
        engine = AIEngine(provider="ollama", model="llama3")
        result = engine.analyze_target(tech_stack, headers, title)
        if result:  # None if AI unavailable
            print(result["recommended_nuclei_tags"])
    """

    def __init__(
        self,
        provider_name: str = "ollama",
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        enabled: bool = True,
    ):
        self.enabled = enabled
        self.provider: AIProvider | None = None

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
            else:
                console.print("  [yellow]⚠ AI provider not configured, running without AI[/yellow]")
                self.enabled = False

    def _call(self, system: str, user: str, json_mode: bool = True) -> dict | None:
        """Internal: call provider and parse JSON response."""
        if not self.enabled or not self.provider:
            return None

        try:
            response = self.provider.complete(
                prompt=user,
                system_prompt=system,
                json_mode=json_mode,
            )

            if response.startswith("[AI Error"):
                console.print(f"  [dim red]{response}[/dim red]")
                return None

            if json_mode:
                # Try to parse JSON from response
                try:
                    return json.loads(response)
                except json.JSONDecodeError:
                    # Try to extract JSON from markdown code block
                    if "```" in response:
                        json_str = response.split("```")[1]
                        if json_str.startswith("json"):
                            json_str = json_str[4:]
                        return json.loads(json_str.strip())
                    return None
            else:
                return {"text": response}

        except Exception as e:
            console.print(f"  [dim red]AI call failed: {e}[/dim red]")
            return None

    def analyze_target(self, tech_stack: dict, headers: dict, title: str) -> dict | None:
        """Post-fingerprint: analyze tech and suggest attack vectors."""
        system, user = prompts.target_analysis_prompt(tech_stack, headers, title)
        result = self._call(system, user)
        if result:
            console.print("  [cyan]🤖 AI target analysis complete[/cyan]")
        return result

    def generate_wordlist(self, tech_stack: list[str], existing_paths: list[str]) -> list[str]:
        """Generate dynamic paths based on detected tech."""
        system, user = prompts.dynamic_wordlist_prompt(tech_stack, existing_paths)
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
        system, user = prompts.subdomain_generation_prompt(domain, known_subs)
        result = self._call(system, user)
        if result and "candidates" in result:
            candidates = result["candidates"]
            console.print(f"  [cyan]🤖 AI generated {len(candidates)} subdomain candidates[/cyan]")
            return candidates
        return []
