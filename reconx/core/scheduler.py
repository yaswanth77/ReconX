"""
Pipeline scheduler — runs stages in order with gating, events, and resume.

This is the orchestration brain. Each stage is a module with a `run(ctx)` function.
The scheduler enforces order, tracks status, and handles failures gracefully.
"""

import json
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Callable
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import Config
from .store import StoreManager
from .runner import ToolRunner
from .ratelimit import RateLimiter
from .scope import Scope

console = Console()


# Stage registry — maps stage name to import path
STAGE_REGISTRY = {
    "dns": "reconx.stages.dns_baseline",
    "subs": "reconx.stages.subdomains",
    "axfr": "reconx.stages.zone_transfer",
    "validate": "reconx.stages.validate_services",
    "vhosts": "reconx.stages.vhosts",
    "fingerprint": "reconx.stages.fingerprint",
    "urls": "reconx.stages.urls",
    "search": "reconx.stages.search_discovery",
    "params": "reconx.stages.params",
    "osint_emails": "reconx.stages.osint_emails",
    "osint_metadata": "reconx.stages.osint_metadata",
    "osint_github": "reconx.stages.osint_github",
    "vuln_nuclei": "reconx.stages.vuln_nuclei",
    "vuln_xss": "reconx.stages.vuln_xss",
    "vuln_sqli": "reconx.stages.vuln_sqli",
    "vuln_misc": "reconx.stages.vuln_misc",
}

# Default stage order
STAGE_ORDER = [
    "dns", "subs", "axfr", "validate", "vhosts",
    "fingerprint", "urls", "search", "params",
    "osint_emails", "osint_metadata", "osint_github",
    "vuln_nuclei", "vuln_xss", "vuln_sqli", "vuln_misc",
]

# Gating rules: stages that require a prior stage's output
STAGE_GATES = {
    "vhosts": "validate",       # need alive services
    "fingerprint": "validate",  # need alive services
    "urls": "validate",         # need alive services
    "search": "subs",           # need discovered hosts
    "params": "urls",           # need discovered URLs
    "vuln_nuclei": "validate",  # need alive services
    "vuln_xss": "params",      # need discovered params
    "vuln_sqli": "params",     # need discovered params
    "vuln_misc": "params",     # need discovered params
    "osint_emails": "dns",     # need domain info
    "osint_metadata": "urls",  # need discovered URLs
    "osint_github": "dns",     # need domain info
}


class PipelineContext:
    """
    Shared context passed to every stage.
    Contains all the resources a stage needs.
    """

    def __init__(
        self,
        target: str,
        run_dir: Path,
        config: Config,
        scope: Scope,
        stores: StoreManager,
        runner: ToolRunner,
        rate_limiter: RateLimiter,
        ai_engine=None,
    ):
        self.target = target
        self.run_dir = run_dir
        self.config = config
        self.scope = scope
        self.stores = stores
        self.runner = runner
        self.rate_limiter = rate_limiter
        self.ai_engine = ai_engine
        self.stage_status: dict[str, str] = {}  # stage → success/failed/skipped
        self.start_time = time.time()

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time


class PipelineScheduler:
    """
    Runs stages in order, enforces gating, tracks status.

    Usage:
        scheduler = PipelineScheduler(context)
        scheduler.run(stages=["dns", "subs", "validate"], skip=["axfr"])
    """

    def __init__(self, context: PipelineContext):
        self.ctx = context

    def run(
        self,
        stages: list[str] | None = None,
        skip: list[str] | None = None,
    ) -> dict[str, str]:
        """
        Execute the pipeline.

        Args:
            stages: Specific stages to run (None = use config).
            skip: Stages to skip.

        Returns:
            Dict of stage_name → status.
        """
        # Determine which stages to run
        enabled = stages or self.ctx.config.get_enabled_stages()
        skip_set = set(skip or [])
        to_run = [s for s in STAGE_ORDER if s in enabled and s not in skip_set]

        console.print(
            Panel(
                f"[bold cyan]Target:[/bold cyan] {self.ctx.target}\n"
                f"[bold cyan]Stages:[/bold cyan] {', '.join(to_run)}\n"
                f"[bold cyan]Profile:[/bold cyan] {self.ctx.config.get('_profile_name', 'custom')}",
                title="[bold white]⚡ ReconX Pipeline[/bold white]",
                border_style="cyan",
            )
        )

        for stage_name in to_run:
            # Check gate
            gate = STAGE_GATES.get(stage_name)
            if gate and self.ctx.stage_status.get(gate) != "success":
                # Check if gate was skipped but has data from a previous run
                gate_store = self._get_gate_store(gate)
                if gate_store > 0:
                    pass  # Gate satisfied by existing data
                else:
                    console.print(
                        f"  [yellow]⏭ Skipping {stage_name} (gate '{gate}' not satisfied)[/yellow]"
                    )
                    self.ctx.stage_status[stage_name] = "skipped"
                    continue

            self._run_stage(stage_name)

        # Print summary
        self._print_summary()
        self._save_manifest()

        return self.ctx.stage_status

    def run_single(self, stage_name: str):
        """Run a single stage (for `reconx stage` command)."""
        if stage_name not in STAGE_REGISTRY:
            console.print(f"[red]✗ Unknown stage: {stage_name}[/red]")
            return
        self._run_stage(stage_name)
        self._save_manifest()

    def _run_stage(self, stage_name: str):
        """Import and execute a single stage."""
        import importlib

        module_path = STAGE_REGISTRY.get(stage_name)
        if not module_path:
            console.print(f"[red]✗ Unknown stage: {stage_name}[/red]")
            self.ctx.stage_status[stage_name] = "failed"
            return

        console.print(f"\n[bold green]▶ Stage: {stage_name}[/bold green]")
        start = time.time()

        try:
            module = importlib.import_module(module_path)
            module.run(self.ctx)
            elapsed = time.time() - start
            self.ctx.stage_status[stage_name] = "success"
            console.print(
                f"  [green]✓ {stage_name} completed ({elapsed:.1f}s)[/green]"
            )
        except Exception as e:
            elapsed = time.time() - start
            self.ctx.stage_status[stage_name] = "failed"
            console.print(
                f"  [red]✗ {stage_name} failed ({elapsed:.1f}s): {e}[/red]"
            )

    def _get_gate_store(self, gate: str) -> int:
        """Return the count of items in the gate's primary store (0 if unknown)."""
        store_map = {
            "dns": self.ctx.stores.hosts.count,
            "subs": self.ctx.stores.hosts.count,
            "validate": self.ctx.stores.services.count,
            "urls": self.ctx.stores.urls.count,
            "params": self.ctx.stores.params.count,
        }
        return store_map.get(gate, 0)

    def _print_summary(self):
        """Print a summary table after pipeline completion."""
        table = Table(title="Pipeline Results", border_style="cyan")
        table.add_column("Stage", style="bold")
        table.add_column("Status")
        table.add_column("", justify="center")

        status_icons = {
            "success": "[green]✓[/green]",
            "failed": "[red]✗[/red]",
            "skipped": "[yellow]⏭[/yellow]",
        }

        for stage, status in self.ctx.stage_status.items():
            icon = status_icons.get(status, "?")
            color = {"success": "green", "failed": "red", "skipped": "yellow"}.get(
                status, "white"
            )
            table.add_row(stage, f"[{color}]{status}[/{color}]", icon)

        console.print()
        console.print(table)

        # Data summary
        summary = self.ctx.stores.summary()
        console.print(f"\n[bold]Data collected:[/bold]")
        for key, count in summary.items():
            if count > 0:
                console.print(f"  {key}: [cyan]{count}[/cyan]")

        console.print(f"\n[dim]Total time: {self.ctx.elapsed:.1f}s[/dim]")

    def _save_manifest(self):
        """Save run manifest with metadata."""
        manifest = {
            "target": self.ctx.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": round(self.ctx.elapsed, 1),
            "config": self.ctx.config.to_dict(),
            "scope": self.ctx.scope.to_dict(),
            "stage_status": self.ctx.stage_status,
            "data_counts": self.ctx.stores.summary(),
        }
        manifest_path = self.ctx.run_dir / "manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, default=str)
