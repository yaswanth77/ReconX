"""
ReconX CLI — Click-based command interface.

Commands: init, doctor, run, stage, scope, export, diff
"""

import click
import os
import re
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel

console = Console(force_terminal=sys.stdout.isatty())

from reconx import __version__

_TARGET_RE = re.compile(r"^(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def _clean_target(raw: str) -> str:
    """Strip scheme/path, lowercase, and validate as a hostname or IP."""
    if not raw:
        raise click.BadParameter("--target is required")
    cleaned = raw.strip().lower()
    if cleaned.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        cleaned = urlparse(cleaned).hostname or ""
    cleaned = cleaned.rstrip(".")
    if not cleaned:
        raise click.BadParameter(f"Invalid --target: {raw!r}")
    try:
        import ipaddress
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass
    try:
        import validators
        if validators.domain(cleaned):
            return cleaned
    except ImportError:
        pass
    if _TARGET_RE.match(cleaned):
        return cleaned
    raise click.BadParameter(f"--target must be a valid domain or IP, got {raw!r}")

BANNER = """
[bold cyan]
    ____                      _  __
   / __ \\___  _________  ____| |/ /
  / /_/ / _ \\/ ___/ __ \\/ __ \\   /
 / _, _/  __/ /__/ /_/ / / / /  |
/_/ |_|\\___/\\___/\\____/_/ /_/_/|_|
[/bold cyan]
[dim]AI-Powered Recon Orchestrator v1.0[/dim]
"""


@click.group()
@click.version_option(version=__version__, prog_name="reconx")
@click.option("--workspace", default="./runs", help="Base directory for runs")
@click.option("--quiet", is_flag=True, help="Suppress verbose output")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.pass_context
def cli(ctx, workspace, quiet, no_color):
    """ReconX — AI-powered automated recon orchestrator."""
    ctx.ensure_object(dict)
    ctx.obj["workspace"] = Path(workspace)
    ctx.obj["quiet"] = quiet
    if no_color:
        console.no_color = True


@cli.command()
@click.option("--workspace", default=".", help="Root directory to scaffold")
@click.pass_context
def init(ctx, workspace):
    """Initialize ReconX project structure and default configs."""
    console.print(BANNER)
    root = Path(workspace)

    dirs = [
        root / "configs" / "profiles",
        root / "configs" / "wordlists",
        root / "runs",
    ]

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        console.print(f"  [green]✓[/green] {d}")

    # Copy default configs if they don't exist
    src_configs = Path(__file__).parent.parent / "configs"
    if src_configs.exists():
        dst_configs = root / "configs"
        for f in src_configs.rglob("*"):
            if f.is_file():
                rel = f.relative_to(src_configs)
                dst = dst_configs / rel
                if not dst.exists():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(f, dst)
                    console.print(f"  [green]✓[/green] {dst}")

    console.print("\n[bold green]✓ ReconX workspace initialized![/bold green]")


@cli.command()
def doctor():
    """Check external tool dependencies and versions."""
    console.print(BANNER)
    console.print("[bold]Checking dependencies...[/bold]")
    console.print("[dim]Tools must be installed and available in your system PATH.[/dim]\n")

    from reconx.core.runner import ToolRunner
    import shutil
    runner = ToolRunner()

    # (name, level, description, install_hint)
    tools = [
        ("finalrecon", "recommended", "Broad surface map (DNS/whois/SSL/CT)",
         "pip install finalrecon  # or https://github.com/thewhiteh4t/FinalRecon"),
        ("httpx", "required", "Service validation & fingerprinting",
         "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("subfinder", "recommended", "Subdomain enumeration",
         "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("gau", "recommended", "Historical URL discovery",
         "go install github.com/lc/gau/v2/cmd/gau@latest"),
        ("waybackurls", "recommended", "Wayback Machine URLs",
         "go install github.com/tomnomnom/waybackurls@latest"),
        ("nuclei", "recommended", "Vulnerability scanning",
         "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("paramspider", "optional", "Passive parameter mining",
         "pip install paramspider"),
        ("arjun", "optional", "Active parameter discovery",
         "pip install arjun"),
        ("theHarvester", "optional", "Email harvesting (OSINT)",
         "pip install theHarvester"),
        ("exiftool", "optional", "Metadata extraction (OSINT)",
         "https://exiftool.org — download and add to PATH"),
        ("katana", "optional", "Advanced crawling",
         "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ]

    results = {"pass": 0, "warn": 0, "fail": 0}

    console.print("[bold]External Tools:[/bold]\n")

    for tool_name, level, desc, install_hint in tools:
        tool_path = shutil.which(tool_name)
        available = tool_path is not None
        version = runner.get_version(tool_name) if available else None

        if available:
            ver_str = f" ({version})" if version else ""
            console.print(f"  [green]✓ PASS[/green]  {tool_name}{ver_str} — {desc}")
            console.print(f"           [dim]→ {tool_path}[/dim]")
            results["pass"] += 1
        elif level == "required":
            console.print(f"  [red]✗ FAIL[/red]  {tool_name} — {desc} [red](REQUIRED)[/red]")
            console.print(f"           [dim]Install: {install_hint}[/dim]")
            results["fail"] += 1
        elif level == "recommended":
            console.print(f"  [yellow]⚠ WARN[/yellow]  {tool_name} — {desc} (recommended)")
            console.print(f"           [dim]Install: {install_hint}[/dim]")
            results["warn"] += 1
        else:
            console.print(f"  [dim]○ SKIP[/dim]  {tool_name} — {desc} (optional)")
            console.print(f"           [dim]Install: {install_hint}[/dim]")

    # Check AI providers
    console.print("\n[bold]AI Providers:[/bold]\n")
    try:
        import openai
        console.print(f"  [green]✓[/green] openai Python library [dim](auto-installed with ReconX)[/dim]")
    except ImportError:
        console.print(f"  [yellow]⚠[/yellow] openai library — [dim]pip install openai[/dim]")

    # Ollama — check server via HTTP (no pip package needed anymore)
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            model_count = len(data.get("models", []))
            console.print(f"  [green]✓[/green] Ollama server running ({model_count} models)")
            if model_count == 0:
                console.print(f"           [dim]No models pulled yet. Run: ollama pull llama3[/dim]")
    except (urllib.error.URLError, Exception):
        console.print(f"  [yellow]⚠[/yellow] Ollama server not reachable at localhost:11434")
        console.print(f"           [dim]Download from: https://ollama.ai/download[/dim]")
        console.print(f"           [dim]Then run: ollama serve[/dim]")

    # Python dependencies
    console.print("\n[bold]Python Dependencies:[/bold]\n")
    py_deps = ["click", "pyyaml", "dnspython", "rich", "httpx"]
    for dep in py_deps:
        try:
            mod = __import__(dep.replace("-", "_").replace("pyyaml", "yaml").replace("dnspython", "dns"))
            console.print(f"  [green]✓[/green] {dep}")
        except ImportError:
            console.print(f"  [red]✗[/red] {dep} — [dim]pip install {dep}[/dim]")

    # Summary
    console.print(f"\n[bold]Summary:[/bold] {results['pass']} pass, {results['warn']} warn, {results['fail']} fail")

    if results["fail"] > 0:
        console.print("\n[red]Required tools are missing. Install them first:[/red]")
        console.print("[dim]Go tools need Go installed: https://go.dev/dl/[/dim]")
        console.print("[dim]After install, ensure $GOPATH/bin is in your PATH[/dim]")
        sys.exit(3)
    elif results["warn"] > 0:
        console.print("\n[yellow]Some recommended tools are missing. ReconX will skip those stages.[/yellow]")
        console.print("[dim]ReconX works without them but results will be limited.[/dim]")
    else:
        console.print("\n[bold green]✓ All tools ready! You're good to go.[/bold green]")

    console.print("\n[dim]Tip: Run 'reconx install' to auto-install tools interactively.[/dim]")


# ── Tool definitions shared between doctor and install ──
INSTALLABLE_TOOLS = [
    {
        "name": "finalrecon",
        "level": "recommended",
        "desc": "Broad surface map (DNS/whois/SSL/CT)",
        "type": "pip",
        "install": "pip install finalrecon",
    },
    {
        "name": "httpx",
        "level": "required",
        "desc": "Service validation & fingerprinting",
        "type": "go",
        "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    {
        "name": "subfinder",
        "level": "recommended",
        "desc": "Subdomain enumeration",
        "type": "go",
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    {
        "name": "gau",
        "level": "recommended",
        "desc": "Historical URL discovery",
        "type": "go",
        "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
    },
    {
        "name": "waybackurls",
        "level": "recommended",
        "desc": "Wayback Machine URLs",
        "type": "go",
        "install": "go install github.com/tomnomnom/waybackurls@latest",
    },
    {
        "name": "nuclei",
        "level": "recommended",
        "desc": "Vulnerability scanning",
        "type": "go",
        "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
    {
        "name": "katana",
        "level": "optional",
        "desc": "Advanced crawling",
        "type": "go",
        "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    {
        "name": "paramspider",
        "level": "optional",
        "desc": "Passive parameter mining",
        "type": "pip",
        "install": "pip install paramspider",
    },
    {
        "name": "arjun",
        "level": "optional",
        "desc": "Active parameter discovery",
        "type": "pip",
        "install": "pip install arjun",
    },
    {
        "name": "theHarvester",
        "level": "optional",
        "desc": "Email harvesting (OSINT)",
        "type": "pip",
        "install": "pip install theHarvester",
    },
]


@cli.command()
@click.option("--all", "install_all", is_flag=True, help="Install all tools without prompting")
def install(install_all):
    """Interactive tool installer — select which tools to install."""
    import subprocess

    console.print(BANNER)
    console.print("[bold]ReconX Tool Installer[/bold]")
    console.print("[dim]Automatically installs external tools needed by the pipeline.[/dim]\n")

    # Check Go availability (needed for most tools)
    go_available = shutil.which("go") is not None
    if not go_available:
        console.print("[yellow]⚠ Go is not installed. Go tools need Go to install.[/yellow]")
        console.print("[dim]  Download Go from: https://go.dev/dl/[/dim]")
        console.print("[dim]  After installing Go, run 'reconx install' again.\n[/dim]")

    # Show numbered tool list
    console.print("[bold]Available tools:[/bold]\n")
    not_installed = []
    for i, tool in enumerate(INSTALLABLE_TOOLS, 1):
        installed = shutil.which(tool["name"]) is not None
        status = "[green]installed[/green]" if installed else "[red]not installed[/red]"
        level_color = {"required": "red", "recommended": "yellow", "optional": "dim"}
        lc = level_color.get(tool["level"], "white")

        console.print(
            f"  [bold]{i:>2}.[/bold] {tool['name']:<15} {status:<30} "
            f"[{lc}]{tool['level']}[/{lc}]  [dim]{tool['desc']}[/dim]"
        )
        if not installed:
            not_installed.append((i, tool))

    if not not_installed:
        console.print("\n[bold green]✓ All tools already installed![/bold green]")
        return

    console.print(f"\n[dim]Not installed: {len(not_installed)} tools[/dim]")

    # Get selection
    if install_all:
        selected_indices = [i for i, _ in not_installed]
    else:
        console.print("\n[bold]Select tools to install:[/bold]")
        console.print("[dim]  Enter numbers separated by commas (e.g., 1,3,5)[/dim]")
        console.print("[dim]  Enter 'all' to install everything[/dim]")
        console.print("[dim]  Enter 'required' for required tools only[/dim]")
        console.print("[dim]  Enter 'recommended' for required + recommended[/dim]")
        console.print("[dim]  Press Enter to cancel\n[/dim]")

        choice = click.prompt("Your selection", default="", show_default=False)
        choice = choice.strip().lower()

        if not choice:
            console.print("[dim]Cancelled.[/dim]")
            return

        if choice == "all":
            selected_indices = [i for i, _ in not_installed]
        elif choice == "required":
            selected_indices = [i for i, t in not_installed if t["level"] == "required"]
        elif choice == "recommended":
            selected_indices = [i for i, t in not_installed if t["level"] in ("required", "recommended")]
        else:
            try:
                selected_indices = [int(x.strip()) for x in choice.split(",")]
            except ValueError:
                console.print("[red]Invalid input. Use numbers separated by commas.[/red]")
                return

    # Install selected tools
    to_install = [t for i, t in not_installed if i in selected_indices]

    if not to_install:
        console.print("[dim]Nothing to install.[/dim]")
        return

    console.print(f"\n[bold]Installing {len(to_install)} tools...[/bold]\n")

    success_count = 0
    fail_count = 0

    for tool in to_install:
        tool_type = tool["type"]
        cmd = tool["install"]

        # Skip Go tools if Go isn't installed
        if tool_type == "go" and not go_available:
            console.print(f"  [yellow]⏭ Skipping {tool['name']} (Go not installed)[/yellow]")
            fail_count += 1
            continue

        console.print(f"  [cyan]⏳ Installing {tool['name']}...[/cyan]")
        console.print(f"     [dim]{cmd}[/dim]")

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Verify installation
            if shutil.which(tool["name"]):
                console.print(f"  [green]✓ {tool['name']} installed successfully![/green]")
                success_count += 1
            elif result.returncode == 0:
                console.print(f"  [yellow]⚠ {tool['name']} — command succeeded but tool not in PATH[/yellow]")
                if tool_type == "go":
                    console.print(f"     [dim]Add $GOPATH/bin to your PATH[/dim]")
                fail_count += 1
            else:
                console.print(f"  [red]✗ {tool['name']} — install failed[/red]")
                if result.stderr:
                    console.print(f"     [dim]{result.stderr[:200]}[/dim]")
                fail_count += 1

        except subprocess.TimeoutExpired:
            console.print(f"  [red]✗ {tool['name']} — timed out after 5 minutes[/red]")
            fail_count += 1
        except Exception as e:
            console.print(f"  [red]✗ {tool['name']} — error: {e}[/red]")
            fail_count += 1

    # Summary
    console.print(f"\n[bold]Install Summary:[/bold] {success_count} installed, {fail_count} failed")

    if success_count > 0:
        console.print("[dim]Run 'reconx doctor' to verify.\n[/dim]")

    if fail_count > 0 and not go_available:
        console.print("[yellow]Most tools need Go. Install Go first: https://go.dev/dl/[/yellow]")
        console.print("[dim]After installing Go, add $GOPATH/bin to PATH and retry.\n[/dim]")


@cli.command()
@click.option("--target", required=True, help="Target domain or URL")
@click.option("--scope", "scope_path", required=True, help="Scope YAML file")
@click.option("--profile", default="normal", help="Profile: fast|normal|deep")
@click.option("--stages", "stage_list", default=None, help="Comma-separated stages to run")
@click.option("--skip", default=None, help="Comma-separated stages to skip")
@click.option("--run-id", default=None, help="Custom run ID")
@click.option("--resume", is_flag=True, help="Resume an incomplete run")
@click.option("--ai/--no-ai", default=None, help="Enable/disable AI")
@click.option("--ai-provider", default=None, help="AI provider: openai|ollama|groq")
@click.option("--ai-model", default=None, help="AI model name")
@click.option("--ai-key", default=None, help="AI API key")
@click.option("--rate", type=int, default=None, help="Rate limit (req/sec)")
@click.option("--concurrency", type=int, default=None, help="Max concurrent workers")
@click.option("--timeout", type=int, default=None, help="Per-request timeout (sec)")
@click.option("--ports", default=None, help="Comma-separated ports")
@click.option("--proxy", default=None, help="HTTP proxy (e.g., http://127.0.0.1:8080)")
@click.option("--insecure", is_flag=True, help="Skip TLS verification")
@click.pass_context
def run(ctx, target, scope_path, profile, stage_list, skip, run_id,
        resume, ai, ai_provider, ai_model, ai_key, rate, concurrency,
        timeout, ports, proxy, insecure):
    """Run the full recon pipeline on a target."""
    console.print(BANNER)

    workspace = ctx.obj.get("workspace", Path("./runs"))

    # Load config
    from reconx.core.config import Config
    profile_path = Path(f"configs/profiles/{profile}.yaml")
    config = Config.load(profile_path if profile_path.exists() else None)
    config.set("_profile_name", profile)

    # Apply CLI overrides
    if rate is not None:
        config.set("network.rate_limit_rps", rate)
    if concurrency is not None:
        config.set("network.concurrency", concurrency)
    if timeout is not None:
        config.set("network.timeout", timeout)
    if ports is not None:
        config.set("http.ports", [int(p) for p in ports.split(",")])
    if proxy:
        config.set("http.proxy", proxy)
    if insecure:
        config.set("http.insecure", True)
    if ai is not None:
        config.set("ai.enabled", ai)
    if ai_provider:
        config.set("ai.provider", ai_provider)
    if ai_model:
        config.set("ai.model", ai_model)
    if ai_key:
        config.set("ai.api_key", ai_key)

    # Load scope
    from reconx.core.scope import Scope
    scope = Scope(scope_path)

    # Validate & clean target (blocks path traversal / argv injection via --target)
    target = _clean_target(target)

    # Create run directory
    if not run_id:
        run_id = datetime.now().strftime("%Y%m%dT%H%M%S") + f"_{target}"
    # Extra safety: ensure the resolved run_dir stays inside the workspace
    workspace_resolved = workspace.resolve()
    run_dir = (workspace / target / run_id).resolve()
    try:
        run_dir.relative_to(workspace_resolved)
    except ValueError:
        console.print(f"[red]✗ Refusing to create run directory outside workspace: {run_dir}[/red]")
        sys.exit(2)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "data").mkdir(exist_ok=True)
    (run_dir / "logs").mkdir(exist_ok=True)
    (run_dir / "reports").mkdir(exist_ok=True)
    (run_dir / "inputs").mkdir(exist_ok=True)

    # Save inputs
    import shutil as sh
    import yaml
    sh.copy2(scope_path, run_dir / "inputs" / "scope.used.yaml")
    with open(run_dir / "inputs" / "profile.used.yaml", "w") as f:
        yaml.dump(config.to_dict(), f)

    # Initialize stores
    from reconx.core.store import StoreManager
    stores = StoreManager(run_dir / "data")

    # Initialize runner
    from reconx.core.runner import ToolRunner
    runner = ToolRunner(log_dir=run_dir / "logs")

    # Initialize rate limiter
    from reconx.core.ratelimit import RateLimiter
    rate_limiter = RateLimiter(rate=config.get("network.rate_limit_rps", 10))

    # Initialize AI engine
    ai_engine = None
    if config.get("ai.enabled", False):
        from reconx.ai.engine import AIEngine
        ai_engine = AIEngine(
            provider_name=config.get("ai.provider", "ollama"),
            api_key=config.get("ai.api_key") or os.environ.get("RECONX_AI_KEY"),
            model=config.get("ai.model"),
            base_url=config.get("ai.base_url"),
            enabled=True,
            cache_path=run_dir / "data" / "ai_cache.json",
            token_budget=config.get("ai.token_budget") or None,
        )

    # Build pipeline context
    from reconx.core.scheduler import PipelineContext, PipelineScheduler
    context = PipelineContext(
        target=target,
        run_dir=run_dir,
        config=config,
        scope=scope,
        stores=stores,
        runner=runner,
        rate_limiter=rate_limiter,
        ai_engine=ai_engine,
    )

    # Run pipeline
    scheduler = PipelineScheduler(context)
    stages = stage_list.split(",") if stage_list else None
    skip_list = skip.split(",") if skip else None

    results = scheduler.run(stages=stages, skip=skip_list)

    # Generate reports
    try:
        from reconx.reports.summary import generate_summary
        generate_summary(context)
    except Exception as e:
        console.print(f"  [yellow]Report generation failed: {e}[/yellow]")

    # AI finding triage
    if ai_engine and ai_engine.enabled:
        all_vulns = stores.vulns.read_all()
        all_findings = stores.findings.read_all()
        combined = all_vulns + all_findings
        if combined:
            triaged = ai_engine.triage_findings(combined[:20])
            if triaged:
                stores.ai_analysis.add({
                    "stage": "triage",
                    "target": target,
                    "analysis": {"triaged_findings": triaged},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })

        # AI summary narrative
        summary_text = ai_engine.generate_summary(
            stores.summary(),
            combined[:15],
        )
        if summary_text:
            (run_dir / "reports" / "ai_narrative.md").write_text(
                summary_text, encoding="utf-8"
            )

    # Generate HTML report
    try:
        from reconx.reports.html_report import generate_html_report
        html_out = generate_html_report(run_dir)
        console.print(f"  [green]✓ HTML report → {html_out}[/green]")
    except Exception as e:
        console.print(f"  [yellow]HTML report failed: {e}[/yellow]")

    console.print(f"\n[bold green]✓ Run complete![/bold green]")
    console.print(f"[dim]Results: {run_dir}[/dim]")


@cli.command()
@click.argument("stage_name")
@click.option("--run", "run_path", required=True, help="Path to existing run directory")
@click.option("--fresh", is_flag=True, help="Ignore cached data")
@click.pass_context
def stage(ctx, stage_name, run_path, fresh):
    """Run a single pipeline stage against an existing run."""
    console.print(f"[bold]Running stage: {stage_name}[/bold]")

    run_dir = Path(run_path)
    if not run_dir.exists():
        console.print(f"[red]Run directory not found: {run_dir}[/red]")
        sys.exit(1)

    # Load manifest
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        console.print("[red]No manifest.json found in run directory[/red]")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    from reconx.core.config import Config
    from reconx.core.scope import Scope
    from reconx.core.store import StoreManager
    from reconx.core.runner import ToolRunner
    from reconx.core.ratelimit import RateLimiter
    from reconx.core.scheduler import PipelineContext, PipelineScheduler

    config = Config(manifest.get("config", {}))
    scope = Scope(run_dir / "inputs" / "scope.used.yaml")
    stores = StoreManager(run_dir / "data")
    runner = ToolRunner(log_dir=run_dir / "logs")
    rate_limiter = RateLimiter(rate=config.get("network.rate_limit_rps", 10))

    context = PipelineContext(
        target=manifest["target"],
        run_dir=run_dir,
        config=config,
        scope=scope,
        stores=stores,
        runner=runner,
        rate_limiter=rate_limiter,
    )

    scheduler = PipelineScheduler(context)
    scheduler.run_single(stage_name)


@cli.group(name="scope")
def scope_group():
    """Scope utilities."""
    pass


@scope_group.command()
@click.option("--scope", "scope_path", required=True, help="Scope YAML file")
@click.option("--target", required=True, help="Host or URL to check")
def check(scope_path, target):
    """Check if a target is in scope."""
    from reconx.core.scope import Scope

    s = Scope(scope_path)

    if "://" in target:
        result = s.url_in_scope(target)
        label = "URL"
    else:
        result = s.host_in_scope(target)
        label = "Host"

    if result:
        console.print(f"[green]✓ {label} '{target}' is IN SCOPE[/green]")
    else:
        console.print(f"[red]✗ {label} '{target}' is OUT OF SCOPE[/red]")


@cli.command(name="export")
@click.option("--run", "run_path", required=True, help="Path to run directory")
@click.option("--format", "fmt", default="csv", help="Format: csv|md|html|burp|nuclei|json")
@click.option("--out", "out_path", default=None, help="Output file path")
def export_cmd(run_path, fmt, out_path):
    """Export run data to various formats."""
    if fmt == "html":
        from reconx.reports.html_report import generate_html_report
        out = generate_html_report(run_path, out_path)
        console.print(f"[green]✓ HTML report → {out}[/green]")
    else:
        from reconx.reports.export import export_data
        export_data(run_path, fmt, out_path)


@cli.command()
@click.option("--old", "old_path", required=True, help="Old run path")
@click.option("--new", "new_path", required=True, help="New run path")
@click.option("--out", "out_path", default=None, help="Output file")
def diff(old_path, new_path, out_path):
    """Compare two runs and show differences."""
    from reconx.reports.diff import diff_runs
    diff_runs(old_path, new_path, out_path)


def main():
    """Entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
