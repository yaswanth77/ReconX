"""
Stage 12: OSINT — GitHub Dorking via GitHub API.

Searches for leaked secrets, exposed configs, and code containing the target domain.
"""

from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console

console = Console()


def run(ctx):
    """Execute GitHub dorking."""
    import httpx as httpx_lib

    if not ctx.config.get("osint.github_enabled", True):
        console.print("  [dim]GitHub dorking disabled[/dim]")
        return

    target = ctx.target
    github_token = ctx.config.get("osint.github_token")

    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    else:
        console.print("  [yellow]⚠ No GitHub token configured (rate-limited to 10 req/min)[/yellow]")

    # Default dork patterns
    dork_patterns = [
        f'"{target}" password',
        f'"{target}" api_key',
        f'"{target}" secret',
        f'"{target}" token',
        f'"{target}" credentials',
        f'"{target}" aws_access',
        f'"{target}" database_url',
        f'"{target}" smtp',
        f'"{target}" private_key',
        f'"{target}" .env',
    ]

    # Load custom dorks from wordlist
    dorks_path = Path(ctx.config.get("wordlists.github_dorks", "configs/wordlists/github_dorks.txt"))
    if dorks_path.exists():
        with open(dorks_path, "r") as f:
            custom_dorks = [line.strip().replace("{domain}", target)
                           for line in f if line.strip() and not line.startswith("#")]
            if custom_dorks:
                dork_patterns = custom_dorks

    console.print(f"  [dim]Running {len(dork_patterns)} GitHub dork queries...[/dim]")

    count = 0
    for dork in dork_patterns:
        ctx.rate_limiter.acquire()
        try:
            resp = httpx_lib.get(
                "https://api.github.com/search/code",
                params={"q": dork, "per_page": 5},
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                for item in items:
                    repo = item.get("repository", {}).get("full_name", "")
                    path = item.get("path", "")
                    html_url = item.get("html_url", "")

                    if ctx.stores.osint.add({
                        "type": "github_dork",
                        "value": html_url,
                        "source": "github_api",
                        "dork_query": dork,
                        "repository": repo,
                        "file_path": path,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }):
                        count += 1
                        console.print(
                            f"  [yellow]⚡ GitHub: {repo}/{path}[/yellow]"
                        )

            elif resp.status_code == 403:
                console.print("  [yellow]⚠ GitHub rate limit hit, stopping[/yellow]")
                break
            elif resp.status_code == 422:
                continue  # Invalid query

        except Exception as e:
            console.print(f"  [dim]GitHub API error: {e}[/dim]")
            continue

    console.print(f"  [dim]GitHub dork results: {count}[/dim]")
