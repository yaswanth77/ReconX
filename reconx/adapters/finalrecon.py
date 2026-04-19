"""
FinalRecon adapter — shell out to FinalRecon and normalize its JSON output
into ReconX data stores.

FinalRecon (https://github.com/thewhiteh4t/FinalRecon) produces broad,
early-stage surface information (DNS, whois, SSL, headers, CT-subdomains).
Rather than re-implement those in Python, we shell to it when it's in PATH
and fall back silently when it's not.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console

console = Console()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_available(ctx) -> bool:
    """Is the FinalRecon binary on PATH?"""
    return ctx.runner.is_available("finalrecon")


def run(ctx, target: str | None = None) -> dict:
    """
    Run FinalRecon against the target. Returns the parsed JSON blob (or {}).
    Writes discovered hosts, services, and findings to ctx.stores.
    """
    target = target or ctx.target
    if not is_available(ctx):
        return {}

    with tempfile.TemporaryDirectory(prefix="reconx_fr_") as tmpdir:
        out_dir = Path(tmpdir)
        url = f"https://{target}"
        result = ctx.runner.run(
            "finalrecon",
            ["--full", "--url", url, "--export", "json", "--output", str(out_dir)],
            timeout=ctx.config.get("finalrecon.timeout", 600),
            attempts=1,
        )
        if not result.success:
            console.print("  [yellow]FinalRecon run failed; skipping ingest[/yellow]")
            return {}

        # FinalRecon writes one JSON per module into the output dir.
        merged: dict = {}
        for jpath in sorted(out_dir.rglob("*.json")):
            try:
                data = json.loads(jpath.read_text(encoding="utf-8"))
            except Exception:
                continue
            merged[jpath.stem] = data

        _ingest(ctx, target, merged)
        return merged


def _ingest(ctx, target: str, merged: dict) -> None:
    """Map merged FinalRecon output into ReconX stores."""
    # Subdomains → hosts
    subs = merged.get("crawler", {}).get("subdomains") or \
           merged.get("dns_enum", {}).get("subdomains") or []
    for sub in subs:
        sub = (sub or "").strip().lower()
        if not sub or not ctx.scope.host_in_scope(sub):
            continue
        ctx.stores.hosts.add({
            "host": sub,
            "source": ["finalrecon"],
            "dns": {},
            "wildcard_suspect": False,
            "first_seen_stage": "dns",
            "timestamp": _ts(),
        })

    # DNS records for the root
    dns_data = merged.get("dns_enum") or {}
    if dns_data:
        ctx.stores.hosts.add({
            "host": target,
            "source": ["finalrecon"],
            "dns": {k.lower(): v for k, v in dns_data.items() if isinstance(v, list)},
            "wildcard_suspect": False,
            "first_seen_stage": "dns",
            "timestamp": _ts(),
        })

    # SSL / headers as findings
    ssl_info = merged.get("ssl") or merged.get("ssl_cert")
    if ssl_info:
        ctx.stores.findings.add({
            "type": "SSL_CERT",
            "severity": "info",
            "asset": target,
            "evidence": ssl_info if isinstance(ssl_info, dict) else {"raw": ssl_info},
            "timestamp": _ts(),
        })

    whois_info = merged.get("whois")
    if whois_info:
        ctx.stores.findings.add({
            "type": "WHOIS",
            "severity": "info",
            "asset": target,
            "evidence": whois_info if isinstance(whois_info, dict) else {"raw": whois_info},
            "timestamp": _ts(),
        })
