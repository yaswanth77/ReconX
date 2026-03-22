"""
Stage 11: OSINT — Metadata Extraction from discoverable documents.

Downloads PDFs/DOCX from discovered URLs, extracts metadata (author, software, dates).
"""

from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console

console = Console()

DOCUMENT_EXTENSIONS = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt"]


def run(ctx):
    """Execute metadata extraction."""
    import httpx as httpx_lib

    if not ctx.config.get("osint.metadata_enabled", True):
        console.print("  [dim]Metadata extraction disabled[/dim]")
        return

    urls = ctx.stores.urls.read_all()
    doc_urls = []
    for u in urls:
        url = u.get("url", "").lower()
        if any(url.endswith(ext) for ext in DOCUMENT_EXTENSIONS):
            doc_urls.append(u["url"])

    if not doc_urls:
        console.print("  [dim]No document URLs found for metadata extraction[/dim]")
        return

    console.print(f"  [dim]Downloading {len(doc_urls[:20])} documents for metadata...[/dim]")

    temp_dir = ctx.run_dir / "temp_docs"
    temp_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for url in doc_urls[:20]:  # Limit downloads
        ctx.rate_limiter.acquire()
        try:
            resp = httpx_lib.get(url, timeout=30, follow_redirects=True, verify=False)
            if resp.status_code == 200:
                filename = url.split("/")[-1].split("?")[0]
                filepath = temp_dir / filename
                filepath.write_bytes(resp.content)

                # Extract metadata with exiftool if available
                if ctx.runner.is_available("exiftool"):
                    result = ctx.runner.run(
                        "exiftool", ["-json", str(filepath)], timeout=30
                    )
                    if result.success:
                        import json
                        try:
                            meta = json.loads(result.stdout)
                            if isinstance(meta, list) and meta:
                                meta = meta[0]
                                interesting = {}
                                for key in ["Author", "Creator", "Producer", "Company",
                                             "Software", "CreateDate", "ModifyDate",
                                             "LastModifiedBy", "Manager"]:
                                    if key in meta and meta[key]:
                                        interesting[key] = meta[key]

                                if interesting and ctx.stores.osint.add({
                                    "type": "metadata",
                                    "value": json.dumps(interesting),
                                    "source": "exiftool",
                                    "url": url,
                                    "metadata": interesting,
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                }):
                                    count += 1
                                    console.print(
                                        f"  [dim]  Metadata: {filename} → "
                                        f"{', '.join(f'{k}={v}' for k,v in interesting.items())}[/dim]"
                                    )
                        except json.JSONDecodeError:
                            pass

                # Clean up
                filepath.unlink(missing_ok=True)

        except Exception:
            continue

    # Cleanup temp dir
    try:
        temp_dir.rmdir()
    except OSError:
        pass

    console.print(f"  [dim]Metadata entries: {count}[/dim]")
