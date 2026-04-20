"""
Tool runner — subprocess wrapper for external tools.

Handles timeout, retries, logging, and output capture for
every external tool (httpx, gau, nuclei, etc.).
"""

import subprocess
import shutil
import time
from pathlib import Path
from rich.console import Console

console = Console()


class ToolRunner:
    """
    Execute external CLI tools with retries, timeout, and logging.

    Usage:
        runner = ToolRunner(log_dir="runs/.../logs")
        result = runner.run("httpx", ["-l", "hosts.txt", "-json"], timeout=300)
        print(result.stdout)
    """

    def __init__(self, log_dir: str | Path | None = None):
        self.log_dir = Path(log_dir) if log_dir else None
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)

    # Expected version-string signatures so we don't mistake a same-name
    # binary (e.g. python3-httpx's `httpx` CLI) for the ProjectDiscovery one.
    _IDENTITY_SIGNATURES: dict[str, tuple[str, ...]] = {
        "httpx": ("projectdiscovery",),
        "subfinder": ("projectdiscovery", "subfinder"),
        "nuclei": ("projectdiscovery", "nuclei"),
        "katana": ("projectdiscovery", "katana"),
        "finalrecon": ("finalrecon",),
    }

    def is_available(self, tool_name: str) -> bool:
        """Check if a tool is available in PATH."""
        return shutil.which(tool_name) is not None

    def identity_ok(self, tool_name: str) -> bool:
        """
        Verify the binary on PATH is the expected upstream tool, not a
        same-name collision (python3-httpx ships a `httpx` CLI that has
        nothing to do with ProjectDiscovery httpx, for instance).

        Returns True when we can't tell (no signature registered) so this
        stays opt-in per tool.
        """
        if not self.is_available(tool_name):
            return False
        signatures = self._IDENTITY_SIGNATURES.get(tool_name)
        if not signatures:
            return True

        probes = [["-version"], ["--version"], ["-h"], ["--help"]]
        for probe in probes:
            try:
                res = subprocess.run(
                    [tool_name] + probe,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except Exception:
                continue
            blob = ((res.stdout or "") + (res.stderr or "")).lower()
            if any(sig in blob for sig in signatures):
                return True
        return False

    def get_version(self, tool_name: str) -> str | None:
        """Try to get tool version string."""
        try:
            result = subprocess.run(
                [tool_name, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = (result.stdout or result.stderr or "").strip()
            return output.split("\n")[0] if output else None
        except Exception:
            # Some tools use -version or -v
            for flag in ["-version", "-v"]:
                try:
                    result = subprocess.run(
                        [tool_name, flag],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    output = (result.stdout or result.stderr or "").strip()
                    if output:
                        return output.split("\n")[0]
                except Exception:
                    continue
            return None

    def run(
        self,
        tool: str,
        args: list[str],
        timeout: int = 600,
        attempts: int = 3,
        input_data: str | None = None,
        cwd: str | Path | None = None,
        env: dict | None = None,
        retries: int | None = None,
    ) -> "ToolResult":
        """
        Run an external tool with retry logic.

        Args:
            tool: The command name (e.g., "httpx").
            args: Command arguments.
            timeout: Max seconds per attempt.
            attempts: Total attempts (1 = single try, no retry). Default 3.
            input_data: Optional stdin data.
            cwd: Working directory.
            env: Additional environment variables.
            retries: Deprecated alias for ``attempts``; kept for one release.

        Returns:
            ToolResult with stdout, stderr, return_code, success.
        """
        if retries is not None:
            attempts = retries
        if attempts < 1:
            attempts = 1
        cmd = [tool] + args
        cmd_str = " ".join(cmd)
        last_error = None

        for attempt in range(1, attempts + 1):
            try:
                console.print(
                    f"  [dim]→ {cmd_str[:120]}{'...' if len(cmd_str) > 120 else ''}[/dim]"
                )

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    input=input_data,
                    cwd=str(cwd) if cwd else None,
                    env=env,
                )

                tool_result = ToolResult(
                    command=cmd_str,
                    stdout=result.stdout or "",
                    stderr=result.stderr or "",
                    return_code=result.returncode,
                    success=result.returncode == 0,
                )

                # Log output
                if self.log_dir:
                    log_file = self.log_dir / f"{tool}.log"
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(f"\n{'='*60}\n")
                        f.write(f"CMD: {cmd_str}\n")
                        f.write(f"EXIT: {result.returncode}\n")
                        f.write(f"STDOUT:\n{result.stdout[:5000]}\n")
                        if result.stderr:
                            f.write(f"STDERR:\n{result.stderr[:2000]}\n")

                if tool_result.success or attempt == attempts:
                    return tool_result

                last_error = tool_result.stderr
                console.print(
                    f"  [yellow]⚠ Attempt {attempt}/{attempts} failed, retrying...[/yellow]"
                )
                time.sleep(2 ** attempt)  # Exponential backoff

            except subprocess.TimeoutExpired:
                last_error = f"Timeout after {timeout}s"
                console.print(
                    f"  [red]✗ Timeout after {timeout}s (attempt {attempt}/{attempts})[/red]"
                )
                if attempt < attempts:
                    time.sleep(2 ** attempt)

            except FileNotFoundError:
                return ToolResult(
                    command=cmd_str,
                    stdout="",
                    stderr=f"Tool not found: {tool}",
                    return_code=-1,
                    success=False,
                )

        return ToolResult(
            command=cmd_str,
            stdout="",
            stderr=last_error or "All attempts failed",
            return_code=-1,
            success=False,
        )


class ToolResult:
    """Result of a tool execution."""

    def __init__(
        self,
        command: str,
        stdout: str,
        stderr: str,
        return_code: int,
        success: bool,
    ):
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code
        self.success = success

    @property
    def lines(self) -> list[str]:
        """Stdout split into non-empty lines."""
        return [l.strip() for l in self.stdout.splitlines() if l.strip()]

    def json_lines(self) -> list[dict]:
        """Parse stdout as JSONL (one JSON object per line)."""
        import json
        results = []
        for line in self.lines:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results
