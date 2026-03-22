"""
Scope enforcement — first-class citizen.

Loads a YAML scope file and provides methods to check if a host,
URL, or service is in-scope. Used as a gate before every expansion.
"""

import fnmatch
import yaml
from pathlib import Path
from urllib.parse import urlparse
from .normalize import normalize_host, normalize_url


class Scope:
    """
    Scope checker loaded from a YAML definition file.

    Example scope.yaml:
        in_scope:
          roots:
            - example.com
          include_subdomains: true
          allowed_ports: [80, 443, 8080, 8443]
        out_of_scope:
          host_patterns:
            - "dev.*"
            - "*.internal.example.com"
          url_patterns:
            - "*/logout*"
          extensions:
            - ".jpg"
            - ".png"
    """

    def __init__(self, scope_path: str | Path):
        self.scope_path = Path(scope_path)
        with open(self.scope_path, "r") as f:
            data = yaml.safe_load(f) or {}

        in_scope = data.get("in_scope", {})
        out_of_scope = data.get("out_of_scope", {})

        self.roots: list[str] = [
            normalize_host(r) for r in in_scope.get("roots", [])
        ]
        self.include_subdomains: bool = in_scope.get("include_subdomains", True)
        self.allowed_schemes: list[str] = [
            s.lower() for s in in_scope.get("include_schemes", ["http", "https"])
        ]
        self.allowed_ports: list[int] = in_scope.get(
            "allowed_ports", [80, 443, 8080, 8443]
        )

        self.exclude_host_patterns: list[str] = out_of_scope.get(
            "host_patterns", []
        )
        self.exclude_url_patterns: list[str] = out_of_scope.get(
            "url_patterns", []
        )
        self.exclude_extensions: list[str] = [
            ext.lower() for ext in out_of_scope.get("extensions", [])
        ]

    def host_in_scope(self, host: str) -> bool:
        """Check if a hostname is within scope."""
        host = normalize_host(host)

        # Check exclusion patterns first
        for pattern in self.exclude_host_patterns:
            if fnmatch.fnmatch(host, pattern):
                return False

        # Check if host matches any root
        for root in self.roots:
            if host == root:
                return True
            if self.include_subdomains and host.endswith(f".{root}"):
                return True

        return False

    def url_in_scope(self, url: str) -> bool:
        """Check if a URL is within scope (host + scheme + port + extension)."""
        url = normalize_url(url)
        parsed = urlparse(url)

        # Scheme check
        if parsed.scheme not in self.allowed_schemes:
            return False

        # Host check
        hostname = parsed.hostname or ""
        if not self.host_in_scope(hostname):
            return False

        # Port check
        port = parsed.port
        if port is None:
            port = 80 if parsed.scheme == "http" else 443
        if port not in self.allowed_ports:
            return False

        # Extension exclusion
        path_lower = parsed.path.lower()
        for ext in self.exclude_extensions:
            if path_lower.endswith(ext):
                return False

        # URL pattern exclusion
        for pattern in self.exclude_url_patterns:
            if fnmatch.fnmatch(url, pattern):
                return False

        return True

    def service_in_scope(self, service: str) -> bool:
        """Check if a service (scheme://host:port) is in scope."""
        parsed = urlparse(service)
        hostname = parsed.hostname or ""
        port = parsed.port
        if port is None:
            port = 80 if parsed.scheme == "http" else 443

        return self.host_in_scope(hostname) and port in self.allowed_ports

    def to_dict(self) -> dict:
        """Serialize scope for manifest."""
        return {
            "roots": self.roots,
            "include_subdomains": self.include_subdomains,
            "allowed_schemes": self.allowed_schemes,
            "allowed_ports": self.allowed_ports,
            "exclude_host_patterns": self.exclude_host_patterns,
            "exclude_url_patterns": self.exclude_url_patterns,
            "exclude_extensions": self.exclude_extensions,
        }
