"""
Configuration loader — merges profile YAML with CLI overrides.
"""

import yaml
from pathlib import Path
from typing import Any


DEFAULT_CONFIG = {
    "stages": {
        "enabled": [
            "dns", "subs", "axfr", "validate", "vhosts",
            "fingerprint", "urls", "search", "params",
            "osint_emails", "osint_metadata", "osint_github",
            "vuln_nuclei", "vuln_xss", "vuln_sqli", "vuln_misc",
        ]
    },
    "network": {
        "rate_limit_rps": 10,
        "concurrency": 50,
        "timeout": 30,
        "retries": 2,
    },
    "http": {
        "ports": [80, 443, 8080, 8443],
        "user_agent": "ReconX/1.0",
        "proxy": None,
        "insecure": False,
    },
    "dns": {
        "resolvers": ["8.8.8.8", "1.1.1.1"],
        "wildcard_detection": True,
    },
    "subs": {
        "brute_force": False,
        "wordlist": None,
    },
    "vhosts": {
        "enabled": True,
        "wordlist": "configs/wordlists/vhosts.txt",
    },
    "crawl": {
        "max_depth": 3,
        "max_urls_per_host": 500,
        "same_origin_only": True,
    },
    "params": {
        "arjun_enabled": True,
        "endpoint_filters": ["id", "user", "account", "order", "search",
                             "redirect", "callback", "url", "next", "return"],
    },
    "osint": {
        "emails_enabled": True,
        "metadata_enabled": True,
        "github_enabled": True,
        "github_token": None,
    },
    "vuln": {
        "nuclei_tags": ["exposure", "misconfig", "cve"],
        "xss_enabled": True,
        "sqli_enabled": True,
        "misc_enabled": True,
    },
    "ai": {
        "enabled": False,
        "provider": "ollama",
        "model": None,
        "api_key": None,
        "base_url": None,
    },
    "wordlists": {
        "creepy_paths": "configs/wordlists/creepy_paths.txt",
        "wellknown": "configs/wordlists/wellknown.txt",
        "github_dorks": "configs/wordlists/github_dorks.txt",
    },
}


class Config:
    """
    Merged configuration from profile YAML + CLI overrides.

    Usage:
        config = Config.load(profile_path="configs/profiles/normal.yaml")
        config.set("ai.enabled", True)
        rps = config.get("network.rate_limit_rps")
    """

    def __init__(self, data: dict):
        self._data = data

    @classmethod
    def load(cls, profile_path: str | Path | None = None) -> "Config":
        """Load config by merging defaults with profile YAML."""
        import copy
        merged = copy.deepcopy(DEFAULT_CONFIG)

        if profile_path:
            path = Path(profile_path)
            if path.exists():
                with open(path, "r") as f:
                    profile_data = yaml.safe_load(f) or {}
                cls._deep_merge(merged, profile_data)

        return cls(merged)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Get a value by dotted key path, e.g., 'network.rate_limit_rps'."""
        keys = dotted_key.split(".")
        current = self._data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def set(self, dotted_key: str, value: Any):
        """Set a value by dotted key path."""
        keys = dotted_key.split(".")
        current = self._data
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value

    def get_enabled_stages(self) -> list[str]:
        """Return list of enabled stage names."""
        return self.get("stages.enabled", [])

    def to_dict(self) -> dict:
        return self._data

    @staticmethod
    def _deep_merge(base: dict, override: dict):
        """Recursively merge override into base."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._deep_merge(base[key], value)
            else:
                base[key] = value
