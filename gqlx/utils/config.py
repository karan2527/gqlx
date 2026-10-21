"""Configuration loading — YAML file merged with hard defaults."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from gqlx.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULTS: dict[str, Any] = {
    "timeout": 30,
    "concurrency": 10,
    "max_retries": 3,
    "rate_limit": 0.0,
    "max_depth": 3,
    "verify_ssl": True,
    "follow_redirects": True,
    "user_agent": "gqlx/1.0 (GraphQL Security Scanner)",
    "dos_max_depth": 15,
    "dos_max_aliases": 100,
    "dos_max_batch": 50,
    "id_range": 10,
}

_SEARCH_PATHS = [
    "config.yaml",
    "config.yml",
    str(Path.home() / ".config" / "gqlx" / "config.yaml"),
]


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load YAML config, merging user values over defaults."""
    cfg = DEFAULTS.copy()
    candidates = ([path] if path else []) + _SEARCH_PATHS

    for candidate in candidates:
        if not candidate:
            continue
        p = Path(candidate)
        if p.exists():
            try:
                with p.open() as f:
                    user = yaml.safe_load(f) or {}
                section_maps = {
                    "http": {
                        "timeout": "timeout",
                        "concurrency": "concurrency",
                        "max_retries": "max_retries",
                        "rate_limit": "rate_limit",
                        "verify_ssl": "verify_ssl",
                        "follow_redirects": "follow_redirects",
                        "user_agent": "user_agent",
                    },
                    "scan": {"max_depth": "max_depth", "id_range": "id_range"},
                    "dos": {
                        "max_depth": "dos_max_depth",
                        "max_aliases": "dos_max_aliases",
                        "max_batch": "dos_max_batch",
                    },
                }
                for section, keys in section_maps.items():
                    values = user.get(section)
                    if isinstance(values, dict):
                        for source, target in keys.items():
                            if source in values:
                                cfg[target] = values[source]
                for key in ("format", "include_info", "level"):
                    for section in ("output", "logging"):
                        values = user.get(section)
                        if isinstance(values, dict) and key in values:
                            cfg[key] = values[key]
                cfg.update({k: v for k, v in user.items() if not isinstance(v, dict)})
                logger.debug("config_loaded", path=str(p))
                break
            except yaml.YAMLError as exc:
                logger.warning("config_parse_error", path=str(p), error=str(exc))

    return cfg
