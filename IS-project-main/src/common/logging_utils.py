from __future__ import annotations

import logging
from typing import Any, Mapping

from .config import LoggingConfig


def _normalize_logging_config(config: LoggingConfig | Mapping[str, Any] | None) -> LoggingConfig:
    if config is None:
        return LoggingConfig()
    if isinstance(config, LoggingConfig):
        return config
    return LoggingConfig(
        level=str(config.get("level", "INFO")),
        format=str(config.get("format", "%(asctime)s | %(levelname)s | %(name)s | %(message)s")),
        datefmt=str(config.get("datefmt", "%Y-%m-%d %H:%M:%S")),
    )


def configure_logging(config: LoggingConfig | Mapping[str, Any] | None = None) -> None:
    resolved = _normalize_logging_config(config)
    level_name = resolved.level.upper()
    level_value = getattr(logging, level_name, logging.INFO)

    logging.basicConfig(
        level=level_value,
        format=resolved.format,
        datefmt=resolved.datefmt,
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
