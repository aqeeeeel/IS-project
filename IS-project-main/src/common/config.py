from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


@dataclass(slots=True)
class LoggingConfig:
    level: str = "INFO"
    format: str = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    datefmt: str = "%Y-%m-%d %H:%M:%S"


@dataclass(slots=True)
class PUFConfig:
    challenge_size: int = 256
    nonce_ttl_seconds: int = 60
    max_retries: int = 3


@dataclass(slots=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    request_timeout_seconds: int = 15


@dataclass(slots=True)
class EncryptionConfig:
    algorithm: str = "AES-GCM"
    key_size_bits: int = 256
    key_rotation_hours: int = 24


@dataclass(slots=True)
class MLConfig:
    model_name: str = "protected-model"
    parameter_chunk_size: int = 1_048_576


@dataclass(slots=True)
class AppConfig:
    environment: str = "dev"
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    puf: PUFConfig = field(default_factory=PUFConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    ml: MLConfig = field(default_factory=MLConfig)


def _deep_merge(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in incoming.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _set_nested(container: dict[str, Any], path: list[str], value: Any) -> None:
    current = container
    for segment in path[:-1]:
        if segment not in current or not isinstance(current[segment], dict):
            current[segment] = {}
        current = current[segment]
    current[path[-1]] = value


def _coerce_value(raw: str) -> Any:
    lower = raw.lower()
    if lower in {"true", "false"}:
        return lower == "true"
    try:
        if "." in raw:
            return float(raw)
        return int(raw)
    except ValueError:
        return raw


def _env_overrides(prefix: str) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    normalized = f"{prefix}_"
    for key, value in os.environ.items():
        if not key.startswith(normalized):
            continue
        suffix = key[len(normalized):]
        if not suffix:
            continue
        path = suffix.lower().split("__")
        _set_nested(overrides, path, _coerce_value(value))
    return overrides


def _as_dict(config: AppConfig) -> dict[str, Any]:
    return {
        "environment": config.environment,
        "logging": {
            "level": config.logging.level,
            "format": config.logging.format,
            "datefmt": config.logging.datefmt,
        },
        "puf": {
            "challenge_size": config.puf.challenge_size,
            "nonce_ttl_seconds": config.puf.nonce_ttl_seconds,
            "max_retries": config.puf.max_retries,
        },
        "server": {
            "host": config.server.host,
            "port": config.server.port,
            "request_timeout_seconds": config.server.request_timeout_seconds,
        },
        "encryption": {
            "algorithm": config.encryption.algorithm,
            "key_size_bits": config.encryption.key_size_bits,
            "key_rotation_hours": config.encryption.key_rotation_hours,
        },
        "ml": {
            "model_name": config.ml.model_name,
            "parameter_chunk_size": config.ml.parameter_chunk_size,
        },
    }


def _build_config(data: dict[str, Any]) -> AppConfig:
    return AppConfig(
        environment=str(data.get("environment", "dev")),
        logging=LoggingConfig(**data.get("logging", {})),
        puf=PUFConfig(**data.get("puf", {})),
        server=ServerConfig(**data.get("server", {})),
        encryption=EncryptionConfig(**data.get("encryption", {})),
        ml=MLConfig(**data.get("ml", {})),
    )


def load_config(path: str | Path | None = None, env_prefix: str = "PUF_PROTECT") -> AppConfig:
    defaults = _as_dict(AppConfig())
    file_data: dict[str, Any] = {}

    if path is not None:
        config_path = Path(path)
        if config_path.exists():
            file_data = tomllib.loads(config_path.read_text(encoding="utf-8"))

    env_data = _env_overrides(env_prefix)
    merged = _deep_merge(defaults, file_data)
    merged = _deep_merge(merged, env_data)
    return _build_config(merged)
