"""Explicit, permission-checked production worker entrypoints."""

from __future__ import annotations

import argparse
import asyncio
import json
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from .production import (
    ProductionConfig,
    ProductionConfigurationError,
    PublicProductionConfig,
    run_private_production_worker,
    run_public_production_worker,
)


def _secure_regular_file(path: Path, label: str) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ProductionConfigurationError(f"{label} must be an absolute regular file")
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as error:
        raise ProductionConfigurationError(f"{label} cannot be inspected") from error
    if mode & 0o077:
        raise ProductionConfigurationError(f"{label} must not be group- or world-readable")


def _read(path: str | Path) -> Mapping[str, object]:
    source = Path(path)
    _secure_regular_file(source, "production config")
    try:
        raw = json.loads(source.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProductionConfigurationError("production config is malformed") from error
    if not isinstance(raw, Mapping):
        raise ProductionConfigurationError("production config must be an object")
    return raw


def load_public_config(path: str | Path) -> PublicProductionConfig:
    raw = _read(path)
    required = {"temporal_address", "artifact_root", "coordination_db", "role_request"}
    if (
        set(raw) != required
        or not all(isinstance(raw[key], str) for key in required - {"role_request"})
        or not isinstance(raw["role_request"], Mapping)
    ):
        raise ProductionConfigurationError("public config fields are not exact")
    return PublicProductionConfig(
        cast(str, raw["temporal_address"]),
        Path(cast(str, raw["artifact_root"])),
        Path(cast(str, raw["coordination_db"])),
        cast(Mapping[str, Any], raw["role_request"]),
    )


def load_private_config(path: str | Path) -> ProductionConfig:
    raw = _read(path)
    required = {
        "temporal_address",
        "artifact_root",
        "private_artifact_root",
        "coordination_db",
        "private_map_db",
        "authority_artifact",
        "fixture_roots",
        "subject_request",
        "evidence_key_hex",
        "fixture_paths",
        "role_request",
    }
    textual = required - {"fixture_roots", "subject_request", "fixture_paths", "role_request"}
    if (
        set(raw) != required
        or any(not isinstance(raw[name], str) for name in textual)
        or not isinstance(raw["role_request"], Mapping)
    ):
        raise ProductionConfigurationError("private config fields are not exact")
    try:
        key = bytes.fromhex(cast(str, raw["evidence_key_hex"]))
        roots = {
            name: Path(value)
            for name, value in cast(Mapping[str, str], raw["fixture_roots"]).items()
        }
    except (TypeError, ValueError, AttributeError) as error:
        raise ProductionConfigurationError(
            "production private configuration is malformed"
        ) from error
    return ProductionConfig(
        cast(str, raw["temporal_address"]),
        Path(cast(str, raw["artifact_root"])),
        Path(cast(str, raw["private_artifact_root"])),
        Path(cast(str, raw["coordination_db"])),
        Path(cast(str, raw["private_map_db"])),
        cast(str, raw["authority_artifact"]),
        roots,
        cast(Mapping[str, Any], raw["subject_request"]),
        key,
        cast(Mapping[str, list[str]], raw["fixture_paths"]),
        cast(Mapping[str, Any], raw["role_request"]),
    )


def cli() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("public", "private"))
    parser.add_argument("config")
    arguments = parser.parse_args()
    if arguments.mode == "public":
        asyncio.run(run_public_production_worker(load_public_config(arguments.config)))
    else:
        asyncio.run(run_private_production_worker(load_private_config(arguments.config)))


if __name__ == "__main__":
    cli()
