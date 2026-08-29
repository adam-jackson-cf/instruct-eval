#!/usr/bin/env python3
"""Define the maintained Python files covered by project quality gates."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "venv",
}
_MAINTAINED_ROOTS = (Path("scripts"), Path("src"), Path("tests"))


def is_excluded_python_path(path: Path) -> bool:
    """Return whether a Python path is generated or tool-owned."""
    return bool(_EXCLUDED_PARTS.intersection(path.parts))


def is_maintained_python_path(path: Path) -> bool:
    """Return whether a Python path belongs to this project's source surface."""
    return (
        path.suffix == ".py"
        and not is_excluded_python_path(path)
        and path.parts[0] in {root.as_posix() for root in _MAINTAINED_ROOTS}
    )


def tracked_python_files() -> set[Path]:
    """Return every present tracked Python file and reject unclassified paths."""
    completed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.py"],
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = {
        Path(raw_path.decode("utf-8")) for raw_path in completed.stdout.split(b"\0") if raw_path
    }
    paths = {path for path in paths if path.is_file()}
    unclassified = [
        path
        for path in sorted(paths)
        if not is_excluded_python_path(path) and not is_maintained_python_path(path)
    ]
    if unclassified:
        formatted_paths = "\n".join(f"  - {path}" for path in unclassified)
        raise RuntimeError(
            "Python quality scope has unclassified tracked files; classify each path in "
            f"scripts/python_quality_scope.py:\n{formatted_paths}"
        )
    return paths


def maintained_python_files() -> list[Path]:
    """Return tracked and untracked maintained Python files in stable order."""
    paths = tracked_python_files()
    for root in _MAINTAINED_ROOTS:
        if root.is_dir():
            paths.update(path for path in root.rglob("*.py") if is_maintained_python_path(path))
    return sorted(paths)


def main() -> int:
    """Write the NUL-delimited maintained Python file set for shell callers."""
    try:
        sys.stdout.buffer.write(
            b"\0".join(path.as_posix().encode("utf-8") for path in maintained_python_files())
        )
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
