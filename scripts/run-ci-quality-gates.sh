#!/usr/bin/env bash
set -euo pipefail

fix=false
stage=false

usage() {
  printf 'Usage: %s [--fix] [--stage]\n' "$0"
}

while (($#)); do
  case "$1" in
    --fix)
      fix=true
      ;;
    --stage)
      stage=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if "$stage" && ! "$fix"; then
  printf '%s\n' '--stage requires --fix.' >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bash scripts/check-quality-gate-parity.sh
uv sync --locked --dev

scope_file="$(mktemp)"
trap 'rm -f "$scope_file"' EXIT
uv run python scripts/python_quality_scope.py > "$scope_file"

python_files=()
while IFS= read -r -d '' file; do
  python_files+=("$file")
done < "$scope_file"

if ((${#python_files[@]} == 0)); then
  printf '%s\n' 'Python quality scope is empty.' >&2
  exit 1
fi

python_hashes=()
if "$fix" && "$stage"; then
  for file in "${python_files[@]}"; do
    python_hashes+=("$(git hash-object "$file")")
  done
fi

if "$fix"; then
  uv run ruff format "${python_files[@]}"
  uv run ruff check --fix "${python_files[@]}"
else
  uv run ruff format --check "${python_files[@]}"
  uv run ruff check "${python_files[@]}"
fi

uv run mypy src
uv run pytest

if "$stage"; then
  for index in "${!python_files[@]}"; do
    file="${python_files[$index]}"
    if [[ "$(git hash-object "$file")" != "${python_hashes[$index]}" ]]; then
      git add -- "$file"
    fi
  done
fi
