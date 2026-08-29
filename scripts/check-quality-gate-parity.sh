#!/usr/bin/env bash
set -euo pipefail

runner_path='scripts/run-ci-quality-gates'

grep -Fq "$runner_path" .pre-commit-config.yaml
grep -Fq "$runner_path" .github/workflows/ci-quality-gates.yml
