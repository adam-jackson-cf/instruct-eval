---
name: "instruct-eval"
description: "Operate canonical Temporal instruction-evaluation campaigns with signed Updates and private artifact boundaries."
---

# instruct-eval — Temporal operations

Run this skill only from its directory with the locked uv environment:

```sh
cd agent/skills/instruct-eval
uv sync --locked
```

## Provision the local Temporal service

The service is loopback-only, uses namespace `instruct-eval`, and keeps its SQLite database outside ephemeral campaign directories. Install the provisioned Temporal CLI v1.8.2, then start it with the exact arguments produced by the provisioner:

```sh
uv run python -c 'from instruct_eval.provision import provision_temporal_cli; print(provision_temporal_cli("/absolute/path/to/bin/temporal"))'
/absolute/path/to/bin/temporal server start-dev --ip 127.0.0.1 --namespace instruct-eval --db-filename /absolute/path/to/state/temporal.sqlite
```

Keep that service process running. The worker and campaign client address it as `127.0.0.1:7233`.

## Start production workers

Run two least-privilege processes: the public mode owns workflows and public Activities on `instruct-eval-public`; the private mode owns only private Activities on `instruct-eval-private`. Both configurations must be absolute, regular JSON files that are neither group- nor world-readable. Each loader rejects unknown, missing, or extra top-level keys.

The public-mode configuration has exactly these keys:

```json
{
  "temporal_address": "127.0.0.1:7233",
  "artifact_root": "/absolute/path/to/artifacts/public",
  "coordination_db": "/absolute/path/to/state/coordination.sqlite",
  "role_request": {"actual": "role execution request"}
}
```

Start it with:

```sh
uv run python -m instruct_eval.production_worker public /absolute/path/to/public.json
```

The private-mode configuration has exactly these keys:

```json
{
  "temporal_address": "127.0.0.1:7233",
  "artifact_root": "/absolute/path/to/artifacts/public",
  "private_artifact_root": "/absolute/path/to/artifacts/private",
  "coordination_db": "/absolute/path/to/state/coordination.sqlite",
  "private_map_db": "/absolute/path/to/state/private-maps.sqlite",
  "authority_artifact": "authority.json",
  "fixture_roots": {"core-1": "/absolute/path/to/fixture/core-1"},
  "subject_request": {"actual": "subject execution request"},
  "evidence_key_hex": "64-lowercase-hex-characters",
  "fixture_paths": {"core-1": []},
  "role_request": {"actual": "role execution request"}
}
```

Start it with:

```sh
uv run python -m instruct_eval.production_worker private /absolute/path/to/private.json
```

`artifact_root`, `private_artifact_root`, `coordination_db`, and `private_map_db` must be absolute; `authority_artifact` is a nonempty private-root-relative path. `evidence_key_hex` decodes to exactly 32 bytes. `fixture_roots`, `subject_request`, `fixture_paths`, and `role_request` must contain the actual protocol inputs; placeholders are not executable configuration. Keep the private root and SQLite files outside campaign artifact directories.

## Campaign control

Start or safely adopt a campaign on the public queue:

```sh
uv run instruct-eval --address 127.0.0.1:7233 start \
  --campaign-id campaign-01234567890123456789012345678901 \
  --model-identity MODEL \
  --runtime-identity RUNTIME \
  --coverage-sha256 64-LOWERCASE-HEX-DIGEST \
  --public-input-json '{"candidate_instruction":"Follow repository instructions exactly.","permissions":{"filesystem":"workspace"},"repository":{"root":"/absolute/path/to/repository"},"fixture_manifest_hash":"64-lowercase-hex-digest","operator_public_key":"BASE64URL-ENCODED-32-BYTE-ED25519-PUBLIC-KEY"}'
```

Inspect its public state:

```sh
uv run instruct-eval --address 127.0.0.1:7233 status \
  --workflow-id campaign-01234567890123456789012345678901
```

Campaign decisions are signed Updates. Obtain a canonical signed decision wire from the campaign principal; submit that exact JSON without changing its payload or signature. A wire has exactly `payload` and `signature`; its payload has exactly `campaign_id`, `target_kind`, `target_id`, `action`, `proposal_hash`, `expected_revision_hash`, and `sequence`.

```sh
uv run instruct-eval --address 127.0.0.1:7233 update \
  --workflow-id campaign-01234567890123456789012345678901 \
  --wire-json '{"payload":{"campaign_id":"campaign-01234567890123456789012345678901","target_kind":"campaign","target_id":"campaign-01234567890123456789012345678901","action":"approve_decomposition","proposal_hash":"64-lowercase-hex-digest","expected_revision_hash":"64-lowercase-hex-digest","sequence":1},"signature":"BASE64URL-ED25519-SIGNATURE"}'
```

The production package has no operator signing command. A principal-specific signing flow is a concrete prerequisite for submitting a decision; do not substitute an unsigned payload.
## Stage the complete design package

The signed `DesignProposal.design` has exactly `experiment_design` and
`preferred_directions`. `DesignProposal.design_hash` covers that complete joint package. Every G1,
G2, and freeze request binds the same proposal hash and G0 record hash. Those Activities run on
`instruct-eval-private` because they re-resolve the signed private staging record.

`experiment_design` has exactly three fixture packages named `core-1`, `core-2`, and
`negative-control`. Each fixture owns its task; complete manifest and hash; verifier source and
hash; observer source and hash; expected verifier results; ordered finite axes; fixture-local
directions; total outcome table; changed-path allowlist; witnesses; evidence contract; and complete
source classification. The source classification hash and byte partition must match the signed
decomposition.

Each fixture manifest has exactly this shape:

```json
{
  "schema": "instruct-eval-fixture-manifest-v1",
  "files": [
    {"path": "relative/path", "sha256": "64-lowercase-hex-digest"}
  ]
}
```

Each evidence contract has exactly this shape:

```json
{
  "schema": "instruct-eval-evidence-contract-v1",
  "verifier_path": "verify.py",
  "observer_path": "observe.py",
  "verifier_command": ["python3", "verify.py"],
  "observer_command": ["python3", "observe.py"]
}
```

Each witness `input` is UTF-8 canonical JSON with exactly this shape:

```json
{
  "schema": "instruct-eval-witness-input-v1",
  "changes": [
    {"path": "allowed/relative/path", "content": "replacement text or null"}
  ]
}
```

G2 copies the configured fixture root, verifies every manifest byte, applies the exact change set,
runs the frozen verifier and observer, and compares changed paths, protected hashes, executable
hashes, evidence hash, verifier result, and observer output with the witness contract. The private
adversary receives one complete packet containing the canonical claim, exact treatment, G0 analyst
assessment, condition-independent experiment design, source classifications, and every actual
witness result. Its returned `packet_sha256` must match the exact supplied packet.


## Inspection and verification

Read public results only from `artifact_root`. The private artifact root, private-map database, authority artifact, subject material, and evidence key are private-worker inputs, not campaign-client inspection inputs. Public workflow history and public packets contain no private assignment or condition joins; the private store resolves those joins and releases them only at G5.

For restart verification, stop and relaunch both unchanged `production_worker` mode commands, then query the same workflow ID with `instruct-eval status`. Temporal replays workflow history as workers process it. This package exposes no separate production replay command; use the status query to confirm recovery rather than inventing one.

Run the sole quality-gate command from the repository root:

```sh
bash scripts/run-ci-quality-gates.sh
```