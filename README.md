# instruct-eval

## Purpose

`instruct-eval` measures whether a candidate instruction changes observable agent behavior. It runs
controlled instruction-evaluation campaigns as durable Temporal workflows, keeps treatment
assignment private until release, executes subjects in isolated OMP contexts, and publishes
evidence that supports a bounded `Keep`, `Revise`, `Remove`, or `Rerun` decision.

The control is behavior without the candidate instruction. The treatment is behavior with the
claim-specific instruction. Inclusion or exact recall is not behavioral-effect evidence.

## How it works

`ExperimentCampaignWorkflow` fingerprints one immutable campaign request and authorizes canonical
claims. Each claim runs as an `InstructionExperimentWorkflow`:

```text
G0 → signed submit_design → G1 → G2 → signed approve_freeze
   → G3 exact-ten private trials → G4 blind scoring → G5 release → G6 terminal result
```

Every experiment design contains exactly three fixture packages named `core-1`, `core-2`, and
`negative-control`. Each fixture owns its task, complete manifest and hash, unchanged verifier,
observer, expected verifier results, ordered finite axes, fixture-local directions, total outcome
table, changed-path allowlist, reachability witnesses, evidence contract, and source classification.

G3 executes subjects through `RuntimeSubjectExecutor → run_subject → execute_omp`. Condition A is an
instruction-free control. Condition B receives the claim-specific treatment. Each execution uses a
fresh OMP home and profile, disabled ambient discovery, a loopback credential gateway, and a
deny-by-default macOS sandbox.

Public and private work are separated:

- `instruct-eval-public` owns workflows and public Activities.
- `instruct-eval-private` owns private Activities, assignments, treatments, subject inputs, private
  evidence, and the G5 release join.
- `artifact_root` contains published public evidence.
- `private_artifact_root` and the private databases are not inspection inputs.

See [workflow lifecycle](references/gate-transitions.md),
[signed design package](references/design-package.md),
[artifact layout](references/artifact-layout.md), and
[artifact routing](references/artifact-routing.md) for the canonical contracts.

## How to use it

### 1. Prepare complete inputs

Before creating campaign state, prepare:

- the exact candidate instruction, model identity, runtime identity, and permissions;
- a caller-supplied `campaign-[0-9]{32}` identifier;
- the campaign principal's Ed25519 public key;
- a signed and privately staged decomposition proposal;
- complete `core-1`, `core-2`, and `negative-control` fixture packages;
- durable public, private, coordination, private-map, and Temporal state paths; and
- actual subject and role execution requests.

The production package has no operator signing or proposal-staging command. A principal-specific
signing and private staging flow is a concrete prerequisite. Do not substitute unsigned payloads,
test helpers, or direct artifact writes.

### 2. Start Temporal

From the repository root, synchronize the locked environment:

```sh
uv sync --locked
```

Provision Temporal CLI v1.8.2 and start the loopback-only `instruct-eval` namespace with an absolute
persistent SQLite path:

```sh
uv run python -c 'from instruct_eval.provision import provision_temporal_cli; print(provision_temporal_cli("/absolute/path/to/bin/temporal"))'
/absolute/path/to/bin/temporal server start-dev --ip 127.0.0.1 --namespace instruct-eval --db-filename /absolute/path/to/state/temporal.sqlite
```

Keep this process running. Workers and the campaign client connect to `127.0.0.1:7233`.

### 3. Start permission-separated workers

Both worker configuration files must be absolute, regular JSON files that are neither group- nor
world-readable. Loaders reject unknown, missing, or extra top-level keys.

`public.json` has exactly:

```json
{
  "temporal_address": "127.0.0.1:7233",
  "artifact_root": "/absolute/path/to/artifacts/public",
  "coordination_db": "/absolute/path/to/state/coordination.sqlite",
  "role_request": {"actual": "role execution request"}
}
```

`private.json` has exactly:

```json
{
  "temporal_address": "127.0.0.1:7233",
  "artifact_root": "/absolute/path/to/artifacts/public",
  "private_artifact_root": "/absolute/path/to/artifacts/private",
  "coordination_db": "/absolute/path/to/state/coordination.sqlite",
  "private_map_db": "/absolute/path/to/state/private-maps.sqlite",
  "authority_artifact": "authority.json",
  "fixture_roots": {
    "core-1": "/absolute/path/to/fixture/core-1",
    "core-2": "/absolute/path/to/fixture/core-2",
    "negative-control": "/absolute/path/to/fixture/negative-control"
  },
  "subject_request": {"actual": "subject execution request"},
  "evidence_key_hex": "64-lowercase-hex-characters",
  "fixture_paths": {
    "core-1": [],
    "core-2": [],
    "negative-control": []
  },
  "role_request": {"actual": "role execution request"}
}
```

The request objects and fixture values must contain actual protocol inputs; the examples above are
shape documentation, not executable configuration. `evidence_key_hex` must decode to exactly 32
bytes. Keep private roots and SQLite files outside campaign artifact directories.

Start both workers:

```sh
uv run python -m instruct_eval.production_worker public /absolute/path/to/public.json
uv run python -m instruct_eval.production_worker private /absolute/path/to/private.json
```

### 4. Start and advance a campaign

Start or safely adopt the campaign:

```sh
uv run instruct-eval --address 127.0.0.1:7233 start \
  --campaign-id campaign-01234567890123456789012345678901 \
  --model-identity MODEL \
  --runtime-identity RUNTIME \
  --coverage-sha256 64-LOWERCASE-HEX-DIGEST \
  --public-input-json '{"candidate_instruction":"Follow repository instructions exactly.","permissions":{"filesystem":"workspace"},"repository":{"root":"/absolute/path/to/repository"},"fixture_manifest_hash":"64-lowercase-hex-digest","operator_public_key":"BASE64URL-ENCODED-32-BYTE-ED25519-PUBLIC-KEY"}'
```

Query its public state:

```sh
uv run instruct-eval --address 127.0.0.1:7233 status \
  --workflow-id campaign-01234567890123456789012345678901
```

The status identifies the outstanding action, expected revision, and sequence. Obtain the exact
canonical signed decision wire from the campaign principal, then submit it unchanged:

```sh
uv run instruct-eval --address 127.0.0.1:7233 update \
  --workflow-id campaign-01234567890123456789012345678901 \
  --wire-json '{"payload":{"campaign_id":"campaign-01234567890123456789012345678901","target_kind":"campaign","target_id":"campaign-01234567890123456789012345678901","action":"approve_decomposition","proposal_hash":"64-lowercase-hex-digest","expected_revision_hash":"64-lowercase-hex-digest","sequence":1},"signature":"BASE64URL-ED25519-SIGNATURE"}'
```

After decomposition approval, each authorized claim waits for a signed `submit_design` decision,
runs G1 and G2, and waits for a signed `approve_freeze` decision. Do not use manual gate commands.
Temporal schedules G3 through G6 after freeze approval.

### 5. Inspect results or recover

Read public results only from `artifact_root`. Do not inspect private roots, private databases,
authority artifacts, subject material, or evidence keys as campaign results.

Each subject, witness, and internal role evaluation uses a workspace below `experiments/`. The
evaluation directory has one UTC-stamped name and contains the non-timestamped runtime directory and
workspace. Runtime directories are removed when execution completes, and `experiments/` is excluded
from Git.

To recover an interrupted campaign, restart the same Temporal service and unchanged public and
private worker commands, then query the original workflow ID. Temporal resumes from workflow
history; there is no separate production replay command.

## Developer guidance

Repository implementation rules and the required development workflow are in
[`AGENTS.md`](AGENTS.md). Runtime role contracts remain under [`references/roles/`](references/roles/).