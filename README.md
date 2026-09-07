# instruct-eval

## Purpose

`instruct-eval` measures whether a candidate instruction changes observable agent behavior. It runs
controlled instruction-evaluation campaigns as durable Temporal workflows, keeps treatment
assignment private until release, executes subjects in isolated OMP contexts, and publishes
evidence that supports a bounded `Keep`, `Revise`, `Remove`, or `Rerun` decision.

The control is behavior without the candidate instruction. The treatment is behavior with the
claim-specific instruction. Inclusion or exact recall is not behavioral-effect evidence.

## How to use it

Open this repository in your coding agent and ask it to evaluate an instruction using the
[experiment development workflow](AGENTS.md#experiment-development-workflow). For example:

> Evaluate the following instruction using the experiment development workflow in AGENTS.md.
> Follow the workflow through Step 9 and return the report required by references/result-reporting.md.
>
> Quality gates must always pass to green for coding tasks to be complete

Provide the exact instruction and any constraints on the model, runtime, or permissions. The agent
handles the workflow: preparing the design and fixtures, establishing the runtime, advancing the
authorized campaign, inspecting released evidence, and returning the evaluation report. You do not
need to prepare fixture packages or run the commands below just to make the initial request.

The workflow still requires the applicable permissions, credentials, and signed approvals. The agent
must request missing access or human decisions when needed; the initial request does not bypass
those boundaries. Do not put credentials or private signing keys in the request.

## How it works

`ExperimentCampaignWorkflow` fingerprints one immutable campaign request and authorizes canonical
claims. Each claim runs as an `InstructionExperimentWorkflow`:

```text
G0 → signed submit_design → G1 → G2 → signed approve_freeze
   → G3 twenty private trials → G4 blind scoring → G5 release → G6 terminal result
```

Every experiment design contains exactly three fixture packages named `core-1`, `core-2`, and
`negative-control`. Each fixture owns its task, complete manifest and hash, unchanged verifier,
observer, expected verifier results, ordered finite axes, fixture-local directions, total outcome
table, changed-path allowlist, reachability witnesses, evidence contract, and source classification.

G3 executes subjects through `RuntimeSubjectExecutor → run_subject → execute_omp`. Condition A is an
instruction-free control. Condition B receives the claim-specific treatment. Each execution uses a
fresh OMP home and profile, disabled ambient discovery, a loopback credential gateway, and a
deny-by-default macOS sandbox.

Each experiment allocates four A controls and four B treatments to each core fixture, plus two A
controls and two B treatments to the negative control: ten control and ten treated subjects. G6
authorizes only when B's preferred-direction count is strictly greater than A's in both core
fixtures and all four negative-control subjects match their preferred direction; otherwise it
records a valid non-authorized terminal result.

Public and private work are separated:

- `instruct-eval-public` owns workflows and public Activities.
- `instruct-eval-private` owns private Activities, assignments, treatments, subject inputs, private
  evidence, and the G5 release join.
- `artifact_root` contains published public evidence.
- `private_artifact_root` and the private databases are not inspection inputs.

See [workflow lifecycle](references/gate-transitions.md),
[signed design package](references/design-package.md),
[artifact layout](references/artifact-layout.md),
[artifact routing](references/artifact-routing.md), and
[evaluation result reporting](references/result-reporting.md) for the canonical contracts.

## Runtime operation reference

The following sections document runtime setup, campaign operations, and recovery for the agent or
an operator administering the runtime. They are not a manual checklist for a human requesting an
instruction evaluation. The ordered workflow remains in
[AGENTS.md](AGENTS.md#experiment-development-workflow).

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

### 2. Prepare local Temporal

Experiments run on this machine. Use the local Temporal development server with persistent SQLite
storage; no external machine, hosted Temporal service, or Docker installation is required.
An absent CLI or stopped service is normal preflight setup, not a missing control or treatment
runtime. Both conditions use the existing subject execution path described above.

Follow the [local Temporal preflight contract](references/gate-transitions.md#local-temporal-preflight).
For a new installation, use `$HOME/.local/share/instruct-eval` for the CLI and durable service state.
For an existing installation, retain its configured absolute paths, especially its database path;
do not create an empty replacement database to recover a campaign.

From the repository root, synchronize the locked environment and provision the pinned CLI:

```sh
uv sync --locked
uv run python - <<'PY'
from pathlib import Path

from instruct_eval.provision import provision_temporal_cli, validate_service_prerequisites

root = Path.home() / ".local/share/instruct-eval"
binary = provision_temporal_cli(root / "bin/temporal")
database = validate_service_prerequisites(
    "127.0.0.1",
    "instruct-eval",
    root / "state/temporal.sqlite",
    run_roots=(Path.cwd() / "experiments",),
)
database.parent.mkdir(parents=True, exist_ok=True)
print(binary)
print(database)
PY
```

`provision_temporal_cli` reuses an installed CLI only when its version matches the pinned release.
Otherwise it downloads Temporal CLI v1.8.2 for the supported host, verifies the checked-in archive
checksum and exact version, and atomically installs it. Do not substitute an unpinned package-manager
version. A download, checksum, version, or path-validation failure must be resolved before continuing.

Check an existing local service:

```sh
"$HOME/.local/share/instruct-eval/bin/temporal" operator cluster health --address 127.0.0.1:7233
"$HOME/.local/share/instruct-eval/bin/temporal" operator namespace describe --address 127.0.0.1:7233 --namespace instruct-eval
```

If the expected service is already running, reuse it after confirming its launch configuration uses
the intended persistent database. If it is stopped, start it in a dedicated terminal or supervised
long-running process:

```sh
"$HOME/.local/share/instruct-eval/bin/temporal" server start-dev \
  --ip 127.0.0.1 \
  --namespace instruct-eval \
  --db-filename "$HOME/.local/share/instruct-eval/state/temporal.sqlite"
```

Keep this process running. In another terminal, repeat both readiness commands: require `SERVING`
and namespace `instruct-eval` in state `Registered` before starting workers or creating campaign state.
Process creation or an open port alone is not readiness. If the port is occupied by an unknown
service, or health/namespace checks fail, inspect and resolve the mismatch; do not kill another
service, switch ports, or replace the database to bypass it.

To restart a stopped service, run the same start command with the same database and repeat readiness
checks. Workers and the campaign client connect to `127.0.0.1:7233`. Continue with the
permission-separated worker setup below.

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

After G5 release and the G6 terminal result, format the released public evidence with the
[evaluation result reporting contract](references/result-reporting.md). Reporting explains the
recorded result; it does not rescore outcomes or create a new authorization decision.

## Developer guidance

Repository implementation rules and the required development workflow are in
[`AGENTS.md`](AGENTS.md). Runtime role contracts remain under [`references/roles/`](references/roles/).