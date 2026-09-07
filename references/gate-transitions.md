# Temporal campaign lifecycle

`ExperimentCampaignWorkflow` is the sole campaign workflow. Start it with the campaign CLI and query `status` to obtain its current state, decision revision, outstanding action, and outstanding sequence.

```text
INITIALIZING → FINGERPRINT_READY → WAITING_DECOMPOSITION
                                      │ signed approve_decomposition, sequence 1
                                      ▼
                                  AUTHORIZING → RUNNING → COMPLETED
```

An operator may submit `cancel` only at the outstanding sequence. A campaign that cannot establish its immutable request fingerprint fails as `FINGERPRINT_FAILED`.

Each authorized claim runs as an `InstructionExperimentWorkflow`. Its decision lifecycle is:

```text
G0 → signed submit_design, sequence 1 → G1 private-map preparation and design commit
   → G2 design validation → signed approve_freeze, sequence 2 → freeze → G3 twenty private trials
   → G4 de-identified scoring → G5 release → G6 terminal result
```

The signed Update binds the campaign ID, target kind and ID, action, proposal hash where required, expected decision revision hash, and sequence. The workflow rejects a stale revision, wrong target, wrong action, repeated sequence, malformed wire, or invalid signature. Do not use manual gate commands.

G3 allocates four A and four B subjects to each core fixture, and two A and two B subjects to the
negative control: ten control and ten treated subjects. G6 authorization requires
`preferred_count_B_strictly_greater_than_A` in both core fixtures and
`all_subjects_match_preferred_direction` for all four negative-control subjects. A valid
non-authorization completes at G6; it is not a protocol failure.

## Local Temporal preflight

Before starting workers or creating campaign state, follow
[Prepare local Temporal](../README.md#2-prepare-local-temporal) to provision the pinned CLI on first
use, reuse the expected running service, or start a stopped service with its existing persistent
SQLite database. An absent CLI or stopped service is normal preflight setup, not a missing control
or treatment runtime.

Exit only when local Temporal at `127.0.0.1:7233` reports cluster health `SERVING` and namespace
`instruct-eval` in state `Registered`. The database must be an absolute non-symlink `.sqlite` path
outside ephemeral evaluation directories. Installation, startup, and readiness commands belong in
the README; public/private worker boundaries remain in [artifact routing](artifact-routing.md).

## Recovery

Temporal persists workflow history. Restarting the service or workers does not create a new campaign: relaunch the unchanged public and private `production_worker` mode commands and query the original campaign workflow ID. The package has no separate production replay CLI; recovery is verified by the resumed workflow status and published public evidence.

Run the [local Temporal preflight](#local-temporal-preflight) before resuming workers. Preserve the
same persistent SQLite database and verify readiness again; never delete or replace workflow history
to restart a stopped service.