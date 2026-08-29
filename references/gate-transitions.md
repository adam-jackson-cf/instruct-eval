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
   → G2 design validation → signed approve_freeze, sequence 2 → freeze → G3 exact-ten private trials
   → G4 de-identified scoring → G5 release → G6 terminal result
```

The signed Update binds the campaign ID, target kind and ID, action, proposal hash where required, expected decision revision hash, and sequence. The workflow rejects a stale revision, wrong target, wrong action, repeated sequence, malformed wire, or invalid signature. Do not use manual gate commands.

## Recovery

Temporal persists workflow history. Restarting the service or workers does not create a new campaign: relaunch the unchanged public and private `production_worker` mode commands and query the original campaign workflow ID. The package has no separate production replay CLI; recovery is verified by the resumed workflow status and published public evidence.