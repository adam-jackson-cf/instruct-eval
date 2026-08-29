# Temporal artifact routing

The campaign client communicates only with `ExperimentCampaignWorkflow` on `instruct-eval-public`. It supplies public campaign input and receives public workflow status, update revisions, and published public artifacts.

Run separate production processes. Public mode registers workflows and public Activities on `instruct-eval-public`; it has no private-map, authority, subject, or evidence-key capability. Private mode registers only private Activities on `instruct-eval-private`; it owns the authority record, private-map store, private evidence, and G5 release.

| Boundary | Allowed data | Prohibited data |
|---|---|---|
| Campaign CLI | Public input, workflow ID, canonical signed decision wire | Signing private key, private maps, worker state |
| Public queue and history | Campaign orchestration and public activity packets | Assignment/condition joins, private maps, subject material, evidence keys |
| Private queue | Fixed-index private trial requests, authorized private resolution, private artifacts | Public-client access to private state |
| `artifact_root` | Published campaign evidence and released results | Private authority, private maps, pre-release private evidence |
| `private_artifact_root` and private SQLite paths | Authority, staged records, maps, subject material, private evidence | Public inspection and client-side reads |

The workflow schedules G3 private trials with the fixed indices `0` through `9`; private storage resolves each index to its assignment. G4 receives closed de-identified outcomes. G5 is the only release boundary for the private assignment and condition join.

Signed Updates are submitted through the public CLI `update` command. The workflow validates the wire against the campaign principal, target, action, proposal binding, expected revision, and sequence before accepting it. A signed wire is an input to the public boundary; its private signing key never is.