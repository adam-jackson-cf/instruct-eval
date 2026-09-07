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

The workflow schedules G3 private trials with the fixed indices `0` through `19`; private storage
resolves each index to its assignment. The canonical allocation is four A and four B subjects for
each core fixture plus two A and two B subjects for the negative control. G4 receives closed
de-identified outcomes. G5 is the only release boundary for the private assignment and condition
join.

When a gate with private artifact capability rejects a protocol-invalid result, its actual reason is
retained in a write-once private `trusted_logs.json` at the immutable gate identity before publishing
the unchanged minimal public failure. Public-only stores retain no private diagnostic and receive no
private-root capability.

Disclosure scanning charges the single concatenated normalized derived disclosure stream once, without multiplying by the number of raw channels. Existing capture and scalar bounds remain enforced. The raw `tool_outputs` stream remains verbatim. Only a successful native `read` result proven to be the exact already-verified supplied treatment input may be projected into the derived disclosure stream. The trusted input pair is the canonical absolute workspace `.omp/AGENTS.md` path and exact treatment text established by pre-prompt context verification. A genuine `tool_execution_start` with a unique call ID and `toolName: "read"` must precede the successful `tool_execution_end` for that same call ID; the end must have `isError: false`, `toolName: "read"`, `result.content == [{"type":"text","text":treatment}]`, `result.details.displayContent.text == treatment`, `result.details.meta.source.type == "path"` with the exact canonical input path, `fileSize` equal to the UTF-8 byte length, and `totalLines`, `displayContent.startLine`, and `displayContent.lineNumbers` describing the whole input. No normalization, substring removal, global replacement, generic path whitelist, or inferred provenance is permitted. Only the matching `content[0].text` and `details.displayContent.text` are projected to `[verified runtime input]`, and only in `tool_execution_end.result`, `toolResult` `message_start` and `message_end` messages, `turn_end.toolResults[]`, and `agent_end.messages[]`. Every copy independently satisfies that metadata and content contract and has `role: "toolResult"`, `toolName: "read"`, `isError: false`, and the proven call ID. Every other scanned field and channel—including assistant echoes, arguments, diffs, stderr, Bash output, unsupported reads, and altered reads—remains unchanged. A genuine disclosure-scan protocol failure retains the existing private subject envelope and produces only `{"protocol_valid": false}` as its public outcome.

Native admission protocol failures retain actual runtime streams in the existing private subject
envelope, including incomplete captures after cancellation; missing completion is never fabricated.
Approval metadata and the failure reason remain private. The public outcome remains
`{"protocol_valid": false}`, and invalid captures are not independently scored as valid behavior.

Signed Updates are submitted through the public CLI `update` command. The workflow validates the wire against the campaign principal, target, action, proposal binding, expected revision, and sequence before accepting it. A signed wire is an input to the public boundary; its private signing key never is.