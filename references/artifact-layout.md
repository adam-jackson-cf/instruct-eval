# Temporal artifact layout

`artifact_root` and `private_artifact_root` are separate persistent directories. Public mode prepares only `artifact_root`; private mode prepares both roots. Artifact names are relative, canonical JSON is write-once, and a repeat publication is accepted only when its bytes are identical.

```text
artifact_root/
└── public campaign evidence and released results

private_artifact_root/
├── staged principal-owned proposals and decision records
├── private authority artifact
└── private execution evidence

state/
├── coordination.sqlite
├── private-maps.sqlite
└── temporal.sqlite
```

The directory names beneath the configured roots are protocol-owned; operators inspect public evidence through `artifact_root` and must not manufacture or modify records. SQLite files are durable service and worker state, not artifacts.

## Privacy boundary

Public artifacts may contain campaign status, released evidence, and result material. Private storage contains proposal control records, authority data, private-map state, assignment mappings, treatment material, and evidence keys. Do not copy private artifacts or databases into `artifact_root`, pass them to the public campaign client, or use them as inspection output.

Each subject has exactly eight private artifact kinds: `outcome`, `response`, `runtime_streams`,
`tool_outputs`, `diff`, `verifier`, `observer`, and `trusted_logs`. This closed inventory and the
private raw-transport, disclosure, and release boundaries remain unchanged.

Opaque subject tokens in `trial_accounting` identify scheduled work; they do not disclose condition
assignments or private joins.

Private subject evidence retains the complete native OMP JSON transport in
`runtime_streams.stdout` and a separate `runtime_streams.output_events` projection for disclosure
checks. The runtime's same-process `get_state` response is retained in the private raw stream. Only
that exact verified context response and exact verified user-input echoes are removed from the
generated-channel projection; every other generated assistant, reasoning, tool, error, diagnostic,
and event field remains evidence. Missing, duplicated, or mismatched input echoes make execution
protocol-invalid. This projection does not alter treatment placement or instruction priority.

Native RPC transport has a separate 64 MiB bound because it repeats partial-message snapshots.
The 1 MiB tool/verifier-stream bound, 256 KiB result-text bound, and 2 MiB workspace-evidence bound
remain unchanged. Oversized transport fails closed; no generated event is dropped to fit the bound.

The verified runtime input proves only that the intended context was included, not that it caused
the observed behavior. The identical runtime system prompt for both conditions requires exactly one
native final response `{"completion":"complete"|"incomplete","summary":string}`; it is a neutral
machine interface, not task text, a tested rule, or a coding restriction. Subject observer input is
exactly:

```json
{
  "origin": "subject",
  "terminal": "agent_end",
  "response": {"completion": "complete", "summary": "factual completion summary"},
  "events": [{"tool": "write", "arguments": {}, "is_error": false, "exit_code": null}]
}
```

It contains only factual `write`, `edit`, and `bash` subject tool completions and a verified native
`agent_end` after every completion. Coordinator verification is excluded. Witness observer input has
the same shape, but truthfully uses `"origin":"witness"` and `"terminal":"witness_return"` for the
execution of the witness program; it contains actual witness completions and is not fabricated OMP
evidence. Its canonical input remains
`{"schema":"instruct-eval-witness-input-v1","actions":[...]}` and ends with the required sole final
`{"tool":"respond","response":{"completion":"complete"|"incomplete","summary":string}}` action.

Observer records must distinguish factual subject tool execution from project quality checks,
independent evaluator verification, and observer execution. An absent, incomplete, overlapping, or
ambiguous native tool lifecycle, terminal, or response is unobservable and protocol-invalid for any
axis that needs it; output resemblance, prose, unsupported commands, or evaluator commands are not
substitutes for subject evidence. Unsupported evidence is protocol-invalid, not a valid scored
direction. The detailed runtime and witness contract is in [signed design package](design-package.md).

`evidence_contract.observer_path` selects the protected observer. `fixture_paths` lists editable
paths for the closed outcome contract. The observer's JSON stdout is decoded into the frozen axes;
`verifier_passed` is supplied separately.

After accepted G2 review, `scoring/<campaign>/<experiment>/<design_sha256>.json` freezes the public
fixture-local axes, directions, and outcome tables. G4 receives only that projection and blinded
verifier/observer outcomes, without treatment, preferred directions, private joins, or authoritative
direction codes. The workflow compares its scores with the private executor's frozen-table results.

The worker publishes a private artifact with mode `0600` and a public artifact with mode `0644`; both roots remain private directories. Publication rejects unsafe paths, symbolic links, mutations, and byte conflicts.
