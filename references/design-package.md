# Signed design package

The signed `DesignProposal.design` has exactly `experiment_design` and
`preferred_directions`. `DesignProposal.design_hash` covers that complete joint package. Every G1,
G2, and freeze request binds the same proposal hash and G0 record hash. Those Activities run on
`instruct-eval-private` because they re-resolve the signed private staging record.

`experiment_design` has exactly three fixture packages named `core-1`, `core-2`, and
`negative-control`. Each fixture owns its task; complete manifest and hash; verifier source and hash;
observer source and hash; expected verifier results; ordered finite axes; fixture-local directions;
total outcome table; changed-path allowlist; witnesses; evidence contract; and complete source
classification. The source classification hash and byte partition must match the signed
decomposition.

Each fixture manifest has exactly this shape:

```json
{
  "schema": "instruct-eval-fixture-manifest-v1",
  "files": [
    {"path": "relative/path", "sha256": "64-lowercase-hex-digest"}
  ],
  "public_files": {"relative/path": "exact UTF-8 file contents"}
}
```

`public_files` binds each published UTF-8 source string to its existing `files` SHA-256.
Publish the applicable project gate instructions and implementation when their execution is
measured, so G2 can establish the passing criteria. An empty mapping is valid where no additional
public criteria apply.

Each evidence contract has exactly this shape:

```json
{
  "schema": "instruct-eval-evidence-contract-v1",
  "verifier_path": "verify.py",
  "observer_path": "observe.py",
  "verifier_command": ["python3", "verify.py"],
  "observer_command": ["python3", "observe.py"],
  "observation_contract": {
    "subject_origin": "subject",
    "subject_terminal": "agent_end",
    "witness_origin": "witness",
    "witness_terminal": "witness_return",
    "tool_events": ["write", "edit", "bash"],
    "changed_paths": "actual_file_content_changes",
    "gate_snapshots": "actual_file_content_changes_since_gate_start",
    "mutating_tool_execution": "serialized",
    "terminal_order": "after_all_tool_completions",
    "completion": {
      "field": "completion",
      "values": ["complete", "incomplete"]
    },
    "coordinator_verification": "excluded"
  }
}
```

`observation_contract` is required and has exactly the shown value.

Each witness `input` is UTF-8 canonical JSON with exactly this shape:

```json
{
  "schema": "instruct-eval-witness-input-v1",
  "actions": [
    {"tool": "write", "path": "allowed/relative/path", "content": "replacement text or null"},
    {"tool": "bash", "command": "a non-empty command"},
    {
      "tool": "respond",
      "response": {"completion": "complete", "summary": "factual completion summary"}
    }
  ]
}
```

`actions` is an ordered, factual execution sequence. A `write` has exactly `tool`, `path`, and
`content`; its relative allowed path is sandbox-checked, `content` is a string or `null`, and
repeated writes are permitted. A `bash` has exactly `tool` and non-empty `command`; it executes in
the witness sandbox. `respond` is required exactly once, is the final action, has exactly `tool` and
`response`, and terminates witness execution; no following action is allowed. Its `response` has
exactly `completion` and `summary`, where `completion` is `complete` or `incomplete` and `summary`
is a string. The coordinator runs every action through `respond`, then passes the observer the
complete witness observation envelope:

```json
{
  "origin": "witness",
  "terminal": "witness_return",
  "response": {"completion": "complete", "summary": "factual completion summary"},
  "events": [{"tool": "write", "arguments": {}, "is_error": false, "exit_code": null, "changed_paths": ["relative/path"]}]
}
```

The envelope contains only actual witness `write`, `edit`, and `bash` completions. It does not
synthesize OMP events or infer subject commands from prose or `verify.py`.

Subject runtime evidence is collected from one native OMP process. Both A and B receive the
identical runtime system prompt, which requires exactly one final JSON object
`{"completion":"complete"|"incomplete","summary":string}` with no extra or duplicate keys. This is
a neutral shared runtime machine interface, not task text, a tested rule, or a coding restriction.
Before that process receives the fixture task, it receives RPC `get_state`; the returned
`systemPrompt` must contain exactly B's workspace `.omp/AGENTS.md` treatment file or no context
file for A, and `dumpTools` must equal the frozen `read`, `edit`, `write`, `glob`, `grep`, and
`bash` set. Only after this check does that same process receive the identical `TASK.txt` prompt for
A and B. Before task submission, context verification establishes B's trusted input pair as the canonical absolute workspace `.omp/AGENTS.md` path and its exact treatment text. Disclosure projection is permitted only for a successful native `read` whose unique call ID has a preceding genuine `tool_execution_start` with `toolName: "read"` and whose same-call `tool_execution_end` has `isError: false`, `toolName: "read"`, `result.content == [{"type":"text","text":treatment}]`, `result.details.displayContent.text == treatment`, `result.details.meta.source.type == "path"` with the exact canonical input path, `fileSize` equal to the treatment UTF-8 byte length, and `totalLines`, `displayContent.startLine`, and `displayContent.lineNumbers` describing the whole input. No normalization, substring removal, global replacement, generic path whitelist, or inferred provenance is permitted. Only the matching `content[0].text` and `details.displayContent.text` become `[verified runtime input]` in `tool_execution_end.result`, `toolResult` `message_start` and `message_end` messages, `turn_end.toolResults[]`, and `agent_end.messages[]`; every copy independently satisfies the same metadata/content contract and has `role: "toolResult"`, `toolName: "read"`, `isError: false`, and the proven call ID. All other fields and channels—including assistant echoes, arguments, diffs, stderr, Bash output, unsupported reads, and altered reads—remain verbatim. Raw `tool_outputs` remain verbatim; the derived disclosure outputs are scanned once as a single concatenated normalized stream.
The native stream's paired `tool_execution_start`/`tool_execution_end`
records bind subject `write`, `edit`, and `bash` observer events. Start records supply
arguments; completion records supply error state and bash exit status. A trusted native hook,
loaded from outside both writable mounts, measures actual file contents through native approval
events. Identical subject profiles set `tools.approval` to `prompt` for `write`, `edit`, and `bash`.
The RPC coordinator queues native approval dialogs outside capped extension handlers and sends
only one `Approve` at a time. Trusted `tool_approval_requested` metadata and the ensuing approved
`tool_approval_resolved` event bind that response to its actual native call ID; dialog titles and
preparation order do not establish that join. The synchronous approved resolution measures contents
before execution, and `tool_result` measures them afterward, including errors. Both the matching
observation and `tool_execution_end` must arrive before the next approval. Requests may be batched;
native registration, arguments, task text, treatment, and tool definitions remain unchanged.
Mismatches cancel pending dialogs, abort execution, and retain actual captured evidence as invalid.
Tool-free roles do not use subject admission control. Native `notify`, `setStatus`, `setWidget`,
`setTitle`, and `set_editor_text` notifications remain captured but require no approval response.
No provider scheduling flag or preparation-time wait establishes serialization. During an active
serialized `bash`, its bound loopback gate endpoint
accepts only `{"script":"check.py"}` and snapshots actual workspace contents before acknowledging;
each resulting `gate_snapshots` entry records the sorted paths that differ between that gate-start
snapshot and the Bash-end snapshot. Gate requests outside an active Bash, malformed or unbounded
gate evidence, and missing measurements invalidate the observation. Trusted observer completion
order defines normalized event order; native completion delivery may be reordered. Its explicitly
`runtime_observer`-origin readiness, correlated `changed_paths`, and `gate_snapshots` measurements
share the existing RPC stream; they are not subject assertions or fabricated native tool events.
Readiness means the gate endpoint is bound and must be verified before task submission. Missing,
duplicate, mismatched, or malformed measurements are invalid. A verified native `agent_end`
follows every subject tool completion and carries the exact final response:

```json
{
  "origin": "subject",
  "terminal": "agent_end",
  "response": {"completion": "complete", "summary": "factual completion summary"},
  "events": [{"tool": "edit", "arguments": {}, "is_error": false, "exit_code": null, "changed_paths": ["relative/path"], "gate_snapshots": []}]
}
```

The subject envelope contains only actual subject tool completions and this terminal native response;
coordinator verification is excluded. Under pinned OMP 18.1.10, a completed foreground bash result
with explicit non-error status, `wallTimeMs`, and `timeoutSeconds` or `timeoutDisabled`, but no
`exitCode`, establishes exit code zero; timeout, async, missing, ambiguous completion, ambiguous
terminal, or ambiguous response evidence is rejected rather than guessed.

`changed_paths` is the sorted list of files whose contents differ across the tool boundary.
`gate_snapshots` is empty for `write` and `edit`; for `bash` it is the ordered list of
`{"script":"check.py","changed_paths":[...]}` source-state measurements from actual protected gate
callbacks. Witness actions use the same before/after measurement semantics. A failed tool can
partially apply changes, and a successful write can leave identical bytes; neither attempted paths
nor error status establish mutation. Snapshots retain the existing workspace evidence bound and
reject symlinks and unsupported entries. When freshness is measured, only actual relevant changes
advance it; a measured gate that itself changes relevant source is invalid.

G2 copies the configured fixture root, verifies every manifest byte, executes the witness actions
or subject runtime as applicable, runs the frozen verifier and observer, and compares changed paths,
protected hashes, executable hashes, evidence hash, verifier result, observer output, observation
envelope, and witness contract. Project quality checks and independent evaluator verification are
separate evidence sources: evaluator verification is excluded from the subject envelope. The private
adversary receives one complete packet containing the canonical claim, exact treatment, G0 analyst
assessment, condition-independent experiment design, source classifications, and every actual
witness result. Its returned `packet_sha256` must match the exact supplied packet.
