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
