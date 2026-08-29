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

The worker publishes a private artifact with mode `0600` and a public artifact with mode `0644`; both roots remain private directories. Publication rejects unsafe paths, symbolic links, mutations, and byte conflicts.
