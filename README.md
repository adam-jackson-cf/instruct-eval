# instruct-eval

`instruct-eval` runs instruction-evaluation campaigns as canonical Temporal workflows. Operators use the locked uv environment, a provisioned Temporal CLI v1.8.2 service, and the pinned loopback namespace `instruct-eval`.

## Operator path

1. From the repository root, run `uv sync --locked`.
2. Provision the CLI and start the loopback service with an absolute persistent SQLite path:

   ```sh
   uv run python -c 'from instruct_eval.provision import provision_temporal_cli; print(provision_temporal_cli("/absolute/path/to/bin/temporal"))'
   /absolute/path/to/bin/temporal server start-dev --ip 127.0.0.1 --namespace instruct-eval --db-filename /absolute/path/to/state/temporal.sqlite
   ```

3. Start two permission-separated workers with absolute, regular JSON configurations that are not group- or world-readable:

   ```sh
   uv run python -m instruct_eval.production_worker public /absolute/path/to/public.json
   uv run python -m instruct_eval.production_worker private /absolute/path/to/private.json
   ```

   Public mode owns `instruct-eval-public` workflows and public Activities. Private mode owns only `instruct-eval-private` Activities.

4. Start or adopt a campaign, inspect it, and submit only a canonical signed Update:

   ```sh
   uv run instruct-eval --address 127.0.0.1:7233 start \
     --campaign-id campaign-01234567890123456789012345678901 \
     --model-identity MODEL --runtime-identity RUNTIME \
     --coverage-sha256 64-LOWERCASE-HEX-DIGEST \
     --public-input-json '{"candidate_instruction":"Follow repository instructions exactly.","permissions":{"filesystem":"workspace"},"repository":{"root":"/absolute/path/to/repository"},"fixture_manifest_hash":"64-lowercase-hex-digest","operator_public_key":"BASE64URL-ENCODED-32-BYTE-ED25519-PUBLIC-KEY"}'
   uv run instruct-eval --address 127.0.0.1:7233 status \
     --workflow-id campaign-01234567890123456789012345678901
   uv run instruct-eval --address 127.0.0.1:7233 update \
     --workflow-id campaign-01234567890123456789012345678901 \
     --wire-json '{"payload":{"campaign_id":"campaign-01234567890123456789012345678901","target_kind":"campaign","target_id":"campaign-01234567890123456789012345678901","action":"approve_decomposition","proposal_hash":"64-lowercase-hex-digest","expected_revision_hash":"64-lowercase-hex-digest","sequence":1},"signature":"BASE64URL-ED25519-SIGNATURE"}'
   ```

The package does not provide an operator signing command. A signed decision wire from the campaign principal is required; unsigned or altered decisions fail.

## Persistent configuration and boundaries

`public.json` has exactly `temporal_address`, `artifact_root`, `coordination_db`, and `role_request`. `private.json` has exactly `temporal_address`, `artifact_root`, `private_artifact_root`, `coordination_db`, `private_map_db`, `authority_artifact`, `fixture_roots`, `subject_request`, `evidence_key_hex`, `fixture_paths`, and `role_request`. `artifact_root`, `coordination_db`, `private_artifact_root`, and `private_map_db` must be absolute. `authority_artifact` is a nonempty private-root-relative path, and `evidence_key_hex` decodes to 32 bytes. Both `role_request` values, and the private fixture and subject fields, must be the actual protocol inputs.

The public worker has no private activities or private capabilities. The private worker owns the private-map store, authority record, subject inputs, evidence key, and G5 release. Public workflow history, public packets, and `artifact_root` contain no private assignment or condition joins; the private store performs that join only for G5 release.
The signed design uses the complete joint package documented in
[`SKILL.md`](SKILL.md#stage-the-complete-design-package). G1, G2, and freeze re-resolve that same
private staged package; G2 executes every frozen witness against the configured fixture roots before
one adversary decision for the exact packet.


Private roots and SQLite state must remain outside campaign artifact directories. Published public evidence is read from `artifact_root`; private roots and databases are not inspection inputs.

## Recovery and quality

Restart verification relaunches both unchanged worker-mode commands, then queries campaign `status`. Temporal replays workflow history during recovery; this package exposes no separate production replay command.

Run the sole quality-gate command from the repository root:

```sh
bash scripts/run-ci-quality-gates.sh
```

The runner verifies pre-commit/CI parity, syncs the locked development environment, checks Ruff
formatting and lint rules, runs strict mypy analysis, and executes the pytest suite. The local
`quality-gates` pre-commit hook invokes the same runner with `--fix --stage`; CI invokes it in
check-only mode.

See [artifact layout](references/artifact-layout.md), [artifact routing](references/artifact-routing.md), and [workflow lifecycle](references/gate-transitions.md).