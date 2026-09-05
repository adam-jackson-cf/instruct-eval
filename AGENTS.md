# Repository guidance

## Documentation ownership

- `README.md` explains the repository's purpose, runtime architecture, operator prerequisites, and
  production usage.
- `AGENTS.md` defines developer guidance, implementation invariants, experiment workflow rules, and
  repository verification.
- `references/gate-transitions.md`, `references/design-package.md`,
  `references/artifact-layout.md`, and `references/artifact-routing.md` are the canonical workflow,
  design, and boundary contracts.
- `references/roles/` contains production runtime role contracts. Do not treat those files as
  operator documentation or move them without updating their production loader.
- Keep each concept in its owning document. Link to canonical text instead of establishing a second
  operational convention.

## Architecture rules

- Preserve `ExperimentCampaignWorkflow` as the sole campaign workflow and
  `InstructionExperimentWorkflow` as the sole authorized-claim workflow.
- Temporal owns assignment, orchestration, retries, recovery, and durable recording. Filesystem and
  subject isolation belong to the runtime boundary, not Temporal.
- Keep public workflows and public Activities on `instruct-eval-public`. Keep private Activities,
  private maps, subject material, treatment material, authority data, and evidence keys on
  `instruct-eval-private`.
- Keep the subject execution path canonical:
  `Temporal → RuntimeSubjectExecutor → run_subject → execute_omp`.
- Never invoke `omp` directly for a scored subject or create another condition-isolation path.
- Condition A is the instruction-free control. Remove `candidate_instruction` at `run_subject`
  before preparing its runtime request or prompt.
- Condition B receives only the claim-specific treatment. Reject a missing or empty treatment.
- `execute_omp` owns the fresh `HOME`, fresh `OMP_HOME`, unique profile, disabled ambient OMP
  discovery, loopback credential gateway, and macOS sandbox.
- Treat treatment material in a condition-A request, prompt, captured context, or other evidenced
  input-side leakage as control contamination. Treatment-like text in an output is an experimental
  outcome; interpret it through the frozen behavioral scorer and do not infer leakage from output
  alone.
- Keep inclusion or recall evidence separate from behavioral-effect evidence.

## Experiment development workflow

Use this section as an ordered index. Before performing a step, read its linked references. Those
references own detailed behavior and boundaries; implementation models own exact wire schemas.

### Step 1: Freeze and decompose

Freeze the campaign inputs and produce the complete canonical claim decomposition.

- Read: [instruction decomposer](references/roles/instruction-decomposer.md) and
  [instruction/behavior analyst](references/roles/instruction-behavior-analyst.md).
- Exit: the immutable campaign fingerprint and complete decomposition package are ready for private
  staging.

### Step 2: Design fixtures and evidence

Produce the condition-independent experiment design and reachable witness set for every claim.

- Read: [signed design package](references/design-package.md),
  [scenario/fixture designer](references/roles/scenario-fixture-designer.md), and
  [artifact layout](references/artifact-layout.md).
- Exit: the complete design package and its hashes are ready for signing and private staging.

### Step 3: Establish runtime boundaries

Provision the production runtime and verify the public/private capability split before creating
campaign state.

- Read: [artifact routing](references/artifact-routing.md) and
  [artifact layout](references/artifact-layout.md).
- Exit: both workers and durable stores satisfy the referenced routing and storage contracts.

### Step 4: Authorize decomposition

Stage the signed decomposition, start or adopt the campaign, and complete campaign-level
authorization.

- Read: [Temporal campaign lifecycle](references/gate-transitions.md),
  [instruction decomposer](references/roles/instruction-decomposer.md), and
  [artifact routing](references/artifact-routing.md).
- Exit: the campaign has created the authorized claim workflows.

### Step 5: Submit and validate each design

Stage each signed design, submit it at G0, and let G1 and G2 perform the referenced commit, witness,
and adversarial validation.

- Read: [Temporal campaign lifecycle](references/gate-transitions.md),
  [signed design package](references/design-package.md),
  [scenario/fixture designer](references/roles/scenario-fixture-designer.md), and
  [oracle/validity adversary](references/roles/oracle-validity-adversary.md).
- Exit: the claim workflow requests `approve_freeze`.

### Step 6: Freeze and execute

Approve the validated design and let G3 execute the frozen private trial schedule.

- Read: [Temporal campaign lifecycle](references/gate-transitions.md) and
  [artifact routing](references/artifact-routing.md).
- Exit: G3 has accepted the complete protocol-valid trial set.

### Step 7: Score, release, and decide

Let G4 score blinded outcomes, G5 release the private join, and G6 record the bounded result.

- Read: [blind behavioral scorer](references/roles/blind-behavioral-scorer.md),
  [evidence/statistical analyst](references/roles/evidence-statistical-analyst.md), and
  [Temporal campaign lifecycle](references/gate-transitions.md).
- Exit: the workflow has recorded its terminal result.

### Step 8: Inspect or recover

Inspect released public evidence or resume an interrupted workflow without creating an alternate
replay path.

- Read: [artifact layout](references/artifact-layout.md),
  [artifact routing](references/artifact-routing.md), and
  [Temporal campaign lifecycle](references/gate-transitions.md).
- Exit: the evidence supports a bounded result or the unresolved prerequisite is reported.

## Reference use rules

- Treat each linked reference and implementation model as the source of truth for its contract. Do
  not copy low-level fields, schemas, packet shapes, or transition rules into `AGENTS.md`.
- Read all references linked by a step before changing or running that part of the experiment.
- If implementation and reference disagree, stop and resolve the contract mismatch instead of
  creating a second convention.
- Keep operator commands and configuration examples in `README.md`; keep implementation guidance
  and repository rules here.

## Developer workflow

- Run commands from the repository root.
- Use the locked Python 3.13.7 uv environment:

  ```sh
  uv sync --locked
  ```

- Reuse existing models, Activities, workflow states, and runtime boundaries. Do not create parallel
  schemas, orchestration paths, isolation layers, or artifact conventions.
- Before changing an exported symbol, inspect every reference and migrate every caller in the same
  change.
- Expand existing behavioral scenarios for missing coverage; do not add regression tests that only
  encode one discovered value.
- Verify focused behavior while developing. Before handoff, run the sole repository quality gate:

  ```sh
  bash scripts/run-ci-quality-gates.sh
  ```

- The quality gate must pass without disabling checks, changing tests to conceal failures, or using
  skip flags.
