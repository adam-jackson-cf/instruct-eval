# Evaluation result reporting

Use this contract only after G5 has released the private assignment/condition join and G6 has
recorded the terminal protocol result. Work only from released public workflow status and published
`artifact_root` evidence. Do not inspect private artifacts, private databases, authority data,
subject material, treatment mappings, or evidence keys.

The report explains the immutable protocol result; it does not rescore outcomes, change the G6
result, or create a new authorization decision. If the released evidence is incomplete,
protocol-invalid, or does not support a directional conclusion, report `Inconclusive` and recommend
`Rerun`.

## Required output template

- Begin with `## Evaluation Result`.
- Write `**Instruction tested:**` followed by the exact instruction.
- Write `**Conclusion:** Effective in tested scenarios | Ineffective in tested scenarios | Inconclusive` and explain the conclusion in plain language.
- Write `**Recommendation:** Keep | Revise | Remove | Rerun` followed by one sentence stating why.
- Add `## What the instruction is meant to change`; explain the intended behavioral rule and why it matters.
- Add `## Results at a glance`; show a compact table with scenario, without-instruction result, with-instruction result, and interpretation, then report protocol-valid trials, negative-control behavior, and terminal authorization or result.
- Add `## What the experiment shows`; state the concrete supported behavior and connect it to observed evidence.
- Add `## What the experiment does not show`; state scope boundaries, untested contexts, and orchestration limitations.
- Add `## Runtime evidence`; summarize model and runtime, trial count, isolation, concurrency, verifier or scorer behavior, and orchestration coverage.
- Add `## Recommendation`; explain the decision, confidence supported by the experiment, and the next action.

## Interpretation requirements

- Lead with the decision; never require the reader to infer it from counts.
- Define the control as behavior without the instruction and the treatment as behavior with the instruction.
- Translate numeric differences into behavioral meaning.
- Report the canonical allocation as ten controls and ten treatments: four A and four B in each
  core fixture, and two A and two B in the negative control.
- Preserve the frozen G6 rule: `preferred_count_B_strictly_greater_than_A` for each core fixture
  and `all_subjects_match_preferred_direction` for all four negative-control subjects. A valid
  non-authorization is a terminal result, not a protocol failure.
- Explain why negative-control behavior matters when a negative control was run.
- Preserve the G6 result and frozen directional rule. Human-facing interpretation must not override either one.
- Distinguish a stale failure retained from an earlier run from a current failure in the immutable
  result: a stale historical failure does not establish a current failure, and a current failure
  must be reported with its actual evidence.
- State separately whether project quality checks passed and whether independent evaluator
  verification passed; neither is subject evidence or a substitute for the other.
- Treat unsupported evidence as protocol-invalid, never as a valid scored direction.
- Use `Inconclusive` and recommend `Rerun` when evidence does not support a directional decision.

## Evidence boundaries

- Separate observed evidence from inference.
- State what the experiment shows and what it does not show with equal specificity.
- Never claim effectiveness beyond the tested scenarios, runtime, model, or protocol.
- Never treat instruction inclusion or recall as behavioral-effect evidence.
- Treat verified native context loading as inclusion evidence only. Do not describe it, matching
  output, a model's recall, or evaluator/verifier/observer activity as proof that the instruction
  changed subject behavior.
- Describe an axis as unobservable or protocol-invalid when the released evidence lacks a complete,
  unambiguous subject tool lifecycle, native terminal, or final response; do not fill that gap with
  inferred commands or a favorable interpretation. Completion withheld is the recorded
  `{"completion":"incomplete","summary":string}` decision, not an inferred declaration or
  automatically a violation.
- Report protocol failures, missing trials, scorer disagreement, unreachable required table tuples,
  and non-production orchestration as limitations rather than smoothing them into a positive result.
  Every table tuple and every direction requires executable reachability; a direction with a witness
  is insufficient if a tuple remains unreachable.

## Presentation

- Use ordinary language before protocol terminology.
- Keep runtime evidence high-level unless the user asks for raw public artifacts.
- Use a table only when it makes the without-instruction and with-instruction difference easier to scan.
- Prefer direct sentences such as `The instruction was effective in these scenarios because ...`.
