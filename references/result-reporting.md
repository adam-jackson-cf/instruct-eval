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
- Explain why negative-control behavior matters when a negative control was run.
- Preserve the G6 result and frozen directional rule. Human-facing interpretation must not override either one.
- Use `Inconclusive` and recommend `Rerun` when evidence does not support a directional decision.

## Evidence boundaries

- Separate observed evidence from inference.
- State what the experiment shows and what it does not show with equal specificity.
- Never claim effectiveness beyond the tested scenarios, runtime, model, or protocol.
- Never treat instruction inclusion or recall as behavioral-effect evidence.
- Report protocol failures, missing trials, scorer disagreement, and non-production orchestration as limitations rather than smoothing them into a positive result.

## Presentation

- Use ordinary language before protocol terminology.
- Keep runtime evidence high-level unless the user asks for raw public artifacts.
- Use a table only when it makes the without-instruction and with-instruction difference easier to scan.
- Prefer direct sentences such as `The instruction was effective in these scenarios because ...`.
