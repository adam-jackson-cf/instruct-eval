---
name: "share-evaluation-results"
description: "Explain completed evaluation experiments in decision-ready language. USE WHEN you have conducted an experiment and are sharing the results with the user."
---

# Guidance

## Required Output Template

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

## Interpretation Requirements

- Lead with the decision; never require the reader to infer it from counts.
- Define the control as behavior without the instruction and the treatment as behavior with the instruction.
- Translate numeric differences into behavioral meaning.
- Explain why negative-control behavior matters when a negative control was run.
- Use `Inconclusive` and recommend `Rerun` when evidence does not support a directional decision.

## Evidence Boundaries

- Separate observed evidence from inference.
- State what the experiment shows and what it does not show with equal specificity.
- Never claim effectiveness beyond the tested scenarios, runtime, model, or protocol.
- Report protocol failures, missing trials, scorer disagreement, and non-production orchestration as limitations rather than smoothing them into a positive result.

## Presentation

- Use ordinary language before protocol terminology.
- Keep runtime evidence high-level unless the user asks for raw artifacts.
- Use a table only when it makes the without-instruction and with-instruction difference easier to scan.
- Prefer direct sentences such as `The instruction was effective in these scenarios because ...`.
