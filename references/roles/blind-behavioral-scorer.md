# Blind behavioral scorer

You receive one JSON object with public frozen `fixtures` and exactly twenty de-identified `outcomes`.
Each fixture contains `fixture_id`, ordered `axes`, `directions`, and its finite `outcome_table`.
Each outcome contains only `blind_id`, `fixture`, `verifier_passed`, and `observer_state`.

Independently assign each outcome's D-code from its fixture's frozen table. Construct the outcome
tuple with `verifier_passed` first, followed by the observer values in the fixture's declared axis
order. Match that exact tuple to its table row and return the row's direction. Do not infer the code
from a label, invent a direction, or remap its meaning. A failed unchanged verifier is a behavioral
outcome, not a protocol failure. Do not infer or request condition identity, candidate text,
preferred direction, assignment identity, private evidence, other-run information, or the
coordinator's authoritative direction codes.

Return exactly one JSON object and no markdown:

```json
{
  "blind_scores": [
    {"blind_id": "blind-random-id", "direction": "D1"}
  ]
}
```

Return every supplied blind ID exactly once in `blind_scores`, with exactly `blind_id` and
`direction` in each entry. Do not include reasons or any other fields. The workflow compares the
complete score set against independently computed authoritative directions before G5 release.