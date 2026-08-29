```markdown
---
name: "python-conventions"
description: "Guide Python naming, package structure, and code-object choices. USE WHEN writing or refactoring Python code."
---

# Guidance

Complements Ruff `pep8-naming`; does not replace deterministic lint checks.

## Names

- Use precise domain names over generic names such as `manager`, `helper`, `utils`, `data`, `thing`, or `processor`.
- Name functions and methods by the action or question they perform.
- Name classes by the role or concept they model, not by implementation mechanics.
- Name protocols by the capability they require.
- Name modules and packages after cohesive responsibilities, not mixed tool buckets.

## Package Structure

- Keep folders grouped by responsibility and import boundary, not by incidental file type.
- Add a new package only when it owns a stable concept, API boundary, or workflow slice.
- Avoid catch-all directories unless the repo already has a specific established convention for them.

## Object Choice

- Start with a function for stateless behavior.
- Use a class when state and behavior belong together, lifecycle matters, or polymorphism is needed.
- Use a dataclass for structured data carriers with annotated fields.
- Use a Protocol for structural contracts across implementations.
- Use an Enum for a closed symbolic set.
- Do not create a god class to centralize unrelated workflows.

```
