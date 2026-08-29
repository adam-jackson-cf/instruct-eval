"""Fail-closed immutable domain model for the instruct-eval protocol."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import product
from types import MappingProxyType
from typing import Any

import rfc8785


class ProtocolError(ValueError):
    """Raised when a protocol object is malformed or semantically unscoreable."""


def _canonical_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def canonical_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(_canonical_value(value))
    except (TypeError, ValueError, OverflowError) as error:
        raise ProtocolError("value is not RFC 8785 canonicalizable") from error


def canonical_hash(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{label} must be a nonempty string")


def _digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ProtocolError(f"{label} must be a lowercase SHA-256 digest")


def _utf8_boundaries(source: str) -> set[int]:
    boundaries, offset = {0}, 0
    for character in source:
        offset += len(character.encode("utf-8"))
        boundaries.add(offset)
    return boundaries


def _utf8_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError(f"{label} must be UTF-8 text")
    encoded = value.encode("utf-8")
    if not encoded:
        raise ProtocolError(f"{label} must be nonempty")
    return encoded


def _exact_mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProtocolError(f"{label} fields are not exact")
    return value


def _freeze(value: Mapping[str, Any], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolError(f"{label} must be a mapping")
    try:
        canonical_bytes(value)
    except ProtocolError:
        raise ProtocolError(f"{label} must be canonical JSON") from None
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class SourceCoverage:
    start_byte: int
    end_byte: int
    classification: str
    owner: str | None = None
    consumers: tuple[str, ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.start_byte, int)
            or not isinstance(self.end_byte, int)
            or self.start_byte < 0
            or self.end_byte <= self.start_byte
        ):
            raise ProtocolError("coverage span must be a nonempty byte range")
        if self.classification == "claim_normative":
            _identifier(self.owner, "normative owner")  # type: ignore[arg-type]
            if self.consumers or self.reason is not None:
                raise ProtocolError("normative coverage has only an owner")
        elif self.classification == "shared_context":
            if (
                self.owner is not None
                or self.reason is not None
                or not self.consumers
                or len(set(self.consumers)) != len(self.consumers)
            ):
                raise ProtocolError("shared context requires unique ordered consumers only")
            for consumer in self.consumers:
                _identifier(consumer, "shared consumer")
        elif self.classification == "non_normative":
            if (
                self.owner is not None
                or self.consumers
                or self.reason not in {"separator", "formatting", "descriptive_context"}
            ):
                raise ProtocolError("non-normative coverage requires one permitted reason only")
        else:
            raise ProtocolError("coverage classification is invalid")

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "classification": self.classification,
        }
        if self.owner is not None:
            result["owner"] = self.owner
        if self.consumers:
            result["consumers"] = list(self.consumers)
        if self.reason is not None:
            result["reason"] = self.reason
        return result


@dataclass(frozen=True, slots=True)
class ProvisionalGroup:
    group_id: str
    triggering_event: str
    preferred_behavior: str
    competing_behaviors: tuple[str, ...]
    observable_evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.group_id, "group id")
        _identifier(self.triggering_event, "triggering event")
        _identifier(self.preferred_behavior, "preferred behavior")
        if (
            not self.competing_behaviors
            or not self.observable_evidence
            or len(set(self.competing_behaviors)) != len(self.competing_behaviors)
            or len(set(self.observable_evidence)) != len(self.observable_evidence)
        ):
            raise ProtocolError("group requires unique competing behaviors and observable evidence")


@dataclass(frozen=True, slots=True)
class TreatmentSpec:
    claim_id: str
    spans: tuple[tuple[int, int], ...]
    exact_instruction: str
    schema: str = field(default="instruct-eval-treatment-v1", init=False)

    def __post_init__(self) -> None:
        _identifier(self.claim_id, "claim id")
        if not self.spans or any(
            not isinstance(span, tuple) or len(span) != 2 for span in self.spans
        ):
            raise ProtocolError("treatment requires spans")

    def payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
            "spans": [list(s) for s in self.spans],
            "exact_instruction": self.exact_instruction,
        }

    @property
    def hash(self) -> str:
        return canonical_hash(self.payload())


@dataclass(frozen=True, slots=True)
class BehavioralClaim:
    claim_id: str
    triggering_event: str
    preferred_behavior: str
    competing_behaviors: tuple[str, ...]
    observable_evidence: tuple[str, ...]
    treatment_hash: str
    schema: str = field(default="instruct-eval-claim-v1", init=False)

    def __post_init__(self) -> None:
        _identifier(self.claim_id, "claim id")
        _identifier(self.triggering_event, "triggering event")
        _identifier(self.preferred_behavior, "preferred behavior")
        if not self.competing_behaviors or not self.observable_evidence:
            raise ProtocolError("claim requires competing behaviors and observable evidence")
        _digest(self.treatment_hash, "treatment hash")

    def payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
            "triggering_event": self.triggering_event,
            "preferred_behavior": self.preferred_behavior,
            "competing_behaviors": list(self.competing_behaviors),
            "observable_evidence": list(self.observable_evidence),
            "treatment_hash": self.treatment_hash,
        }

    @property
    def hash(self) -> str:
        return canonical_hash(self.payload())


def derive_claims(
    source: str, groups: Sequence[ProvisionalGroup], coverage: Sequence[SourceCoverage]
) -> tuple[tuple[BehavioralClaim, ...], tuple[TreatmentSpec, ...], tuple[SourceCoverage, ...]]:
    if not isinstance(source, str):
        raise ProtocolError("source instruction must be text")
    if not groups or len({g.group_id for g in groups}) != len(groups):
        raise ProtocolError("provisional groups must be nonempty and unique")
    if not coverage:
        raise ProtocolError("source coverage is required")
    expected_length, boundaries, cursor = len(source.encode()), _utf8_boundaries(source), 0
    ordered = sorted(coverage, key=lambda item: item.start_byte)
    group_ids = {group.group_id for group in groups}
    owner_start: dict[str, int] = {}
    for item in ordered:
        if (
            item.start_byte != cursor
            or item.end_byte > expected_length
            or item.start_byte not in boundaries
            or item.end_byte not in boundaries
        ):
            raise ProtocolError("coverage must form a UTF-8-boundary partition")
        cursor = item.end_byte
        refs = ((item.owner,) if item.owner else ()) + item.consumers
        if any(ref not in group_ids for ref in refs):
            raise ProtocolError("coverage references an unknown provisional group")
        if item.owner is not None:
            owner_start[item.owner] = min(
                owner_start.get(item.owner, item.start_byte), item.start_byte
            )
    if cursor != expected_length or set(owner_start) != group_ids:
        raise ProtocolError(
            "each group must own normative coverage and all bytes must be classified"
        )
    ranked = sorted(groups, key=lambda g: owner_start[g.group_id])
    if len({owner_start[g.group_id] for g in ranked}) != len(ranked):
        raise ProtocolError("provisional group ownership ties are invalid")
    ids = {g.group_id: f"claim-{i:04d}" for i, g in enumerate(ranked, 1)}
    canonical_coverage = tuple(
        SourceCoverage(
            x.start_byte,
            x.end_byte,
            x.classification,
            ids[x.owner] if x.owner else None,
            tuple(ids[c] for c in x.consumers),
            x.reason,
        )
        for x in ordered
    )
    treatments = tuple(
        derive_treatment(source, ids[g.group_id], canonical_coverage) for g in ranked
    )
    by_id = {t.claim_id: t for t in treatments}
    return (
        tuple(
            BehavioralClaim(
                ids[g.group_id],
                g.triggering_event,
                g.preferred_behavior,
                g.competing_behaviors,
                g.observable_evidence,
                by_id[ids[g.group_id]].hash,
            )
            for g in ranked
        ),
        treatments,
        canonical_coverage,
    )


def derive_treatment(
    source: str, claim_id: str, coverage: Sequence[SourceCoverage]
) -> TreatmentSpec:
    _identifier(claim_id, "claim id")
    raw = source.encode()
    spans = tuple(
        (x.start_byte, x.end_byte)
        for x in coverage
        if x.owner == claim_id or claim_id in x.consumers
    )
    if not spans:
        raise ProtocolError("claim has no treatment coverage")
    try:
        text = b"".join(raw[a:b] for a, b in spans).decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ProtocolError("treatment is not valid UTF-8") from error
    return TreatmentSpec(claim_id, spans, text)


@dataclass(frozen=True, slots=True)
class EvidenceAxis:
    name: str
    values: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.name, "axis name")
        if (
            not self.values
            or len(set(self.values)) != len(self.values)
            or any(not isinstance(x, str) or not x for x in self.values)
        ):
            raise ProtocolError("axis values must be unique nonempty strings")


@dataclass(frozen=True, slots=True)
class Direction:
    code: str
    description: str

    def __post_init__(self) -> None:
        _identifier(self.code, "direction code")
        _identifier(self.description, "direction description")


@dataclass(frozen=True, slots=True)
class Verifier:
    source: bytes
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, bytes) or not self.source:
            raise ProtocolError("verifier source must be nonempty bytes")
        _digest(self.sha256, "verifier hash")
        if sha256(self.source).hexdigest() != self.sha256:
            raise ProtocolError("verifier source hash does not match")


@dataclass(frozen=True, slots=True)
class SourceClassification:
    source_sha256: str
    coverage: tuple[SourceCoverage, ...]

    def __post_init__(self) -> None:
        _digest(self.source_sha256, "source classification hash")
        if not self.coverage:
            raise ProtocolError("source classification requires coverage")

    def payload(self) -> dict[str, Any]:
        return {
            "source_sha256": self.source_sha256,
            "coverage": [item.as_json() for item in self.coverage],
        }

    @property
    def hash(self) -> str:
        return canonical_hash(self.payload())

    @classmethod
    def from_payload(cls, payload: Any) -> SourceClassification:
        value = _exact_mapping(
            payload,
            {"source_sha256", "coverage"},
            "source classification",
        )
        coverage = value["coverage"]
        if not isinstance(coverage, list):
            raise ProtocolError("source classification coverage must be a list")
        parsed: list[SourceCoverage] = []
        for raw in coverage:
            if not isinstance(raw, Mapping):
                raise ProtocolError("source coverage must be an object")
            required = {"start_byte", "end_byte", "classification"}
            optional = {"owner", "consumers", "reason"}
            if not required <= set(raw) or set(raw) - required - optional:
                raise ProtocolError("source coverage fields are not exact")
            consumers = raw.get("consumers", [])
            if not isinstance(consumers, list):
                raise ProtocolError("source coverage consumers must be a list")
            parsed.append(
                SourceCoverage(
                    raw["start_byte"],
                    raw["end_byte"],
                    raw["classification"],
                    raw.get("owner"),
                    tuple(consumers),
                    raw.get("reason"),
                )
            )
        return cls(value["source_sha256"], tuple(parsed))


@dataclass(frozen=True, slots=True)
class AdversaryDecision:
    accepted: bool
    packet_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, bool):
            raise ProtocolError("adversary decision must be boolean")
        _digest(self.packet_sha256, "adversary packet hash")


@dataclass(frozen=True, slots=True)
class ReachabilityWitness:
    witness_id: str
    direction_code: str
    input_bytes: bytes
    expected_verifier_passed: bool
    expected_observer: tuple[tuple[str, str], ...]
    expected_evidence_sha256: str
    expected_tool_hashes: tuple[tuple[str, str], ...]
    expected_unchanged_hashes: tuple[tuple[str, str], ...]
    expected_changed_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.witness_id, "witness id")
        _identifier(self.direction_code, "witness direction")
        if not isinstance(self.input_bytes, bytes) or not isinstance(
            self.expected_verifier_passed, bool
        ):
            raise ProtocolError("witness contract is malformed")
        for pairs, label in (
            (self.expected_observer, "observer"),
            (self.expected_tool_hashes, "tool hashes"),
            (self.expected_unchanged_hashes, "unchanged hashes"),
        ):
            if not pairs or len({k for k, _ in pairs}) != len(pairs):
                raise ProtocolError(f"witness {label} must be nonempty and unique")
            for key, digest in pairs:
                _identifier(key, f"witness {label} key")
                _digest(digest, f"witness {label}") if label != "observer" else _identifier(
                    digest, "observer value"
                )
        _digest(self.expected_evidence_sha256, "witness evidence hash")


@dataclass(frozen=True, slots=True)
class WitnessExecutionResult:
    unchanged_hashes: Mapping[str, str]
    changed_paths: tuple[str, ...]
    protocol_valid: bool
    contaminated: bool
    verifier_passed: bool
    observer_output: Mapping[str, Any]
    evidence_sha256: str
    tool_hashes: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "unchanged_hashes", _freeze(self.unchanged_hashes, "unchanged hashes")
        )
        object.__setattr__(
            self, "observer_output", _freeze(self.observer_output, "observer output")
        )
        object.__setattr__(self, "tool_hashes", _freeze(self.tool_hashes, "tool hashes"))
        if (
            not isinstance(self.protocol_valid, bool)
            or not isinstance(self.contaminated, bool)
            or not isinstance(self.verifier_passed, bool)
        ):
            raise ProtocolError("execution booleans are malformed")
        _digest(self.evidence_sha256, "execution evidence hash")
        for values, label in (
            (self.unchanged_hashes, "unchanged hash"),
            (self.tool_hashes, "tool hash"),
        ):
            if not values:
                raise ProtocolError(f"{label}s are required")
            for key, digest in values.items():
                _identifier(key, label)
                _digest(digest, label)

    def payload(self) -> dict[str, Any]:
        return {
            "unchanged_hashes": self.unchanged_hashes,
            "changed_paths": list(self.changed_paths),
            "protocol_valid": self.protocol_valid,
            "contaminated": self.contaminated,
            "verifier_passed": self.verifier_passed,
            "observer_output": self.observer_output,
            "evidence_sha256": self.evidence_sha256,
            "tool_hashes": self.tool_hashes,
        }


@dataclass(frozen=True, slots=True)
class ObservedOutcome:
    fixture_id: str
    verifier_passed: bool
    axis_values: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Fixture:
    fixture_id: str
    task: str
    manifest: Mapping[str, Any]
    manifest_sha256: str
    verifier: Verifier
    observe_source: bytes
    observe_sha256: str
    expected_verifier_results: Mapping[str, bool]
    axes: tuple[EvidenceAxis, ...]
    directions: tuple[Direction, ...]
    outcome_table: Mapping[tuple[Any, ...], str]
    allowed_changed_paths: tuple[str, ...]
    witnesses: tuple[ReachabilityWitness, ...]
    evidence_contract: Mapping[str, Any]
    source_classification: SourceClassification

    def __post_init__(self) -> None:
        _identifier(self.fixture_id, "fixture id")
        _identifier(self.task, "fixture task")
        manifest_hash = canonical_hash(self.manifest)
        object.__setattr__(self, "manifest", _freeze(self.manifest, "manifest"))
        object.__setattr__(
            self, "evidence_contract", _freeze(self.evidence_contract, "evidence contract")
        )
        object.__setattr__(
            self,
            "expected_verifier_results",
            _freeze(self.expected_verifier_results, "expected verifier results"),
        )
        object.__setattr__(self, "outcome_table", MappingProxyType(dict(self.outcome_table)))
        _digest(self.manifest_sha256, "fixture manifest hash")
        _digest(self.observe_sha256, "observer hash")
        if (
            manifest_hash != self.manifest_sha256
            or not isinstance(self.observe_source, bytes)
            or sha256(self.observe_source).hexdigest() != self.observe_sha256
        ):
            raise ProtocolError("fixture frozen artifact hash does not match")
        if not isinstance(self.source_classification, SourceClassification):
            raise ProtocolError("fixture source classification is required")
        if not self.evidence_contract:
            raise ProtocolError("fixture evidence contract is required")

    def payload(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "task": self.task,
            "manifest": self.manifest,
            "manifest_sha256": self.manifest_sha256,
            "verifier": {
                "source": self.verifier.source.decode("utf-8", "strict"),
                "sha256": self.verifier.sha256,
            },
            "observer": {
                "source": self.observe_source.decode("utf-8", "strict"),
                "sha256": self.observe_sha256,
            },
            "expected_verifier_results": self.expected_verifier_results,
            "axes": [{"name": axis.name, "values": list(axis.values)} for axis in self.axes],
            "directions": [
                {"code": direction.code, "description": direction.description}
                for direction in self.directions
            ],
            "outcome_table": [
                {"outcome": list(key), "direction": value}
                for key, value in sorted(
                    self.outcome_table.items(), key=lambda item: canonical_bytes(list(item[0]))
                )
            ],
            "allowed_changed_paths": list(self.allowed_changed_paths),
            "witnesses": [
                {
                    "witness_id": witness.witness_id,
                    "direction_code": witness.direction_code,
                    "input": witness.input_bytes.decode("utf-8", "strict"),
                    "expected_verifier_passed": witness.expected_verifier_passed,
                    "expected_observer": list(witness.expected_observer),
                    "expected_evidence_sha256": witness.expected_evidence_sha256,
                    "expected_tool_hashes": list(witness.expected_tool_hashes),
                    "expected_unchanged_hashes": list(witness.expected_unchanged_hashes),
                    "expected_changed_paths": list(witness.expected_changed_paths),
                }
                for witness in self.witnesses
            ],
            "evidence_contract": self.evidence_contract,
            "source_classification": self.source_classification.payload(),
        }

    @classmethod
    def from_payload(cls, payload: Any) -> Fixture:
        value = _exact_mapping(
            payload,
            {
                "fixture_id",
                "task",
                "manifest",
                "manifest_sha256",
                "verifier",
                "observer",
                "expected_verifier_results",
                "axes",
                "directions",
                "outcome_table",
                "allowed_changed_paths",
                "witnesses",
                "evidence_contract",
                "source_classification",
            },
            "fixture",
        )
        verifier = _exact_mapping(value["verifier"], {"source", "sha256"}, "verifier")
        observer = _exact_mapping(value["observer"], {"source", "sha256"}, "observer")
        axes = value["axes"]
        directions = value["directions"]
        rows = value["outcome_table"]
        changed = value["allowed_changed_paths"]
        witnesses = value["witnesses"]
        if not all(isinstance(item, list) for item in (axes, directions, rows, changed, witnesses)):
            raise ProtocolError("fixture collections must be lists")
        parsed_axes = tuple(
            EvidenceAxis(
                item["name"],
                tuple(item["values"]) if isinstance(item.get("values"), list) else (),
            )
            for item in (_exact_mapping(raw, {"name", "values"}, "evidence axis") for raw in axes)
        )
        parsed_directions = tuple(
            Direction(item["code"], item["description"])
            for item in (
                _exact_mapping(raw, {"code", "description"}, "direction") for raw in directions
            )
        )
        table: dict[tuple[Any, ...], str] = {}
        for raw in rows:
            item = _exact_mapping(raw, {"outcome", "direction"}, "outcome row")
            if not isinstance(item["outcome"], list):
                raise ProtocolError("outcome row must contain a list")
            key = tuple(item["outcome"])
            if key in table:
                raise ProtocolError("outcome rows must be unique")
            table[key] = item["direction"]
        parsed_witnesses: list[ReachabilityWitness] = []
        witness_fields = {
            "witness_id",
            "direction_code",
            "input",
            "expected_verifier_passed",
            "expected_observer",
            "expected_evidence_sha256",
            "expected_tool_hashes",
            "expected_unchanged_hashes",
            "expected_changed_paths",
        }
        for raw in witnesses:
            item = _exact_mapping(raw, witness_fields, "witness")
            pairs = []
            for field_name in (
                "expected_observer",
                "expected_tool_hashes",
                "expected_unchanged_hashes",
            ):
                raw_pairs = item[field_name]
                if not isinstance(raw_pairs, (list, tuple)) or any(
                    not isinstance(pair, (list, tuple)) or len(pair) != 2 for pair in raw_pairs
                ):
                    raise ProtocolError(f"{field_name} must be key-value pairs")
                pairs.append(tuple((pair[0], pair[1]) for pair in raw_pairs))
            if not isinstance(item["expected_changed_paths"], list):
                raise ProtocolError("expected changed paths must be a list")
            parsed_witnesses.append(
                ReachabilityWitness(
                    item["witness_id"],
                    item["direction_code"],
                    _utf8_bytes(item["input"], "witness input"),
                    item["expected_verifier_passed"],
                    pairs[0],
                    item["expected_evidence_sha256"],
                    pairs[1],
                    pairs[2],
                    tuple(item["expected_changed_paths"]),
                )
            )
        return cls(
            value["fixture_id"],
            value["task"],
            value["manifest"],
            value["manifest_sha256"],
            Verifier(_utf8_bytes(verifier["source"], "verifier source"), verifier["sha256"]),
            _utf8_bytes(observer["source"], "observer source"),
            observer["sha256"],
            value["expected_verifier_results"],
            parsed_axes,
            parsed_directions,
            table,
            tuple(changed),
            tuple(parsed_witnesses),
            value["evidence_contract"],
            SourceClassification.from_payload(value["source_classification"]),
        )


@dataclass(frozen=True, slots=True)
class ExperimentDesign:
    fixtures: tuple[Fixture, ...]

    def __post_init__(self) -> None:
        if len(self.fixtures) != 3 or len({x.fixture_id for x in self.fixtures}) != 3:
            raise ProtocolError("design requires exactly three unique fixture packages")

    def payload(self) -> dict[str, Any]:
        return {"fixtures": [fixture.payload() for fixture in self.fixtures]}

    @property
    def hash(self) -> str:
        return canonical_hash(self.payload())

    @classmethod
    def from_payload(cls, payload: Any) -> ExperimentDesign:
        value = _exact_mapping(payload, {"fixtures"}, "experiment design")
        fixtures = value["fixtures"]
        if not isinstance(fixtures, list):
            raise ProtocolError("experiment design fixtures must be a list")
        return cls(tuple(Fixture.from_payload(item) for item in fixtures))


def adversary_packet_hash(
    design: ExperimentDesign, source_classification: SourceClassification
) -> str:
    return canonical_hash(
        {
            "schema": "instruct-eval-adversary-packet-v1",
            "design_sha256": design.hash,
            "source_classification_sha256": source_classification.hash,
        }
    )


def validate_adversary_decision(
    design: ExperimentDesign,
    source_classification: SourceClassification,
    decision: AdversaryDecision,
) -> None:
    if (
        not isinstance(decision, AdversaryDecision)
        or not decision.accepted
        or decision.packet_sha256 != adversary_packet_hash(design, source_classification)
    ):
        raise ProtocolError(
            "G2 requires an accepted adversary decision for the exact design and "
            "source-classification packet"
        )


def construct_outcome_tuple(
    design: ExperimentDesign,
    fixture_id: str,
    verifier_passed: bool,
    observer_output: Mapping[str, Any],
    *,
    protocol_valid: bool = True,
) -> ObservedOutcome:
    fixture = next((x for x in design.fixtures if x.fixture_id == fixture_id), None)
    if fixture is None:
        raise ProtocolError("unknown fixture")
    if not protocol_valid:
        raise ProtocolError("protocol-invalid execution is not scoreable")
    if not isinstance(verifier_passed, bool):
        raise ProtocolError("verifier result must be boolean")
    if (
        not isinstance(observer_output, Mapping)
        or "verifier_passed" in observer_output
        or set(observer_output) != {x.name for x in fixture.axes}
    ):
        raise ProtocolError(
            "observer output must contain exactly declared axes and never verifier_passed"
        )
    values = tuple(observer_output[x.name] for x in fixture.axes)
    if any(value not in axis.values for value, axis in zip(values, fixture.axes, strict=True)):
        raise ProtocolError("observer output contains an undeclared enum value")
    return ObservedOutcome(fixture_id, verifier_passed, values)


def _validate_fixture_shape(fixture: Fixture) -> tuple[set[str], set[tuple[Any, ...]]]:
    if (
        not fixture.axes
        or len({axis.name for axis in fixture.axes}) != len(fixture.axes)
        or not fixture.directions
        or len({direction.code for direction in fixture.directions}) != len(fixture.directions)
    ):
        raise ProtocolError("fixture axes and directions must be nonempty and unique")
    states = set(product((False, True), *(axis.values for axis in fixture.axes)))
    if len(states) > 256:
        raise ProtocolError("fixture outcome state space exceeds 256")
    codes = {direction.code for direction in fixture.directions}
    if (
        set(fixture.outcome_table) != states
        or any(code not in codes for code in fixture.outcome_table.values())
        or set(fixture.outcome_table.values()) != codes
    ):
        raise ProtocolError("fixture outcome table must be finite, total, and direction-complete")
    witness_ids = {witness.witness_id for witness in fixture.witnesses}
    if (
        not fixture.witnesses
        or len(witness_ids) != len(fixture.witnesses)
        or set(fixture.expected_verifier_results) != witness_ids
    ):
        raise ProtocolError("fixture witnesses and expected verifier results must match exactly")
    if any(not isinstance(value, bool) for value in fixture.expected_verifier_results.values()):
        raise ProtocolError("expected verifier results must be booleans")
    if any(
        not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/")
        for path in fixture.allowed_changed_paths
    ):
        raise ProtocolError("allowed changed paths are unsafe")
    return codes, states


def _expected_witness_outcome(
    design: ExperimentDesign,
    fixture: Fixture,
    witness: ReachabilityWitness,
    codes: set[str],
) -> ObservedOutcome:
    if (
        witness.direction_code not in codes
        or witness.expected_verifier_passed != fixture.expected_verifier_results[witness.witness_id]
    ):
        raise ProtocolError("witness direction or verifier expectation is invalid")
    expected = construct_outcome_tuple(
        design,
        fixture.fixture_id,
        witness.expected_verifier_passed,
        dict(witness.expected_observer),
    )
    state = (expected.verifier_passed, *expected.axis_values)
    if fixture.outcome_table.get(state) != witness.direction_code:
        raise ProtocolError("witness does not reach its declared direction")
    return expected


def _validate_witness_execution(
    design: ExperimentDesign,
    fixture: Fixture,
    witness: ReachabilityWitness,
    expected: ObservedOutcome,
    witness_executor: Callable[[Fixture, ReachabilityWitness], WitnessExecutionResult],
) -> None:
    actual = witness_executor(fixture, witness)
    unsafe_paths = set(actual.changed_paths) - set(fixture.allowed_changed_paths)
    if not actual.protocol_valid or actual.contaminated or unsafe_paths:
        raise ProtocolError("witness execution violates the protocol or changed-path policy")
    frozen_artifacts = (
        dict(witness.expected_unchanged_hashes),
        dict(witness.expected_tool_hashes),
        witness.expected_changed_paths,
        witness.expected_evidence_sha256,
    )
    actual_artifacts = (
        dict(actual.unchanged_hashes),
        dict(actual.tool_hashes),
        actual.changed_paths,
        actual.evidence_sha256,
    )
    if frozen_artifacts != actual_artifacts:
        raise ProtocolError("witness execution differs from frozen artifacts")
    observed = construct_outcome_tuple(
        design,
        fixture.fixture_id,
        actual.verifier_passed,
        actual.observer_output,
        protocol_valid=actual.protocol_valid,
    )
    if observed != expected:
        raise ProtocolError("witness verifier or observer output differs from frozen contract")


def validate_experiment_design(
    design: ExperimentDesign,
    witness_executor: Callable[[Fixture, ReachabilityWitness], WitnessExecutionResult]
    | None = None,
) -> None:
    for fixture in design.fixtures:
        codes, _states = _validate_fixture_shape(fixture)
        witnessed: set[str] = set()
        for witness in fixture.witnesses:
            expected = _expected_witness_outcome(design, fixture, witness, codes)
            if witness_executor is not None:
                _validate_witness_execution(design, fixture, witness, expected, witness_executor)
            witnessed.add(witness.direction_code)
        if witnessed != codes:
            raise ProtocolError("a declared direction is unreachable by witnesses")
