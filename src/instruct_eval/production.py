"""Concrete, fail-closed production adapters for instruct-eval activities."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any

from temporalio import activity
from temporalio.client import Client

from . import role_runtime
from .activities import ActivityRequest, ActivitySemanticError, GatePublication, ReleasePublication
from .artifacts import ArtifactMode, ArtifactStore, canonical_bytes
from .coordination import (
    ClaimedChildAuthorizationRequest,
    CoordinationError,
    CoordinationStore,
    PublishedDecisionRequest,
)
from .messages import ProposalControl, PublishDecisionRequest, request_fingerprint
from .models import (
    ExperimentDesign,
    ProtocolError,
    SourceClassification,
    SourceCoverage,
    WitnessExecutionResult,
    canonical_hash,
    construct_outcome_tuple,
    derive_treatment,
    validate_experiment_design,
)
from .signing import (
    DecisionWire,
    DecompositionProposal,
    DesignProposal,
    DesignProposalValidationParameters,
    StageAttestation,
    load_public_key,
    principal_id,
    validate_decomposition_proposal,
    validate_design_proposal,
)
from .trials import (
    ASSIGNMENT_IDS,
    ClosedOutcomeParams,
    PrivateAssignment,
    TrialProtocolError,
    closed_outcome,
    g6_authorized,
    scan_disclosure,
)
from .worker import (
    PRIVATE_TASK_QUEUE,
    PUBLIC_TASK_QUEUE,
    TEMPORAL_NAMESPACE,
    ActivityBackendRequest,
    DomainOperations,
    InstructEvalActivityBackend,
    PrivateAuthorityResolver,
    PrivateMapAuthority,
    create_private_worker,
    create_public_worker,
    run_workers,
)

_ROLE_ROOT = Path(__file__).resolve().parents[2] / "references" / "roles"
_ROLE_FOR_OPERATION = MappingProxyType(
    {
        "decomposition": "instruction-decomposer.md",
        "eligibility": "instruction-behavior-analyst.md",
        "design_draft": "experiment-designer.md",
        "pre_run_validity": "oracle-validity-adversary.md",
        "evidence_audit": "blind-behavioral-scorer.md",
        "analysis": "evidence-statistical-analyst.md",
    }
)
_GATE_OPERATIONS = frozenset(
    {
        "design_commit",
        "g0_commit",
        "pre_run_validity",
        "freeze",
        "execution_commit",
        "post_run_validity",
        "release",
        "analysis",
        "terminal_commit",
    }
)
_CLAIM_FIELDS = frozenset(
    {
        "schema",
        "claim_id",
        "triggering_event",
        "preferred_behavior",
        "competing_behaviors",
        "observable_evidence",
        "treatment_hash",
        "coverage_sha256",
    }
)


class ProductionConfigurationError(RuntimeError):
    """A production configuration would make protocol execution ambiguous."""


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProductionConfigurationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _public(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or key.lower().replace("-", "_") in {
                "treatment",
                "token",
                "private",
            }:
                raise ProtocolError("private data cannot enter a public operation")
            _public(child)
    elif isinstance(value, (tuple, list)):
        for child in value:
            _public(child)
    elif not isinstance(value, (str, int, float, bool, type(None))):
        raise ProtocolError("public operation output is not canonical JSON")


def _gate(name: str, result: Mapping[str, Any], artifacts: ArtifactStore) -> GatePublication:
    immutable = json.loads(canonical_bytes(result))
    artifact = canonical_bytes(immutable)
    digest = sha256(artifact).hexdigest()
    relative = f"public/gates/{name}/sha256/{digest}.json"
    artifacts.publish_bytes(relative, artifact, ArtifactMode.PUBLIC)
    return GatePublication(
        immutable,
        artifacts.path_for(relative, ArtifactMode.PUBLIC),
        artifact,
        digest,
    )


def _role_output(
    name: str,
    payload: Mapping[str, Any],
    runtime: Any,
    role_request: Mapping[str, Any],
) -> Mapping[str, Any]:
    contract = _ROLE_ROOT / _ROLE_FOR_OPERATION[name]
    if not contract.is_file() or contract.is_symlink():
        raise ProductionConfigurationError("role contract is unavailable")
    result = runtime.invoke_role(contract, payload, role_request)
    if not isinstance(result, Mapping):
        raise ProtocolError("role returned malformed output")
    public_result = dict(result)
    _public(public_result)
    return public_result


def _exact_hashes(payload: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(payload) != fields:
        raise ProtocolError(f"{label} payload is not exact")
    for field_name in fields:
        if field_name.endswith("_sha256"):
            _digest(payload[field_name], field_name.replace("_", " "))


def _blind_scores(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != 10:
        raise ProtocolError("scorer must return exactly ten blind scores")
    scores: list[dict[str, str]] = []
    blind_ids: set[str] = set()
    for score in value:
        if (
            not isinstance(score, Mapping)
            or set(score) != {"blind_id", "direction"}
            or not isinstance(score["blind_id"], str)
            or not score["blind_id"]
            or not isinstance(score["direction"], str)
            or not score["direction"]
            or score["blind_id"] in blind_ids
        ):
            raise ProtocolError("scorer blind score is malformed")
        blind_ids.add(score["blind_id"])
        scores.append({"blind_id": score["blind_id"], "direction": score["direction"]})
    return scores


def _proposal_packet(payload: Mapping[str, Any]) -> tuple[set[str], str, int]:
    required = {
        "wire",
        "workflow_id",
        "run_id",
        "prior_decision_sha256",
        "target_kind",
        "target_id",
        "action",
        "proposal_hash",
        "expected_revision_sha256",
        "sequence",
        "owner_public_key",
    }
    payload_fields = set(payload)
    if payload_fields not in (required, required | {"request_fingerprint"}) or not isinstance(
        payload["wire"], Mapping
    ):
        raise ProtocolError("proposal decision requires an exact signed workflow packet")
    sequence = payload["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ProtocolError("proposal decision sequence is invalid")
    prior = _digest(payload["prior_decision_sha256"], "prior decision hash")
    if sequence == 1 and prior != "0" * 64:
        raise ProtocolError("first proposal decision must have a zero prior hash")
    identities = (
        "workflow_id",
        "run_id",
        "target_kind",
        "target_id",
        "action",
        "expected_revision_sha256",
        "owner_public_key",
    )
    if any(not isinstance(payload[name], str) or not payload[name] for name in identities):
        raise ProtocolError("proposal decision identity is invalid")
    proposal_hash = payload["proposal_hash"]
    if proposal_hash is not None:
        _digest(proposal_hash, "proposal hash")
    return payload_fields, prior, sequence


def _decomposition_projection(
    request: ActivityRequest,
    payload: Mapping[str, Any],
    fields: set[str],
    owner_key: Any,
) -> Mapping[str, Any]:
    proposal_hash = payload["proposal_hash"]
    if (
        proposal_hash is None
        or "request_fingerprint" not in fields
        or not isinstance(payload["request_fingerprint"], str)
    ):
        raise ProtocolError("decomposition approval requires the authoritative request fingerprint")
    _digest(payload["request_fingerprint"], "request fingerprint")
    record = json.loads(
        payload["artifacts"].read_bytes(
            f"control/proposals/sha256/{proposal_hash}/record.json",
            ArtifactMode.PRIVATE,
        )
    )
    if (
        not isinstance(record, Mapping)
        or set(record) != {"schema", "owner_principal", "proposal"}
        or record["schema"] != "instruct-eval-staged-decomposition-v1"
        or record["owner_principal"] != principal_id(owner_key)
    ):
        raise ProtocolError("staged decomposition is malformed")
    proposal = DecompositionProposal.from_json(record["proposal"])
    validate_decomposition_proposal(
        proposal,
        campaign_id=request.campaign_id,
        request_fingerprint=payload["request_fingerprint"],
        proposal_hash=proposal_hash,
    )
    return {"proposal_sha256": proposal_hash, "claims": proposal.ordered_claims}


def _design_projection(
    request: ActivityRequest,
    payload: Mapping[str, Any],
    owner_key: Any,
) -> Mapping[str, Any]:
    proposal_hash = payload["proposal_hash"]
    if proposal_hash is None:
        raise ProtocolError("design submission requires a staged proposal")
    record = json.loads(
        payload["artifacts"].read_bytes(
            f"control/proposals/sha256/{proposal_hash}/record.json",
            ArtifactMode.PRIVATE,
        )
    )
    if (
        not isinstance(record, Mapping)
        or set(record) != {"schema", "owner_principal", "proposal", "attestation"}
        or record["schema"] != "instruct-eval-staged-design-v1"
        or record["owner_principal"] != principal_id(owner_key)
    ):
        raise ProtocolError("staged design is malformed")
    proposal = DesignProposal.from_json(record["proposal"])
    attestation = StageAttestation.from_json(record["attestation"])
    validate_design_proposal(
        proposal,
        attestation,
        owner_key,
        DesignProposalValidationParameters(
            campaign_id=request.campaign_id,
            claim_hash=proposal.claim_hash,
            g0_commit_hash=proposal.g0_commit_hash,
            treatment_hash=proposal.treatment_hash,
            fixture_manifest_hash=proposal.fixture_manifest_hash,
            proposal_hash=proposal_hash,
            design_hash=proposal.design_hash,
        ),
    )
    return {"proposal_sha256": proposal_hash, "design_sha256": proposal.design_hash}


def _proposal_decision(
    request: ActivityRequest,
    payload: Mapping[str, Any],
    artifacts: ArtifactStore,
    coordination: CoordinationStore,
) -> Mapping[str, Any]:
    fields, prior, sequence = _proposal_packet(payload)
    private_payload = dict(payload)
    private_payload["artifacts"] = artifacts
    try:
        owner_key = load_public_key(payload["owner_public_key"])
        projection: Mapping[str, Any] = {}
        if payload["action"] == "approve_decomposition":
            projection = _decomposition_projection(
                request,
                private_payload,
                fields,
                owner_key,
            )
        elif payload["action"] == "submit_design":
            projection = _design_projection(request, private_payload, owner_key)
    except (OSError, ValueError, TypeError) as error:
        raise ProtocolError("staged owner-private proposal is unavailable or invalid") from error
    published = ProposalControl(artifacts, coordination).publish_decision(
        PublishDecisionRequest(
            owner_public_key=payload["owner_public_key"],
            wire=payload["wire"],
            workflow_id=payload["workflow_id"],
            run_id=payload["run_id"],
            prior_record_hash=prior,
            campaign_id=request.campaign_id,
            target_kind=payload["target_kind"],
            target_id=payload["target_id"],
            action=payload["action"],
            proposal_hash=payload["proposal_hash"],
            expected_revision_hash=_digest(
                payload["expected_revision_sha256"],
                "expected revision hash",
            ),
            sequence=sequence,
        )
    )
    result = {
        "accepted": True,
        "decision_sha256": published.decision_sha256,
        "decision_artifact_sha256": published.decision_artifact_sha256,
        "decision_artifact_path": str(published.decision_artifact_path),
        **projection,
    }
    _public(result)
    return result


def _source_partition(
    candidate_instruction: str,
    coverage: Sequence[SourceCoverage],
    error_type: type[Exception],
) -> None:
    raw_source = candidate_instruction.encode()
    boundaries = {
        len(candidate_instruction[:index].encode())
        for index in range(len(candidate_instruction) + 1)
    }
    cursor = 0
    for item in coverage:
        if (
            item.start_byte != cursor
            or item.end_byte > len(raw_source)
            or item.start_byte not in boundaries
            or item.end_byte not in boundaries
        ):
            raise error_type("decomposition coverage is not a source partition")
        cursor = item.end_byte
    if cursor != len(raw_source):
        raise error_type("decomposition coverage is not a source partition")


def _bound_claim(
    claims: Sequence[Any],
    claim_sha256: str,
    coverage_sha256: str,
    error_type: type[Exception],
) -> Mapping[str, Any]:
    matching = [
        item
        for item in claims
        if isinstance(item, Mapping) and canonical_hash(dict(item)) == claim_sha256
    ]
    if len(matching) != 1:
        raise error_type("claimed child does not bind one decomposition claim")
    claim = matching[0]
    if (
        set(claim) != _CLAIM_FIELDS
        or claim["schema"] != "instruct-eval-claim-v1"
        or claim["coverage_sha256"] != coverage_sha256
    ):
        raise error_type("decomposition claim is malformed")
    return claim


def _activity_execution_identity() -> tuple[str, str]:
    execution = activity.info()
    workflow_id = execution.workflow_id
    run_id = execution.workflow_run_id
    if (
        not isinstance(workflow_id, str)
        or not workflow_id
        or not isinstance(run_id, str)
        or not run_id
    ):
        raise ProtocolError("activity execution identity is unavailable")
    return workflow_id, run_id


def _claim_context(
    request: ActivityRequest,
    candidate_instruction: str,
    artifacts: ArtifactStore,
    coordination: CoordinationStore,
) -> tuple[Mapping[str, Any], Any, SourceClassification, str]:
    workflow_id, run_id = _activity_execution_identity()
    claimed = coordination.claimed_child_authorization(
        ClaimedChildAuthorizationRequest(
            campaign_id=request.campaign_id,
            experiment_id=request.experiment_id,
            child_workflow_id=workflow_id,
            child_run_id=run_id,
        )
    )
    decision = coordination.published_decision(
        PublishedDecisionRequest(
            workflow_id=claimed.parent_workflow_id,
            run_id=claimed.parent_run_id,
            target_kind="campaign",
            target_id=request.campaign_id,
            sequence=1,
        )
    )
    if decision.publication_sha256 is None:
        raise ProtocolError("signed decomposition decision is unavailable")
    wire = DecisionWire.from_json(
        json.loads(
            artifacts.read_bytes(
                f"public/decisions/sha256/{decision.publication_sha256}.json",
                ArtifactMode.PUBLIC,
            )
        )
    )
    if (
        wire.hash != decision.publication_sha256
        or wire.payload.action != "approve_decomposition"
        or wire.payload.target_kind != "campaign"
        or wire.payload.target_id != request.campaign_id
        or not isinstance(wire.payload.proposal_hash, str)
    ):
        raise ProtocolError("signed decomposition decision is not bound to this campaign")
    record = json.loads(
        artifacts.read_bytes(
            f"control/proposals/sha256/{wire.payload.proposal_hash}/record.json",
            ArtifactMode.PRIVATE,
        )
    )
    if (
        not isinstance(record, Mapping)
        or set(record) != {"schema", "owner_principal", "proposal"}
        or record["schema"] != "instruct-eval-staged-decomposition-v1"
        or not isinstance(record["owner_principal"], str)
    ):
        raise ProtocolError("staged decomposition record is malformed")
    decomposition = DecompositionProposal.from_json(record["proposal"])
    validate_decomposition_proposal(
        decomposition,
        campaign_id=request.campaign_id,
        request_fingerprint=claimed.fingerprint_sha256,
        proposal_hash=wire.payload.proposal_hash,
    )
    classification = SourceClassification.from_payload(
        {
            "source_sha256": sha256(candidate_instruction.encode()).hexdigest(),
            "coverage": decomposition.source_coverage,
        }
    )
    if (
        canonical_hash({"source_coverage": [item.as_json() for item in classification.coverage]})
        != claimed.coverage_sha256
    ):
        raise ProtocolError("decomposition coverage is not bound to the child")
    _source_partition(candidate_instruction, classification.coverage, ProtocolError)
    claim = _bound_claim(
        decomposition.ordered_claims,
        claimed.claim_sha256,
        claimed.coverage_sha256,
        ProtocolError,
    )
    treatment = derive_treatment(
        candidate_instruction,
        claim["claim_id"],
        classification.coverage,
    )
    if treatment.hash != claim["treatment_hash"]:
        raise ProtocolError("derived treatment is not bound to the child")
    return claim, treatment, classification, record["owner_principal"]


def _staged_design_input(
    payload: Mapping[str, Any],
) -> tuple[Mapping[str, Any], str, str]:
    public_input = payload.get("input")
    proposal_sha256 = payload.get("proposal_sha256")
    g0_record_sha256 = payload.get("g0_record_sha256")
    if (
        not isinstance(public_input, Mapping)
        or not isinstance(proposal_sha256, str)
        or not isinstance(g0_record_sha256, str)
        or not isinstance(public_input.get("candidate_instruction"), str)
        or not isinstance(public_input.get("fixture_manifest_hash"), str)
        or not isinstance(public_input.get("operator_public_key"), str)
    ):
        raise ProtocolError("design gate does not bind complete public input and proposal")
    _digest(proposal_sha256, "design proposal hash")
    _digest(g0_record_sha256, "G0 record hash")
    return public_input, proposal_sha256, g0_record_sha256


@dataclass(frozen=True, slots=True)
class _StagedDesignSlots:
    request: ActivityRequest
    public_input: Mapping[str, Any]
    proposal_sha256: str
    g0_record_sha256: str
    claim: Mapping[str, Any]
    treatment: Any
    owner_principal: str
    artifacts: ArtifactStore
    coordination: CoordinationStore


def _staged_design_owner_key(slots: _StagedDesignSlots) -> Any:
    workflow_id, run_id = _activity_execution_identity()
    decision = slots.coordination.published_decision(
        PublishedDecisionRequest(
            workflow_id=workflow_id,
            run_id=run_id,
            target_kind="claim",
            target_id=canonical_hash(dict(slots.claim)),
            sequence=1,
        )
    )
    if (
        decision.publication_sha256 is None
        or decision.expected_revision_sha256 != slots.g0_record_sha256
    ):
        raise ProtocolError("signed design decision is not bound to the G0 record")
    wire = DecisionWire.from_json(
        json.loads(
            slots.artifacts.read_bytes(
                f"public/decisions/sha256/{decision.publication_sha256}.json",
                ArtifactMode.PUBLIC,
            )
        )
    )
    owner_key = load_public_key(slots.public_input["operator_public_key"])
    wire.verify(owner_key)
    if (
        wire.hash != decision.publication_sha256
        or wire.payload.action != "submit_design"
        or wire.payload.target_kind != "claim"
        or wire.payload.target_id != canonical_hash(dict(slots.claim))
        or wire.payload.proposal_hash != slots.proposal_sha256
        or wire.payload.expected_revision_hash != slots.g0_record_sha256
    ):
        raise ProtocolError("signed design decision is not bound to this child gate")
    return owner_key


def _staged_design_proposal(
    slots: _StagedDesignSlots,
    owner_key: Any,
) -> DesignProposal:
    record = json.loads(
        slots.artifacts.read_bytes(
            f"control/proposals/sha256/{slots.proposal_sha256}/record.json",
            ArtifactMode.PRIVATE,
        )
    )
    if (
        not isinstance(record, Mapping)
        or set(record) != {"schema", "owner_principal", "proposal", "attestation"}
        or record["schema"] != "instruct-eval-staged-design-v1"
        or record["owner_principal"] != slots.owner_principal
        or record["owner_principal"] != principal_id(owner_key)
    ):
        raise ProtocolError("staged design record is malformed")
    proposal = DesignProposal.from_json(record["proposal"])
    attestation = StageAttestation.from_json(record["attestation"])
    validate_design_proposal(
        proposal,
        attestation,
        owner_key,
        DesignProposalValidationParameters(
            campaign_id=slots.request.campaign_id,
            claim_hash=canonical_hash(dict(slots.claim)),
            g0_commit_hash=slots.g0_record_sha256,
            treatment_hash=slots.treatment.hash,
            fixture_manifest_hash=slots.public_input["fixture_manifest_hash"],
            proposal_hash=slots.proposal_sha256,
            design_hash=proposal.design_hash,
        ),
    )
    return proposal


def _staged_design_package(
    proposal: DesignProposal,
    classification: SourceClassification,
) -> tuple[ExperimentDesign, dict[str, str]]:
    package = proposal.design
    if not isinstance(package, Mapping) or set(package) != {
        "experiment_design",
        "preferred_directions",
    }:
        raise ProtocolError("staged design package fields are not exact")
    design = ExperimentDesign.from_payload(package["experiment_design"])
    if canonical_hash(package) != proposal.design_hash:
        raise ProtocolError("staged design package differs from the signed design")
    fixture_ids = {"core-1", "core-2", "negative-control"}
    if {fixture.fixture_id for fixture in design.fixtures} != fixture_ids:
        raise ProtocolError("experiment design requires the canonical three fixtures")
    if any(fixture.source_classification != classification for fixture in design.fixtures):
        raise ProtocolError("fixture source classifications differ from signed decomposition")
    manifest_hash = canonical_hash(
        {
            "fixtures": [
                {
                    "fixture_id": fixture.fixture_id,
                    "manifest_sha256": fixture.manifest_sha256,
                }
                for fixture in sorted(design.fixtures, key=lambda item: item.fixture_id)
            ],
        }
    )
    if manifest_hash != proposal.fixture_manifest_hash:
        raise ProtocolError("fixture manifests differ from the signed request")
    preferred = package["preferred_directions"]
    directions = (
        {
            direction.code
            for fixture in design.fixtures
            for direction in fixture.directions
            if preferred.get(fixture.fixture_id) == direction.code
        }
        if isinstance(preferred, Mapping)
        else set()
    )
    if not isinstance(preferred, Mapping) or set(preferred) != fixture_ids or not directions:
        raise ProtocolError("preferred directions are not bound to fixture-local directions")
    if any(
        preferred[fixture.fixture_id] not in {direction.code for direction in fixture.directions}
        for fixture in design.fixtures
    ):
        raise ProtocolError("preferred directions are not bound to fixture-local directions")
    validate_experiment_design(design)
    return design, dict(preferred)


def _staged_design(
    request: ActivityRequest,
    payload: Mapping[str, Any],
    artifacts: ArtifactStore,
    coordination: CoordinationStore,
) -> tuple[ExperimentDesign, Mapping[str, str], Mapping[str, Any], Any, DesignProposal]:
    public_input, proposal_sha256, g0_record_sha256 = _staged_design_input(payload)
    claim, treatment, classification, owner_principal = _claim_context(
        request,
        public_input["candidate_instruction"],
        artifacts,
        coordination,
    )
    slots = _StagedDesignSlots(
        request,
        public_input,
        proposal_sha256,
        g0_record_sha256,
        claim,
        treatment,
        owner_principal,
        artifacts,
        coordination,
    )
    owner_key = _staged_design_owner_key(slots)
    proposal = _staged_design_proposal(slots, owner_key)
    design, preferred = _staged_design_package(proposal, classification)
    return design, preferred, claim, treatment, proposal


@dataclass(frozen=True, slots=True)
class _OperationSlots:
    name: str
    request: ActivityRequest
    artifacts: ArtifactStore
    coordination: CoordinationStore
    runtime: Any
    role_request: Mapping[str, Any]
    fixture_roots: Mapping[str, Path]

    @property
    def payload(self) -> dict[str, Any]:
        return dict(self.request.payload)


def _fingerprint_result(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(payload) != {
        "candidate_instruction",
        "model_identity",
        "runtime_identity",
        "request",
    } or not isinstance(payload["request"], Mapping):
        raise ProtocolError("fingerprint requires exact public request identities")
    return {
        "schema": "instruct-eval-fingerprint-v1",
        "fingerprint_sha256": request_fingerprint(
            payload["request"],
            payload["model_identity"],
            payload["runtime_identity"],
        ),
    }


def _analysis_result(slots: _OperationSlots, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(payload) != {"gate", "design_sha256", "release_sha256"} or payload["gate"] != "G6":
        raise ProtocolError("G6 requires the exact release identity")
    design_sha256 = _digest(payload["design_sha256"], "design hash")
    release_sha256 = _digest(payload["release_sha256"], "release hash")
    relative = (
        f"releases/{slots.request.campaign_id}/{slots.request.experiment_id}/{release_sha256}.json"
    )
    try:
        raw = slots.artifacts.read_bytes(relative, ArtifactMode.PUBLIC)
        release = json.loads(raw)
        ReleasePublication(
            release,
            slots.artifacts.path_for(relative, ArtifactMode.PUBLIC),
            raw,
            sha256(raw).hexdigest(),
        )
        if release["release_sha256"] != release_sha256:
            raise ActivitySemanticError("G5 release identity does not match G6 request")
    except (OSError, ValueError, TypeError, ActivitySemanticError) as error:
        raise ProtocolError("G6 release is not the exact public G5 packet") from error
    return {
        "schema": "instruct-eval-g6-analysis-v1",
        "design_sha256": design_sha256,
        "release_sha256": release_sha256,
        "authorized": g6_authorized(release["assignments"], release["preferred_directions"]),
    }


def _design_commit_result(
    slots: _OperationSlots,
    payload: Mapping[str, Any],
) -> Mapping[str, Any]:
    _exact_hashes(
        payload,
        {
            "input",
            "gate",
            "design_sha256",
            "staged_design_sha256",
            "proposal_sha256",
            "g0_record_sha256",
        },
        "G1",
    )
    design, _, _, _, proposal = _staged_design(
        slots.request,
        payload,
        slots.artifacts,
        slots.coordination,
    )
    if (
        payload["gate"] != "G1"
        or payload["design_sha256"] != payload["staged_design_sha256"]
        or payload["design_sha256"] != proposal.design_hash
        or canonical_hash(proposal.design) != proposal.design_hash
    ):
        raise ProtocolError("G1 design commitment is not bound to the staged design")
    return {
        "schema": "instruct-eval-g1-design-commit-v1",
        "accepted": True,
        "design_sha256": proposal.design_hash,
        "proposal_sha256": proposal.hash,
        "experiment_design_sha256": design.hash,
    }


def _witness_executions(
    design: ExperimentDesign,
    runtime: Any,
    fixture_roots: Mapping[str, Path],
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], WitnessExecutionResult]]:
    executions: list[dict[str, Any]] = []
    by_witness: dict[tuple[str, str], WitnessExecutionResult] = {}
    for fixture in design.fixtures:
        for witness in fixture.witnesses:
            execution = runtime.run_witness(
                fixture,
                witness,
                fixture_roots[fixture.fixture_id],
            )
            by_witness[(fixture.fixture_id, witness.witness_id)] = execution
            executions.append(
                {
                    "fixture_id": fixture.fixture_id,
                    "witness_id": witness.witness_id,
                    "result": execution.payload(),
                }
            )
    return executions, by_witness


def _g0_assessment(artifacts: ArtifactStore, proposal: DesignProposal) -> Mapping[str, Any]:
    g0 = json.loads(
        artifacts.read_bytes(
            f"public/gates/g0_commit/sha256/{proposal.g0_commit_hash}.json",
            ArtifactMode.PUBLIC,
        )
    )
    eligibility = g0.get("eligibility") if isinstance(g0, Mapping) else None
    if (
        not isinstance(g0, Mapping)
        or g0.get("schema") != "instruct-eval-g0-commit-v1"
        or not isinstance(eligibility, Mapping)
    ):
        raise ProtocolError("G2 analyst assessment is unavailable")
    return eligibility


def _pre_run_review(
    slots: _OperationSlots,
    claim: Mapping[str, Any],
    treatment: Any,
    design: ExperimentDesign,
    proposal: DesignProposal,
) -> Mapping[str, Any]:
    executions, by_witness = _witness_executions(
        design,
        slots.runtime,
        slots.fixture_roots,
    )
    validate_experiment_design(
        design,
        lambda fixture, witness: by_witness[(fixture.fixture_id, witness.witness_id)],
    )
    unsigned = {
        "schema": "instruct-eval-adversary-review-packet-v1",
        "claim": claim,
        "treatment": treatment.payload(),
        "analyst_assessment": _g0_assessment(slots.artifacts, proposal),
        "experiment_design": design.payload(),
        "witness_executions": executions,
    }
    packet = {**unsigned, "packet_sha256": canonical_hash(unsigned)}
    return _role_output("pre_run_validity", packet, slots.runtime, slots.role_request)


def _pre_run_result(slots: _OperationSlots, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_hashes(
        payload,
        {"input", "gate", "design_sha256", "proposal_sha256", "g0_record_sha256"},
        "G2",
    )
    if payload["gate"] != "G2":
        raise ProtocolError("G2 gate is invalid")
    design, _, claim, treatment, proposal = _staged_design(
        slots.request,
        payload,
        slots.artifacts,
        slots.coordination,
    )
    if payload["design_sha256"] != proposal.design_hash:
        raise ProtocolError("G2 design differs from the G1 staged bytes")
    if set(slots.fixture_roots) != {fixture.fixture_id for fixture in design.fixtures}:
        raise ProtocolError("G2 fixture roots do not match the frozen design")
    review = _pre_run_review(slots, claim, treatment, design, proposal)
    if (
        set(review) != {"adversary_decision", "rejections", "stress_review"}
        or not isinstance(review["adversary_decision"], Mapping)
        or set(review["adversary_decision"]) != {"accepted", "packet_sha256"}
        or not isinstance(review["adversary_decision"]["accepted"], bool)
        or not isinstance(review["rejections"], list)
    ):
        raise ProtocolError("G2 adversary review is malformed")
    if review["adversary_decision"]["packet_sha256"] != canonical_hash(
        {
            "schema": "instruct-eval-adversary-review-packet-v1",
            "claim": claim,
            "treatment": treatment.payload(),
            "analyst_assessment": _g0_assessment(slots.artifacts, proposal),
            "experiment_design": design.payload(),
            "witness_executions": _witness_executions(
                design,
                slots.runtime,
                slots.fixture_roots,
            )[0],
        }
    ):
        raise ProtocolError("G2 adversary review is malformed")
    accepted = review["adversary_decision"]["accepted"]
    if accepted is False and not review["rejections"]:
        raise ProtocolError("G2 rejection requires concrete defects")
    return {
        "schema": "instruct-eval-g2-pre-run-validity-v1",
        "accepted": accepted,
        "design_sha256": proposal.design_hash,
        "proposal_sha256": proposal.hash,
        "experiment_design_sha256": design.hash,
        "adversary_decision": dict(review["adversary_decision"]),
        "rejections": list(review["rejections"]),
        "stress_review": review["stress_review"],
    }


def _freeze_result(slots: _OperationSlots, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_hashes(
        payload,
        {
            "input",
            "commit",
            "design_sha256",
            "proposal_sha256",
            "g0_record_sha256",
            "map_ref",
            "map_commitment",
            "tokens",
            "pre_map_input_hash",
            "authorization_rule_sha256",
            "authorization_sha256",
        },
        "freeze",
    )
    _, _, _, _, proposal = _staged_design(
        slots.request,
        payload,
        slots.artifacts,
        slots.coordination,
    )
    tokens = payload["tokens"]
    if (
        payload["commit"] != "freeze"
        or payload["design_sha256"] != proposal.design_hash
        or payload["proposal_sha256"] != proposal.hash
        or not isinstance(payload["map_ref"], str)
        or not isinstance(payload["map_commitment"], str)
        or not isinstance(tokens, (list, tuple))
        or len(tokens) != 10
        or len(set(tokens)) != 10
    ):
        raise ProtocolError("freeze commitment is malformed")
    for value in (
        payload["design_sha256"],
        payload["pre_map_input_hash"],
        payload["authorization_rule_sha256"],
        payload["authorization_sha256"],
    ):
        _digest(value, "freeze hash")
    return {
        "schema": "instruct-eval-freeze-v1",
        "accepted": True,
        "design_sha256": payload["design_sha256"],
        "proposal_sha256": proposal.hash,
        "map_ref": payload["map_ref"],
        "map_commitment": payload["map_commitment"],
        "tokens": list(tokens),
        "pre_map_input_hash": payload["pre_map_input_hash"],
        "authorization_rule_sha256": payload["authorization_rule_sha256"],
    }


def _valid_accounting(accounting: Any) -> bool:
    dispositions = {
        "result",
        "terminal",
        "canceled-before-invocation",
        "indeterminate",
        "UNSCHEDULED_DUE_TO_TERMINAL",
        "UNSCHEDULED_DUE_TO_CANCELLATION",
    }
    return (
        isinstance(accounting, (list, tuple))
        and len(accounting) == 10
        and all(
            isinstance(entry, Mapping)
            and set(entry) == {"token", "disposition"}
            and isinstance(entry["token"], str)
            and entry["disposition"] in dispositions
            for entry in accounting
        )
        and len({entry["token"] for entry in accounting}) == 10
    )


def _execution_result(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_hashes(
        payload,
        {
            "input",
            "gate",
            "design_sha256",
            "outcome_sha256s",
            "outcomes_sha256",
            "trial_accounting",
            "protocol_valid",
            "verifier_passed",
            "accepted",
        },
        "G3",
    )
    outcomes = payload["outcome_sha256s"]
    accounting = payload["trial_accounting"]
    if payload["gate"] != "G3" or not _valid_accounting(accounting):
        raise ProtocolError("G3 execution commitment is malformed")
    if (
        not isinstance(outcomes, (list, tuple))
        or len(outcomes) != sum(entry["disposition"] == "result" for entry in accounting)
        or len(set(outcomes)) != len(outcomes)
        or any(_digest(outcome, "G3 outcome hash") != outcome for outcome in outcomes)
    ):
        raise ProtocolError("G3 execution commitment is malformed")
    passed = payload["verifier_passed"]
    accepted = len(outcomes) == 10 and all(entry["disposition"] == "result" for entry in accounting)
    if (
        payload["outcomes_sha256"] != canonical_hash({"outcome_sha256s": outcomes})
        or not isinstance(payload["protocol_valid"], bool)
        or not isinstance(passed, (list, tuple))
        or len(passed) != len(outcomes)
        or any(type(value) is not bool for value in passed)
        or payload["accepted"] is not payload["protocol_valid"]
        or payload["accepted"] is not accepted
    ):
        raise ProtocolError("G3 execution commitment is malformed")
    return {
        "schema": "instruct-eval-g3-execution-commit-v1",
        "accepted": payload["accepted"],
        "design_sha256": payload["design_sha256"],
        "outcomes_sha256": payload["outcomes_sha256"],
        "trial_accounting": list(accounting),
    }


def _evidence_result(slots: _OperationSlots, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_hashes(payload, {"design_sha256", "outcomes"}, "scorer")
    if not isinstance(payload["outcomes"], list) or len(payload["outcomes"]) != 10:
        raise ProtocolError("scorer outcomes are malformed")
    scorer = _role_output("evidence_audit", payload, slots.runtime, slots.role_request)
    if set(scorer) != {"blind_scores"}:
        raise ProtocolError("scorer output is not the canonical blind_scores packet")
    return {"blind_scores": _blind_scores(scorer["blind_scores"])}


def _post_run_result(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_hashes(
        payload,
        {"gate", "evidence_sha256", "design_sha256", "blind_scores", "scorer_agrees"},
        "G4",
    )
    if payload["gate"] != "G4" or not isinstance(payload["scorer_agrees"], bool):
        raise ProtocolError("G4 gate is invalid")
    return {
        "schema": "instruct-eval-g4-post-run-validity-v1",
        "accepted": payload["scorer_agrees"],
        "design_sha256": payload["design_sha256"],
        "evidence_sha256": payload["evidence_sha256"],
        "blind_scores": _blind_scores(payload["blind_scores"]),
    }


def _terminal_result(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    _exact_hashes(payload, {"input", "terminal_gate", "reason", "prior_sha256"}, "terminal")
    reasons = {
        "DESIGN_REJECTED": frozenset(
            {
                "G0 rejected",
                "G1 rejected",
                "G2 rejected",
                "freeze binding failed",
                "authorization rejected or preempted",
            }
        ),
        "SCORING_REJECTED": frozenset({"G4 scorer disagreement"}),
        "PROTOCOL_FAILURE": frozenset(
            {
                "G3 protocol failure",
                "G6 authorization result is invalid",
                "protocol_failure",
            }
        ),
        "CANCELED": frozenset({"operator_cancelled"}),
        "AUTHORIZED": frozenset({"G6 authorized"}),
        "COMPLETED_NOT_AUTHORIZED": frozenset({"G6 completed without authorization"}),
    }
    if (
        payload["terminal_gate"] not in reasons
        or payload["reason"] not in reasons[payload["terminal_gate"]]
    ):
        raise ProtocolError("terminal commitment is malformed")
    return {
        "schema": "instruct-eval-terminal-commit-v1",
        "terminal_gate": payload["terminal_gate"],
        "reason": payload["reason"],
        "prior_sha256": payload["prior_sha256"],
    }


def _g0_result(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    if (
        set(payload) != {"gate", "eligibility", "accepted"}
        or payload["gate"] != "G0"
        or not isinstance(payload["eligibility"], Mapping)
        or payload["accepted"] is not (payload["eligibility"].get("accepted") is True)
    ):
        raise ProtocolError("G0 acceptance must derive from exact eligibility output")
    return {"schema": "instruct-eval-g0-commit-v1", **payload}


def _operation_value(slots: _OperationSlots, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    handlers: Mapping[str, Callable[[], Mapping[str, Any]]] = {
        "fingerprint": lambda: _fingerprint_result(payload),
        "proposal_decision": lambda: _proposal_decision(
            slots.request,
            payload,
            slots.artifacts,
            slots.coordination,
        ),
        "analysis": lambda: _analysis_result(slots, payload),
        "design_commit": lambda: _design_commit_result(slots, payload),
        "pre_run_validity": lambda: _pre_run_result(slots, payload),
        "freeze": lambda: _freeze_result(slots, payload),
        "execution_commit": lambda: _execution_result(payload),
        "evidence_audit": lambda: _evidence_result(slots, payload),
        "post_run_validity": lambda: _post_run_result(payload),
        "terminal_commit": lambda: _terminal_result(payload),
        "g0_commit": lambda: _g0_result(payload),
    }
    handler = handlers.get(slots.name)
    if handler is not None:
        result = handler()
        if not isinstance(result, Mapping):
            raise ProtocolError("production operation output is not canonical JSON")
        return result
    if slots.name in _ROLE_FOR_OPERATION:
        return _role_output(slots.name, payload, slots.runtime, slots.role_request)
    raise ProtocolError("production operation is unsupported")


def _operation_result(slots: _OperationSlots) -> Mapping[str, Any] | GatePublication:
    if not isinstance(slots.request, ActivityRequest):
        raise ProtocolError("operation request is malformed")
    payload = slots.payload
    _public(payload)
    result = _operation_value(slots, payload)
    if slots.name in _GATE_OPERATIONS:
        return _gate(slots.name, result, slots.artifacts)
    immutable = json.loads(canonical_bytes(result))
    if not isinstance(immutable, Mapping):
        raise ProtocolError("public operation output is not canonical JSON")
    return immutable


def concrete_domain_operations(
    role_request: Mapping[str, Any] | None = None,
    fixture_roots: Mapping[str, Path] | None = None,
) -> DomainOperations:
    """Build the complete canonical operation set without test doubles."""
    execution = MappingProxyType(dict(role_request or {}))
    roots = MappingProxyType(dict(fixture_roots or {}))

    def operation(
        name: str,
        request: ActivityRequest,
        artifacts: ArtifactStore,
        coordination: CoordinationStore,
        runtime: Any,
    ) -> Mapping[str, Any] | GatePublication:
        return _operation_result(
            _OperationSlots(name, request, artifacts, coordination, runtime, execution, roots)
        )

    return DomainOperations(
        **{
            name: (
                lambda request, artifacts, coordination, runtime, name=name: operation(
                    name,
                    request,
                    artifacts,
                    coordination,
                    runtime,
                )
            )
            for name in DomainOperations.__dataclass_fields__
        }
    )


@dataclass(frozen=True, slots=True)
class DurableAuthoritySlots:
    """Durable identities and source material for one child authority issuance."""

    coordination: CoordinationStore
    campaign_id: str
    experiment_id: str
    workflow_id: str
    run_id: str
    parent_workflow_id: str
    parent_run_id: str
    candidate_instruction: str


@dataclass(frozen=True, slots=True)
class _DesignAuthoritySlots:
    """Durable records required to validate one staged design authority."""

    durable: DurableAuthoritySlots
    claimed: Any
    decomposition_record: Mapping[str, Any]
    treatment: Any
    coverage: tuple[SourceCoverage, ...]
    decision: Any
    wire: DecisionWire
    record: Any


@dataclass(frozen=True, slots=True)
class ArtifactPrivateAuthority(PrivateAuthorityResolver):
    """Resolves a distinct, durable authority record for each child execution."""

    artifacts: ArtifactStore
    relative_path: str = "child-authorities"

    def _relative(
        self,
        campaign_id: str,
        experiment_id: str,
        workflow_id: str,
        run_id: str,
    ) -> str:
        if any(
            not isinstance(value, str) or not value
            for value in (campaign_id, experiment_id, workflow_id, run_id)
        ):
            raise ProductionConfigurationError("child authority identity is invalid")
        return (
            f"{self.relative_path.strip('/')}/{campaign_id}/{experiment_id}/"
            f"{workflow_id}/{run_id}.json"
        )

    def issue_for(
        self,
        *,
        campaign_id: str,
        experiment_id: str,
        workflow_id: str,
        run_id: str,
        authority: PrivateMapAuthority,
    ) -> None:
        """Write the immutable authority bound to one frozen child execution."""
        if not isinstance(authority, PrivateMapAuthority):
            raise ProductionConfigurationError("child authority is malformed")
        self.artifacts.publish_json(
            self._relative(campaign_id, experiment_id, workflow_id, run_id),
            {
                "campaign_id": campaign_id,
                "experiment_id": experiment_id,
                "workflow_id": workflow_id,
                "run_id": run_id,
                "authority": {
                    name: getattr(authority, name) for name in authority.__dataclass_fields__
                },
            },
            ArtifactMode.PRIVATE,
        )

    def issue_from_durable_records(self, slots: DurableAuthoritySlots) -> None:
        """Issue the one child authority from claimed and signed durable records."""
        if not isinstance(slots.candidate_instruction, str) or not slots.candidate_instruction:
            raise ProductionConfigurationError("candidate instruction is invalid")
        try:
            authority = self._authority_from_durable_records(slots)
            self.issue_for(
                campaign_id=slots.campaign_id,
                experiment_id=slots.experiment_id,
                workflow_id=slots.workflow_id,
                run_id=slots.run_id,
                authority=authority,
            )
        except (CoordinationError, OSError, TypeError, ValueError, KeyError) as error:
            if isinstance(error, ProductionConfigurationError):
                raise
            raise ProductionConfigurationError(
                "durable private authority issuance failed"
            ) from error

    def _claimed_context(
        self,
        slots: DurableAuthoritySlots,
    ) -> tuple[Any, Any, Mapping[str, Any], DecompositionProposal]:
        claimed = slots.coordination.claimed_child_authorization(
            ClaimedChildAuthorizationRequest(
                campaign_id=slots.campaign_id,
                experiment_id=slots.experiment_id,
                child_workflow_id=slots.workflow_id,
                child_run_id=slots.run_id,
            )
        )
        if slots.parent_workflow_id != slots.campaign_id or (
            claimed.parent_workflow_id,
            claimed.parent_run_id,
        ) != (slots.parent_workflow_id, slots.parent_run_id):
            raise ProductionConfigurationError(
                "claimed authorization parent does not match Temporal"
            )
        decision = slots.coordination.published_decision(
            PublishedDecisionRequest(
                workflow_id=slots.parent_workflow_id,
                run_id=slots.parent_run_id,
                target_kind="campaign",
                target_id=slots.campaign_id,
                sequence=1,
            )
        )
        if decision.publication_sha256 is None:
            raise ProductionConfigurationError("signed decomposition decision is unavailable")
        wire = DecisionWire.from_json(
            json.loads(
                self.artifacts.read_bytes(
                    f"public/decisions/sha256/{decision.publication_sha256}.json",
                    ArtifactMode.PUBLIC,
                )
            )
        )
        if (
            wire.hash != decision.publication_sha256
            or wire.payload.campaign_id != slots.campaign_id
            or wire.payload.target_kind != "campaign"
            or wire.payload.target_id != slots.campaign_id
            or wire.payload.action != "approve_decomposition"
            or wire.payload.expected_revision_hash != "0" * 64
            or wire.payload.sequence != 1
            or not isinstance(wire.payload.proposal_hash, str)
        ):
            raise ProductionConfigurationError(
                "signed decomposition decision is not bound to this campaign"
            )
        record = json.loads(
            self.artifacts.read_bytes(
                f"control/proposals/sha256/{wire.payload.proposal_hash}/record.json",
                ArtifactMode.PRIVATE,
            )
        )
        if (
            not isinstance(record, Mapping)
            or set(record) != {"schema", "owner_principal", "proposal"}
            or record["schema"] != "instruct-eval-staged-decomposition-v1"
            or not isinstance(record["owner_principal"], str)
            or not record["owner_principal"]
        ):
            raise ProductionConfigurationError("staged decomposition record is malformed")
        proposal = DecompositionProposal.from_json(record["proposal"])
        validate_decomposition_proposal(
            proposal,
            campaign_id=slots.campaign_id,
            request_fingerprint=claimed.fingerprint_sha256,
            proposal_hash=wire.payload.proposal_hash,
        )
        return claimed, wire, record, proposal

    def _claimed_treatment(
        self,
        slots: DurableAuthoritySlots,
        claimed: Any,
        decomposition: DecompositionProposal,
    ) -> tuple[Mapping[str, Any], Any, tuple[SourceCoverage, ...]]:
        coverage = tuple(
            SourceCoverage(
                start_byte=item["start_byte"],
                end_byte=item["end_byte"],
                classification=item["classification"],
                owner=item.get("owner"),
                consumers=tuple(item.get("consumers", ())),
                reason=item.get("reason"),
            )
            for item in decomposition.source_coverage
            if isinstance(item, Mapping)
            and set(item)
            == set(
                SourceCoverage(
                    start_byte=item["start_byte"],
                    end_byte=item["end_byte"],
                    classification=item["classification"],
                    owner=item.get("owner"),
                    consumers=tuple(item.get("consumers", ())),
                    reason=item.get("reason"),
                ).as_json()
            )
        )
        if (
            len(coverage) != len(decomposition.source_coverage)
            or canonical_hash({"source_coverage": [item.as_json() for item in coverage]})
            != claimed.coverage_sha256
        ):
            raise ProductionConfigurationError(
                "decomposition coverage is not bound to claimed authorization"
            )
        _source_partition(
            slots.candidate_instruction,
            coverage,
            ProductionConfigurationError,
        )
        claim = _bound_claim(
            decomposition.ordered_claims,
            claimed.claim_sha256,
            claimed.coverage_sha256,
            ProductionConfigurationError,
        )
        if not isinstance(claim["claim_id"], str) or not isinstance(claim["treatment_hash"], str):
            raise ProductionConfigurationError("decomposition claim is malformed")
        treatment = derive_treatment(slots.candidate_instruction, claim["claim_id"], coverage)
        if treatment.hash != claim["treatment_hash"]:
            raise ProductionConfigurationError("derived treatment is not bound to claimed child")
        return claim, treatment, coverage

    def _design_authority(
        self,
        slots: DurableAuthoritySlots,
        claimed: Any,
        decomposition_record: Mapping[str, Any],
        treatment: Any,
        coverage: tuple[SourceCoverage, ...],
    ) -> PrivateMapAuthority:
        decision = slots.coordination.published_decision(
            PublishedDecisionRequest(
                workflow_id=slots.workflow_id,
                run_id=slots.run_id,
                target_kind="claim",
                target_id=claimed.claim_sha256,
                sequence=1,
            )
        )
        if decision.publication_sha256 is None:
            raise ProductionConfigurationError("signed design decision is unavailable")
        wire = DecisionWire.from_json(
            json.loads(
                self.artifacts.read_bytes(
                    f"public/decisions/sha256/{decision.publication_sha256}.json",
                    ArtifactMode.PUBLIC,
                )
            )
        )
        if (
            wire.hash != decision.publication_sha256
            or wire.payload.action != "submit_design"
            or wire.payload.campaign_id != slots.campaign_id
            or wire.payload.target_kind != "claim"
            or wire.payload.target_id != claimed.claim_sha256
            or not isinstance(wire.payload.proposal_hash, str)
        ):
            raise ProductionConfigurationError("signed design decision is not bound to this child")
        record = json.loads(
            self.artifacts.read_bytes(
                f"control/proposals/sha256/{wire.payload.proposal_hash}/record.json",
                ArtifactMode.PRIVATE,
            )
        )
        return self._authority_from_design_record(
            _DesignAuthoritySlots(
                slots,
                claimed,
                decomposition_record,
                treatment,
                coverage,
                decision,
                wire,
                record,
            )
        )

    def _authority_from_design_record(
        self,
        context: _DesignAuthoritySlots,
    ) -> PrivateMapAuthority:
        slots = context.durable
        claimed = context.claimed
        record = context.record
        if (
            not isinstance(record, Mapping)
            or set(record) != {"schema", "owner_principal", "proposal", "attestation"}
            or record["schema"] != "instruct-eval-staged-design-v1"
            or record["owner_principal"] != context.decomposition_record["owner_principal"]
        ):
            raise ProductionConfigurationError("staged design record is malformed")
        proposal = DesignProposal.from_json(record["proposal"])
        attestation = StageAttestation.from_json(record["attestation"])
        if (
            proposal.hash != context.wire.payload.proposal_hash
            or context.decision.expected_revision_sha256 != proposal.g0_commit_hash
            or proposal.campaign_id != slots.campaign_id
            or proposal.claim_hash != claimed.claim_sha256
            or proposal.g0_commit_hash != attestation.g0_commit_hash
            or proposal.treatment_hash != context.treatment.hash
            or proposal.fixture_manifest_hash != attestation.fixture_manifest_hash
            or attestation.proposal_hash != proposal.hash
            or attestation.campaign_id != slots.campaign_id
            or attestation.claim_hash != claimed.claim_sha256
            or attestation.treatment_hash != proposal.treatment_hash
        ):
            raise ProductionConfigurationError("staged design authority bindings are invalid")
        return self._private_authority(
            slots,
            context.treatment,
            context.coverage,
            proposal,
            context.wire,
        )

    def _private_authority(
        self,
        slots: DurableAuthoritySlots,
        treatment: Any,
        coverage: tuple[SourceCoverage, ...],
        proposal: DesignProposal,
        wire: DecisionWire,
    ) -> PrivateMapAuthority:
        package = proposal.design
        if not isinstance(package, Mapping) or set(package) != {
            "experiment_design",
            "preferred_directions",
        }:
            raise ProductionConfigurationError("staged design package fields are not exact")
        design = ExperimentDesign.from_payload(package["experiment_design"])
        validate_experiment_design(design)
        classification = SourceClassification(
            sha256(slots.candidate_instruction.encode()).hexdigest(),
            coverage,
        )
        if canonical_hash(package) != proposal.design_hash:
            raise ProductionConfigurationError("staged design package hash is invalid")
        manifest = canonical_hash(
            {
                "fixtures": [
                    {
                        "fixture_id": fixture.fixture_id,
                        "manifest_sha256": fixture.manifest_sha256,
                    }
                    for fixture in sorted(design.fixtures, key=lambda item: item.fixture_id)
                ],
            }
        )
        if manifest != proposal.fixture_manifest_hash:
            raise ProductionConfigurationError("staged design fixture manifests are not bound")
        if any(fixture.source_classification != classification for fixture in design.fixtures):
            raise ProductionConfigurationError(
                "staged design source classification is not bound to decomposition"
            )
        preferred = package["preferred_directions"]
        fixture_ids = {fixture.fixture_id for fixture in design.fixtures}
        if (
            not isinstance(preferred, Mapping)
            or set(preferred) != {"core-1", "core-2", "negative-control"}
            or fixture_ids != set(preferred)
            or any(
                preferred[fixture.fixture_id]
                not in {direction.code for direction in fixture.directions}
                for fixture in design.fixtures
            )
        ):
            raise ProductionConfigurationError(
                "staged design does not contain exact private preferred directions"
            )
        treatments = {
            assignment_id: (
                treatment.exact_instruction if assignment_id.rsplit("-", 2)[1] == "B" else None
            )
            for assignment_id in ASSIGNMENT_IDS
        }
        return PrivateMapAuthority(
            parent_workflow_id=slots.parent_workflow_id,
            parent_run_id=slots.parent_run_id,
            freeze_chain=wire.hash,
            claim_hash=proposal.claim_hash,
            g0_record_hash=proposal.g0_commit_hash,
            design_proposal_hash=proposal.hash,
            design_hash=proposal.design_hash,
            treatment_hash=proposal.treatment_hash,
            fixture_manifest_hash=proposal.fixture_manifest_hash,
            preferred_directions=preferred,
            treatments=treatments,
            experiment_design=design.payload(),
        )

    def _authority_from_durable_records(
        self,
        slots: DurableAuthoritySlots,
    ) -> PrivateMapAuthority:
        claimed, _, record, decomposition = self._claimed_context(slots)
        _, treatment, coverage = self._claimed_treatment(slots, claimed, decomposition)
        return self._design_authority(slots, claimed, record, treatment, coverage)

    def authority_for(
        self,
        *,
        campaign_id: str,
        experiment_id: str,
        workflow_id: str,
        run_id: str,
    ) -> PrivateMapAuthority:
        relative = self._relative(campaign_id, experiment_id, workflow_id, run_id)
        try:
            data = json.loads(self.artifacts.read_bytes(relative, ArtifactMode.PRIVATE))
        except (OSError, ValueError, TypeError) as error:
            raise ProductionConfigurationError("child authority artifact is unavailable") from error
        if (
            not isinstance(data, Mapping)
            or set(data) != {"campaign_id", "experiment_id", "workflow_id", "run_id", "authority"}
            or (
                data["campaign_id"],
                data["experiment_id"],
                data["workflow_id"],
                data["run_id"],
            )
            != (campaign_id, experiment_id, workflow_id, run_id)
            or not isinstance(data["authority"], Mapping)
        ):
            raise ProductionConfigurationError(
                "child authority artifact is not bound to this execution"
            )
        try:
            return PrivateMapAuthority(**data["authority"])
        except (TypeError, ValueError) as error:
            raise ProductionConfigurationError("child authority payload is malformed") from error


@dataclass(frozen=True, slots=True)
class RuntimeSubjectExecutor:
    fixture_roots: Mapping[str, Path]
    request: Mapping[str, Any]
    evidence_key: bytes
    fixture_paths: Mapping[str, Sequence[str]]

    def __call__(
        self,
        *,
        assignment: PrivateAssignment,
        treatment: str | None,
        disclosure_treatment: str,
        frozen_design: ExperimentDesign,
    ) -> Mapping[str, Any]:
        if (
            not isinstance(assignment, PrivateAssignment)
            or (treatment is not None and not isinstance(treatment, str))
            or not isinstance(disclosure_treatment, str)
            or not disclosure_treatment
        ):
            raise TrialProtocolError("invalid subject assignment")
        fixture = self.fixture_roots.get(assignment.scenario)
        if fixture is None or not fixture.is_dir() or len(self.evidence_key) != 32:
            raise TrialProtocolError("private subject configuration is unavailable")
        if not isinstance(frozen_design, ExperimentDesign):
            raise TrialProtocolError("subject frozen design is unavailable")
        subject_request = dict(self.request)
        if treatment is not None:
            subject_request["candidate_instruction"] = treatment
        result = role_runtime.run_subject(
            assignment.assignment_id,
            assignment.condition,
            fixture,
            subject_request,
            observer_paths=self.fixture_paths.get(assignment.scenario, ()),
        )
        raw_channels = (
            result.response,
            result.changes,
            *result.tool_outputs,
            result.runtime_stdout,
            result.runtime_stderr,
            result.verifier_stdout,
            result.verifier_stderr,
            *result.observer_output.values(),
        )
        if scan_disclosure(
            raw=tuple(channel.encode("utf-8") for channel in raw_channels),
            treatment=disclosure_treatment,
        ):
            raise TrialProtocolError("subject evidence disclosed treatment or protocol labels")
        if not result.protocol_valid:
            raise TrialProtocolError("subject execution was protocol-invalid")
        try:
            observed = construct_outcome_tuple(
                frozen_design,
                assignment.scenario,
                result.verifier_passed,
                result.observer_output,
                protocol_valid=result.protocol_valid,
            )
            frozen_fixture = next(
                item for item in frozen_design.fixtures if item.fixture_id == assignment.scenario
            )
            direction_code = frozen_fixture.outcome_table[
                (observed.verifier_passed, *observed.axis_values)
            ]
        except (ProtocolError, KeyError, StopIteration) as error:
            raise TrialProtocolError(
                "subject observer outcome is not a frozen fixture outcome"
            ) from error
        changed = {
            line.split("file/", 1)[1] if "file/" in line else line.split("/", 1)[1]
            for line in result.changes.splitlines()
            if line.startswith(
                ("+++ created file/", "--- removed file/", "--- before/", "+++ after/")
            )
        }
        outcome = closed_outcome(
            ClosedOutcomeParams(
                blind_id=assignment.blind_id,
                fixture=assignment.scenario,
                verifier_passed=observed.verifier_passed,
                observer_state=observed.axis_values,
                direction_code=direction_code,
                changed_paths=tuple(sorted(changed)),
                token=assignment.token,
                k_evidence=self.evidence_key,
                fixture_paths=self.fixture_paths,
                root=fixture,
            )
        )
        return {
            "outcome": outcome,
            "private_artifacts": {
                "response": result.response,
                "runtime_streams": {
                    "stdout": result.runtime_stdout,
                    "stderr": result.runtime_stderr,
                },
                "tool_outputs": list(result.tool_outputs),
                "diff": result.changes,
                "verifier": {
                    "passed": result.verifier_passed,
                    "stdout": result.verifier_stdout,
                    "stderr": result.verifier_stderr,
                },
                "observer": dict(result.observer_output),
                "trusted_logs": {
                    "reason": result.reason,
                    "unchanged_hashes": dict(result.unchanged_hashes),
                },
            },
        }


@dataclass(frozen=True, slots=True)
class ProductionConfig:
    temporal_address: str
    artifact_root: Path
    private_artifact_root: Path
    coordination_db: Path
    private_map_db: Path
    authority_artifact: str
    fixture_roots: Mapping[str, Path]
    subject_request: Mapping[str, Any]
    evidence_key: bytes
    fixture_paths: Mapping[str, Sequence[str]]
    role_request: Mapping[str, Any] = field(default_factory=dict)
    public_task_queue: str = PUBLIC_TASK_QUEUE
    private_task_queue: str = PRIVATE_TASK_QUEUE

    def __post_init__(self) -> None:
        if (
            not isinstance(self.temporal_address, str)
            or not self.temporal_address
            or not all(
                Path(value).is_absolute()
                for value in (
                    self.artifact_root,
                    self.private_artifact_root,
                    self.coordination_db,
                    self.private_map_db,
                )
            )
        ):
            raise ProductionConfigurationError(
                "production paths must be caller-supplied absolute paths"
            )
        if (
            self.public_task_queue == self.private_task_queue
            or not self.authority_artifact
            or len(self.evidence_key) != 32
        ):
            raise ProductionConfigurationError(
                "production queue or private configuration is invalid"
            )
        if not isinstance(self.role_request, Mapping) or not self.role_request:
            raise ProductionConfigurationError("production role request is required")


def build_production_backend(config: ProductionConfig) -> InstructEvalActivityBackend:
    from .trials import PrivateMapLifecycle

    if not isinstance(config, ProductionConfig):
        raise ProductionConfigurationError("explicit ProductionConfig is required")
    artifacts = ArtifactStore(config.artifact_root, config.private_artifact_root)
    return InstructEvalActivityBackend(
        ActivityBackendRequest(
            artifacts=artifacts,
            coordination=CoordinationStore(config.coordination_db),
            operations=concrete_domain_operations(config.role_request, config.fixture_roots),
            private_maps=PrivateMapLifecycle(config.private_map_db, config.private_artifact_root),
            private_authority=ArtifactPrivateAuthority(artifacts, config.authority_artifact),
            subject_executor=RuntimeSubjectExecutor(
                config.fixture_roots,
                config.subject_request,
                config.evidence_key,
                config.fixture_paths,
            ),
        )
    )


@dataclass(frozen=True, slots=True)
class PublicProductionConfig:
    """Public process configuration deliberately excludes private capabilities."""

    temporal_address: str
    artifact_root: Path
    coordination_db: Path
    role_request: Mapping[str, Any]
    public_task_queue: str = PUBLIC_TASK_QUEUE

    def __post_init__(self) -> None:
        if (
            not isinstance(self.temporal_address, str)
            or not self.temporal_address
            or not self.artifact_root.is_absolute()
            or not self.coordination_db.is_absolute()
            or not isinstance(self.role_request, Mapping)
            or not self.role_request
        ):
            raise ProductionConfigurationError("public production configuration is invalid")


def build_public_production_backend(
    config: PublicProductionConfig,
) -> InstructEvalActivityBackend:
    """Build only the state reachable from public Activities."""
    if not isinstance(config, PublicProductionConfig):
        raise ProductionConfigurationError("explicit PublicProductionConfig is required")
    backend = object.__new__(InstructEvalActivityBackend)
    public_artifacts = ArtifactStore.public_only(config.artifact_root)
    backend._artifacts = public_artifacts
    backend._coordination = CoordinationStore(config.coordination_db)
    backend._operations = concrete_domain_operations(config.role_request)
    backend._runtime = role_runtime
    return backend


async def run_public_production_worker(config: PublicProductionConfig) -> None:
    backend = build_public_production_backend(config)
    client = await Client.connect(config.temporal_address, namespace=TEMPORAL_NAMESPACE)
    if client.namespace != TEMPORAL_NAMESPACE:
        raise ProductionConfigurationError("Temporal namespace must be instruct-eval")
    await create_public_worker(
        client,
        backend,
        public_task_queue=config.public_task_queue,
    ).run()


async def run_private_production_worker(config: ProductionConfig) -> None:
    backend = build_production_backend(config)
    client = await Client.connect(config.temporal_address, namespace=TEMPORAL_NAMESPACE)
    if client.namespace != TEMPORAL_NAMESPACE:
        raise ProductionConfigurationError("Temporal namespace must be instruct-eval")
    await create_private_worker(
        client,
        backend,
        private_task_queue=config.private_task_queue,
    ).run()


async def run_production_worker(config: ProductionConfig) -> None:
    backend = build_production_backend(config)
    client = await Client.connect(config.temporal_address, namespace=TEMPORAL_NAMESPACE)
    if client.namespace != TEMPORAL_NAMESPACE:
        raise ProductionConfigurationError("Temporal namespace must be instruct-eval")
    await run_workers(
        client,
        backend,
        public_task_queue=config.public_task_queue,
        private_task_queue=config.private_task_queue,
    )


def main(config: ProductionConfig) -> None:
    asyncio.run(run_production_worker(config))
