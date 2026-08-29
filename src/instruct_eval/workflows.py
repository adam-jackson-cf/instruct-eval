"""Deterministic public Temporal orchestration for instruction experiments."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError
from temporalio.workflow import ParentClosePolicy

from .activities import (
    ActivityResult,
    AnalysisRequest,
    ChildAuthorizationClaimRequest,
    ChildAuthorizationIssueRequest,
    DesignCommitRequest,
    EligibilityRequest,
    EvidenceAuditRequest,
    ExecutionCommitRequest,
    FingerprintRequest,
    FreezeRequest,
    GateRequest,
    GateResult,
    MapLifecycleRequest,
    PostRunValidityRequest,
    PreRunValidityRequest,
    ProposalDecisionRequest,
    ReleaseRequest,
    SubjectTrialRequest,
    TerminalCommitRequest,
)

with workflow.unsafe.imports_passed_through():
    from .signing import (
        DecisionValidationParameters,
        DecisionWire,
        SigningError,
        load_public_key,
        validate_decision_wire,
    )
from .messages import request_fingerprint
from .models import canonical_bytes, canonical_hash

_GATE_NAMES = ("G0", "G1", "G2", "G3", "G4", "G5", "G6")
_CAMPAIGN_ID = re.compile(r"campaign-[0-9]{32}\Z")
_ACTIVITY_TIMEOUT = timedelta(minutes=5)
_DETERMINISTIC_RETRY = RetryPolicy(
    maximum_attempts=3, initial_interval=timedelta(seconds=1), maximum_interval=timedelta(seconds=5)
)
_MODEL_RETRY = RetryPolicy(maximum_attempts=1)
_SUBJECT_HEARTBEAT_TIMEOUT = timedelta(seconds=5)
_PRIVATE_TASK_QUEUE = "instruct-eval-private"
_PRIVATE_ACTIVITY_NAMES = frozenset(
    {
        "instruct_eval.child_authorization_claim",
        "instruct_eval.child_authorization_issue",
        "instruct_eval.design_commit",
        "instruct_eval.pre_run_validity",
        "instruct_eval.freeze",
        "instruct_eval.map_lifecycle",
        "instruct_eval.proposal_decision",
        "instruct_eval.subject_trial",
        "instruct_eval.release",
    }
)
_GATE_ACTIVITY_NAMES = frozenset(
    {
        "instruct_eval.g0_commit",
        "instruct_eval.design_commit",
        "instruct_eval.pre_run_validity",
        "instruct_eval.freeze",
        "instruct_eval.execution_commit",
        "instruct_eval.post_run_validity",
        "instruct_eval.release",
        "instruct_eval.analysis",
        "instruct_eval.terminal_commit",
    }
)
_FORBIDDEN_PUBLIC_FIELDS = frozenset(
    {
        "private",
        "private_map",
        "private_join",
        "private_evidence",
        "blind_id_join",
        "blind_ids",
        "raw_evidence",
        "condition_join",
        "condition_assignment",
        "condition_assignments",
        "conditions",
        "condition",
        "preferred_direction",
        "preferred_directions",
        "preferred_direction_assignment",
        "preferred_direction_assignments",
        "quarantine",
        "quarantined",
    }
)

_FINGERPRINT_REQUEST_FIELDS = frozenset(
    {
        "candidate_instruction",
        "permissions",
        "repository",
        "fixture_manifest_hash",
        "operator_public_key",
    }
)


class WorkflowProtocolError(ValueError):
    """A public workflow input or transition violates the fixed protocol."""


class ExperimentGate(StrEnum):
    INITIALIZING = "INITIALIZING"
    G0 = "G0"
    G1 = "G1"
    G2 = "G2"
    FROZEN = "FROZEN"
    G3 = "G3"
    G4 = "G4"
    RELEASING = "RELEASING"
    G5 = "G5"
    G6 = "G6"
    DESIGN_REJECTED = "DESIGN_REJECTED"
    AUTHORIZED = "AUTHORIZED"
    COMPLETED_NOT_AUTHORIZED = "COMPLETED_NOT_AUTHORIZED"
    SCORING_REJECTED = "SCORING_REJECTED"
    PROTOCOL_FAILURE = "PROTOCOL_FAILURE"
    CANCELED = "CANCELED"


@dataclass(frozen=True, slots=True)
class ExperimentInput:
    campaign_id: str
    experiment_id: str
    claim_sha256: str
    claim: Mapping[str, Any]
    coverage_sha256: str
    model_identity: str
    runtime_identity: str
    public_input: Mapping[str, Any]
    authorization: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ExperimentResult:
    experiment_id: str
    claim_sha256: str
    status: str
    terminal_gate: str
    artifact_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class ExperimentStatus:
    experiment_id: str
    gate: str
    terminal: bool
    authorization_claimed: bool
    gate_artifact_sha256: Mapping[str, str] = field(default_factory=dict)
    current_revision_sha256: str = "0" * 64
    outstanding_action: str | None = None
    sequence: int | None = None
    expected_revision_sha256: str | None = None
    proposal_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class CampaignInput:
    campaign_id: str
    model_identity: str
    runtime_identity: str
    public_input: Mapping[str, Any]
    coverage_sha256: str


@dataclass(frozen=True, slots=True)
class CampaignClaimResult:
    claim_sha256: str
    status: str
    terminal_gate: str
    artifact_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class CampaignResult:
    campaign_id: str
    fingerprint_sha256: str
    claims: tuple[CampaignClaimResult, ...]


@dataclass(frozen=True, slots=True)
class CampaignStatus:
    campaign_id: str
    state: str
    fingerprint_sha256: str | None
    claim_count: int
    current_revision_sha256: str = "0" * 64
    outstanding_action: str | None = None
    sequence: int | None = None
    expected_revision_sha256: str | None = None
    proposal_sha256: str | None = None


@dataclass(slots=True)
class _TrialRun:
    trials: dict[str, ActivityResult] = field(default_factory=dict)
    accounting: dict[str, str] = field(default_factory=dict)
    outstanding: dict[Any, str] = field(default_factory=dict)
    next_token: int = 0
    terminal: bool = False
    cancelled: bool = False


@dataclass(frozen=True, slots=True)
class _G3Outcomes:
    outcomes: list[Mapping[str, Any]]
    blind_ids: set[str]


def _digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise WorkflowProtocolError(f"{label} must be a lowercase SHA-256 digest")


def _identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise WorkflowProtocolError(f"{label} must be a nonempty string")


def _public_packet(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkflowProtocolError("public input must be a mapping")

    def validate(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise WorkflowProtocolError("public input keys must be strings")
                normalized = key.lower().replace("-", "_")
                if normalized in _FORBIDDEN_PUBLIC_FIELDS or normalized.startswith(
                    ("condition_", "preferred_direction_")
                ):
                    raise WorkflowProtocolError(
                        "public input must not contain private joins or evidence"
                    )
                validate(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                validate(child)

    validate(value)
    canonical_hash(value)
    return value


def _deidentified_outcomes(trials: list[ActivityResult]) -> list[Mapping[str, Any]]:
    fields = {
        "blind_id",
        "fixture",
        "protocol_valid",
        "verifier_passed",
        "observer_state",
        "direction_code",
        "changed_paths",
        "evidence_id",
    }
    outcomes = [result.payload for result in trials]
    if len(outcomes) != 10 or any(set(outcome) != fields for outcome in outcomes):
        raise WorkflowProtocolError("G4 requires exactly ten closed deidentified outcomes")
    blind_ids = [outcome["blind_id"] for outcome in outcomes]
    if (
        any(not isinstance(blind_id, str) or not blind_id for blind_id in blind_ids)
        or any(
            not isinstance(outcome["direction_code"], str) or not outcome["direction_code"]
            for outcome in outcomes
        )
        or len(set(blind_ids)) != 10
    ):
        raise WorkflowProtocolError("G4 outcomes must cover ten unique blind ids and directions")
    return outcomes


def _blind_scores(value: Any, blind_ids: set[str]) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) != 10:
        raise WorkflowProtocolError("scorer must return exactly ten blind scores")
    fields = {"blind_id", "direction"}
    if any(not isinstance(score, Mapping) or set(score) != fields for score in value):
        raise WorkflowProtocolError("scorer blind-score fields are invalid")
    ids = [score["blind_id"] for score in value]
    if set(ids) != blind_ids or any(
        not isinstance(score["direction"], str) or not score["direction"] for score in value
    ):
        raise WorkflowProtocolError("scorer blind-score coverage is invalid")
    return [dict(score) for score in value]


def _g5_release(value: Any, blind_ids: set[str]) -> Mapping[str, Any]:
    fields = {"assignments", "preferred_directions", "authorization_rule", "release_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WorkflowProtocolError("G5 release packet is not exact")
    assignments = value["assignments"]
    if not isinstance(assignments, list) or len(assignments) != 10:
        raise WorkflowProtocolError("G5 release must contain ten joined records")
    row_fields = {"blind_id", "scenario", "condition", "direction"}
    if any(not isinstance(row, Mapping) or set(row) != row_fields for row in assignments):
        raise WorkflowProtocolError("G5 released record fields are invalid")
    if (
        {row["blind_id"] for row in assignments} != blind_ids
        or any(
            not all(isinstance(row[key], str) and row[key] for key in row_fields)
            for row in assignments
        )
        or assignments != sorted(assignments, key=lambda row: row["blind_id"])
    ):
        raise WorkflowProtocolError("G5 release join coverage is invalid")
    preferred = value["preferred_directions"]
    if (
        not isinstance(preferred, Mapping)
        or set(preferred) != {"core-1", "core-2", "negative-control"}
        or any(not isinstance(direction, str) or not direction for direction in preferred.values())
    ):
        raise WorkflowProtocolError("G5 preferred directions are invalid")
    authorization_rule = value["authorization_rule"]
    if authorization_rule != {
        "schema": "instruct-eval-authorization-rule-v1",
        "core_scenarios": ["core-1", "core-2"],
        "negative_control_scenario": "negative-control",
        "core_comparison": "preferred_count_B_strictly_greater_than_A",
        "negative_control_comparison": "both_subjects_match_preferred_direction",
    }:
        raise WorkflowProtocolError("G5 authorization rule is invalid")
    release_sha256 = value["release_sha256"]
    if not isinstance(release_sha256, str):
        raise WorkflowProtocolError("G5 release hash is missing")
    _digest(release_sha256, "G5 release hash")
    if canonical_hash({key: value[key] for key in fields - {"release_sha256"}}) != release_sha256:
        raise WorkflowProtocolError("G5 release hash does not bind exact release packet")
    return dict(value)


def _fingerprint_payload(input_: CampaignInput) -> Mapping[str, Any]:
    request = input_.public_input
    if set(request) != _FINGERPRINT_REQUEST_FIELDS:
        raise WorkflowProtocolError("fingerprint requires an exact public request")
    return {
        "candidate_instruction": request["candidate_instruction"],
        "model_identity": input_.model_identity,
        "runtime_identity": input_.runtime_identity,
        "request": request,
    }


def _proposal_decision_payload(
    input_: ExperimentInput | CampaignInput,
    wire: DecisionWire,
    prior_decision_sha256: str,
) -> Mapping[str, Any]:
    payload = wire.payload
    owner_public_key = input_.public_input.get("operator_public_key")
    if not isinstance(owner_public_key, str):
        raise WorkflowProtocolError("operator public key must be a nonempty string")
    _identifier(owner_public_key, "operator public key")
    info = workflow.info()
    packet = {
        "wire": wire.as_json(),
        "workflow_id": info.workflow_id,
        "run_id": info.run_id,
        "prior_decision_sha256": prior_decision_sha256,
        "target_kind": payload.target_kind,
        "target_id": payload.target_id,
        "action": payload.action,
        "proposal_hash": payload.proposal_hash,
        "expected_revision_sha256": payload.expected_revision_hash,
        "sequence": payload.sequence,
        "owner_public_key": owner_public_key,
    }
    if isinstance(input_, CampaignInput):
        packet["request_fingerprint"] = request_fingerprint(
            input_.public_input, input_.model_identity, input_.runtime_identity
        )
    return packet


def _activity_payload(
    input_: ExperimentInput | CampaignInput, extra: Mapping[str, Any]
) -> Mapping[str, Any]:
    return {"input": input_.public_input, **extra}


def _request_hash(payload: Mapping[str, Any]) -> str:
    return canonical_hash(payload)


def _validate_published_decision(result: ActivityResult, wire: DecisionWire) -> None:
    """Require the revalidated signature to have an immutable public publication."""
    payload = result.payload
    if payload.get("accepted") is not True:
        raise WorkflowProtocolError("decision revalidation failed")
    if payload.get("decision_sha256") != wire.hash:
        raise WorkflowProtocolError("decision response is not bound to the signed wire")
    artifact_sha256 = payload.get("decision_artifact_sha256")
    if not isinstance(artifact_sha256, str):
        raise WorkflowProtocolError("decision publication digest is missing")
    _digest(artifact_sha256, "decision publication digest")
    if artifact_sha256 != wire.hash:
        raise WorkflowProtocolError("decision publication digest is not bound to the signed wire")
    if (
        not isinstance(payload.get("decision_artifact_path"), str)
        or not payload["decision_artifact_path"]
    ):
        raise WorkflowProtocolError("decision publication path is missing")


@workflow.defn
class InstructionExperimentWorkflow:
    """One fail-closed G0--G6 experiment with no private data in history."""

    def __init__(self) -> None:
        self._input: ExperimentInput | None = None
        self._gate = ExperimentGate.INITIALIZING
        self._authorization_claimed = False
        self._terminal_committed = False
        self._gate_artifacts: dict[str, str] = {}
        self._decision_revision_sha256 = "0" * 64
        self._outstanding_action: str | None = None
        self._outstanding_sequence: int | None = None
        self._prior_decision_sha256 = "0" * 64
        self._outstanding_proposal_sha256: str | None = None
        self._cancelled = False
        self._prior_sha256 = "0" * 64
        self._frozen_design_sha256: str | None = None
        self._frozen_input_sha256: str | None = None
        self._map_ref: str | None = None
        self._map_commitment: str | None = None
        self._trial_tokens: tuple[str, ...] = ()
        self._pre_map_input_hash: str | None = None
        self._authorization_rule_sha256: str | None = None
        self._next_ordinal = 0
        self._pending_gate: tuple[str, GateRequest, str | None] | None = None
        self._release_payload: Mapping[str, Any] | None = None
        self._release_blind_ids: frozenset[str] = frozenset()

    @workflow.query
    def status(self) -> ExperimentStatus:
        experiment_id = self._input.experiment_id if self._input else ""
        return ExperimentStatus(
            experiment_id,
            self._gate.value,
            self._terminal_committed,
            self._authorization_claimed,
            dict(self._gate_artifacts),
            self._decision_revision_sha256,
            self._outstanding_action,
            self._outstanding_sequence,
            self._decision_revision_sha256,
            self._outstanding_proposal_sha256,
        )

    def _validate_decision(self, wire_json: Mapping[str, Any]) -> None:
        if self._input is None or self._terminal_committed:
            raise WorkflowProtocolError("decision target is not accepting updates")
        try:
            wire = DecisionWire.from_json(wire_json)
            public_key = load_public_key(self._input.public_input["operator_public_key"])
            payload = wire.payload
            validate_decision_wire(
                wire,
                public_key,
                DecisionValidationParameters(
                    campaign_id=self._input.campaign_id,
                    target_kind="claim",
                    target_id=self._input.claim_sha256,
                    action=payload.action,
                    proposal_hash=payload.proposal_hash,
                    expected_revision_hash=self._decision_revision_sha256,
                    sequence=payload.sequence,
                ),
            )
        except (KeyError, SigningError, TypeError, ValueError) as error:
            raise WorkflowProtocolError("decision wire is invalid") from error
        expected = (
            "submit_design"
            if self._gate is ExperimentGate.G0
            else "approve_freeze"
            if self._gate is ExperimentGate.G2
            else None
        )
        if payload.action != expected:
            raise WorkflowProtocolError("decision action is not outstanding")

    @workflow.update(name="decision")
    async def decision(self, wire_json: Mapping[str, Any]) -> str:
        self._validate_decision(wire_json)
        assert self._input is not None
        wire = DecisionWire.from_json(wire_json)
        payload = _proposal_decision_payload(self._input, wire, self._prior_decision_sha256)
        result = await self._execute(
            "instruct_eval.proposal_decision",
            self._activity_request(ProposalDecisionRequest, payload),
        )
        if not isinstance(result, ActivityResult):
            raise WorkflowProtocolError("decision revalidation failed")
        _validate_published_decision(result, wire)
        if wire.payload.action == "submit_design":
            if result.payload.get("proposal_sha256") != wire.payload.proposal_hash:
                raise WorkflowProtocolError(
                    "submitted design is not bound to its signed staged proposal"
                )
            design = result.payload.get("design_sha256")
            if not isinstance(design, str):
                raise WorkflowProtocolError("staged design hash is missing")
            _digest(design, "staged design hash")
            self._frozen_design_sha256 = design
        self._decision_revision_sha256 = wire.hash
        self._prior_decision_sha256 = wire.hash
        self._outstanding_action = None
        self._outstanding_sequence = None
        self._outstanding_proposal_sha256 = wire.payload.proposal_hash
        return self._decision_revision_sha256

    @decision.validator
    def validate_decision_update(self, wire_json: Mapping[str, Any]) -> None:
        self._validate_decision(wire_json)

    def _initialize(self, input_: ExperimentInput) -> None:
        if self._input is not None:
            if self._input != input_:
                raise WorkflowProtocolError("experiment input is immutable")
            return
        for value, label in (
            (input_.campaign_id, "campaign id"),
            (input_.experiment_id, "experiment id"),
            (input_.model_identity, "model identity"),
            (input_.runtime_identity, "runtime identity"),
        ):
            _identifier(value, label)
        _digest(input_.claim_sha256, "claim hash")
        _digest(input_.coverage_sha256, "coverage hash")
        _public_packet(input_.claim)
        if canonical_hash(dict(input_.claim)) != input_.claim_sha256:
            raise WorkflowProtocolError("claim hash does not bind exact canonical claim")
        if input_.claim.get("coverage_sha256") != input_.coverage_sha256:
            raise WorkflowProtocolError("claim is not bound to campaign coverage")
        _public_packet(input_.public_input)
        if set(input_.authorization) != {
            "authorized",
            "experiment_id",
            "campaign_id",
            "claim_sha256",
            "coverage_sha256",
            "fingerprint_sha256",
        }:
            raise WorkflowProtocolError("child authorization input fields are invalid")
        _public_packet(input_.authorization)
        self._input = ExperimentInput(
            input_.campaign_id,
            input_.experiment_id,
            input_.claim_sha256,
            json.loads(canonical_bytes(input_.claim)),
            input_.coverage_sha256,
            input_.model_identity,
            input_.runtime_identity,
            json.loads(canonical_bytes(input_.public_input)),
            json.loads(canonical_bytes(input_.authorization)),
        )
        self._frozen_input_sha256 = _request_hash(self._input.public_input)

    def _claim_authorization(self, result: ActivityResult) -> bool:
        assert self._input is not None
        if self._authorization_claimed:
            return True
        fingerprint = self._input.authorization.get("fingerprint_sha256")
        if (
            set(result.payload)
            != {
                "authorized",
                "experiment_id",
                "campaign_id",
                "claim_sha256",
                "coverage_sha256",
                "fingerprint_sha256",
            }
            or result.payload != self._input.authorization
            or result.payload.get("authorized") is not True
            or result.payload.get("campaign_id") != self._input.campaign_id
            or result.payload.get("experiment_id") != self._input.experiment_id
            or result.payload.get("claim_sha256") != self._input.claim_sha256
            or result.payload.get("coverage_sha256") != self._input.coverage_sha256
            or result.payload.get("fingerprint_sha256") != fingerprint
        ):
            return False
        self._authorization_claimed = True
        return True

    def _advance_gate(self, gate: ExperimentGate, result: ActivityResult | GateResult) -> None:
        if self._terminal_committed:
            raise WorkflowProtocolError("terminal experiment cannot advance")
        if not self._authorization_claimed:
            raise WorkflowProtocolError("authorization must be claimed before G0")
        expected = _GATE_NAMES[len(self._gate_artifacts)]
        if gate.value != expected:
            raise WorkflowProtocolError(f"expected {expected}, received {gate.value}")
        payload = result.payload
        if gate in (ExperimentGate.G1, ExperimentGate.G2) and (
            self._frozen_design_sha256 is None
            or payload.get("design_sha256") != self._frozen_design_sha256
        ):
            raise WorkflowProtocolError(f"{gate.value} must bind the exact staged design bytes")
        artifact_sha256 = (
            result.artifact_sha256 if isinstance(result, GateResult) else result.result_sha256
        )
        _digest(artifact_sha256, "gate artifact hash")
        self._gate_artifacts[gate.value] = artifact_sha256
        self._prior_sha256 = artifact_sha256
        self._gate = gate

    def _commit_terminal(self, terminal: ExperimentGate) -> None:
        if terminal not in (
            ExperimentGate.DESIGN_REJECTED,
            ExperimentGate.AUTHORIZED,
            ExperimentGate.COMPLETED_NOT_AUTHORIZED,
            ExperimentGate.SCORING_REJECTED,
            ExperimentGate.PROTOCOL_FAILURE,
            ExperimentGate.CANCELED,
        ):
            raise WorkflowProtocolError("invalid terminal state")
        if self._terminal_committed:
            if self._gate is not terminal:
                raise WorkflowProtocolError("terminal state is immutable")
            return
        self._terminal_committed = True
        self._gate = terminal

    def _activity_request(self, request_type: type[Any], payload: Mapping[str, Any]) -> Any:
        assert self._input is not None
        assert self._frozen_input_sha256 is not None
        return request_type(
            self._input.campaign_id,
            self._input.experiment_id,
            self._input.claim_sha256,
            _request_hash(payload),
            self._input.model_identity,
            self._input.runtime_identity,
            payload,
        )

    def _gate_request(
        self, request_type: type[GateRequest], ordinal: int, payload: Mapping[str, Any]
    ) -> GateRequest:
        assert self._input is not None
        assert self._frozen_input_sha256 is not None
        if ordinal != self._next_ordinal:
            raise WorkflowProtocolError("protocol commit ordinal collision")
        return request_type(
            self._input.campaign_id,
            self._input.experiment_id,
            self._input.claim_sha256,
            _request_hash(payload),
            self._input.model_identity,
            self._input.runtime_identity,
            payload,
            workflow.info().workflow_id,
            workflow.info().run_id,
            ordinal,
            self._prior_sha256,
            self._frozen_input_sha256,
            "canonical",
        )

    async def _execute(
        self, activity_name: str, request: Any, *, activity_id: str | None = None
    ) -> ActivityResult | GateResult:
        options: dict[str, Any] = {
            "start_to_close_timeout": _ACTIVITY_TIMEOUT,
            "task_queue": _PRIVATE_TASK_QUEUE if activity_name in _PRIVATE_ACTIVITY_NAMES else None,
            "retry_policy": _MODEL_RETRY
            if activity_name == "instruct_eval.design_draft"
            else _DETERMINISTIC_RETRY,
            "result_type": GateResult if activity_name in _GATE_ACTIVITY_NAMES else ActivityResult,
        }
        if activity_name == "instruct_eval.subject_trial":
            options["heartbeat_timeout"] = _SUBJECT_HEARTBEAT_TIMEOUT
        if activity_id is not None:
            options["activity_id"] = activity_id
        result = await workflow.execute_activity(activity_name, request, **options)
        if not isinstance(result, (ActivityResult, GateResult)):
            raise WorkflowProtocolError("activity result is malformed")
        return result

    async def _execute_gate(
        self,
        activity_name: str,
        request_type: type[GateRequest],
        payload: Mapping[str, Any],
        *,
        activity_id: str | None = None,
    ) -> GateResult:
        if self._pending_gate is None:
            request = self._gate_request(request_type, self._next_ordinal, payload)
            self._pending_gate = (activity_name, request, activity_id)
        else:
            pending_name, request, pending_id = self._pending_gate
            expected = self._gate_request(request_type, self._next_ordinal, payload)
            if pending_name != activity_name or request != expected or pending_id != activity_id:
                raise WorkflowProtocolError("pending gate recovery does not match its reservation")
        result = await self._execute(activity_name, request, activity_id=activity_id)
        if not isinstance(result, GateResult):
            raise WorkflowProtocolError("gate commit must be durable")
        self._pending_gate = None
        self._next_ordinal += 1
        if result.payload == {"accepted": False, "protocol_failure": True}:
            self._prior_sha256 = result.artifact_sha256
            raise WorkflowProtocolError("gate committed a protocol failure")
        return result

    async def _terminal_result(self, state: ExperimentGate, reason: str) -> ExperimentResult:
        assert self._input is not None
        await self._execute_gate(
            "instruct_eval.terminal_commit",
            GateRequest,
            _activity_payload(
                self._input,
                {
                    "terminal_gate": state.value,
                    "reason": reason,
                    "prior_sha256": self._prior_sha256,
                },
            ),
        )
        self._commit_terminal(state)
        return self._result()

    async def _finish_released(self) -> ExperimentResult:
        if self._release_payload is None or self._frozen_design_sha256 is None:
            raise WorkflowProtocolError("G5 release state is incomplete")
        g6 = await self._execute_gate(
            "instruct_eval.analysis",
            AnalysisRequest,
            {
                "gate": "G6",
                "design_sha256": self._frozen_design_sha256,
                "release_sha256": self._release_payload["release_sha256"],
            },
        )
        authorized = g6.payload.get("authorized")
        if not isinstance(authorized, bool):
            self._advance_gate(ExperimentGate.G6, g6)
            return await self._terminal_result(
                ExperimentGate.PROTOCOL_FAILURE,
                "G6 authorization result is invalid",
            )
        self._advance_gate(ExperimentGate.G6, g6)
        return await self._terminal_result(
            ExperimentGate.AUTHORIZED if authorized else ExperimentGate.COMPLETED_NOT_AUTHORIZED,
            "G6 authorized" if authorized else "G6 completed without authorization",
        )

    async def _claim_and_commit_g0(self, input_: ExperimentInput) -> ExperimentResult | None:
        fingerprint = input_.authorization.get("fingerprint_sha256")
        if not isinstance(fingerprint, str):
            raise WorkflowProtocolError("authorization fingerprint is missing")
        _digest(fingerprint, "authorization fingerprint")
        authorization = await self._execute(
            "instruct_eval.child_authorization_claim",
            self._activity_request(
                ChildAuthorizationClaimRequest,
                {
                    "claim_sha256": input_.claim_sha256,
                    "coverage_sha256": input_.coverage_sha256,
                    "fingerprint_sha256": fingerprint,
                },
            ),
        )
        if not isinstance(authorization, ActivityResult):
            raise WorkflowProtocolError("authorization claim is malformed")
        if not self._claim_authorization(authorization):
            return await self._terminal_result(
                ExperimentGate.DESIGN_REJECTED, "authorization rejected or preempted"
            )
        eligibility = await self._execute(
            "instruct_eval.eligibility",
            self._activity_request(EligibilityRequest, {"claim": input_.claim}),
        )
        if not isinstance(eligibility, ActivityResult):
            raise WorkflowProtocolError("eligibility result is malformed")
        eligibility_accepted = eligibility.payload.get("accepted") is True
        g0 = await self._execute_gate(
            "instruct_eval.g0_commit",
            GateRequest,
            {"gate": "G0", "eligibility": eligibility.payload, "accepted": eligibility_accepted},
        )
        if g0.payload.get("accepted") is not True:
            self._advance_gate(ExperimentGate.G0, g0)
            return await self._terminal_result(ExperimentGate.DESIGN_REJECTED, "G0 rejected")
        self._advance_gate(ExperimentGate.G0, g0)
        self._decision_revision_sha256 = g0.artifact_sha256
        self._outstanding_action, self._outstanding_sequence = "submit_design", 1
        return None

    async def _commit_design_gates(
        self, input_: ExperimentInput
    ) -> tuple[str, str, str] | ExperimentResult:
        await workflow.wait_condition(lambda: self._frozen_design_sha256 is not None)
        design_sha256 = self._frozen_design_sha256
        assert design_sha256 is not None
        proposal_sha256 = self._outstanding_proposal_sha256
        if proposal_sha256 is None:
            raise WorkflowProtocolError("submitted design proposal identity is unavailable")
        g0_record_sha256 = self._gate_artifacts["G0"]
        g1 = await self._execute_gate(
            "instruct_eval.design_commit",
            DesignCommitRequest,
            _activity_payload(
                input_,
                {
                    "gate": "G1",
                    "design_sha256": design_sha256,
                    "staged_design_sha256": design_sha256,
                    "proposal_sha256": proposal_sha256,
                    "g0_record_sha256": g0_record_sha256,
                },
            ),
        )
        if g1.payload.get("accepted") is False:
            self._advance_gate(ExperimentGate.G1, g1)
            return await self._terminal_result(ExperimentGate.DESIGN_REJECTED, "G1 rejected")
        self._advance_gate(ExperimentGate.G1, g1)
        g2 = await self._execute_gate(
            "instruct_eval.pre_run_validity",
            PreRunValidityRequest,
            _activity_payload(
                input_,
                {
                    "gate": "G2",
                    "design_sha256": design_sha256,
                    "proposal_sha256": proposal_sha256,
                    "g0_record_sha256": g0_record_sha256,
                },
            ),
        )
        if g2.payload.get("accepted") is False:
            self._advance_gate(ExperimentGate.G2, g2)
            return await self._terminal_result(ExperimentGate.DESIGN_REJECTED, "G2 rejected")
        self._advance_gate(ExperimentGate.G2, g2)
        self._decision_revision_sha256 = g2.artifact_sha256
        self._outstanding_action, self._outstanding_sequence = "approve_freeze", 2
        await workflow.wait_condition(lambda: self._outstanding_action is None)
        return design_sha256, proposal_sha256, g0_record_sha256

    def _record_map_lifecycle(
        self, prepared: ActivityResult
    ) -> tuple[str, str, list[str] | tuple[str, ...]]:
        required_map_fields = {
            "map_ref",
            "map_commitment",
            "tokens",
            "pre_map_input_hash",
            "authorization_rule_sha256",
        }
        if set(prepared.payload) != required_map_fields:
            raise WorkflowProtocolError("map lifecycle response is malformed")
        map_ref = prepared.payload["map_ref"]
        map_commitment = prepared.payload["map_commitment"]
        tokens = prepared.payload["tokens"]
        if (
            not isinstance(map_ref, str)
            or not isinstance(map_commitment, str)
            or not isinstance(tokens, (list, tuple))
            or len(tokens) != 10
            or len(set(tokens)) != 10
        ):
            raise WorkflowProtocolError(
                "freeze requires one map reference, commitment, and ten unique opaque tokens"
            )
        for value in (
            prepared.payload["pre_map_input_hash"],
            prepared.payload["authorization_rule_sha256"],
        ):
            _digest(value, "frozen map hash")
        self._map_ref = map_ref
        self._map_commitment = map_commitment
        self._trial_tokens = tuple(tokens)
        self._pre_map_input_hash = prepared.payload["pre_map_input_hash"]
        self._authorization_rule_sha256 = prepared.payload["authorization_rule_sha256"]
        return map_ref, map_commitment, tokens

    async def _prepare_freeze(
        self,
        input_: ExperimentInput,
        design_sha256: str,
        proposal_sha256: str,
        g0_record_sha256: str,
    ) -> tuple[str, str] | ExperimentResult:
        prepared = await self._execute(
            "instruct_eval.map_lifecycle",
            self._activity_request(
                MapLifecycleRequest,
                {
                    "design_sha256": design_sha256,
                    "candidate_instruction": input_.public_input["candidate_instruction"],
                    "fixture_manifest_hash": input_.public_input["fixture_manifest_hash"],
                },
            ),
            activity_id="instruct-eval-map-lifecycle",
        )
        if not isinstance(prepared, ActivityResult):
            raise WorkflowProtocolError("map lifecycle response is malformed")
        map_ref, map_commitment, tokens = self._record_map_lifecycle(prepared)
        freeze = await self._execute_gate(
            "instruct_eval.freeze",
            FreezeRequest,
            _activity_payload(
                input_,
                {
                    "commit": "freeze",
                    "design_sha256": design_sha256,
                    "proposal_sha256": proposal_sha256,
                    "g0_record_sha256": g0_record_sha256,
                    "map_ref": map_ref,
                    "map_commitment": map_commitment,
                    "tokens": tokens,
                    "pre_map_input_hash": self._pre_map_input_hash,
                    "authorization_rule_sha256": self._authorization_rule_sha256,
                    "authorization_sha256": canonical_hash(input_.authorization),
                },
            ),
        )
        self._prior_sha256 = freeze.artifact_sha256
        if (
            freeze.payload.get("accepted") is False
            or freeze.payload.get("design_sha256") != design_sha256
        ):
            return await self._terminal_result(
                ExperimentGate.DESIGN_REJECTED, "freeze binding failed"
            )
        self._gate = ExperimentGate.FROZEN
        return map_ref, design_sha256

    def _dispatch_trials(self, state: _TrialRun, map_ref: str, design_sha256: str) -> None:
        while (
            not state.terminal
            and not state.cancelled
            and len(state.outstanding) < 4
            and state.next_token < 10
        ):
            token = self._trial_tokens[state.next_token]
            state.next_token += 1
            state.accounting[token] = "started"
            state.outstanding[
                asyncio.create_task(
                    self._execute(
                        "instruct_eval.subject_trial",
                        self._activity_request(
                            SubjectTrialRequest,
                            {
                                "map_ref": map_ref,
                                "token": token,
                                "design_sha256": design_sha256,
                            },
                        ),
                        activity_id=f"instruct-eval-subject-trial-{token}",
                    )
                )
            ] = token

    async def _drain_trials(self, state: _TrialRun) -> None:
        for task in state.outstanding:
            task.cancel()
        tasks = tuple(state.outstanding)
        drained = await asyncio.gather(*tasks, return_exceptions=True)
        for task, completion in zip(tasks, drained, strict=True):
            token = state.outstanding[task]
            if isinstance(completion, ActivityResult):
                state.trials[token] = completion
                state.accounting[token] = (
                    "terminal"
                    if completion.payload.get("terminal") is True
                    or completion.payload.get("protocol_valid") is not True
                    else "result"
                )
            else:
                state.accounting[token] = "indeterminate"
        state.outstanding.clear()

    def _record_trial_completion(self, state: _TrialRun, task: Any) -> None:
        token = state.outstanding.pop(task)
        try:
            result = task.result()
        except asyncio.CancelledError:
            state.accounting[token] = "indeterminate"
            state.terminal = True
        except BaseException:
            state.accounting[token] = "indeterminate"
            state.terminal = True
        else:
            if not isinstance(result, ActivityResult):
                state.accounting[token] = "indeterminate"
                state.terminal = True
            elif (
                result.payload.get("protocol_valid") is not True
                or result.payload.get("terminal") is True
            ):
                state.trials[token] = result
                state.accounting[token] = "terminal"
                state.terminal = True
            else:
                state.trials[token] = result
                state.accounting[token] = "result"

    async def _collect_trials(self, map_ref: str, design_sha256: str) -> _TrialRun:
        state = _TrialRun()
        self._dispatch_trials(state, map_ref, design_sha256)
        try:
            while state.outstanding:
                done, _ = await workflow.wait(
                    tuple(state.outstanding),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in sorted(
                    done,
                    key=lambda completed: self._trial_tokens.index(state.outstanding[completed]),
                ):
                    self._record_trial_completion(state, task)
                if state.terminal:
                    await self._drain_trials(state)
                else:
                    self._dispatch_trials(state, map_ref, design_sha256)
        except asyncio.CancelledError:
            state.cancelled = True
            await self._drain_trials(state)
        return state

    def _g3_trial_data(
        self, state: _TrialRun
    ) -> tuple[tuple[dict[str, str], ...], list[ActivityResult], bool]:
        disposition = (
            "UNSCHEDULED_DUE_TO_CANCELLATION"
            if state.cancelled
            else "UNSCHEDULED_DUE_TO_TERMINAL"
            if state.terminal
            else "result"
        )
        for token in self._trial_tokens:
            state.accounting.setdefault(token, disposition)
        trial_accounting = tuple(
            {"token": token, "disposition": state.accounting[token]} for token in self._trial_tokens
        )
        accepted_trials = [
            state.trials[token]
            for token in self._trial_tokens
            if state.accounting[token] == "result"
        ]
        outcome_sha256s = tuple(result.result_sha256 for result in accepted_trials)
        exact_ten_accepted = (
            len(accepted_trials) == 10
            and len(set(outcome_sha256s)) == 10
            and all(result.payload.get("protocol_valid") is True for result in accepted_trials)
        )
        return trial_accounting, accepted_trials, exact_ten_accepted

    async def _commit_g3(
        self, input_: ExperimentInput, map_ref: str, design_sha256: str
    ) -> _G3Outcomes | ExperimentResult:
        state = await self._collect_trials(map_ref, design_sha256)
        trial_accounting, accepted_trials, exact_ten_accepted = self._g3_trial_data(state)
        outcomes = _deidentified_outcomes(accepted_trials) if len(accepted_trials) == 10 else []
        outcome_sha256s = tuple(result.result_sha256 for result in accepted_trials)
        verifier_passed = tuple(result.payload.get("verifier_passed") for result in accepted_trials)
        execution = await self._execute_gate(
            "instruct_eval.execution_commit",
            ExecutionCommitRequest,
            _activity_payload(
                input_,
                {
                    "gate": "G3",
                    "design_sha256": design_sha256,
                    "outcome_sha256s": outcome_sha256s,
                    "outcomes_sha256": canonical_hash({"outcome_sha256s": outcome_sha256s}),
                    "trial_accounting": trial_accounting,
                    "protocol_valid": exact_ten_accepted,
                    "verifier_passed": verifier_passed,
                    "accepted": exact_ten_accepted,
                },
            ),
        )
        if state.cancelled:
            self._advance_gate(ExperimentGate.G3, execution)
            return await self._terminal_result(ExperimentGate.CANCELED, "operator_cancelled")
        if not exact_ten_accepted or execution.payload.get("accepted") is not True:
            self._advance_gate(ExperimentGate.G3, execution)
            return await self._terminal_result(
                ExperimentGate.PROTOCOL_FAILURE, "G3 protocol failure"
            )
        self._advance_gate(ExperimentGate.G3, execution)
        return _G3Outcomes(outcomes, {outcome["blind_id"] for outcome in outcomes})

    async def _complete_after_g3(
        self, design_sha256: str, g3_outcomes: _G3Outcomes
    ) -> ExperimentResult:
        evidence = await self._execute(
            "instruct_eval.evidence_audit",
            self._activity_request(
                EvidenceAuditRequest,
                {"design_sha256": design_sha256, "outcomes": g3_outcomes.outcomes},
            ),
        )
        if not isinstance(evidence, ActivityResult):
            raise WorkflowProtocolError("G4 evidence is malformed")
        scored_directions = _blind_scores(
            evidence.payload.get("blind_scores"), g3_outcomes.blind_ids
        )
        authoritative_directions = sorted(
            (
                {"blind_id": outcome["blind_id"], "direction": outcome["direction_code"]}
                for outcome in g3_outcomes.outcomes
            ),
            key=lambda score: score["blind_id"],
        )
        scorer_agrees = (
            sorted(scored_directions, key=lambda score: score["blind_id"])
            == authoritative_directions
        )
        g4 = await self._execute_gate(
            "instruct_eval.post_run_validity",
            PostRunValidityRequest,
            {
                "gate": "G4",
                "evidence_sha256": evidence.result_sha256,
                "design_sha256": design_sha256,
                "blind_scores": scored_directions,
                "scorer_agrees": scorer_agrees,
            },
        )
        if g4.payload.get("accepted") is not True:
            self._advance_gate(ExperimentGate.G4, g4)
            return await self._terminal_result(
                ExperimentGate.SCORING_REJECTED, "G4 scorer disagreement"
            )
        self._advance_gate(ExperimentGate.G4, g4)
        self._release_blind_ids = frozenset(g3_outcomes.blind_ids)
        self._gate = ExperimentGate.RELEASING
        g5 = await self._execute_gate(
            "instruct_eval.release",
            ReleaseRequest,
            {"design_sha256": design_sha256},
            activity_id="instruct-eval-release-g5",
        )
        self._release_payload = _g5_release(g5.payload, g3_outcomes.blind_ids)
        self._advance_gate(ExperimentGate.G5, g5)
        return await self._finish_released()

    async def _run(self, input_: ExperimentInput) -> ExperimentResult:
        self._initialize(input_)
        assert self._input is not None
        input_ = self._input
        result = await self._claim_and_commit_g0(input_)
        if result is not None:
            return result
        design = await self._commit_design_gates(input_)
        if isinstance(design, ExperimentResult):
            return design
        design_sha256, proposal_sha256, g0_record_sha256 = design
        frozen = await self._prepare_freeze(
            input_, design_sha256, proposal_sha256, g0_record_sha256
        )
        if isinstance(frozen, ExperimentResult):
            return frozen
        map_ref, _ = frozen
        g3_outcomes = await self._commit_g3(input_, map_ref, design_sha256)
        if isinstance(g3_outcomes, ExperimentResult):
            return g3_outcomes
        return await self._complete_after_g3(design_sha256, g3_outcomes)

    async def _recover_pending_gate(self) -> None:
        if self._pending_gate is None:
            return
        activity_name, request, activity_id = self._pending_gate
        recovered = await self._execute(activity_name, request, activity_id=activity_id)
        if not isinstance(recovered, GateResult):
            raise WorkflowProtocolError("canceled gate recovery was not durable")
        self._pending_gate = None
        self._next_ordinal += 1
        self._prior_sha256 = recovered.artifact_sha256

    async def _handle_cancellation(self, input_: ExperimentInput) -> ExperimentResult:
        self._initialize(input_)
        if self._terminal_committed:
            return self._result()
        if self._gate in {ExperimentGate.RELEASING, ExperimentGate.G5, ExperimentGate.G6}:
            if self._gate is ExperimentGate.RELEASING:
                g5 = await self._execute_gate(
                    "instruct_eval.release",
                    ReleaseRequest,
                    {"design_sha256": self._frozen_design_sha256},
                    activity_id="instruct-eval-release-g5",
                )
                self._release_payload = _g5_release(g5.payload, set(self._release_blind_ids))
                self._advance_gate(ExperimentGate.G5, g5)
            return await self._finish_released()
        await self._recover_pending_gate()
        return await self._terminal_result(ExperimentGate.CANCELED, "operator_cancelled")

    async def _handle_protocol_failure(self, input_: ExperimentInput) -> ExperimentResult:
        self._initialize(input_)
        if not self._terminal_committed:
            return await self._terminal_result(ExperimentGate.PROTOCOL_FAILURE, "protocol_failure")
        return self._result()

    @workflow.run
    async def run(self, input_: ExperimentInput) -> ExperimentResult:
        try:
            return await self._run(input_)
        except ActivityError as error:
            cause = error.cause
            if not isinstance(cause, ApplicationError) or cause.type not in {
                "InstructEvalSemanticError",
                "InstructEvalIndeterminate",
            }:
                raise
            return await self._handle_protocol_failure(input_)
        except asyncio.CancelledError:
            return await self._handle_cancellation(input_)
        except WorkflowProtocolError:
            return await self._handle_protocol_failure(input_)

    def _result(self) -> ExperimentResult:
        assert self._input is not None
        return ExperimentResult(
            self._input.experiment_id,
            self._input.claim_sha256,
            self._gate.value,
            self._gate.value,
            self._gate_artifacts.get("G6"),
        )


@workflow.defn
class ExperimentCampaignWorkflow:
    """Bounded deterministic campaign fan-out with isolated per-claim results."""

    def __init__(self) -> None:
        self._input: CampaignInput | None = None
        self._state = "INITIALIZING"
        self._fingerprint_sha256: str | None = None
        self._claims: tuple[Mapping[str, Any], ...] = ()
        self._decision_revision_sha256 = "0" * 64
        self._prior_decision_sha256 = "0" * 64
        self._outstanding_action: str | None = None
        self._outstanding_sequence: int | None = None
        self._outstanding_proposal_sha256: str | None = None
        self._decomposition_approved = False
        self._cancelled = False
        self._cancel_artifact_sha256: str | None = None
        self._children: list[Any] = []

    @workflow.query
    def status(self) -> CampaignStatus:
        return CampaignStatus(
            self._input.campaign_id if self._input else "",
            self._state,
            self._fingerprint_sha256,
            len(self._claims),
            self._decision_revision_sha256,
            self._outstanding_action,
            self._outstanding_sequence,
            self._decision_revision_sha256,
            self._outstanding_proposal_sha256,
        )

    def _validate_decision(self, wire_json: Mapping[str, Any]) -> None:
        if self._input is None or self._state in {"COMPLETED", "CANCELED", "RELEASE_COMMITTING"}:
            raise WorkflowProtocolError("campaign is not accepting updates")
        try:
            wire = DecisionWire.from_json(wire_json)
            public_key = load_public_key(self._input.public_input["operator_public_key"])
            payload = wire.payload
            if payload.target_kind != "campaign" or payload.target_id != self._input.campaign_id:
                raise SigningError("cross-target decision")
            validate_decision_wire(
                wire,
                public_key,
                DecisionValidationParameters(
                    campaign_id=self._input.campaign_id,
                    target_kind="campaign",
                    target_id=self._input.campaign_id,
                    action=payload.action,
                    proposal_hash=payload.proposal_hash,
                    expected_revision_hash=self._decision_revision_sha256,
                    sequence=payload.sequence,
                ),
            )
        except (KeyError, SigningError, TypeError, ValueError) as error:
            raise WorkflowProtocolError("decision wire is invalid") from error
        if payload.action not in {"approve_decomposition", "cancel"}:
            raise WorkflowProtocolError("campaign decision action is not outstanding")
        if (
            payload.action == "approve_decomposition"
            and self._outstanding_action != "approve_decomposition"
        ):
            raise WorkflowProtocolError("decomposition is not outstanding")
        if payload.action == "cancel" and payload.sequence != (self._outstanding_sequence or 0):
            raise WorkflowProtocolError("cancel sequence is stale")

    @workflow.update(name="decision")
    async def decision(self, wire_json: Mapping[str, Any]) -> str:
        self._validate_decision(wire_json)
        assert self._input is not None
        claims: tuple[Mapping[str, Any], ...] | None = None
        wire = DecisionWire.from_json(wire_json)
        payload = wire.payload
        decision_payload = _proposal_decision_payload(
            self._input, wire, self._prior_decision_sha256
        )
        request = ProposalDecisionRequest(
            self._input.campaign_id,
            "campaign",
            canonical_hash({"campaign": self._input.campaign_id}),
            _request_hash(decision_payload),
            self._input.model_identity,
            self._input.runtime_identity,
            decision_payload,
        )
        result = await self._execute("instruct_eval.proposal_decision", request)
        _validate_published_decision(result, wire)
        if payload.action == "approve_decomposition":
            if result.payload.get("proposal_sha256") != payload.proposal_hash:
                raise WorkflowProtocolError(
                    "decomposition response is not bound to its signed proposal"
                )
            claims = self._extract_claims(result)
        self._decision_revision_sha256 = wire.hash
        self._prior_decision_sha256 = wire.hash
        self._outstanding_proposal_sha256 = payload.proposal_hash
        if payload.action == "cancel" and await self._release_is_irreversible():
            return "release_committed"
        if payload.action == "cancel":
            cancel = await self._commit_cancellation()
            self._cancel_artifact_sha256 = cancel.artifact_sha256
            self._cancelled = True
            self._state = "CANCELED"
            self._outstanding_action = None
            await self._cancel_active_children()
        else:
            if claims is None:
                raise WorkflowProtocolError("decomposition claims are missing")
            self._decomposition_approved = True
            self._claims = claims
            self._outstanding_action = None
            self._outstanding_sequence = 2
        return self._decision_revision_sha256

    @decision.validator
    def validate_decision_update(self, wire_json: Mapping[str, Any]) -> None:
        self._validate_decision(wire_json)

    def _initialize(self, input_: CampaignInput) -> None:
        if self._input is not None:
            if self._input != input_:
                raise WorkflowProtocolError("campaign input is immutable")
            return
        if not _CAMPAIGN_ID.fullmatch(input_.campaign_id):
            raise WorkflowProtocolError("campaign id must match campaign-[0-9]{32}")
        _identifier(input_.model_identity, "model identity")
        _identifier(input_.runtime_identity, "runtime identity")
        _digest(input_.coverage_sha256, "coverage hash")
        _public_packet(input_.public_input)
        self._input = CampaignInput(
            input_.campaign_id,
            input_.model_identity,
            input_.runtime_identity,
            json.loads(canonical_bytes(input_.public_input)),
            input_.coverage_sha256,
        )

    def _record_fingerprint(self, result: ActivityResult) -> None:
        fingerprint = result.payload.get("fingerprint_sha256", result.result_sha256)
        _digest(fingerprint, "fingerprint hash")
        if self._fingerprint_sha256 is not None and self._fingerprint_sha256 != fingerprint:
            raise WorkflowProtocolError("campaign fingerprint changed during initializing")
        self._fingerprint_sha256 = fingerprint
        self._state = "FINGERPRINT_READY"

    def _extract_claims(self, result: ActivityResult) -> tuple[Mapping[str, Any], ...]:
        assert self._input is not None
        raw_claims = result.payload.get("claims")
        if not isinstance(raw_claims, list) or not raw_claims:
            raise WorkflowProtocolError("decomposition must contain claims")
        claims: list[Mapping[str, Any]] = []
        hashes: set[str] = set()
        for claim in raw_claims:
            if (
                not isinstance(claim, Mapping)
                or claim.get("coverage_sha256") != self._input.coverage_sha256
            ):
                raise WorkflowProtocolError("claim is not bound to campaign coverage")
            _public_packet(claim)
            canonical = json.loads(canonical_bytes(claim))
            claim_hash = canonical_hash(canonical)
            if claim_hash in hashes:
                raise WorkflowProtocolError("campaign claims must be unique")
            hashes.add(claim_hash)
            claims.append(canonical)
        if len(claims) > 32:
            raise WorkflowProtocolError("campaign requires one to 32 coverage-bound claims")
        return tuple(sorted(claims, key=canonical_hash))

    async def _execute(self, name: str, request: Any) -> ActivityResult:
        result = await workflow.execute_activity(
            name,
            request,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            task_queue=_PRIVATE_TASK_QUEUE if name in _PRIVATE_ACTIVITY_NAMES else None,
            retry_policy=_DETERMINISTIC_RETRY,
            result_type=ActivityResult,
        )
        assert isinstance(result, ActivityResult)
        return result

    async def _commit_cancellation(self) -> GateResult:
        """Select the immutable cancellation branch before draining children."""
        assert self._input is not None
        payload = {
            "terminal_gate": "CANCELED",
            "reason": "operator_cancelled",
            "prior_sha256": "0" * 64,
        }
        request = TerminalCommitRequest(
            self._input.campaign_id,
            "campaign",
            canonical_hash({"campaign": self._input.campaign_id}),
            _request_hash(payload),
            self._input.model_identity,
            self._input.runtime_identity,
            payload,
            workflow.info().workflow_id,
            workflow.info().run_id,
            0,
            "0" * 64,
            self._decision_revision_sha256,
            "canonical",
        )
        result = await workflow.execute_activity(
            "instruct_eval.terminal_commit",
            request,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_DETERMINISTIC_RETRY,
            result_type=GateResult,
        )
        if not isinstance(result, GateResult):
            raise WorkflowProtocolError("cancellation terminal commit must be durable")
        return result

    async def _release_is_irreversible(self) -> bool:
        if not self._children:
            return False
        statuses = await asyncio.gather(
            *(handle.query("status") for handle in self._children),
            return_exceptions=True,
        )
        for status in statuses:
            gate = (
                status.get("gate") if isinstance(status, Mapping) else getattr(status, "gate", None)
            )
            if gate in {
                ExperimentGate.G5.value,
                ExperimentGate.G6.value,
                ExperimentGate.AUTHORIZED.value,
                ExperimentGate.COMPLETED_NOT_AUTHORIZED.value,
            }:
                return True
        return False

    async def _cancel_active_children(self) -> None:
        handles, self._children = self._children, []
        if handles:
            for handle in handles:
                handle.cancel()
            await asyncio.gather(*handles, return_exceptions=True)

    def _empty_result(self, input_: CampaignInput) -> CampaignResult:
        return CampaignResult(input_.campaign_id, self._fingerprint_sha256 or "", ())

    async def _await_decomposition(self, input_: CampaignInput) -> bool:
        try:
            fingerprint_payload = _fingerprint_payload(input_)
            fingerprint_request = FingerprintRequest(
                input_.campaign_id,
                "campaign",
                canonical_hash({"campaign": input_.campaign_id}),
                _request_hash(fingerprint_payload),
                input_.model_identity,
                input_.runtime_identity,
                fingerprint_payload,
            )
            fingerprint = await self._execute("instruct_eval.fingerprint", fingerprint_request)
            self._record_fingerprint(fingerprint)
            self._state = "WAITING_DECOMPOSITION"
            self._outstanding_action = "approve_decomposition"
            self._outstanding_sequence = 1
            await workflow.wait_condition(lambda: self._decomposition_approved or self._cancelled)
            return self._cancelled
        except Exception:
            if self._state != "CANCELED":
                self._state = "FINGERPRINT_FAILED"
            raise

    def _validate_issued_authorization(
        self, issued: ActivityResult, input_: CampaignInput, claim_hash: str
    ) -> Mapping[str, Any]:
        if set(issued.payload) != {
            "authorized",
            "experiment_id",
            "campaign_id",
            "claim_sha256",
            "coverage_sha256",
            "fingerprint_sha256",
        }:
            raise WorkflowProtocolError("child authorization issuance fields are invalid")
        experiment_id = issued.payload.get("experiment_id")
        if (
            not bool(issued.payload.get("authorized"))
            or not isinstance(experiment_id, str)
            or not re.fullmatch(r"experiment-[0-9]{32}", experiment_id)
        ):
            raise WorkflowProtocolError(
                "child authorization must issue an authoritative experiment id"
            )
        if (
            issued.payload.get("campaign_id") != input_.campaign_id
            or issued.payload.get("claim_sha256") != claim_hash
            or issued.payload.get("coverage_sha256") != input_.coverage_sha256
            or issued.payload.get("fingerprint_sha256") != self._fingerprint_sha256
        ):
            raise WorkflowProtocolError(
                "child authorization issuance does not bind its public inputs"
            )
        return issued.payload

    async def _issue_authorizations(
        self, input_: CampaignInput
    ) -> dict[str, Mapping[str, Any]] | None:
        authorizations: dict[str, Mapping[str, Any]] = {}
        for claim in self._claims:
            claim_hash = canonical_hash(claim)
            if self._cancelled:
                return None
            payload = {
                "claim_sha256": claim_hash,
                "coverage_sha256": input_.coverage_sha256,
                "fingerprint_sha256": self._fingerprint_sha256,
            }
            request = ChildAuthorizationIssueRequest(
                input_.campaign_id,
                "campaign",
                claim_hash,
                _request_hash(payload),
                input_.model_identity,
                input_.runtime_identity,
                payload,
            )
            issued = await self._execute("instruct_eval.child_authorization_issue", request)
            if self._cancelled:
                return None
            authorizations[claim_hash] = self._validate_issued_authorization(
                issued, input_, claim_hash
            )
        return authorizations

    async def _start_child_batch(
        self,
        input_: CampaignInput,
        base: Mapping[str, Any],
        batch: tuple[Mapping[str, Any], ...],
        authorizations: Mapping[str, Mapping[str, Any]],
    ) -> list[Any]:
        handles: list[Any] = []
        for claim in batch:
            claim_hash = canonical_hash(claim)
            authorization = authorizations[claim_hash]
            handles.append(
                await workflow.start_child_workflow(
                    InstructionExperimentWorkflow.run,
                    ExperimentInput(
                        input_.campaign_id,
                        authorization["experiment_id"],
                        claim_hash,
                        claim,
                        input_.coverage_sha256,
                        input_.model_identity,
                        input_.runtime_identity,
                        base,
                        authorization,
                    ),
                    id=authorization["experiment_id"],
                    parent_close_policy=ParentClosePolicy.REQUEST_CANCEL,
                )
            )
        return handles

    async def _run_child_batches(
        self,
        input_: CampaignInput,
        authorizations: Mapping[str, Mapping[str, Any]],
    ) -> list[CampaignClaimResult] | None:
        base = input_.public_input
        results: list[CampaignClaimResult] = []
        for index in range(0, len(self._claims), 4):
            if self._cancelled:
                return None
            batch = self._claims[index : index + 4]
            handles = await self._start_child_batch(input_, base, batch, authorizations)
            self._children.extend(handles)
            try:
                children = await asyncio.gather(*handles)
            except asyncio.CancelledError:
                if self._state != "CANCELED":
                    self._state = "CANCELED"
                raise
            if self._cancelled:
                return None
            for handle in handles:
                self._children.remove(handle)
            results.extend(
                CampaignClaimResult(
                    child.claim_sha256, child.status, child.terminal_gate, child.artifact_sha256
                )
                for child in children
            )
        return results

    @workflow.run
    async def run(self, input_: CampaignInput) -> CampaignResult:
        self._initialize(input_)
        assert self._input is not None
        input_ = self._input
        if await self._await_decomposition(input_):
            return self._empty_result(input_)
        self._state = "AUTHORIZING"
        authorizations = await self._issue_authorizations(input_)
        if authorizations is None:
            return self._empty_result(input_)
        self._state = "RUNNING"
        results = await self._run_child_batches(input_, authorizations)
        if results is None or self._cancelled:
            return self._empty_result(input_)
        self._state = "COMPLETED"
        return CampaignResult(
            input_.campaign_id,
            self._fingerprint_sha256 or "",
            tuple(sorted(results, key=lambda result: result.claim_sha256)),
        )
