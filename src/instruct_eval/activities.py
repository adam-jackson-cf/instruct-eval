"""Fail-closed, typed Temporal activities for the instruct-eval protocol."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any, ClassVar

from temporalio import activity
from temporalio.exceptions import ApplicationError

from .artifacts import ArtifactMode, ArtifactStore
from .coordination import (
    CoordinationError,
    CoordinationStore,
    GateCommitRequest,
    GateDisposition,
    GatePublicationRequest,
    InvocationDisposition,
)
from .coordination import (
    GateRequest as CoordinationGateRequest,
)
from .models import ProtocolError, canonical_bytes

_MAX_PACKET_BYTES = 1 << 20
_FORBIDDEN_KEYS = frozenset(
    {
        "private",
        "private_map",
        "private_join",
        "private_evidence",
        "blind_id_join",
        "blind_ids",
        "opaque_id",
        "authorization_id",
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


def _forbidden_public_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return normalized in _FORBIDDEN_KEYS or normalized.startswith(
        ("condition_", "preferred_direction_")
    )


class ActivitySemanticError(ProtocolError):
    """A request is invalid or cannot be safely authorized."""


class PreInvocationInfrastructureError(RuntimeError):
    """A preflight check failed before an invocation or gate was reserved."""


def _digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ActivitySemanticError(f"{label} must be a lowercase SHA-256 digest")


def _identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ActivitySemanticError(f"{label} must be a nonempty string")


def _public(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ActivitySemanticError("activity packet keys must be strings")
            if _forbidden_public_key(key):
                raise ActivitySemanticError(
                    "activity packets must not contain private joins or raw evidence"
                )
            _public(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _public(child)


def _packet(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, Mapping):
        raise ActivitySemanticError("activity payload must be a mapping")
    _public(value)
    try:
        encoded = canonical_bytes(value)
    except ProtocolError as error:
        raise ActivitySemanticError("activity payload is not canonicalizable") from error
    if len(encoded) > _MAX_PACKET_BYTES:
        raise ActivitySemanticError("activity payload exceeds the public packet bound")
    return encoded


def _private_subject_packet(value: Mapping[str, Any]) -> bytes:
    if not isinstance(value, Mapping):
        raise ActivitySemanticError("private subject result must be a mapping")
    try:
        encoded = canonical_bytes(value)
    except ProtocolError as error:
        raise ActivitySemanticError("private subject result is not canonicalizable") from error
    if len(encoded) > 64 * 1024 * 1024:
        raise ActivitySemanticError("private subject result exceeds its bound")
    return encoded


@dataclass(frozen=True)
class ActivityRequest:
    campaign_id: str
    experiment_id: str
    role_token: str
    frozen_input_sha256: str
    model_identity: str
    runtime_identity: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    _payload_bytes: ClassVar[bytes]
    _request_bytes: ClassVar[bytes]

    def __post_init__(self) -> None:
        for value, label in (
            (self.campaign_id, "campaign id"),
            (self.experiment_id, "experiment id"),
            (self.role_token, "role token"),
            (self.model_identity, "model identity"),
            (self.runtime_identity, "runtime identity"),
        ):
            _identifier(value, label)
        payload_bytes = _packet(self.payload)
        _digest(self.frozen_input_sha256, "frozen input hash")
        if sha256(payload_bytes).hexdigest() != self.frozen_input_sha256:
            raise ActivitySemanticError("frozen input hash does not match exact canonical payload")
        object.__setattr__(self, "_payload_bytes", payload_bytes)
        self._freeze_request()

    def _request_data(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "experiment_id": self.experiment_id,
            "role_token": self.role_token,
            "frozen_input_sha256": self.frozen_input_sha256,
            "model_identity": self.model_identity,
            "runtime_identity": self.runtime_identity,
            "payload": json.loads(self._payload_bytes),
        }

    def _freeze_request(self) -> None:
        object.__setattr__(self, "_request_bytes", _packet(self._request_data()))

    def invocation_key(self, purpose: str) -> str:
        _identifier(purpose, "purpose")
        return sha256(
            canonical_bytes({"purpose": purpose, "request": json.loads(self._request_bytes)})
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class GateRequest(ActivityRequest):
    workflow_id: str = ""
    run_id: str = ""
    ordinal: int = 0
    prior_record_sha256: str = ""
    expected_revision_sha256: str = ""
    branch_kind: str = ""

    def __post_init__(self) -> None:
        super(GateRequest, self).__post_init__()
        for value, label in (
            (self.workflow_id, "workflow id"),
            (self.run_id, "run id"),
            (self.branch_kind, "branch kind"),
        ):
            _identifier(value, label)
        if not isinstance(self.ordinal, int) or self.ordinal < 0:
            raise ActivitySemanticError("gate ordinal must be nonnegative")
        _digest(self.prior_record_sha256, "prior record hash")
        _digest(self.expected_revision_sha256, "expected revision hash")
        self._freeze_request()

    def _request_data(self) -> dict[str, Any]:
        return {
            **super(GateRequest, self)._request_data(),
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "ordinal": self.ordinal,
            "prior_record_sha256": self.prior_record_sha256,
            "expected_revision_sha256": self.expected_revision_sha256,
            "branch_kind": self.branch_kind,
        }


@dataclass(frozen=True, slots=True)
class ActivityResult:
    invocation_key: str
    result_sha256: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _digest(self.invocation_key, "invocation key")
        if self.result_sha256 != sha256(_packet(self.payload)).hexdigest():
            raise ActivitySemanticError("result hash does not match public payload")


@dataclass(frozen=True, slots=True)
class GatePublication:
    """The exact public artifact a gate may materialize and publish."""

    payload: Mapping[str, Any]
    final_artifact_path: str | Path
    artifact_bytes: bytes
    artifact_sha256: str

    def __post_init__(self) -> None:
        payload_bytes = _packet(self.payload)
        _digest(self.artifact_sha256, "artifact hash")
        if not isinstance(self.artifact_bytes, bytes) or self.artifact_bytes != payload_bytes:
            raise ActivitySemanticError(
                "artifact bytes do not match exact canonical public payload"
            )
        if sha256(self.artifact_bytes).hexdigest() != self.artifact_sha256:
            raise ActivitySemanticError("artifact hash does not match artifact bytes")


def _release_preferred_directions(payload: Mapping[str, Any]) -> None:
    preferred = payload["preferred_directions"]
    if (
        not isinstance(preferred, Mapping)
        or set(preferred) != {"core-1", "core-2", "negative-control"}
        or any(not isinstance(value, str) or not value for value in preferred.values())
    ):
        raise ActivitySemanticError("G5 release preferred directions are invalid")


def _release_authorization_rule(payload: Mapping[str, Any]) -> None:
    expected_rule = {
        "schema": "instruct-eval-authorization-rule-v1",
        "core_scenarios": ["core-1", "core-2"],
        "negative_control_scenario": "negative-control",
        "core_comparison": "preferred_count_B_strictly_greater_than_A",
        "negative_control_comparison": "both_subjects_match_preferred_direction",
    }
    if payload["authorization_rule"] != expected_rule:
        raise ActivitySemanticError("G5 release authorization rule is invalid")


def _release_assignment_records(assignments: Any) -> list[tuple[str, str, str, str]]:
    if not isinstance(assignments, list) or len(assignments) != 10:
        raise ActivitySemanticError("G5 release must contain exactly ten assignments")
    records: list[tuple[str, str, str, str]] = []
    for record in assignments:
        if not isinstance(record, Mapping) or set(record) != {
            "blind_id",
            "scenario",
            "condition",
            "direction",
        }:
            raise ActivitySemanticError("G5 release assignment is invalid")
        values = tuple(record[key] for key in ("blind_id", "scenario", "condition", "direction"))
        if not all(isinstance(value, str) and value for value in values):
            raise ActivitySemanticError("G5 release assignment fields must be nonempty text")
        records.append(values)
    return records


def _validate_release_assignment_design(records: list[tuple[str, str, str, str]]) -> None:
    expected = {
        ("core-1", "A"),
        ("core-1", "B"),
        ("core-2", "A"),
        ("core-2", "B"),
        ("negative-control", "A"),
        ("negative-control", "B"),
    }
    if (
        records != sorted(records)
        or len({record[0] for record in records}) != 10
        or {(record[1], record[2]) for record in records} != expected
    ):
        raise ActivitySemanticError("G5 release assignments do not cover the exact design")
    counts = {
        (scenario, condition): sum(record[1:3] == (scenario, condition) for record in records)
        for scenario, condition in expected
    }
    if any(
        counts[(scenario, condition)] != (1 if scenario == "negative-control" else 2)
        for scenario, condition in expected
    ):
        raise ActivitySemanticError("G5 release assignment multiplicity is invalid")


def _release_packet(payload: Mapping[str, Any]) -> bytes:
    fields = {"assignments", "preferred_directions", "authorization_rule", "release_sha256"}
    if not isinstance(payload, Mapping) or set(payload) != fields:
        raise ActivitySemanticError("G5 release payload is not exact")
    _digest(payload["release_sha256"], "release hash")
    _release_preferred_directions(payload)
    _release_authorization_rule(payload)
    records = _release_assignment_records(payload["assignments"])
    _validate_release_assignment_design(records)
    release = {key: value for key, value in payload.items() if key != "release_sha256"}
    if sha256(canonical_bytes(release)).hexdigest() != payload["release_sha256"]:
        raise ActivitySemanticError("G5 release hash does not match exact release packet")
    return canonical_bytes(payload)


@dataclass(frozen=True, slots=True)
class ReleasePublication:
    """The sole post-G5 public artifact: a validated private-release commitment."""

    payload: Mapping[str, Any]
    final_artifact_path: str | Path
    artifact_bytes: bytes
    artifact_sha256: str

    def __post_init__(self) -> None:
        payload_bytes = _release_packet(self.payload)
        _digest(self.artifact_sha256, "artifact hash")
        if not isinstance(self.artifact_bytes, bytes) or self.artifact_bytes != payload_bytes:
            raise ActivitySemanticError(
                "artifact bytes do not match exact canonical G5 release payload"
            )
        if sha256(self.artifact_bytes).hexdigest() != self.artifact_sha256:
            raise ActivitySemanticError("artifact hash does not match artifact bytes")


@dataclass(frozen=True, slots=True)
class GateResult:
    workflow_id: str
    run_id: str
    ordinal: int
    artifact_path: str
    artifact_sha256: str
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class TerminalizeRequest:
    invocation_key: str
    owner_epoch: int

    def __post_init__(self) -> None:
        _digest(self.invocation_key, "invocation key")
        if not isinstance(self.owner_epoch, int) or self.owner_epoch < 1:
            raise ActivitySemanticError("owner epoch must be positive")


@dataclass(frozen=True, slots=True)
class TerminalizeResult:
    invocation_key: str
    terminalized: bool


@dataclass(frozen=True, slots=True)
class FingerprintRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class ProposalDecisionRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class DecompositionRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class EligibilityRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class ChildAuthorizationIssueRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class ChildAuthorizationClaimRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class DesignDraftRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class DesignCommitRequest(GateRequest):
    pass


@dataclass(frozen=True, slots=True)
class G0CommitRequest(GateRequest):
    pass


@dataclass(frozen=True, slots=True)
class PreRunValidityRequest(GateRequest):
    pass


@dataclass(frozen=True, slots=True)
class FreezeRequest(GateRequest):
    pass


@dataclass(frozen=True, slots=True)
class ExecutionCommitRequest(GateRequest):
    pass


@dataclass(frozen=True, slots=True)
class SubjectTrialRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class EvidenceAuditRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class PostRunValidityRequest(GateRequest):
    pass


@dataclass(frozen=True, slots=True)
class MapLifecycleRequest(ActivityRequest):
    pass


@dataclass(frozen=True, slots=True)
class ReleaseRequest(GateRequest):
    pass


@dataclass(frozen=True, slots=True)
class AnalysisRequest(GateRequest):
    pass


@dataclass(frozen=True, slots=True)
class TerminalCommitRequest(GateRequest):
    pass


@dataclass(frozen=True, slots=True)
class ActivityInvocationContext:
    """The durable invocation state shared by execution and result commitment."""

    purpose: str
    request: ActivityRequest
    key: str
    input_bytes: bytes
    owner_epoch: int
    execute: Any


class ActivityBackend(ABC):
    """Complete concrete backend; each public endpoint has one typed operation."""

    @abstractmethod
    def fingerprint(self, request: FingerprintRequest) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def proposal_decision(self, request: ProposalDecisionRequest) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def decomposition(self, request: DecompositionRequest) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def eligibility(self, request: EligibilityRequest) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def child_authorization_issue(
        self, request: ChildAuthorizationIssueRequest
    ) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def child_authorization_claim(
        self, request: ChildAuthorizationClaimRequest
    ) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def design_draft(self, request: DesignDraftRequest) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def design_commit(self, request: DesignCommitRequest) -> GatePublication | Any:
        raise NotImplementedError

    @abstractmethod
    def g0_commit(self, request: G0CommitRequest) -> GatePublication | Any:
        raise NotImplementedError

    @abstractmethod
    def pre_run_validity(self, request: PreRunValidityRequest) -> GatePublication | Any:
        raise NotImplementedError

    @abstractmethod
    def freeze(self, request: FreezeRequest) -> GatePublication | Any:
        raise NotImplementedError

    @abstractmethod
    def execution_commit(self, request: ExecutionCommitRequest) -> GatePublication | Any:
        raise NotImplementedError

    @abstractmethod
    def subject_trial(self, request: SubjectTrialRequest) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def finalize_subject_trial(
        self, request: SubjectTrialRequest, outcome: Mapping[str, Any]
    ) -> Any:
        raise NotImplementedError

    @abstractmethod
    def evidence_audit(self, request: EvidenceAuditRequest) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def post_run_validity(self, request: PostRunValidityRequest) -> GatePublication | Any:
        raise NotImplementedError

    @abstractmethod
    def map_lifecycle(self, request: MapLifecycleRequest) -> Mapping[str, Any] | Any:
        raise NotImplementedError

    @abstractmethod
    def release(self, request: ReleaseRequest) -> GatePublication | ReleasePublication | Any:
        raise NotImplementedError

    @abstractmethod
    def analysis(self, request: AnalysisRequest) -> GatePublication | Any:
        raise NotImplementedError

    @abstractmethod
    def terminal_commit(self, request: TerminalCommitRequest) -> GatePublication | Any:
        raise NotImplementedError


class InstructEvalActivities:
    """Named activities backed by typed execution and durable CAS protocols."""

    def __init__(self, coordination: CoordinationStore, backend: ActivityBackend) -> None:
        if not isinstance(backend, ActivityBackend) or inspect.isabstract(backend):
            raise TypeError("activities require a complete concrete ActivityBackend")
        self._coordination = coordination
        self._backend = backend

    async def _preflight(self, endpoint: str, request: ActivityRequest) -> None:
        check = getattr(self._backend, f"preflight_{endpoint}", None)
        if check is not None:
            value = check(request)
            if inspect.isawaitable(value):
                await value

    @staticmethod
    def _reconstruct(request: ActivityRequest) -> ActivityRequest:
        return type(request)(**json.loads(request._request_bytes))

    def _reserve_activity_invocation(
        self, purpose: str, request: ActivityRequest
    ) -> tuple[str, bytes, Any]:
        try:
            input_bytes = _packet(
                {"purpose": purpose, "request": json.loads(request._request_bytes)}
            )
            key = request.invocation_key(purpose)
            reservation = self._coordination.reserve_invocation(key, input_bytes)
        except (ActivitySemanticError, CoordinationError) as error:
            raise ApplicationError(
                str(error), type="InstructEvalSemanticError", non_retryable=True
            ) from error
        return key, input_bytes, reservation

    async def _invoke(self, purpose: str, request: ActivityRequest, execute: Any) -> ActivityResult:
        canonical_request = self._reconstruct(request)
        await self._preflight(purpose, canonical_request)
        key, input_bytes, reservation = self._reserve_activity_invocation(
            purpose, canonical_request
        )
        if reservation.disposition is InvocationDisposition.RESULT_RECOVERED:
            return await self._finalize_committed_subject(
                purpose, canonical_request, key, reservation.result_bytes
            )
        if reservation.disposition is InvocationDisposition.INDETERMINATE:
            raise ApplicationError(
                "invocation was terminalized as indeterminate",
                type="InstructEvalIndeterminate",
                non_retryable=True,
            )
        if reservation.disposition is InvocationDisposition.IN_FLIGHT:
            self._terminalize_stale_invocation(key)
            raise ApplicationError(
                "invocation was terminalized as indeterminate",
                type="InstructEvalIndeterminate",
                non_retryable=True,
            )
        if reservation.owner_epoch is None:
            raise ApplicationError(
                "invocation reservation has no owner epoch",
                type="InstructEvalSemanticError",
                non_retryable=True,
            )
        invocation = ActivityInvocationContext(
            purpose,
            canonical_request,
            key,
            input_bytes,
            reservation.owner_epoch,
            execute,
        )
        return await self._execute_activity_invocation(invocation)

    async def _execute_activity_invocation(
        self, invocation: ActivityInvocationContext
    ) -> ActivityResult:
        heartbeat = self._start_subject_heartbeat(invocation.purpose)
        try:
            committed_bytes = await self._commit_activity_result(invocation)
            return await self._finalize_committed_subject(
                invocation.purpose,
                invocation.request,
                invocation.key,
                committed_bytes,
            )
        finally:
            await self._stop_subject_heartbeat(heartbeat)

    def _start_subject_heartbeat(self, purpose: str) -> asyncio.Task[None] | None:
        if purpose != "subject_trial":
            return None
        return asyncio.create_task(self._heartbeat_subject())

    async def _heartbeat_subject(self) -> None:
        while True:
            try:
                activity.heartbeat()
            except RuntimeError:
                return
            await asyncio.sleep(1)

    @staticmethod
    async def _stop_subject_heartbeat(heartbeat: asyncio.Task[None] | None) -> None:
        if heartbeat is not None:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)

    async def _commit_activity_result(self, invocation: ActivityInvocationContext) -> bytes | None:
        try:
            value = invocation.execute(invocation.request)
            if inspect.isawaitable(value):
                value = await value
            result_bytes = self._activity_result_bytes(invocation.purpose, value)
            commit = self._activity_result_commit(invocation.purpose)
            committed = commit(
                invocation.key,
                invocation.owner_epoch,
                result_bytes,
            )
            committed_bytes = committed.result_bytes
            if isinstance(committed_bytes, bytes):
                return committed_bytes
            if committed_bytes is None:
                return None
            raise ActivitySemanticError("committed invocation result is invalid")
        except Exception as error:
            return self._recover_activity_result(
                invocation.key,
                invocation.input_bytes,
                invocation.owner_epoch,
                error,
            )

    @staticmethod
    def _activity_result_bytes(purpose: str, value: Any) -> bytes:
        return _private_subject_packet(value) if purpose == "subject_trial" else _packet(value)

    def _activity_result_commit(self, purpose: str) -> Any:
        if purpose == "subject_trial":
            return self._coordination.commit_private_subject_result
        return self._coordination.commit_result

    def _recover_activity_result(
        self, key: str, input_bytes: bytes, owner_epoch: int, error: Exception
    ) -> bytes | None:
        recovered = self._coordination.reserve_invocation(key, input_bytes)
        if recovered.disposition is InvocationDisposition.RESULT_RECOVERED:
            return recovered.result_bytes
        self._terminalize_after_invocation(key, owner_epoch)
        raise ApplicationError(
            "invocation outcome is indeterminate",
            type="InstructEvalIndeterminate",
            non_retryable=True,
        ) from error

    async def _finalize_committed_subject(
        self, purpose: str, request: ActivityRequest, key: str, result_bytes: bytes | None
    ) -> ActivityResult:
        """Materialize private subject evidence only after its result is durable."""
        if purpose != "subject_trial":
            return self._decoded(key, result_bytes)
        if result_bytes is None:
            raise ApplicationError(
                "committed subject result is missing",
                type="InstructEvalSemanticError",
                non_retryable=True,
            )
        try:
            committed_payload = json.loads(result_bytes)
            if (
                not isinstance(committed_payload, Mapping)
                or _private_subject_packet(committed_payload) != result_bytes
            ):
                raise ActivitySemanticError("committed subject result is invalid")
        except (json.JSONDecodeError, ActivitySemanticError) as error:
            raise ApplicationError(
                "committed subject result is invalid",
                type="InstructEvalSemanticError",
                non_retryable=True,
            ) from error
        subject_request = (
            request
            if isinstance(request, SubjectTrialRequest)
            else SubjectTrialRequest(**json.loads(request._request_bytes))
        )
        public_payload = committed_payload
        if (
            set(committed_payload) == {"outcome", "private_artifacts"}
            and isinstance(committed_payload["outcome"], Mapping)
            and isinstance(committed_payload["private_artifacts"], Mapping)
        ):
            public_payload = committed_payload["outcome"]
        try:
            finalized = self._backend.finalize_subject_trial(subject_request, committed_payload)
            if inspect.isawaitable(finalized):
                await finalized
        except Exception as error:
            raise ApplicationError(
                "committed subject result finalization failed",
                type="InstructEvalFinalizationError",
                non_retryable=False,
            ) from error
        return ActivityResult(
            key,
            sha256(canonical_bytes(public_payload)).hexdigest(),
            public_payload,
        )

    async def _gate(self, endpoint: str, request: GateRequest, execute: Any) -> GateResult:
        canonical_request = self._reconstruct(request)
        if not isinstance(canonical_request, GateRequest):
            raise ApplicationError(
                "gate request reconstruction failed",
                type="InstructEvalSemanticError",
                non_retryable=True,
            )
        await self._preflight(endpoint, canonical_request)
        try:
            record = _packet(
                {"purpose": endpoint, "request": json.loads(canonical_request._request_bytes)}
            )
            reservation = self._reserve_gate(canonical_request, record)
            return await self._complete_gate(
                endpoint, canonical_request, record, reservation, execute
            )
        except (ActivitySemanticError, CoordinationError) as error:
            raise ApplicationError(
                str(error), type="InstructEvalSemanticError", non_retryable=True
            ) from error

    def _reserve_gate(self, request: GateRequest, record: bytes) -> Any:
        return self._coordination.reserve_gate(
            CoordinationGateRequest(
                request.workflow_id,
                request.run_id,
                request.ordinal,
                request.prior_record_sha256,
                request.expected_revision_sha256,
                request.branch_kind,
                record,
            )
        )

    async def _complete_gate(
        self, endpoint: str, request: GateRequest, record: bytes, reservation: Any, execute: Any
    ) -> GateResult:
        release = endpoint == "release"
        if reservation.disposition is GateDisposition.PUBLISHED:
            return self._published_gate(reservation, release=release)
        epoch, published = self._begin_gate_commit(request, reservation, release)
        if published is not None:
            return published
        publication = await self._gate_publication(endpoint, request, record, execute)
        self._materialize_protocol_failure(publication)
        ledger_bytes, ledger_path, ledger_sha256 = self._publish_ledger(
            request,
            endpoint,
            reservation.record_input_bytes,
            publication,
        )
        published_reservation = self._coordination.publish_gate(
            GatePublicationRequest(
                request.workflow_id,
                request.run_id,
                request.ordinal,
                request.expected_revision_sha256,
                epoch,
                ledger_path,
                ledger_bytes,
                ledger_sha256,
            )
        )
        payload = self._decode_published_payload(publication.artifact_bytes, release=release)
        return GateResult(
            request.workflow_id,
            request.run_id,
            request.ordinal,
            str(published_reservation.publication_path or ledger_path),
            published_reservation.publication_sha256 or ledger_sha256,
            payload,
        )

    def _begin_gate_commit(
        self, request: GateRequest, reservation: Any, release: bool
    ) -> tuple[int, GateResult | None]:
        epoch = reservation.owner_epoch
        if epoch is None:
            raise CoordinationError("gate reservation has no owner epoch")
        if reservation.disposition is GateDisposition.COMMITTING:
            return epoch, None
        committed = self._coordination.begin_release_commit(
            GateCommitRequest(
                request.workflow_id,
                request.run_id,
                request.ordinal,
                request.expected_revision_sha256,
                epoch,
            )
        )
        if committed.disposition is GateDisposition.PUBLISHED:
            return epoch, self._published_gate(committed, release=release)
        if committed.owner_epoch is None:
            raise CoordinationError("release commit has no owner epoch")
        return committed.owner_epoch, None

    async def _gate_publication(
        self, endpoint: str, request: GateRequest, record: bytes, execute: Any
    ) -> GatePublication | ReleasePublication:
        invocation = self._coordination.reserve_gate_invocation(record)
        release = endpoint == "release"
        if invocation.disposition is InvocationDisposition.RESULT_RECOVERED:
            return self._recovered_gate_publication(invocation.result_bytes, release=release)
        if (
            invocation.disposition is InvocationDisposition.ACQUIRED
            and invocation.owner_epoch is not None
        ):
            return await self._execute_gate_invocation(endpoint, request, invocation, execute)
        self._terminalize_stale_invocation(invocation.invocation_key)
        raise ApplicationError(
            "gate role invocation is indeterminate",
            type="InstructEvalIndeterminate",
            non_retryable=True,
        )

    async def _execute_gate_invocation(
        self, endpoint: str, request: GateRequest, invocation: Any, execute: Any
    ) -> GatePublication | ReleasePublication:
        try:
            publication = await self._backend_gate_publication(endpoint, request, execute)
            committed = self._coordination.commit_result(
                invocation.invocation_key,
                invocation.owner_epoch,
                self._encode_gate_publication(publication),
            )
            return self._recovered_gate_publication(
                committed.result_bytes, release=endpoint == "release"
            )
        except Exception:
            self._terminalize_after_invocation(invocation.invocation_key, invocation.owner_epoch)
            raise

    async def _backend_gate_publication(
        self, endpoint: str, request: GateRequest, execute: Any
    ) -> GatePublication | ReleasePublication:
        try:
            publication = execute(request)
            if inspect.isawaitable(publication):
                publication = await publication
            if not isinstance(publication, GatePublication | ReleasePublication) or (
                isinstance(publication, ReleasePublication) and endpoint != "release"
            ):
                raise ActivitySemanticError("gate backend returned an invalid publication type")
            return publication
        except ProtocolError:
            return self._protocol_failure_publication(request, endpoint)

    def _protocol_failure_publication(self, request: GateRequest, endpoint: str) -> GatePublication:
        payload = {"accepted": False, "protocol_failure": True}
        artifact_bytes = canonical_bytes(payload)
        artifacts = getattr(self._backend, "_artifacts", None)
        if not isinstance(artifacts, ArtifactStore):
            raise ActivitySemanticError("gate backend has no immutable artifact store")
        relative_path = (
            f"campaigns/{request.campaign_id}/{request.experiment_id}/"
            f"{request.workflow_id}/{request.run_id}/protocol-failures/"
            f"{request.ordinal:03d}-{endpoint}.json"
        )
        return GatePublication(
            payload,
            artifacts.path_for(relative_path, ArtifactMode.PUBLIC),
            artifact_bytes,
            sha256(artifact_bytes).hexdigest(),
        )

    def _materialize_protocol_failure(
        self, publication: GatePublication | ReleasePublication
    ) -> None:
        if publication.payload != {"accepted": False, "protocol_failure": True}:
            return
        artifacts = getattr(self._backend, "_artifacts", None)
        if not isinstance(artifacts, ArtifactStore):
            raise ActivitySemanticError("gate backend has no immutable artifact store")
        relative_path = Path(publication.final_artifact_path).relative_to(artifacts.root)
        artifacts.publish_bytes(relative_path, publication.artifact_bytes, ArtifactMode.PUBLIC)

    @staticmethod
    def _encode_gate_publication(publication: GatePublication | ReleasePublication) -> bytes:
        return _packet(
            {
                "artifact_bytes_hex": publication.artifact_bytes.hex(),
                "artifact_sha256": publication.artifact_sha256,
                "final_artifact_path": str(publication.final_artifact_path),
            }
        )

    def _recovered_gate_publication(
        self, result_bytes: bytes | None, *, release: bool
    ) -> GatePublication | ReleasePublication:
        if result_bytes is None:
            raise ActivitySemanticError("committed gate invocation has no result")
        try:
            value = json.loads(result_bytes)
            if (
                not isinstance(value, dict)
                or _packet(value) != result_bytes
                or set(value) != {"artifact_bytes_hex", "artifact_sha256", "final_artifact_path"}
            ):
                raise ValueError
            artifact_bytes = bytes.fromhex(value["artifact_bytes_hex"])
            artifact_sha256 = value["artifact_sha256"]
            artifact_path = value["final_artifact_path"]
            if not isinstance(artifact_path, str) or not artifact_path:
                raise ValueError
            payload = self._decode_published_payload(artifact_bytes, release=release)
            publication = (
                ReleasePublication
                if release and payload != {"accepted": False, "protocol_failure": True}
                else GatePublication
            )
            return publication(payload, artifact_path, artifact_bytes, artifact_sha256)
        except (KeyError, TypeError, ValueError, ActivitySemanticError) as error:
            raise ActivitySemanticError("committed gate invocation is invalid") from error

    def _publish_ledger(
        self,
        request: GateRequest,
        endpoint: str,
        record_input_bytes: bytes,
        publication: GatePublication | ReleasePublication,
    ) -> tuple[bytes, Path, str]:
        artifacts = getattr(self._backend, "_artifacts", None)
        if not isinstance(artifacts, ArtifactStore):
            raise ActivitySemanticError("gate backend has no immutable artifact store")
        record = {
            "schema": "instruct-eval-ledger-v1",
            "ordinal": request.ordinal,
            "gate": endpoint,
            "prior_record_sha256": request.prior_record_sha256,
            "workflow_id": request.workflow_id,
            "run_id": request.run_id,
            "reservation_sha256": sha256(record_input_bytes).hexdigest(),
            "reservation": json.loads(record_input_bytes),
            "public_artifact_sha256": publication.artifact_sha256,
            "public_artifact_path": str(publication.final_artifact_path),
            "public_payload_sha256": sha256(publication.artifact_bytes).hexdigest(),
            "status": "PUBLISHED",
        }
        ledger_bytes = canonical_bytes(record)
        ledger_sha256 = sha256(ledger_bytes).hexdigest()
        relative_path = (
            f"campaigns/{request.campaign_id}/{request.experiment_id}/"
            f"{request.workflow_id}/{request.run_id}/ledger/"
            f"{request.ordinal:03d}-{endpoint}.json"
        )
        ledger_path = artifacts.path_for(relative_path, ArtifactMode.PUBLIC)
        artifacts.publish_bytes(relative_path, ledger_bytes, ArtifactMode.PUBLIC)
        return ledger_bytes, ledger_path, ledger_sha256

    def _published_gate(self, reservation: Any, *, release: bool) -> GateResult:
        if reservation.publication_path is None or reservation.publication_sha256 is None:
            raise ApplicationError(
                "published gate has no ledger", type="InstructEvalSemanticError", non_retryable=True
            )
        try:
            ledger_bytes = reservation.publication_path.read_bytes()
            if sha256(ledger_bytes).hexdigest() != reservation.publication_sha256:
                raise ValueError
            ledger = json.loads(ledger_bytes)
            expected = {
                "schema",
                "ordinal",
                "gate",
                "prior_record_sha256",
                "workflow_id",
                "run_id",
                "reservation_sha256",
                "reservation",
                "public_artifact_sha256",
                "public_artifact_path",
                "public_payload_sha256",
                "status",
            }
            if (
                not isinstance(ledger, dict)
                or set(ledger) != expected
                or canonical_bytes(ledger) != ledger_bytes
                or ledger["schema"] != "instruct-eval-ledger-v1"
                or ledger["status"] != "PUBLISHED"
                or ledger["workflow_id"] != reservation.workflow_id
                or ledger["run_id"] != reservation.run_id
                or ledger["ordinal"] != reservation.ordinal
                or ledger["prior_record_sha256"] != reservation.prior_record_sha256
                or ledger["reservation_sha256"]
                != sha256(reservation.record_input_bytes).hexdigest()
                or canonical_bytes(ledger["reservation"]) != reservation.record_input_bytes
            ):
                raise ValueError
            artifact_path = Path(ledger["public_artifact_path"])
            artifact_bytes = artifact_path.read_bytes()
            if (
                artifact_path.is_symlink()
                or sha256(artifact_bytes).hexdigest() != ledger["public_artifact_sha256"]
                or ledger["public_artifact_sha256"] != ledger["public_payload_sha256"]
            ):
                raise ValueError
            payload = self._decode_published_payload(artifact_bytes, release=release)
        except (OSError, ValueError, TypeError, ActivitySemanticError) as error:
            raise ApplicationError(
                "published gate ledger is invalid",
                type="InstructEvalSemanticError",
                non_retryable=True,
            ) from error
        return GateResult(
            reservation.workflow_id,
            reservation.run_id,
            reservation.ordinal,
            str(reservation.publication_path),
            reservation.publication_sha256,
            payload,
        )

    @staticmethod
    def _decode_published_payload(artifact_bytes: bytes, *, release: bool) -> Mapping[str, Any]:
        payload = json.loads(artifact_bytes)
        if not isinstance(payload, dict) or canonical_bytes(payload) != artifact_bytes:
            raise ActivitySemanticError(
                "published gate artifact is not exact canonical public JSON"
            )
        if payload == {"accepted": False, "protocol_failure": True}:
            _packet(payload)
        elif release:
            _release_packet(payload)
        else:
            _packet(payload)
        return payload

    def _terminalize_stale_invocation(self, key: str) -> None:
        """Terminalize a recovered STARTED journal before any replacement execution."""
        with contextlib.suppress(CoordinationError):
            self._coordination.terminalize_indeterminate(key, 1)

    def _terminalize_after_invocation(self, key: str, owner_epoch: int) -> None:
        with contextlib.suppress(CoordinationError):
            self._coordination.terminalize_indeterminate(key, owner_epoch)

    def _decoded(self, key: str, result_bytes: bytes | None) -> ActivityResult:
        if result_bytes is None:
            raise ApplicationError(
                "committed invocation has no result",
                type="InstructEvalSemanticError",
                non_retryable=True,
            )
        try:
            value = json.loads(result_bytes)
            if not isinstance(value, dict):
                raise ValueError
            return ActivityResult(key, sha256(result_bytes).hexdigest(), value)
        except (ValueError, TypeError, ActivitySemanticError) as error:
            raise ApplicationError(
                "committed result is invalid", type="InstructEvalSemanticError", non_retryable=True
            ) from error

    @activity.defn(name="instruct_eval.fingerprint")
    async def fingerprint(self, request: FingerprintRequest) -> ActivityResult:
        return await self._invoke("fingerprint", request, self._backend.fingerprint)

    @activity.defn(name="instruct_eval.proposal_decision")
    async def proposal_decision(self, request: ProposalDecisionRequest) -> ActivityResult:
        return await self._invoke("proposal_decision", request, self._backend.proposal_decision)

    @activity.defn(name="instruct_eval.decomposition")
    async def decomposition(self, request: DecompositionRequest) -> ActivityResult:
        return await self._invoke("decomposition", request, self._backend.decomposition)

    @activity.defn(name="instruct_eval.eligibility")
    async def eligibility(self, request: EligibilityRequest) -> ActivityResult:
        return await self._invoke("eligibility", request, self._backend.eligibility)

    @activity.defn(name="instruct_eval.child_authorization_issue")
    async def child_authorization_issue(
        self, request: ChildAuthorizationIssueRequest
    ) -> ActivityResult:
        return await self._invoke(
            "child_authorization_issue", request, self._backend.child_authorization_issue
        )

    @activity.defn(name="instruct_eval.child_authorization_claim")
    async def child_authorization_claim(
        self, request: ChildAuthorizationClaimRequest
    ) -> ActivityResult:
        return await self._invoke(
            "child_authorization_claim", request, self._backend.child_authorization_claim
        )

    @activity.defn(name="instruct_eval.design_draft")
    async def design_draft(self, request: DesignDraftRequest) -> ActivityResult:
        return await self._invoke("design_draft", request, self._backend.design_draft)

    @activity.defn(name="instruct_eval.design_commit")
    async def design_commit(self, request: DesignCommitRequest) -> GateResult:
        return await self._gate("design_commit", request, self._backend.design_commit)

    @activity.defn(name="instruct_eval.g0_commit")
    async def g0_commit(self, request: G0CommitRequest) -> GateResult:
        return await self._gate("g0_commit", request, self._backend.g0_commit)

    @activity.defn(name="instruct_eval.pre_run_validity")
    async def pre_run_validity(self, request: PreRunValidityRequest) -> GateResult:
        return await self._gate("pre_run_validity", request, self._backend.pre_run_validity)

    @activity.defn(name="instruct_eval.freeze")
    async def freeze(self, request: FreezeRequest) -> GateResult:
        return await self._gate("freeze", request, self._backend.freeze)

    @activity.defn(name="instruct_eval.execution_commit")
    async def execution_commit(self, request: ExecutionCommitRequest) -> GateResult:
        return await self._gate("execution_commit", request, self._backend.execution_commit)

    @activity.defn(name="instruct_eval.subject_trial")
    async def subject_trial(self, request: SubjectTrialRequest) -> ActivityResult:
        return await self._invoke("subject_trial", request, self._backend.subject_trial)

    @activity.defn(name="instruct_eval.evidence_audit")
    async def evidence_audit(self, request: EvidenceAuditRequest) -> ActivityResult:
        return await self._invoke("evidence_audit", request, self._backend.evidence_audit)

    @activity.defn(name="instruct_eval.post_run_validity")
    async def post_run_validity(self, request: PostRunValidityRequest) -> GateResult:
        return await self._gate("post_run_validity", request, self._backend.post_run_validity)

    @activity.defn(name="instruct_eval.map_lifecycle")
    async def map_lifecycle(self, request: MapLifecycleRequest) -> ActivityResult:
        return await self._invoke("map_lifecycle", request, self._backend.map_lifecycle)

    @activity.defn(name="instruct_eval.release")
    async def release(self, request: ReleaseRequest) -> GateResult:
        return await self._gate("release", request, self._backend.release)

    @activity.defn(name="instruct_eval.analysis")
    async def analysis(self, request: AnalysisRequest) -> GateResult:
        return await self._gate("analysis", request, self._backend.analysis)

    @activity.defn(name="instruct_eval.terminal_commit")
    async def terminal_commit(self, request: TerminalCommitRequest) -> GateResult:
        return await self._gate("terminal_commit", request, self._backend.terminal_commit)

    @activity.defn(name="instruct_eval.terminalize_invocation")
    async def terminalize_invocation(self, request: TerminalizeRequest) -> TerminalizeResult:
        try:
            self._coordination.terminalize_indeterminate(
                request.invocation_key, request.owner_epoch
            )
        except CoordinationError as error:
            raise ApplicationError(
                str(error), type="InstructEvalSemanticError", non_retryable=True
            ) from error
        return TerminalizeResult(request.invocation_key, True)

    def registered(self) -> tuple[Any, ...]:
        return (
            self.fingerprint,
            self.proposal_decision,
            self.decomposition,
            self.eligibility,
            self.child_authorization_issue,
            self.child_authorization_claim,
            self.design_draft,
            self.design_commit,
            self.g0_commit,
            self.pre_run_validity,
            self.freeze,
            self.execution_commit,
            self.subject_trial,
            self.evidence_audit,
            self.post_run_validity,
            self.map_lifecycle,
            self.release,
            self.analysis,
            self.terminal_commit,
            self.terminalize_invocation,
        )
