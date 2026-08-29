"""Temporal worker assembly for the instruct-eval public and private queues."""

from __future__ import annotations

import asyncio
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

from temporalio import activity
from temporalio.api.common.v1 import WorkflowExecution
from temporalio.api.workflowservice.v1 import DescribeWorkflowExecutionRequest
from temporalio.client import Client
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import (
    SandboxedWorkflowRunner,
    SandboxRestrictions,
)

from . import role_runtime
from .activities import (
    ActivityBackend,
    ActivityRequest,
    AnalysisRequest,
    ChildAuthorizationClaimRequest,
    ChildAuthorizationIssueRequest,
    DecompositionRequest,
    DesignCommitRequest,
    DesignDraftRequest,
    EligibilityRequest,
    EvidenceAuditRequest,
    ExecutionCommitRequest,
    FingerprintRequest,
    FreezeRequest,
    G0CommitRequest,
    GatePublication,
    InstructEvalActivities,
    MapLifecycleRequest,
    PostRunValidityRequest,
    PreRunValidityRequest,
    ProposalDecisionRequest,
    ReleasePublication,
    ReleaseRequest,
    SubjectTrialRequest,
    TerminalCommitRequest,
)
from .artifacts import ArtifactMode, ArtifactStore, canonical_bytes
from .coordination import (
    ChildAuthorizationClaimRequest as CoordinationChildAuthorizationClaimRequest,
)
from .coordination import (
    ChildAuthorizationRequest,
    CoordinationStore,
)
from .models import ExperimentDesign, ProtocolError, canonical_hash
from .trials import (
    SUBJECT_ARTIFACT_KINDS,
    ArtifactRecordParams,
    PrivateMapLifecycle,
    PrivateMapParams,
    SubjectExecutor,
    TrialProtocolError,
    TrustedActivityMetadata,
    TrustedActivityMetadataParams,
    map_commitment,
    pre_map_input_hash,
    trusted_activity_metadata,
)
from .workflows import (
    ExperimentCampaignWorkflow,
    InstructionExperimentWorkflow,
    WorkflowProtocolError,
)

TEMPORAL_NAMESPACE = "instruct-eval"
PUBLIC_TASK_QUEUE = "instruct-eval-public"
PRIVATE_TASK_QUEUE = "instruct-eval-private"
_WORKFLOW_SANDBOX_RESTRICTIONS = SandboxRestrictions.default.with_passthrough_modules(
    "cryptography"
)


def workflow_runner() -> SandboxedWorkflowRunner:
    """Create the deterministic workflow sandbox with Ed25519 verification support."""
    return SandboxedWorkflowRunner(restrictions=_WORKFLOW_SANDBOX_RESTRICTIONS)


PUBLIC_ACTIVITY_METHODS = (
    "fingerprint",
    "decomposition",
    "eligibility",
    "design_draft",
    "g0_commit",
    "execution_commit",
    "evidence_audit",
    "post_run_validity",
    "analysis",
    "terminal_commit",
)
PRIVATE_ACTIVITY_METHODS = (
    "proposal_decision",
    "child_authorization_issue",
    "child_authorization_claim",
    "design_commit",
    "pre_run_validity",
    "freeze",
    "subject_trial",
    "map_lifecycle",
    "release",
    "terminalize_invocation",
)


class DomainOperation(Protocol):
    def __call__(
        self,
        request: ActivityRequest,
        artifacts: ArtifactStore,
        coordination: CoordinationStore,
        runtime: Any,
    ) -> Mapping[str, Any] | GatePublication | Any: ...


@dataclass(frozen=True, slots=True)
class DomainOperations:
    """The required domain behavior for every named Activity endpoint."""

    fingerprint: DomainOperation
    proposal_decision: DomainOperation
    decomposition: DomainOperation
    eligibility: DomainOperation
    design_draft: DomainOperation
    g0_commit: DomainOperation
    design_commit: DomainOperation
    pre_run_validity: DomainOperation
    freeze: DomainOperation
    execution_commit: DomainOperation
    evidence_audit: DomainOperation
    post_run_validity: DomainOperation
    analysis: DomainOperation
    terminal_commit: DomainOperation

    def __post_init__(self) -> None:
        if any(not callable(getattr(self, name)) for name in self.__dataclass_fields__):
            raise TypeError("every domain Activity operation must be callable")


@dataclass(frozen=True, slots=True)
class PrivateMapAuthority:
    """Durably configured private authority for one experiment execution."""

    parent_workflow_id: str
    parent_run_id: str
    freeze_chain: str
    claim_hash: str
    g0_record_hash: str
    design_proposal_hash: str
    design_hash: str
    treatment_hash: str
    fixture_manifest_hash: str
    preferred_directions: Mapping[str, str]
    treatments: Mapping[str, str | None]
    experiment_design: Mapping[str, Any]

    def __post_init__(self) -> None:
        hashes = (
            self.freeze_chain,
            self.claim_hash,
            self.g0_record_hash,
            self.design_proposal_hash,
            self.design_hash,
            self.treatment_hash,
            self.fixture_manifest_hash,
        )
        try:
            experiment_design = ExperimentDesign.from_payload(self.experiment_design)
        except ProtocolError as error:
            raise ValueError("private map authority is malformed") from error
        if (
            not isinstance(self.parent_workflow_id, str)
            or not self.parent_workflow_id
            or not isinstance(self.parent_run_id, str)
            or not self.parent_run_id
            or any(
                not isinstance(value, str)
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
                for value in hashes
            )
            or set(self.preferred_directions) != {"core-1", "core-2", "negative-control"}
            or any(
                not isinstance(value, str) or not value
                for value in self.preferred_directions.values()
            )
            or any(
                not isinstance(key, str) or not isinstance(value, str | None)
                for key, value in self.treatments.items()
            )
            or canonical_hash(
                {
                    "experiment_design": experiment_design.payload(),
                    "preferred_directions": self.preferred_directions,
                }
            )
            != self.design_hash
        ):
            raise ValueError("private map authority is malformed")


class PrivateAuthorityResolver(Protocol):
    """Resolve configured private authority; never accept it from a request."""

    def authority_for(
        self, *, campaign_id: str, experiment_id: str, workflow_id: str, run_id: str
    ) -> PrivateMapAuthority: ...


@dataclass(frozen=True, slots=True)
class ActivityBackendRequest:
    """Dependencies required to assemble the complete Activity backend."""

    artifacts: ArtifactStore
    coordination: CoordinationStore
    operations: DomainOperations
    private_maps: PrivateMapLifecycle
    private_authority: PrivateAuthorityResolver
    subject_executor: SubjectExecutor
    runtime: Any = role_runtime


@dataclass(frozen=True, slots=True)
class BuildBackendRequest:
    """Durable services and behavior required to build an Activity backend."""

    artifact_root: str | Path
    private_artifact_root: str | Path
    coordination_database: str | Path
    private_database: str | Path
    operations: DomainOperations
    private_authority: PrivateAuthorityResolver
    subject_executor: SubjectExecutor


PRIVATE_MAP_ACTIVITY_ID = "instruct-eval-map-lifecycle"

PRIVATE_RELEASE_ACTIVITY_ID = "instruct-eval-release-g5"


def private_subject_activity_id(token: str) -> str:
    if (
        not isinstance(token, str)
        or len(token) != 43
        or any(
            character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for character in token
        )
    ):
        raise TrialProtocolError("private trial token is invalid")
    return f"instruct-eval-subject-trial-{token}"


class InstructEvalActivityBackend(ActivityBackend):
    """Complete Activity backend assembled from the canonical durable services."""

    def __init__(self, request: ActivityBackendRequest) -> None:
        artifacts = request.artifacts
        coordination = request.coordination
        operations = request.operations
        private_maps = request.private_maps
        private_authority = request.private_authority
        subject_executor = request.subject_executor
        runtime = request.runtime
        if not isinstance(artifacts, ArtifactStore):
            raise TypeError("activities require an ArtifactStore")
        if not isinstance(coordination, CoordinationStore):
            raise TypeError("activities require a CoordinationStore")
        if not isinstance(operations, DomainOperations):
            raise TypeError("activities require complete DomainOperations")
        if not isinstance(private_maps, PrivateMapLifecycle):
            raise TypeError("activities require a durable PrivateMapLifecycle")
        if not callable(getattr(private_authority, "authority_for", None)):
            raise TypeError("activities require a private authority resolver")
        if not callable(subject_executor):
            raise TypeError("activities require a SubjectExecutor")
        if runtime is None:
            raise TypeError("activities require a role runtime")
        self._artifacts = artifacts
        self._coordination = coordination
        self._operations = operations
        self._private_maps = private_maps
        self._private_authority = private_authority
        self._subject_executor = subject_executor
        self._runtime = runtime

    def _call(self, name: str, request: ActivityRequest) -> Any:
        return getattr(self._operations, name)(
            request, self._artifacts, self._coordination, self._runtime
        )

    def fingerprint(self, request: FingerprintRequest) -> Any:
        return self._call("fingerprint", request)

    def bind_client(self, client: Client) -> None:
        if getattr(client, "namespace", None) != TEMPORAL_NAMESPACE:
            raise ValueError("worker client must use the pinned instruct-eval namespace")
        self._client = client

    async def _describe(self, workflow_id: str, run_id: str) -> Any:
        client = getattr(self, "_client", None)
        if client is None:
            raise RuntimeError("worker client is required for child authorization")
        return await client.workflow_service.describe_workflow_execution(
            DescribeWorkflowExecutionRequest(
                namespace=TEMPORAL_NAMESPACE,
                execution=WorkflowExecution(workflow_id=workflow_id, run_id=run_id),
            )
        )

    @staticmethod
    def _workflow_type(description: Any) -> str:
        info = getattr(description, "workflow_execution_info", None)
        workflow_type = getattr(info, "type", None) or getattr(info, "workflow_type", None)
        return str(getattr(workflow_type, "name", ""))

    @staticmethod
    def _parent_execution(description: Any) -> tuple[str, str]:
        parent = getattr(
            getattr(description, "workflow_execution_info", None), "parent_execution", None
        )
        return str(getattr(parent, "workflow_id", "")), str(getattr(parent, "run_id", ""))

    async def child_authorization_issue(
        self, request: ChildAuthorizationIssueRequest
    ) -> Mapping[str, Any]:
        payload = request.payload
        if set(payload) != {"claim_sha256", "coverage_sha256", "fingerprint_sha256"}:
            raise ValueError("child authorization issue payload is not exact")
        info = activity.info()
        workflow_id, run_id = (
            getattr(info, "workflow_id", None),
            getattr(info, "workflow_run_id", None),
        )
        if (
            not isinstance(workflow_id, str)
            or not workflow_id
            or not isinstance(run_id, str)
            or not run_id
        ):
            raise ValueError("child authorization issuer has no stable execution identity")
        description = await self._describe(workflow_id, run_id)
        if (
            self._workflow_type(description) != "ExperimentCampaignWorkflow"
            or request.campaign_id != workflow_id
        ):
            raise ValueError("child authorization issuer is not the campaign execution")
        authorization = self._coordination.issue_child_authorization(
            ChildAuthorizationRequest(
                request.campaign_id,
                workflow_id,
                run_id,
                str(payload["claim_sha256"]),
                str(payload["fingerprint_sha256"]),
                str(payload["coverage_sha256"]),
            )
        )
        return {
            "authorized": True,
            "experiment_id": authorization.experiment_id,
            "campaign_id": authorization.campaign_id,
            "claim_sha256": authorization.claim_sha256,
            "coverage_sha256": authorization.coverage_sha256,
            "fingerprint_sha256": authorization.fingerprint_sha256,
        }

    async def child_authorization_claim(
        self, request: ChildAuthorizationClaimRequest
    ) -> Mapping[str, Any]:
        payload = request.payload
        if set(payload) != {"claim_sha256", "coverage_sha256", "fingerprint_sha256"}:
            raise ValueError("child authorization claim payload is not exact")
        info = activity.info()
        workflow_id, run_id = (
            getattr(info, "workflow_id", None),
            getattr(info, "workflow_run_id", None),
        )
        if (
            not isinstance(workflow_id, str)
            or not workflow_id
            or not isinstance(run_id, str)
            or not run_id
        ):
            raise ValueError("child authorization claimant has no stable execution identity")
        child = await self._describe(workflow_id, run_id)
        parent_id, parent_run_id = self._parent_execution(child)
        parent = await self._describe(parent_id, parent_run_id)
        if (
            self._workflow_type(child) != "InstructionExperimentWorkflow"
            or self._workflow_type(parent) != "ExperimentCampaignWorkflow"
            or request.campaign_id != parent_id
        ):
            raise ValueError("child authorization claimant is not a campaign child")
        claimed = self._coordination.claim_child_authorization(
            CoordinationChildAuthorizationClaimRequest(
                request.campaign_id,
                parent_id,
                parent_run_id,
                str(payload["claim_sha256"]),
                str(payload["fingerprint_sha256"]),
                str(payload["coverage_sha256"]),
                request.experiment_id,
                workflow_id,
                run_id,
            )
        )
        return {
            "authorized": True,
            "experiment_id": claimed.experiment_id,
            "campaign_id": claimed.campaign_id,
            "claim_sha256": claimed.claim_sha256,
            "coverage_sha256": claimed.coverage_sha256,
            "fingerprint_sha256": claimed.fingerprint_sha256,
        }

    def proposal_decision(self, request: ProposalDecisionRequest) -> Any:
        return self._call("proposal_decision", request)

    def decomposition(self, request: DecompositionRequest) -> Any:
        return self._call("decomposition", request)

    def eligibility(self, request: EligibilityRequest) -> Any:
        return self._call("eligibility", request)

    def design_draft(self, request: DesignDraftRequest) -> Any:
        return self._call("design_draft", request)

    def design_commit(self, request: DesignCommitRequest) -> Any:
        return self._call("design_commit", request)

    def g0_commit(self, request: G0CommitRequest) -> Any:
        return self._call("g0_commit", request)

    def pre_run_validity(self, request: PreRunValidityRequest) -> Any:
        return self._call("pre_run_validity", request)

    def freeze(self, request: FreezeRequest) -> Any:
        return self._call("freeze", request)

    def execution_commit(self, request: ExecutionCommitRequest) -> Any:
        return self._call("execution_commit", request)

    async def _private_metadata(
        self, request: ActivityRequest, activity_type: str, activity_id: str
    ) -> tuple[PrivateMapAuthority, TrustedActivityMetadata]:
        info = activity.info()
        workflow_id, run_id = (
            getattr(info, "workflow_id", None),
            getattr(info, "workflow_run_id", None),
        )
        if (
            not isinstance(workflow_id, str)
            or not workflow_id
            or not isinstance(run_id, str)
            or not run_id
        ):
            raise TrialProtocolError("private activity has unstable workflow identity")
        child = await self._describe(workflow_id, run_id)
        parent_workflow_id, parent_run_id = self._parent_execution(child)
        parent = await self._describe(parent_workflow_id, parent_run_id)
        if (
            self._workflow_type(child) != "InstructionExperimentWorkflow"
            or self._workflow_type(parent) != "ExperimentCampaignWorkflow"
            or request.campaign_id != parent_workflow_id
        ):
            raise TrialProtocolError(
                "private activity does not belong to the authorized campaign parent"
            )
        issue = getattr(self._private_authority, "issue_from_durable_records", None)
        if activity_type == "instruct_eval.map_lifecycle" and callable(issue):
            candidate_instruction = request.payload.get("candidate_instruction")
            issue(
                coordination=self._coordination,
                campaign_id=request.campaign_id,
                experiment_id=request.experiment_id,
                workflow_id=workflow_id,
                run_id=run_id,
                parent_workflow_id=parent_workflow_id,
                parent_run_id=parent_run_id,
                candidate_instruction=candidate_instruction,
            )
        authority = self._private_authority.authority_for(
            campaign_id=request.campaign_id,
            experiment_id=request.experiment_id,
            workflow_id=workflow_id,
            run_id=run_id,
        )
        if not isinstance(authority, PrivateMapAuthority):
            raise TrialProtocolError("private authority resolver returned an invalid authority")
        if not hmac.compare_digest(
            parent_workflow_id, authority.parent_workflow_id
        ) or not hmac.compare_digest(parent_run_id, authority.parent_run_id):
            raise TrialProtocolError("private authority does not bind the claimed campaign parent")
        return authority, trusted_activity_metadata(
            TrustedActivityMetadataParams(
                info,
                TEMPORAL_NAMESPACE,
                activity_type,
                PRIVATE_TASK_QUEUE,
                activity_id,
                parent_workflow_id,
                parent_run_id,
                authority.freeze_chain,
            )
        )

    @staticmethod
    def _private_hashes(payload: Mapping[str, Any], keys: set[str]) -> None:
        if set(payload) != keys or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for key, value in payload.items()
            if key.endswith("_sha256")
        ):
            raise TrialProtocolError("private lifecycle payload is not an exact public-hash packet")

    async def map_lifecycle(self, request: MapLifecycleRequest) -> Mapping[str, Any]:
        self._private_hashes(
            request.payload,
            {"design_sha256", "candidate_instruction", "fixture_manifest_hash"},
        )
        if (
            not isinstance(request.payload["candidate_instruction"], str)
            or not request.payload["candidate_instruction"]
        ):
            raise TrialProtocolError("map lifecycle candidate instruction is invalid")
        authority, metadata = await self._private_metadata(
            request, "instruct_eval.map_lifecycle", PRIVATE_MAP_ACTIVITY_ID
        )
        if request.payload["design_sha256"] != authority.design_hash:
            raise TrialProtocolError("map lifecycle design hash does not match frozen authority")
        if request.payload["fixture_manifest_hash"] != authority.fixture_manifest_hash:
            raise TrialProtocolError("map lifecycle fixture hash does not match frozen authority")
        prepared = self._private_maps.prepare(
            PrivateMapParams(
                request.campaign_id,
                request.experiment_id,
                metadata,
                pre_map_input_hash(
                    namespace=metadata.identity.namespace,
                    workflow_type=metadata.identity.workflow_type,
                    task_queue=metadata.identity.task_queue,
                    campaign_id=request.campaign_id,
                    experiment_id=request.experiment_id,
                    workflow_id=metadata.identity.workflow_id,
                    run_id=metadata.identity.run_id,
                    claim_hash=authority.claim_hash,
                    g0_record_hash=authority.g0_record_hash,
                    design_proposal_hash=authority.design_proposal_hash,
                    design_hash=authority.design_hash,
                    treatment_hash=authority.treatment_hash,
                    fixture_manifest_hash=authority.fixture_manifest_hash,
                ),
                authority.preferred_directions,
            )
        )
        tokens = tuple(
            assignment.token
            for assignment_id in prepared.mapping.assignment_order
            for assignment in prepared.mapping.assignments
            if assignment.assignment_id == assignment_id
        )
        return {
            "map_ref": prepared.map_ref,
            "map_commitment": map_commitment(prepared.mapping, prepared.map_ref, prepared.k_map),
            "tokens": tokens,
            "pre_map_input_hash": prepared.mapping.pre_map_input_hash,
            "authorization_rule_sha256": sha256(
                canonical_bytes(prepared.mapping.authorization_rule)
            ).hexdigest(),
        }

    async def subject_trial(self, request: SubjectTrialRequest) -> Mapping[str, Any]:
        payload = request.payload
        if set(payload) != {"map_ref", "token", "design_sha256"}:
            raise TrialProtocolError("private subject payload is not exact")
        map_ref, token, design_sha256 = (
            payload["map_ref"],
            payload["token"],
            payload["design_sha256"],
        )
        if not isinstance(map_ref, str) or not isinstance(token, str):
            raise TrialProtocolError("subject map reference or token is invalid")
        if (
            not isinstance(design_sha256, str)
            or len(design_sha256) != 64
            or any(char not in "0123456789abcdef" for char in design_sha256)
        ):
            raise TrialProtocolError("subject trial design hash is invalid")
        authority, metadata = await self._private_metadata(
            request,
            "instruct_eval.subject_trial",
            private_subject_activity_id(token),
        )
        if design_sha256 != authority.design_hash:
            raise TrialProtocolError("subject trial design hash does not match frozen authority")
        assignment = self._private_maps.resolve(map_ref=map_ref, metadata=metadata, token=token)
        disclosure_treatment = next(
            (value for value in authority.treatments.values() if isinstance(value, str)),
            None,
        )
        if disclosure_treatment is None:
            raise TrialProtocolError("child treatment is unavailable")
        result = await asyncio.to_thread(
            self._subject_executor,
            assignment=assignment,
            treatment=authority.treatments.get(assignment.assignment_id)
            if assignment.condition == "B"
            else None,
            disclosure_treatment=disclosure_treatment,
            frozen_design=ExperimentDesign.from_payload(authority.experiment_design),
        )
        if (
            not isinstance(result, Mapping)
            or set(result) != {"outcome", "private_artifacts"}
            or not isinstance(result["private_artifacts"], Mapping)
            or set(result["private_artifacts"]) != SUBJECT_ARTIFACT_KINDS - {"outcome"}
        ):
            raise TrialProtocolError("subject executor did not return exact private evidence")
        closed = self._closed_subject_outcome(result["outcome"])
        return {
            "outcome": closed,
            "private_artifacts": result["private_artifacts"],
        }

    async def finalize_subject_trial(
        self, request: SubjectTrialRequest, outcome: Mapping[str, Any]
    ) -> None:
        """Inventory immutable token-bound evidence after Activity result commit."""
        payload = request.payload
        if set(payload) != {"map_ref", "token", "design_sha256"}:
            raise TrialProtocolError("private subject payload is not exact")
        map_ref, token, design_sha256 = (
            payload["map_ref"],
            payload["token"],
            payload["design_sha256"],
        )
        if (
            not isinstance(map_ref, str)
            or not isinstance(token, str)
            or not isinstance(design_sha256, str)
        ):
            raise TrialProtocolError("private subject payload is invalid")
        authority, metadata = await self._private_metadata(
            request,
            "instruct_eval.subject_trial",
            private_subject_activity_id(token),
        )
        if design_sha256 != authority.design_hash:
            raise TrialProtocolError("subject trial design hash does not match frozen authority")
        self._private_maps.resolve(map_ref=map_ref, metadata=metadata, token=token)
        result = outcome
        if (
            set(result) != {"outcome", "private_artifacts"}
            or not isinstance(result["private_artifacts"], Mapping)
            or set(result["private_artifacts"]) != SUBJECT_ARTIFACT_KINDS - {"outcome"}
        ):
            raise TrialProtocolError("committed subject evidence is not exact")
        closed_outcome = self._closed_subject_outcome(result["outcome"])
        outcome_relative = (
            f"quarantine/{request.campaign_id}/{request.experiment_id}/{token}/outcome.json"
        )
        self._artifacts.publish_json(
            outcome_relative,
            closed_outcome,
            ArtifactMode.PRIVATE,
        )
        for artifact_kind, artifact in result["private_artifacts"].items():
            self._artifacts.publish_json(
                f"quarantine/{request.campaign_id}/"
                f"{request.experiment_id}/{token}/{artifact_kind}.json",
                artifact,
                ArtifactMode.PRIVATE,
            )
        for artifact_kind in SUBJECT_ARTIFACT_KINDS:
            relative = (
                f"quarantine/{request.campaign_id}/"
                f"{request.experiment_id}/{token}/{artifact_kind}.json"
            )
            raw = self._artifacts.read_bytes(relative, ArtifactMode.PRIVATE)
            self._private_maps.record_artifact(
                ArtifactRecordParams(
                    map_ref,
                    metadata,
                    token,
                    artifact_kind,
                    sha256(raw).hexdigest(),
                )
            )

    @staticmethod
    def _closed_subject_outcome(result: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(result, Mapping):
            raise TrialProtocolError("subject executor must return a closed outcome mapping")
        outcome = dict(result)
        if set(outcome) != {
            "blind_id",
            "fixture",
            "protocol_valid",
            "verifier_passed",
            "observer_state",
            "direction_code",
            "changed_paths",
            "evidence_id",
        }:
            raise TrialProtocolError(
                "subject executor did not return a closed de-identified outcome"
            )
        return outcome

    def evidence_audit(self, request: EvidenceAuditRequest) -> Any:
        return self._call("evidence_audit", request)

    def post_run_validity(self, request: PostRunValidityRequest) -> Any:
        return self._call("post_run_validity", request)

    async def release(self, request: ReleaseRequest) -> ReleasePublication:
        payload = request.payload
        if set(payload) != {"design_sha256"}:
            raise TrialProtocolError("G5 release payload is not exact")
        design_sha256 = payload["design_sha256"]
        if (
            not isinstance(design_sha256, str)
            or len(design_sha256) != 64
            or any(char not in "0123456789abcdef" for char in design_sha256)
        ):
            raise TrialProtocolError("G5 design hash is invalid")
        authority, metadata = await self._private_metadata(
            request, "instruct_eval.release", PRIVATE_RELEASE_ACTIVITY_ID
        )
        if design_sha256 != authority.design_hash:
            raise TrialProtocolError("G5 design hash does not match frozen authority")
        release = self._private_maps.release(metadata=metadata)
        artifact_bytes = canonical_bytes(release)
        path = (
            f"releases/{request.campaign_id}/{request.experiment_id}/"
            f"{release['release_sha256']}.json"
        )
        self._artifacts.publish_bytes(path, artifact_bytes, ArtifactMode.PUBLIC)
        return ReleasePublication(
            payload=release,
            final_artifact_path=self._artifacts.path_for(path, ArtifactMode.PUBLIC),
            artifact_bytes=artifact_bytes,
            artifact_sha256=sha256(artifact_bytes).hexdigest(),
        )

    def analysis(self, request: AnalysisRequest) -> Any:
        return self._call("analysis", request)

    def terminal_commit(self, request: TerminalCommitRequest) -> Any:
        return self._call("terminal_commit", request)


def build_backend(request: BuildBackendRequest) -> InstructEvalActivityBackend:
    """Construct a backend with distinct durable public and private authorities."""
    if (
        not request.artifact_root
        or not request.private_artifact_root
        or not request.coordination_database
        or not request.private_database
    ):
        raise ValueError("worker durable storage paths are required")
    return InstructEvalActivityBackend(
        ActivityBackendRequest(
            artifacts=ArtifactStore(
                request.artifact_root,
                request.private_artifact_root,
            ),
            coordination=CoordinationStore(request.coordination_database),
            operations=request.operations,
            private_maps=PrivateMapLifecycle(
                request.private_database,
                request.private_artifact_root,
            ),
            private_authority=request.private_authority,
            subject_executor=request.subject_executor,
        )
    )


def registration_sets(
    activities: InstructEvalActivities,
) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Return the exact public and private Activity registration sets."""
    registered = {method.__name__: method for method in activities.registered()}
    expected = set(PUBLIC_ACTIVITY_METHODS) | set(PRIVATE_ACTIVITY_METHODS)
    if set(registered) != expected:
        raise RuntimeError("Activity registration set does not match canonical worker allowlists")
    return (
        tuple(registered[name] for name in PUBLIC_ACTIVITY_METHODS),
        tuple(registered[name] for name in PRIVATE_ACTIVITY_METHODS),
    )


def create_public_worker(
    client: Client,
    backend: InstructEvalActivityBackend,
    *,
    public_task_queue: str = PUBLIC_TASK_QUEUE,
) -> Worker:
    """Create the public-only process without registering private Activities."""
    if getattr(client, "namespace", None) != TEMPORAL_NAMESPACE or not public_task_queue:
        raise ValueError("public worker requires the pinned namespace and queue")
    activities = InstructEvalActivities(backend._coordination, backend)
    registered = {method.__name__: method for method in activities.registered()}
    return Worker(
        client,
        task_queue=public_task_queue,
        workflows=[ExperimentCampaignWorkflow, InstructionExperimentWorkflow],
        activities=[registered[name] for name in PUBLIC_ACTIVITY_METHODS],
        workflow_runner=workflow_runner(),
        workflow_failure_exception_types=[WorkflowProtocolError],
    )


def create_private_worker(
    client: Client,
    backend: InstructEvalActivityBackend,
    *,
    private_task_queue: str = PRIVATE_TASK_QUEUE,
) -> Worker:
    """Create the private-only process without workflows or public Activities."""
    if getattr(client, "namespace", None) != TEMPORAL_NAMESPACE or not private_task_queue:
        raise ValueError("private worker requires the pinned namespace and queue")
    activities = InstructEvalActivities(backend._coordination, backend)
    backend.bind_client(client)
    registered = {method.__name__: method for method in activities.registered()}
    return Worker(
        client,
        task_queue=private_task_queue,
        activities=[registered[name] for name in PRIVATE_ACTIVITY_METHODS],
    )


def create_workers(
    client: Client,
    backend: InstructEvalActivityBackend,
    *,
    public_task_queue: str = PUBLIC_TASK_QUEUE,
    private_task_queue: str = PRIVATE_TASK_QUEUE,
) -> tuple[Worker, Worker]:
    """Create queue-isolated workers without exposing private activities publicly."""
    if not isinstance(backend, InstructEvalActivityBackend):
        raise TypeError("worker requires the complete instruct-eval Activity backend")
    if backend._artifacts.private_root == backend._artifacts.root:
        raise ValueError("worker private artifact storage must be separate")
    if not public_task_queue or not private_task_queue or public_task_queue == private_task_queue:
        raise ValueError("public and private task queues must be distinct and nonempty")
    return (
        create_public_worker(client, backend, public_task_queue=public_task_queue),
        create_private_worker(client, backend, private_task_queue=private_task_queue),
    )


async def run_workers(client: Client, backend: InstructEvalActivityBackend, **queues: str) -> None:
    """Run both queue-isolated workers until cancelled."""
    workers = create_workers(client, backend, **queues)
    await asyncio.gather(*(worker.run() for worker in workers))
