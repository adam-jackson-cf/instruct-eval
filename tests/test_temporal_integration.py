"""End-to-end Temporal scheduling, durable activity, history, and replay coverage."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import re
import tempfile
import unittest
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio import activity, workflow
from temporalio.api.common.v1 import WorkflowExecution
from temporalio.client import WorkflowFailureError, WorkflowUpdateFailedError
from temporalio.common import RetryPolicy
from temporalio.converter import DataConverter
from temporalio.exceptions import CancelledError
from temporalio.exceptions import TimeoutError as TemporalTimeoutError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer, Worker

from instruct_eval import worker
from instruct_eval.activities import (
    ActivityRequest,
    ChildAuthorizationClaimRequest,
    ChildAuthorizationIssueRequest,
    GatePublication,
    GateRequest,
    InstructEvalActivities,
    MapLifecycleRequest,
    ReleasePublication,
    ReleaseRequest,
    SubjectTrialRequest,
)
from instruct_eval.artifacts import ArtifactMode, ArtifactStore
from instruct_eval.coordination import CoordinationStore
from instruct_eval.messages import request_fingerprint
from instruct_eval.models import canonical_bytes, canonical_hash
from instruct_eval.signing import DecisionPayload, DecisionWire, public_key_base64url
from instruct_eval.trials import authorization_rule
from instruct_eval.workflows import (
    CampaignInput,
    ExperimentCampaignWorkflow,
    InstructionExperimentWorkflow,
    WorkflowProtocolError,
)

CAMPAIGN_ID = "campaign-" + "1" * 32
COVERAGE = "2" * 64
DESIGN = "3" * 64
ZERO = "0" * 64
PROPOSAL = "7" * 64
PUBLIC_QUEUE = "instruct-eval-public"
PRIVATE_QUEUE = "instruct-eval-private"


@activity.defn
async def timeout_probe_activity() -> None:
    await asyncio.sleep(0.1)


@workflow.defn
class TimeoutProbeWorkflow:
    @workflow.run
    async def run(self) -> None:
        await workflow.execute_activity(
            timeout_probe_activity,
            start_to_close_timeout=timedelta(milliseconds=10),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )


@dataclass(frozen=True, slots=True)
class _Description:
    workflow_execution_info: Any


@dataclass(frozen=True, slots=True)
class _OperationContext:
    operation_name: str
    request: ActivityRequest
    artifacts: ArtifactStore
    coordination: CoordinationStore
    runtime: Any


@dataclass(frozen=True, slots=True)
class _DecisionRequest:
    target_kind: str
    target_id: str
    action: str
    proposal_hash: str | None
    revision: str
    sequence: int


@dataclass(frozen=True, slots=True)
class _CampaignStartRequest:
    workflow_id: str
    campaign_input: CampaignInput


@dataclass(frozen=True, slots=True)
class _AuthorizationContext:
    claim_sha256: str
    child_id: str
    child: Any


@dataclass(frozen=True, slots=True)
class _HappyPathContext:
    campaign: Any
    child: Any
    claim_sha256: str
    result: Any


@dataclass(frozen=True, slots=True)
class _TerminalScenario:
    label: str
    reject_g0: bool
    reject_g2: bool
    terminal_gate: str = "DESIGN_REJECTED"


class _DescribeService:
    """Typed Describe facade used by the production child-authorization adapter."""

    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.campaign_run_id: str | None = None

    async def describe_workflow_execution(self, request: Any) -> _Description:
        self.requests.append(request)
        workflow_id, run_id = request.execution.workflow_id, request.execution.run_id
        if workflow_id.startswith("experiment-"):
            if self.campaign_run_id is None:
                raise AssertionError("campaign Describe must precede child Describe")
            info = SimpleNamespace(
                type=SimpleNamespace(name="InstructionExperimentWorkflow"),
                parent_execution=WorkflowExecution(
                    workflow_id=CAMPAIGN_ID,
                    run_id=self.campaign_run_id,
                ),
            )
        else:
            if workflow_id != CAMPAIGN_ID or not run_id:
                raise AssertionError("Describe campaign identity is not exact")
            self.campaign_run_id = run_id
            info = SimpleNamespace(
                type=SimpleNamespace(name="ExperimentCampaignWorkflow"),
                parent_execution=WorkflowExecution(),
            )
        return _Description(info)


class _DescribeClient:
    namespace = worker.TEMPORAL_NAMESPACE

    def __init__(self) -> None:
        self.workflow_service = _DescribeService()


class _PrivateAuthority:
    def authority_for(
        self,
        *,
        campaign_id: str,
        experiment_id: str,
        workflow_id: str,
        run_id: str,
    ) -> worker.PrivateMapAuthority:
        fields = worker.PrivateMapAuthority.__dataclass_fields__
        values: dict[str, Any] = {
            "parent_workflow_id": CAMPAIGN_ID,
            "parent_run_id": "campaign-run",
            "freeze_chain": "f" * 64,
            "preferred_directions": {
                "core-1": "better",
                "core-2": "better",
                "negative-control": "same",
            },
            "treatments": {},
        }
        for name in fields:
            if name.endswith("hash") and name not in values:
                values[name] = "f" * 64
        return worker.PrivateMapAuthority(**values)


class _ControlledBackend(worker.InstructEvalActivityBackend):
    """Production adapter with only model operations and private execution controlled."""

    _GATE_NAMES = frozenset(
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

    def __init__(self, root: Path, *, reject_g0: bool = False, reject_g2: bool = False) -> None:
        self.calls: Counter[str] = Counter()
        self.packets: dict[str, list[Mapping[str, Any]]] = {}
        self.issued: list[Mapping[str, Any]] = []
        self.finalized_subjects: dict[str, str] = {}
        self.tokens = tuple(f"{index:043d}" for index in range(10))
        self.active_subjects = self.max_active_subjects = 0
        self.describe_client = _DescribeClient()
        self.artifacts = ArtifactStore(root / "public", root / "private")
        self.coordination = CoordinationStore(root / "coordination.sqlite")
        self.private_maps = worker.PrivateMapLifecycle(root / "private.sqlite", root / "private")
        self.reject_g0, self.reject_g2 = reject_g0, reject_g2
        operations = worker.DomainOperations(
            **cast(
                Any,
                {
                    name: self._operation(name)
                    for name in worker.DomainOperations.__dataclass_fields__
                },
            )
        )
        super().__init__(
            worker.ActivityBackendRequest(
                artifacts=self.artifacts,
                coordination=self.coordination,
                operations=operations,
                private_maps=self.private_maps,
                private_authority=_PrivateAuthority(),
                subject_executor=cast(Any, self._subject),
                runtime=object(),
            )
        )
        self.bind_client(cast(Any, self.describe_client))

    def close(self) -> None:
        self.private_maps.close()

    def _record(self, name: str, request: ActivityRequest) -> None:
        self.calls[name] += 1
        self.packets.setdefault(name, []).append(dict(request.payload))

    def _operation(
        self,
        name: str,
    ) -> Callable[
        [ActivityRequest, ArtifactStore, CoordinationStore, Any],
        Mapping[str, Any] | GatePublication,
    ]:
        handler = self._operation_handlers().get(name, self._accepted_payload)

        def invoke(
            request: ActivityRequest,
            artifacts: ArtifactStore,
            coordination: CoordinationStore,
            runtime: Any,
        ) -> Mapping[str, Any] | GatePublication:
            operation_name = name
            payload_handler = handler
            context = _OperationContext(
                operation_name,
                request,
                artifacts,
                coordination,
                runtime,
            )
            self._record(f"instruct_eval.{operation_name}", request)
            payload = payload_handler(context)
            if operation_name in self._GATE_NAMES:
                return self._gate_payload(context, payload)
            return payload

        return invoke

    def _operation_handlers(
        self,
    ) -> dict[str, Callable[[_OperationContext], Mapping[str, Any]]]:
        return {
            "fingerprint": self._fingerprint_payload,
            "decomposition": self._decomposition_payload,
            "eligibility": self._eligibility_payload,
            "proposal_decision": self._proposal_decision_payload,
            "design_draft": self._design_draft_payload,
            "g0_commit": self._g0_commit_payload,
            "design_commit": self._design_commit_payload,
            "pre_run_validity": self._pre_run_validity_payload,
            "freeze": self._design_commit_payload,
            "execution_commit": self._design_commit_payload,
            "evidence_audit": self._evidence_audit_payload,
            "post_run_validity": self._post_run_validity_payload,
            "analysis": self._analysis_payload,
        }

    @staticmethod
    def _fingerprint_payload(context: _OperationContext) -> Mapping[str, Any]:
        payload = context.request.payload
        return {
            "fingerprint_sha256": request_fingerprint(
                payload["request"],
                payload["model_identity"],
                payload["runtime_identity"],
            )
        }

    @staticmethod
    def _decomposition_payload(context: _OperationContext) -> Mapping[str, Any]:
        del context
        return {"claims": [{"coverage_sha256": COVERAGE, "claim": "one"}]}

    def _eligibility_payload(self, context: _OperationContext) -> Mapping[str, Any]:
        del context
        return {"accepted": not self.reject_g0}

    @staticmethod
    def _design_draft_payload(context: _OperationContext) -> Mapping[str, Any]:
        del context
        return {"design_sha256": DESIGN}

    @staticmethod
    def _accepted_payload(context: _OperationContext) -> Mapping[str, Any]:
        del context
        return {"accepted": True}

    def _g0_commit_payload(self, context: _OperationContext) -> Mapping[str, Any]:
        del context
        return {"accepted": not self.reject_g0}

    @staticmethod
    def _design_commit_payload(context: _OperationContext) -> Mapping[str, Any]:
        del context
        return {"accepted": True, "design_sha256": DESIGN}

    def _pre_run_validity_payload(self, context: _OperationContext) -> Mapping[str, Any]:
        del context
        return {"accepted": not self.reject_g2, "design_sha256": DESIGN}

    @staticmethod
    def _evidence_audit_payload(context: _OperationContext) -> Mapping[str, Any]:
        outcomes = context.request.payload["outcomes"]
        return {
            "blind_scores": [
                {
                    "blind_id": outcome["blind_id"],
                    "direction": outcome["direction_code"],
                }
                for outcome in outcomes
            ]
        }

    @staticmethod
    def _post_run_validity_payload(context: _OperationContext) -> Mapping[str, Any]:
        return {"accepted": context.request.payload["scorer_agrees"]}

    @staticmethod
    def _analysis_payload(context: _OperationContext) -> Mapping[str, Any]:
        del context
        return {"accepted": True, "authorized": True}

    def _proposal_decision_payload(self, context: _OperationContext) -> Mapping[str, Any]:
        payload = context.request.payload
        wire_sha256 = canonical_hash(payload["wire"])
        relative_path = Path("public/decisions/sha256") / f"{wire_sha256}.json"
        context.artifacts.publish_bytes(relative_path, canonical_bytes(payload["wire"]))
        publication: dict[str, Any] = {
            "accepted": True,
            "decision_sha256": wire_sha256,
            "decision_artifact_sha256": wire_sha256,
            "decision_artifact_path": str(context.artifacts.path_for(relative_path)),
        }
        action_updates = {
            "approve_decomposition": {
                "proposal_sha256": payload["proposal_hash"],
                "claims": [{"coverage_sha256": COVERAGE, "claim": "one"}],
            },
            "submit_design": {
                "proposal_sha256": payload["proposal_hash"],
                "design_sha256": DESIGN,
            },
        }
        return publication | action_updates.get(payload["action"], {})

    @staticmethod
    def _gate_payload(
        context: _OperationContext,
        payload: Mapping[str, Any],
    ) -> GatePublication:
        artifact_bytes = canonical_bytes(payload)
        gate_request = cast(GateRequest, context.request)
        relative_path = (
            Path("gates")
            / gate_request.experiment_id
            / f"{context.operation_name}-{gate_request.ordinal}.json"
        )
        artifact_sha256 = context.artifacts.publish_bytes(relative_path, artifact_bytes)
        if artifact_sha256 != sha256(artifact_bytes).hexdigest():
            raise AssertionError("ArtifactStore returned the wrong publication hash")
        return GatePublication(
            payload,
            context.artifacts.path_for(relative_path),
            artifact_bytes,
            artifact_sha256,
        )

    async def child_authorization_issue(
        self,
        request: ChildAuthorizationIssueRequest,
    ) -> Mapping[str, Any]:
        self._record("instruct_eval.child_authorization_issue", request)
        issued = await super().child_authorization_issue(request)
        self.issued.append(issued)
        return issued

    async def child_authorization_claim(
        self,
        request: ChildAuthorizationClaimRequest,
    ) -> Mapping[str, Any]:
        self._record("instruct_eval.child_authorization_claim", request)
        return await super().child_authorization_claim(request)

    async def map_lifecycle(self, request: MapLifecycleRequest) -> Mapping[str, Any]:
        self._record("instruct_eval.map_lifecycle", request)
        return {
            "map_ref": "map",
            "map_commitment": "m" * 43,
            "tokens": self.tokens,
            "pre_map_input_hash": "e" * 64,
            "authorization_rule_sha256": "f" * 64,
        }

    async def release(self, request: ReleaseRequest) -> ReleasePublication:
        self._record("instruct_eval.release", request)
        assignment_pairs = (
            ("core-1", "A"),
            ("core-1", "A"),
            ("core-1", "B"),
            ("core-1", "B"),
            ("core-2", "A"),
            ("core-2", "A"),
            ("core-2", "B"),
            ("core-2", "B"),
            ("negative-control", "A"),
            ("negative-control", "B"),
        )
        outcomes = self.packets["instruct_eval.evidence_audit"][-1]["outcomes"]
        released = [
            {
                "blind_id": outcome["blind_id"],
                "scenario": scenario,
                "condition": condition,
                "direction": outcome["direction_code"],
            }
            for outcome, (scenario, condition) in zip(
                outcomes,
                assignment_pairs,
                strict=True,
            )
        ]
        unsigned = {
            "assignments": sorted(released, key=lambda record: record["blind_id"]),
            "preferred_directions": {
                "core-1": "better",
                "core-2": "better",
                "negative-control": "same",
            },
            "authorization_rule": authorization_rule(),
        }
        payload = {**unsigned, "release_sha256": canonical_hash(unsigned)}
        artifact_bytes = canonical_bytes(payload)
        relative_path = Path("releases") / f"{request.experiment_id}.json"
        artifact_sha256 = self.artifacts.publish_bytes(relative_path, artifact_bytes)
        return ReleasePublication(
            payload,
            self.artifacts.path_for(relative_path),
            artifact_bytes,
            artifact_sha256,
        )

    def _subject(self, **_: Any) -> Mapping[str, Any]:
        raise AssertionError(
            "private mapping is intentionally controlled in this default-namespace integration test"
        )

    async def _subject_trial(self, request: SubjectTrialRequest) -> Mapping[str, Any]:
        self._record("instruct_eval.subject_trial", request)
        self.active_subjects += 1
        self.max_active_subjects = max(self.max_active_subjects, self.active_subjects)
        try:
            await asyncio.sleep(0)
            token = request.payload["token"]
            index = self.tokens.index(token)
            return {
                "blind_id": sha256(token.encode()).hexdigest(),
                "fixture": "fixture",
                "protocol_valid": True,
                "verifier_passed": index in {2, 3, 6, 7},
                "observer_state": "passed",
                "direction_code": "better" if index in {2, 3, 6, 7} else "same",
                "changed_paths": [],
                "evidence_id": "evidence",
            }
        finally:
            self.active_subjects -= 1

    async def subject_trial(self, request: SubjectTrialRequest) -> Mapping[str, Any]:
        return await self._subject_trial(request)

    async def finalize_subject_trial(
        self,
        request: SubjectTrialRequest,
        outcome: Mapping[str, Any],
    ) -> None:
        token = request.payload["token"]
        if token not in self.tokens:
            raise AssertionError("controlled subject finalization received an invalid token")
        closed_outcome = self._closed_subject_outcome(outcome)
        outcome_sha256 = self.artifacts.publish_json(
            f"quarantine/{request.campaign_id}/{request.experiment_id}/{token}.json",
            closed_outcome,
            ArtifactMode.PRIVATE,
        )
        existing = self.finalized_subjects.setdefault(token, outcome_sha256)
        if existing != outcome_sha256:
            raise AssertionError("controlled subject finalization is not immutable")


def _provisioning_error(error: BaseException) -> bool:
    text = f"{type(error).__module__}.{type(error).__name__}: {error}".lower()
    return any(
        marker in text
        for marker in ("test server", "test_server", "download", "provision", "ephemeral")
    )


class TemporalIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        try:
            self.env = await WorkflowEnvironment.start_time_skipping()
        except Exception as error:
            if _provisioning_error(error):
                self.skipTest(f"Temporal SDK test server cannot be provisioned: {error}")
            raise
        self.directory, self.private_key = (
            tempfile.TemporaryDirectory(),
            Ed25519PrivateKey.generate(),
        )

    async def asyncTearDown(self) -> None:
        if hasattr(self, "env"):
            await self.env.shutdown()
        if hasattr(self, "directory"):
            self.directory.cleanup()

    def _input(self) -> CampaignInput:
        return CampaignInput(
            CAMPAIGN_ID,
            "model",
            "runtime",
            {
                "candidate_instruction": "be exact",
                "permissions": {"network": False},
                "repository": "integration-fixture",
                "fixture_manifest_hash": "6" * 64,
                "operator_public_key": public_key_base64url(self.private_key.public_key()),
            },
            COVERAGE,
        )

    def _campaign_start_request(self, workflow_id: str) -> _CampaignStartRequest:
        return _CampaignStartRequest(workflow_id, self._input())

    def _wire(self, request: _DecisionRequest) -> dict[str, Any]:
        return DecisionWire.sign(
            self.private_key,
            DecisionPayload(
                CAMPAIGN_ID,
                request.target_kind,
                request.target_id,
                request.action,
                request.proposal_hash,
                request.revision,
                request.sequence,
            ),
        ).as_json()

    def _decomposition_decision(self, revision: str) -> dict[str, Any]:
        return self._wire(
            _DecisionRequest(
                "campaign",
                CAMPAIGN_ID,
                "approve_decomposition",
                PROPOSAL,
                revision,
                1,
            )
        )

    async def _workers(self, backend: _ControlledBackend) -> tuple[Worker, Worker]:
        activities = InstructEvalActivities(backend.coordination, backend)
        public_activities, private_activities = worker.registration_sets(activities)
        public = Worker(
            self.env.client,
            task_queue=PUBLIC_QUEUE,
            workflows=[
                ExperimentCampaignWorkflow,
                InstructionExperimentWorkflow,
                TimeoutProbeWorkflow,
            ],
            activities=[*public_activities, timeout_probe_activity],
            workflow_runner=worker.workflow_runner(),
            workflow_failure_exception_types=[WorkflowProtocolError],
        )
        private = Worker(
            self.env.client,
            task_queue=PRIVATE_QUEUE,
            activities=private_activities,
        )
        assert isinstance(self.env.client.data_converter, DataConverter)
        return public, private

    async def _start_campaign(self, request: _CampaignStartRequest) -> Any:
        return await self.env.client.start_workflow(
            ExperimentCampaignWorkflow.run,
            request.campaign_input,
            id=request.workflow_id,
            task_queue=PUBLIC_QUEUE,
        )

    async def _await_action(self, handle: Any, action: str, backend: _ControlledBackend) -> None:
        status: Mapping[str, Any] = {}
        for _ in range(100):
            status = await handle.query("status")
            if status.get("outstanding_action") == action:
                return
            if status.get("terminal_gate") is not None:
                self.fail(
                    f"workflow terminalized before {action}: status={status}, calls={backend.calls}"
                )
            await asyncio.sleep(0.05)
        self.fail(f"workflow did not reach {action}: status={status}, calls={backend.calls}")

    async def _await_count(
        self,
        observed: Any,
        count: int,
        label: str,
        backend: _ControlledBackend,
    ) -> None:
        for _ in range(100):
            value = observed() if callable(observed) else observed
            reached = len(value) if isinstance(value, list) else cast(int, value)
            if reached >= count:
                return
            await asyncio.sleep(0.05)
        self.fail(f"{label} did not reach {count}: calls={backend.calls}")

    @staticmethod
    def _cause_chain(error: BaseException) -> list[BaseException]:
        chain: list[BaseException] = []
        current: BaseException | None = error
        while current is not None and current not in chain:
            chain.append(current)
            next_error = getattr(current, "cause", None) or current.__cause__
            current = next_error if isinstance(next_error, BaseException) else None
        return chain

    @staticmethod
    def _history_text(history: Any) -> str:
        raw = history.to_json()
        decoded: list[str] = [raw]

        def visit(value: Any) -> None:
            if isinstance(value, Mapping):
                for key, nested in value.items():
                    if key == "data" and isinstance(nested, str):
                        with contextlib.suppress(ValueError, UnicodeDecodeError):
                            decoded.append(base64.b64decode(nested, validate=True).decode("utf-8"))
                    visit(nested)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested)

        visit(json.loads(raw))
        return "\n".join(decoded)

    async def _assert_history_private_and_replayable(self, campaign: Any, child: Any) -> None:
        for handle in (campaign, child):
            history = await handle.fetch_history()
            text = self._history_text(history)
            assert "condition_join" not in text
            replay = await Replayer(
                workflows=[ExperimentCampaignWorkflow, InstructionExperimentWorkflow],
                workflow_runner=worker.workflow_runner(),
            ).replay_workflow(history)
            assert replay.replay_failure is None
        child_history = self._history_text(await child.fetch_history())
        assert "assignments" in child_history
        assert "authorization_rule" in child_history
        assert "preferred_directions" in child_history
        assert "map_ref" in child_history
        assert "tokens" in child_history

    async def _assert_invalid_decomposition(self, campaign: Any) -> None:
        with pytest.raises(WorkflowUpdateFailedError, match="Workflow update failed"):
            await campaign.execute_update("decision", self._decomposition_decision("8" * 64))

    async def _approve_decomposition(self, campaign: Any) -> None:
        await campaign.execute_update("decision", self._decomposition_decision(ZERO))

    async def _await_authorized_child(self, backend: _ControlledBackend) -> _AuthorizationContext:
        claim_sha256 = canonical_hash({"coverage_sha256": COVERAGE, "claim": "one"})
        await self._await_count(backend.issued, 1, "authorization issue", backend)
        assert len(backend.issued) == 1
        issued = backend.issued[0]
        assert set(issued) == {
            "authorized",
            "experiment_id",
            "campaign_id",
            "claim_sha256",
            "coverage_sha256",
            "fingerprint_sha256",
        }
        assert issued["claim_sha256"] == claim_sha256
        child_id = str(issued["experiment_id"])
        assert re.search(r"experiment-[0-9]{32}", child_id)
        await self._await_count(
            lambda: backend.calls["instruct_eval.child_authorization_claim"],
            1,
            "authorization claim",
            backend,
        )
        child = self.env.client.get_workflow_handle(child_id)
        await self.env.sleep(0)
        return _AuthorizationContext(claim_sha256, child_id, child)

    async def _submit_design(
        self,
        authorization: _AuthorizationContext,
        backend: _ControlledBackend,
    ) -> Any:
        child = authorization.child
        await self._await_action(child, "submit_design", backend)
        submit_revision = (await child.query("status"))["current_revision_sha256"]
        assert submit_revision != ZERO
        return await child.execute_update(
            "decision",
            self._wire(
                _DecisionRequest(
                    "claim",
                    authorization.claim_sha256,
                    "submit_design",
                    DESIGN,
                    submit_revision,
                    1,
                )
            ),
        )

    async def _approve_freeze(
        self,
        authorization: _AuthorizationContext,
        revision: Any,
        backend: _ControlledBackend,
    ) -> None:
        child = authorization.child
        await self._await_action(child, "approve_freeze", backend)
        freeze_revision = (await child.query("status"))["current_revision_sha256"]
        assert freeze_revision != revision
        await child.execute_update(
            "decision",
            self._wire(
                _DecisionRequest(
                    "claim",
                    authorization.claim_sha256,
                    "approve_freeze",
                    None,
                    freeze_revision,
                    2,
                )
            ),
        )

    async def _run_happy_path(self, backend: _ControlledBackend) -> _HappyPathContext:
        campaign = await self._start_campaign(self._campaign_start_request(CAMPAIGN_ID))
        await self.env.sleep(0)
        await self._await_action(campaign, "approve_decomposition", backend)
        await self._assert_invalid_decomposition(campaign)
        await self._approve_decomposition(campaign)
        authorization = await self._await_authorized_child(backend)
        revision = await self._submit_design(authorization, backend)
        await self._approve_freeze(authorization, revision, backend)
        result = await campaign.result()
        return _HappyPathContext(
            campaign,
            authorization.child,
            authorization.claim_sha256,
            result,
        )

    def _assert_authorization_packets(
        self,
        backend: _ControlledBackend,
        claim_sha256: str,
    ) -> None:
        campaign_input = self._input()
        fingerprint = request_fingerprint(
            campaign_input.public_input,
            campaign_input.model_identity,
            campaign_input.runtime_identity,
        )
        expected = {
            "claim_sha256": claim_sha256,
            "coverage_sha256": COVERAGE,
            "fingerprint_sha256": fingerprint,
        }
        assert backend.packets["instruct_eval.child_authorization_issue"] == [expected]
        claim_packet = backend.packets["instruct_eval.child_authorization_claim"][0]
        assert set(claim_packet) == set(expected)
        assert claim_packet == expected

    @staticmethod
    def _assert_freeze_and_execution_packets(backend: _ControlledBackend) -> None:
        assert backend.calls["instruct_eval.execution_commit"] == 1
        assert backend.calls["instruct_eval.freeze"] == 1
        freeze_packet = backend.packets["instruct_eval.freeze"][0]
        assert freeze_packet["authorization_sha256"] == canonical_hash(backend.issued[0])
        assert freeze_packet["map_ref"] == "map"
        assert freeze_packet["map_commitment"] == "m" * 43
        assert freeze_packet["tokens"] == list(backend.tokens)
        assert freeze_packet["pre_map_input_hash"] == "e" * 64
        assert freeze_packet["authorization_rule_sha256"] == "f" * 64
        execution_packet = backend.packets["instruct_eval.execution_commit"][0]
        assert execution_packet["protocol_valid"] is True
        assert execution_packet["verifier_passed"] == [
            False,
            False,
            True,
            True,
            False,
            False,
            True,
            True,
            False,
            False,
        ]

    @staticmethod
    def _assert_analysis_matches_release(backend: _ControlledBackend) -> None:
        analysis_packet = backend.packets["instruct_eval.analysis"][0]
        release_artifact = json.loads(
            backend.artifacts.read_bytes(f"releases/{backend.issued[0]['experiment_id']}.json")
        )
        assert analysis_packet["release_sha256"] == release_artifact["release_sha256"]

    async def _assert_happy_path_oracles(
        self,
        context: _HappyPathContext,
        backend: _ControlledBackend,
    ) -> None:
        assert context.result.campaign_id == CAMPAIGN_ID
        await self._await_count(
            lambda: backend.calls["instruct_eval.subject_trial"],
            10,
            "subject trials",
            backend,
        )
        assert backend.calls["instruct_eval.subject_trial"] == 10
        assert backend.max_active_subjects <= 4
        self._assert_authorization_packets(backend, context.claim_sha256)
        self._assert_freeze_and_execution_packets(backend)
        self._assert_analysis_matches_release(backend)
        assert len(backend.describe_client.workflow_service.requests) == 3
        await self._assert_history_private_and_replayable(context.campaign, context.child)

    async def _submit_terminal_design(
        self,
        campaign: Any,
        backend: _ControlledBackend,
    ) -> None:
        authorization = await self._await_authorized_child(backend)
        child = authorization.child
        await self._await_action(child, "submit_design", backend)
        submit_revision = (await child.query("status"))["current_revision_sha256"]
        await child.execute_update(
            "decision",
            self._wire(
                _DecisionRequest(
                    "claim",
                    authorization.claim_sha256,
                    "submit_design",
                    DESIGN,
                    submit_revision,
                    1,
                )
            ),
        )
        del campaign

    async def _run_terminal_scenario(self, scenario: _TerminalScenario) -> None:
        root = Path(self.directory.name) / scenario.label
        root.mkdir()
        backend = _ControlledBackend(
            root,
            reject_g0=scenario.reject_g0,
            reject_g2=scenario.reject_g2,
        )
        public, private = await self._workers(backend)
        try:
            async with public, private:
                campaign = await self._start_campaign(self._campaign_start_request(CAMPAIGN_ID))
                await self.env.sleep(0)
                await self._await_action(campaign, "approve_decomposition", backend)
                await self._approve_decomposition(campaign)
                if scenario.reject_g2:
                    await self._submit_terminal_design(campaign, backend)
                await campaign.result()
            await self._await_count(
                lambda: backend.calls["instruct_eval.terminal_commit"],
                1,
                "terminal commit",
                backend,
            )
            assert backend.calls["instruct_eval.terminal_commit"] == 1
            assert backend.calls["instruct_eval.subject_trial"] == 0
            terminal = backend.packets["instruct_eval.terminal_commit"][0]
            assert terminal["terminal_gate"] == scenario.terminal_gate
        finally:
            backend.close()

    async def _assert_timeout_failure(self, probe: Any) -> None:
        with pytest.raises(WorkflowFailureError, match="Workflow execution failed") as failure:
            await probe.result()
        assert any(
            isinstance(error, TemporalTimeoutError) for error in self._cause_chain(failure.value)
        )

    async def _assert_cancellation_failure(self, handle: Any) -> None:
        with pytest.raises(WorkflowFailureError, match="Workflow execution failed") as failure:
            await handle.result()
        assert any(isinstance(error, CancelledError) for error in self._cause_chain(failure.value))

    async def test_campaign_happy_path_has_real_history_routing_and_replay(self) -> None:
        backend = _ControlledBackend(Path(self.directory.name))
        public, private = await self._workers(backend)
        try:
            async with public, private:
                context = await self._run_happy_path(backend)
            await self._assert_happy_path_oracles(context, backend)
        finally:
            backend.close()

    async def test_terminal_gates_are_durable_after_real_authorization(self) -> None:
        scenarios = (
            _TerminalScenario("terminal-0", reject_g0=True, reject_g2=False),
            _TerminalScenario("terminal-1", reject_g0=False, reject_g2=True),
        )
        for scenario in scenarios:
            await self._run_terminal_scenario(scenario)

    async def test_activity_timeout_and_cancellation_surface_as_failures(self) -> None:
        backend = _ControlledBackend(Path(self.directory.name))
        public, private = await self._workers(backend)
        try:
            async with public, private:
                probe = await self.env.client.start_workflow(
                    TimeoutProbeWorkflow.run,
                    id="timeout-probe",
                    task_queue=PUBLIC_QUEUE,
                )
                await self._assert_timeout_failure(probe)
                handle = await self._start_campaign(
                    self._campaign_start_request("cancel-integration")
                )
                await self.env.sleep(0)
                await handle.cancel()
                await self._assert_cancellation_failure(handle)
        finally:
            backend.close()
