"""Fake-based contracts for the public Temporal entrypoints and worker assembly."""

from __future__ import annotations

import asyncio
import json
import re
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, cast
from unittest.mock import AsyncMock, patch

import pytest
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from instruct_eval import cli, production_worker, worker
from instruct_eval.activities import (
    ChildAuthorizationClaimRequest,
    ChildAuthorizationIssueRequest,
    InstructEvalActivities,
    MapLifecycleRequest,
    SubjectTrialRequest,
)
from instruct_eval.artifacts import ArtifactStore
from instruct_eval.coordination import CoordinationError, CoordinationStore
from instruct_eval.messages import request_fingerprint
from instruct_eval.models import (
    Direction,
    EvidenceAxis,
    ExperimentDesign,
    Fixture,
    ReachabilityWitness,
    SourceClassification,
    SourceCoverage,
    Verifier,
    canonical_bytes,
    canonical_hash,
)
from instruct_eval.trials import ASSIGNMENT_IDS, pre_map_input_hash
from instruct_eval.workflows import (
    CampaignInput,
    CampaignStatus,
    ExperimentCampaignWorkflow,
    InstructionExperimentWorkflow,
    WorkflowProtocolError,
)

DIGEST = "a" * 64
CAMPAIGN_ID = "campaign-" + "1" * 32


def complete_design_package() -> dict[str, object]:
    verifier, observer = b"verify\n", b"observe\n"
    unchanged = (
        ("verify.py", sha256(verifier).hexdigest()),
        ("observe.py", sha256(observer).hexdigest()),
    )
    classification = SourceClassification(
        "1" * 64,
        (SourceCoverage(0, 1, "claim_normative", "claim-0001"),),
    )
    fixtures = []
    for fixture_id in ("core-1", "core-2", "negative-control"):
        manifest = {
            "schema": "instruct-eval-fixture-manifest-v1",
            "files": [
                {"path": "observe.py", "sha256": sha256(observer).hexdigest()},
                {"path": "out.txt", "sha256": "a" * 64},
                {"path": "verify.py", "sha256": sha256(verifier).hexdigest()},
            ],
        }
        witnesses = tuple(
            ReachabilityWitness(
                f"{fixture_id}-{direction}",
                direction,
                canonical_bytes(
                    {
                        "schema": "instruct-eval-witness-input-v1",
                        "changes": [{"path": "out.txt", "content": result}],
                    }
                ),
                passed,
                (("result", result),),
                "b" * 64,
                (("python", "c" * 64),),
                unchanged,
                ("out.txt",),
            )
            for direction, result, passed in (("good", "yes", True), ("bad", "no", False))
        )
        fixtures.append(
            Fixture(
                fixture_id,
                "scenario",
                manifest,
                canonical_hash(manifest),
                Verifier(verifier, sha256(verifier).hexdigest()),
                observer,
                sha256(observer).hexdigest(),
                {w.witness_id: w.expected_verifier_passed for w in witnesses},
                (EvidenceAxis("result", ("yes", "no")),),
                (Direction("good", "good"), Direction("bad", "bad")),
                {
                    (False, "yes"): "good",
                    (True, "yes"): "good",
                    (False, "no"): "bad",
                    (True, "no"): "bad",
                },
                ("out.txt",),
                witnesses,
                {
                    "schema": "instruct-eval-evidence-contract-v1",
                    "verifier_path": "verify.py",
                    "observer_path": "observe.py",
                    "verifier_command": ["python", "verify.py"],
                    "observer_command": ["python", "observe.py"],
                },
                classification,
            )
        )
    design = ExperimentDesign(tuple(fixtures))
    return json.loads(
        canonical_bytes(
            {
                "experiment_design": design.payload(),
                "preferred_directions": {
                    "core-1": "good",
                    "core-2": "good",
                    "negative-control": "bad",
                },
            }
        )
    )


def campaign_input(campaign_id: str = CAMPAIGN_ID, **public: object) -> CampaignInput:
    return CampaignInput(
        campaign_id,
        "model",
        "runtime",
        {
            "candidate_instruction": "be concise",
            "permissions": {"filesystem": "read"},
            "repository": "example/repository",
            "fixture_manifest_hash": DIGEST,
            "operator_public_key": "public-key",
            **public,
        },
        "b" * 64,
    )


class FakeClient:
    def __init__(
        self, *, duplicate: bool = False, status: object | Exception | list[object] | None = None
    ) -> None:
        self.namespace = worker.TEMPORAL_NAMESPACE
        self.duplicate = duplicate
        self.status = status
        self.started: list[tuple[object, object, dict[str, object]]] = []
        self.requested_handles: list[str] = []
        self.handle = FakeHandle(status)

    async def start_workflow(
        self, workflow_run: object, input_: object, **options: object
    ) -> object:
        self.started.append((workflow_run, input_, options))
        if self.duplicate:
            raise WorkflowAlreadyStartedError("duplicate", "ExperimentCampaignWorkflow")
        return self.handle

    def get_workflow_handle_for(self, workflow_run: object, workflow_id: str) -> FakeHandle:
        self.requested_handles.append(workflow_id)
        return self.handle


class FakeHandle:
    def __init__(self, status: object | Exception | list[object] | None) -> None:
        self.status = status
        self.queries: list[str] = []

    async def query(self, name: str, **_: object) -> object:
        self.queries.append(name)
        value = self.status.pop(0) if isinstance(self.status, list) else self.status
        if isinstance(value, Exception):
            raise value
        return value


class FakeWorker:
    created: ClassVar[list[FakeWorker]] = []

    def __init__(self, client: object, **options: object) -> None:
        self.client = client
        self.options = options
        self.created.append(self)


class PrivateAuthority:
    def authority_for(
        self, *, campaign_id: str, experiment_id: str, workflow_id: str, run_id: str
    ) -> worker.PrivateMapAuthority:
        package = complete_design_package()
        return worker.PrivateMapAuthority(
            "campaign",
            "campaign-run",
            "f" * 64,
            "1" * 64,
            "2" * 64,
            "3" * 64,
            canonical_hash(package),
            "4" * 64,
            "5" * 64,
            cast(dict[str, str], package["preferred_directions"]),
            {
                assignment: "exact child treatment" if assignment.rsplit("-", 2)[1] == "B" else None
                for assignment in ASSIGNMENT_IDS
            },
            cast(dict[str, object], package["experiment_design"]),
        )


class Subject:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(
        self,
        *,
        assignment: object,
        treatment: str | None,
        disclosure_treatment: str,
        frozen_design: ExperimentDesign,
    ) -> dict[str, object]:
        self.calls += 1
        blind_id = assignment.blind_id
        return {
            "outcome": {
                "blind_id": blind_id,
                "fixture": assignment.scenario,
                "protocol_valid": True,
                "verifier_passed": True,
                "observer_state": [],
                "direction_code": "good",
                "changed_paths": [],
                "evidence_id": "evidence",
            },
            "private_artifacts": {
                "response": "completed",
                "runtime_streams": {"stdout": "", "stderr": ""},
                "tool_outputs": [],
                "diff": "",
                "verifier": {"passed": True, "stdout": "", "stderr": ""},
                "observer": {},
                "trusted_logs": {"reason": None, "unchanged_hashes": {}},
            },
        }


class PrivateInfo:
    workflow_namespace = worker.TEMPORAL_NAMESPACE
    workflow_type = "InstructionExperimentWorkflow"
    task_queue = worker.PRIVATE_TASK_QUEUE
    workflow_id = "experiment-workflow"
    workflow_run_id = "experiment-run"

    def __init__(self, activity_type: str, activity_id: str) -> None:
        self.activity_type = activity_type
        self.activity_id = activity_id


class EntrypointWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.artifacts = ArtifactStore(root / "public", root / "private")
        self.coordination = CoordinationStore(root / "coordination.sqlite")
        self.private_maps = worker.PrivateMapLifecycle(root / "private.sqlite", root / "private")
        self.authority = PrivateAuthority()
        self.subject = Subject()
        self.calls: list[tuple[str, object, object, object, object]] = []
        operations = worker.DomainOperations(
            **cast(
                Any,
                {
                    name: self.operation(name)
                    for name in worker.DomainOperations.__dataclass_fields__
                },
            )
        )
        self.backend = worker.InstructEvalActivityBackend(
            worker.ActivityBackendRequest(
                artifacts=self.artifacts,
                coordination=self.coordination,
                operations=operations,
                private_maps=self.private_maps,
                private_authority=self.authority,
                subject_executor=self.subject,
                runtime=object(),
            )
        )

    def tearDown(self) -> None:
        self.private_maps.close()
        self.directory.cleanup()

    def operation(self, name: str):
        def invoke(
            request: object, artifacts: object, coordination: object, runtime: object
        ) -> dict[str, str]:
            self.calls.append((name, request, artifacts, coordination, runtime))
            return {"operation": name}

        return invoke

    def test_complete_backend_delegates_every_named_operation_with_durable_dependencies(
        self,
    ) -> None:
        request = object()
        for name in worker.DomainOperations.__dataclass_fields__:
            assert getattr(self.backend, name)(request) == {"operation": name}
        assert [call[0] for call in self.calls] == list(
            worker.DomainOperations.__dataclass_fields__
        )
        assert all(
            call[2] is self.artifacts and call[3] is self.coordination for call in self.calls
        )
        assert "map_lifecycle" not in worker.DomainOperations.__dataclass_fields__
        assert "subject_trial" not in worker.DomainOperations.__dataclass_fields__

    def test_child_authorization_packets_bind_one_issued_experiment_to_one_child(self) -> None:
        issue_payload = {
            "claim_sha256": "1" * 64,
            "coverage_sha256": "2" * 64,
            "fingerprint_sha256": "3" * 64,
        }
        issue = ChildAuthorizationIssueRequest(
            "campaign",
            "ignored",
            "role",
            sha256(canonical_bytes(issue_payload)).hexdigest(),
            "model",
            "runtime",
            issue_payload,
        )
        campaign_description = SimpleNamespace(
            workflow_execution_info=SimpleNamespace(
                type=SimpleNamespace(name="ExperimentCampaignWorkflow")
            )
        )
        self.backend._describe = AsyncMock(return_value=campaign_description)
        issuer_info = SimpleNamespace(workflow_id="campaign", workflow_run_id="campaign-run")
        with patch("instruct_eval.worker.activity.info", return_value=issuer_info):
            issued = asyncio.run(self.backend.child_authorization_issue(issue))
            recovered = asyncio.run(self.backend.child_authorization_issue(issue))
        assert issued == recovered
        assert set(issue.payload) == {"claim_sha256", "coverage_sha256", "fingerprint_sha256"}
        assert re.search(r"^experiment-\d{32}$", str(issued["experiment_id"]))
        assert set(issued) == {
            "authorized",
            "experiment_id",
            "campaign_id",
            "claim_sha256",
            "coverage_sha256",
            "fingerprint_sha256",
        }

        claim_payload = dict(issue_payload)
        claim = ChildAuthorizationClaimRequest(
            "campaign",
            str(issued["experiment_id"]),
            "role",
            sha256(canonical_bytes(claim_payload)).hexdigest(),
            "model",
            "runtime",
            claim_payload,
        )
        child_description = SimpleNamespace(
            workflow_execution_info=SimpleNamespace(
                type=SimpleNamespace(name="InstructionExperimentWorkflow"),
                parent_execution=SimpleNamespace(workflow_id="campaign", run_id="campaign-run"),
            )
        )
        self.backend._describe = AsyncMock(side_effect=(child_description, campaign_description))
        claimant_info = SimpleNamespace(workflow_id="exact-child", workflow_run_id="child-run")
        with patch("instruct_eval.worker.activity.info", return_value=claimant_info):
            claimed = asyncio.run(self.backend.child_authorization_claim(claim))
        assert claimed["experiment_id"] == issued["experiment_id"]
        assert claimed == issued
        mismatch = ChildAuthorizationClaimRequest(
            "campaign",
            "experiment-" + "9" * 32,
            "role",
            sha256(canonical_bytes(claim_payload)).hexdigest(),
            "model",
            "runtime",
            claim_payload,
        )
        self.backend._describe = AsyncMock(side_effect=(child_description, campaign_description))
        with (
            patch("instruct_eval.worker.activity.info", return_value=claimant_info),
            pytest.raises(CoordinationError, match="was not issued"),
        ):
            asyncio.run(self.backend.child_authorization_claim(mismatch))

    def test_private_lifecycle_uses_temporal_metadata_and_survives_reconstruction(self) -> None:
        payload = {
            "design_sha256": canonical_hash(complete_design_package()),
            "candidate_instruction": "candidate",
            "fixture_manifest_hash": "5" * 64,
        }
        map_request = MapLifecycleRequest(
            "campaign",
            "experiment",
            "role",
            sha256(canonical_bytes(payload)).hexdigest(),
            "model",
            "runtime",
            payload,
        )
        child_description = SimpleNamespace(
            workflow_execution_info=SimpleNamespace(
                type=SimpleNamespace(name="InstructionExperimentWorkflow"),
                parent_execution=SimpleNamespace(workflow_id="campaign", run_id="campaign-run"),
            )
        )
        campaign_description = SimpleNamespace(
            workflow_execution_info=SimpleNamespace(
                type=SimpleNamespace(name="ExperimentCampaignWorkflow")
            )
        )
        self.backend._describe = AsyncMock(side_effect=(child_description, campaign_description))
        with patch(
            "instruct_eval.worker.activity.info",
            return_value=PrivateInfo(
                "instruct_eval.map_lifecycle",
                worker.PRIVATE_MAP_ACTIVITY_ID,
            ),
        ):
            first = asyncio.run(self.backend.map_lifecycle(map_request))
        recovered_private_maps = worker.PrivateMapLifecycle(
            self.private_maps.path, self.artifacts.private_root
        )
        try:
            recovered_backend = worker.InstructEvalActivityBackend(
                worker.ActivityBackendRequest(
                    artifacts=self.artifacts,
                    coordination=self.coordination,
                    operations=worker.DomainOperations(
                        **cast(
                            Any,
                            {
                                name: self.operation(name)
                                for name in worker.DomainOperations.__dataclass_fields__
                            },
                        )
                    ),
                    private_maps=recovered_private_maps,
                    private_authority=self.authority,
                    subject_executor=self.subject,
                )
            )
            recovered_backend._describe = AsyncMock(
                side_effect=(child_description, campaign_description)
            )
            with patch(
                "instruct_eval.worker.activity.info",
                return_value=PrivateInfo(
                    "instruct_eval.map_lifecycle",
                    worker.PRIVATE_MAP_ACTIVITY_ID,
                ),
            ):
                recovered = asyncio.run(recovered_backend.map_lifecycle(map_request))
        finally:
            recovered_private_maps.close()
        expected_pre_map_hash = pre_map_input_hash(
            namespace=worker.TEMPORAL_NAMESPACE,
            workflow_type="InstructionExperimentWorkflow",
            task_queue=worker.PRIVATE_TASK_QUEUE,
            campaign_id="campaign",
            experiment_id="experiment",
            workflow_id="experiment-workflow",
            run_id="experiment-run",
            claim_hash="1" * 64,
            g0_record_hash="2" * 64,
            design_proposal_hash="3" * 64,
            design_hash=canonical_hash(complete_design_package()),
            treatment_hash="4" * 64,
            fixture_manifest_hash="5" * 64,
        )
        assert (
            self.private_maps._db.execute(
                "SELECT input_hash FROM private_maps WHERE workflow_id=? AND run_id=?",
                ("experiment-workflow", "experiment-run"),
            ).fetchone()[0]
            == expected_pre_map_hash
        )
        assert first == recovered
        assert set(first) == {
            "map_ref",
            "map_commitment",
            "tokens",
            "pre_map_input_hash",
            "authorization_rule_sha256",
        }
        assert len(first["tokens"]) == 10

        subject_payload = {
            "map_ref": first["map_ref"],
            "token": first["tokens"][0],
            "design_sha256": canonical_hash(complete_design_package()),
        }
        subject_request = SubjectTrialRequest(
            "campaign",
            "experiment",
            "role",
            sha256(canonical_bytes(subject_payload)).hexdigest(),
            "model",
            "runtime",
            subject_payload,
        )
        activities = InstructEvalActivities(self.coordination, self.backend)
        self.backend._describe = AsyncMock(
            side_effect=(child_description, campaign_description) * 4
        )
        with patch(
            "instruct_eval.worker.activity.info",
            return_value=PrivateInfo(
                "instruct_eval.subject_trial",
                worker.private_subject_activity_id(first["tokens"][0]),
            ),
        ):
            first_outcome = asyncio.run(activities.subject_trial(subject_request))
            second_outcome = asyncio.run(activities.subject_trial(subject_request))
        assert first_outcome == second_outcome
        assert self.subject.calls == 1
        assert set(first_outcome.payload) == {
            "blind_id",
            "fixture",
            "protocol_valid",
            "verifier_passed",
            "observer_state",
            "direction_code",
            "changed_paths",
            "evidence_id",
        }

    def test_forged_private_metadata_and_joins_fail_closed(self) -> None:
        bad_payload = {"design_sha256": DIGEST, "workflow_id": "forged"}
        forged = MapLifecycleRequest(
            "campaign",
            "experiment",
            "role",
            sha256(canonical_bytes(bad_payload)).hexdigest(),
            "model",
            "runtime",
            bad_payload,
        )
        with (
            patch(
                "instruct_eval.worker.activity.info",
                return_value=PrivateInfo(
                    "instruct_eval.map_lifecycle",
                    worker.PRIVATE_MAP_ACTIVITY_ID,
                ),
            ),
            pytest.raises(
                ValueError,
                match="private lifecycle payload is not an exact public-hash packet",
            ),
        ):
            asyncio.run(self.backend.map_lifecycle(forged))
        payload = {
            "design_sha256": DIGEST,
            "candidate_instruction": "candidate",
            "fixture_manifest_hash": "5" * 64,
        }
        request = MapLifecycleRequest(
            "campaign",
            "experiment",
            "role",
            sha256(canonical_bytes(payload)).hexdigest(),
            "model",
            "runtime",
            payload,
        )
        child_description = SimpleNamespace(
            workflow_execution_info=SimpleNamespace(
                type=SimpleNamespace(name="InstructionExperimentWorkflow"),
                parent_execution=SimpleNamespace(workflow_id="campaign", run_id="campaign-run"),
            )
        )
        campaign_description = SimpleNamespace(
            workflow_execution_info=SimpleNamespace(
                type=SimpleNamespace(name="ExperimentCampaignWorkflow")
            )
        )
        self.backend._describe = AsyncMock(side_effect=(child_description, campaign_description))
        with (
            patch(
                "instruct_eval.worker.activity.info",
                return_value=PrivateInfo(
                    "instruct_eval.map_lifecycle",
                    "forged-activity-id",
                ),
            ),
            pytest.raises(ValueError, match="untrusted Temporal activity metadata"),
        ):
            asyncio.run(self.backend.map_lifecycle(request))

    def test_absent_backend_dependencies_and_operations_fail_closed(self) -> None:
        operations = worker.DomainOperations(
            **cast(
                Any,
                {
                    name: self.operation(name)
                    for name in worker.DomainOperations.__dataclass_fields__
                },
            )
        )
        with pytest.raises(TypeError, match="ArtifactStore"):
            worker.InstructEvalActivityBackend(
                worker.ActivityBackendRequest(
                    artifacts=cast(Any, object()),
                    coordination=self.coordination,
                    operations=operations,
                    private_maps=self.private_maps,
                    private_authority=self.authority,
                    subject_executor=self.subject,
                )
            )
        with pytest.raises(TypeError, match="callable"):
            worker.DomainOperations(
                **cast(
                    Any,
                    {
                        name: None if name == "analysis" else self.operation(name)
                        for name in worker.DomainOperations.__dataclass_fields__
                    },
                )
            )
        with pytest.raises(ValueError, match="storage paths"):
            worker.build_backend(
                worker.BuildBackendRequest(
                    artifact_root="",
                    private_artifact_root="private",
                    coordination_database="coordination.sqlite",
                    private_database="private.sqlite",
                    operations=operations,
                    private_authority=self.authority,
                    subject_executor=self.subject,
                )
            )

    def test_worker_registration_partitions_public_and_private_activities_exactly(self) -> None:
        FakeWorker.created.clear()
        with patch("instruct_eval.worker.Worker", FakeWorker):
            public, private = worker.create_workers(cast(Any, FakeClient()), self.backend)
        public, private = cast(FakeWorker, public), cast(FakeWorker, private)
        assert (public.options["task_queue"], private.options["task_queue"]) == (
            worker.PUBLIC_TASK_QUEUE,
            worker.PRIVATE_TASK_QUEUE,
        )
        assert public.options["workflows"] == [
            ExperimentCampaignWorkflow,
            InstructionExperimentWorkflow,
        ]
        assert public.options["workflow_failure_exception_types"] == [WorkflowProtocolError]
        assert "workflows" not in private.options
        assert (
            tuple(method.__name__ for method in cast(tuple[Any, ...], public.options["activities"]))
            == worker.PUBLIC_ACTIVITY_METHODS
        )
        assert (
            tuple(
                method.__name__ for method in cast(tuple[Any, ...], private.options["activities"])
            )
            == worker.PRIVATE_ACTIVITY_METHODS
        )
        assert "proposal_decision" not in worker.PUBLIC_ACTIVITY_METHODS
        assert "proposal_decision" in worker.PRIVATE_ACTIVITY_METHODS

    def test_worker_rejects_wrong_namespace_shared_storage_and_queue(self) -> None:
        client = FakeClient()
        client.namespace = "wrong"
        with pytest.raises(ValueError, match="namespace"):
            worker.create_workers(cast(Any, client), self.backend)
        private_root = self.backend._artifacts.private_root
        self.backend._artifacts.private_root = self.backend._artifacts.root
        with pytest.raises(ValueError, match="separate"):
            worker.create_workers(cast(Any, FakeClient()), self.backend)
        self.backend._artifacts.private_root = private_root
        with pytest.raises(ValueError, match="distinct"):
            worker.create_workers(
                cast(Any, FakeClient()),
                self.backend,
                public_task_queue="same",
                private_task_queue="same",
            )

    def test_production_worker_has_only_mode_specific_config_loaders(self) -> None:
        assert callable(production_worker.load_public_config)
        assert callable(production_worker.load_private_config)
        assert not hasattr(production_worker, "load_config")


class CampaignEntrypointTests(unittest.TestCase):
    def test_campaign_only_start_uses_exact_reject_duplicate_options(self) -> None:
        client = FakeClient()
        result = asyncio.run(cli.start_campaign(cast(Any, client), campaign_input()))
        assert (result.state, result.handle) == ("started", client.handle)
        workflow_run, input_, options = client.started[0]
        assert workflow_run is ExperimentCampaignWorkflow.run
        assert input_ == campaign_input()
        assert options == {
            "id": CAMPAIGN_ID,
            "task_queue": worker.PUBLIC_TASK_QUEUE,
            "id_reuse_policy": WorkflowIDReusePolicy.REJECT_DUPLICATE,
        }

    def test_campaign_id_grammar_namespace_and_queue_fail_before_start(self) -> None:
        for campaign_id in ("campaign-not-hex", "experiment-" + "1" * 32, "campaign-" + "A" * 32):
            with pytest.raises(cli.CampaignStartError, match="campaign id"):
                asyncio.run(
                    cli.start_campaign(cast(Any, FakeClient()), campaign_input(campaign_id))
                )
        client = FakeClient()
        client.namespace = "wrong"
        with pytest.raises(cli.CampaignStartError, match="namespace"):
            asyncio.run(cli.start_campaign(cast(Any, client), campaign_input()))
        with pytest.raises(ValueError, match="task queue"):
            asyncio.run(
                cli.start_campaign(cast(Any, FakeClient()), campaign_input(), task_queue="")
            )

    def test_ready_equal_duplicate_is_adopted(self) -> None:
        input_ = campaign_input()
        expected = request_fingerprint(
            input_.public_input, input_.model_identity, input_.runtime_identity
        )
        for state in ("FINGERPRINT_READY", "WAITING_DECOMPOSITION", "COMPLETED"):
            with self.subTest(state=state):
                client = FakeClient(
                    duplicate=True, status=CampaignStatus(CAMPAIGN_ID, state, expected, 0)
                )
                result = asyncio.run(cli.start_campaign(cast(Any, client), input_))
                assert (result.state, result.handle) == ("adopted", client.handle)
                assert client.requested_handles == [CAMPAIGN_ID]
                assert client.handle.queries == ["status"]

    def test_duplicate_mismatch_failed_closed_and_query_failure_are_not_adopted(self) -> None:
        input_ = campaign_input()
        expected = request_fingerprint(
            input_.public_input, input_.model_identity, input_.runtime_identity
        )
        cases = (
            CampaignStatus(CAMPAIGN_ID, "FINGERPRINT_READY", "c" * 64, 0),
            CampaignStatus(
                CAMPAIGN_ID,
                "FINGERPRINT_READY",
                expected[:-1] + ("0" if expected[-1] != "0" else "1"),
                0,
            ),
            CampaignStatus(CAMPAIGN_ID, "FINGERPRINT_FAILED", None, 0),
            CampaignStatus(CAMPAIGN_ID, "COMPLETED", None, 0),
            RuntimeError("unavailable"),
        )
        for status in cases:
            with self.subTest(status=status), pytest.raises(cli.CampaignStartError):
                asyncio.run(
                    cli.start_campaign(cast(Any, FakeClient(duplicate=True, status=status)), input_)
                )

    def test_duplicate_initialization_timeout_caps_exponential_delay_at_deadline(self) -> None:
        now = [0.0]
        sleeps: list[float] = []

        async def sleep(delay: float) -> None:
            sleeps.append(delay)
            now[0] += delay

        client = FakeClient(
            duplicate=True, status=CampaignStatus(CAMPAIGN_ID, "INITIALIZING", None, 0)
        )
        result = asyncio.run(
            cli.start_campaign(
                cast(Any, client), campaign_input(), sleep=sleep, monotonic=lambda: now[0]
            )
        )
        assert (result.state, result.handle) == ("initialization_pending", None)
        assert sleeps[:5] == [0.03125, 0.0625, 0.125, 0.25, 0.5]
        assert all(delay <= 1.0 for delay in sleeps)
        assert sum(sleeps) == 30.0
        assert max(sleeps) == 1.0
        assert sleeps[-1] <= 1.0


if __name__ == "__main__":
    unittest.main()
