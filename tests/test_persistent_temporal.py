"""Persistent real-server campaign recovery, privacy, and replay proof."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from collections import Counter
from collections.abc import Callable, Mapping
from contextlib import closing, suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, override
from uuid import uuid4

import pytest
import test_temporal_integration as baseline
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from temporalio.client import Client, WorkflowUpdateFailedError
from temporalio.service import RPCError
from temporalio.worker import Replayer, Worker

from instruct_eval import cli, worker
from instruct_eval.activities import GatePublication, InstructEvalActivities
from instruct_eval.coordination import CoordinationError, CoordinationStore, InvocationDisposition
from instruct_eval.messages import ProposalControl, request_fingerprint
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
    construct_outcome_tuple,
    derive_treatment,
)
from instruct_eval.production import (
    ArtifactPrivateAuthority,
    concrete_domain_operations,
    g6_authorized,
)
from instruct_eval.provision import TEMPORAL_CLI_VERSION_OUTPUT
from instruct_eval.signing import (
    DecisionPayload,
    DecisionWire,
    DecompositionProposal,
    DesignProposal,
    StageAttestation,
    public_key_base64url,
)
from instruct_eval.workflows import (
    CampaignInput,
    ExperimentCampaignWorkflow,
    InstructionExperimentWorkflow,
    WorkflowProtocolError,
)

CANDIDATE = "be exact"
COVERAGE_SOURCE = [
    SourceCoverage(0, 3, "claim_normative", "claim-0001").as_json(),
    SourceCoverage(3, len(CANDIDATE.encode()), "claim_normative", "claim-0002").as_json(),
]
COVERAGE = canonical_hash({"source_coverage": COVERAGE_SOURCE})
ZERO = "0" * 64


@dataclass(frozen=True, slots=True)
class _BackendOptions:
    interrupt_after_subject_commit: bool = False
    interrupt_after_release_publish: bool = False
    hold_release: bool = False
    authorize_g6: bool = True
    claims: tuple[str, ...] = ("atomic", "compound")


@dataclass(frozen=True, slots=True)
class _Decision:
    target_kind: str
    target_id: str
    action: str
    proposal: str | None
    revision: str
    sequence: int


@dataclass(frozen=True, slots=True)
class _InterruptedCampaign:
    campaign: Any
    children: tuple[Any, ...]
    claims: tuple[str, ...]
    first_backend: _TwoClaimBackend
    first_executor_calls: dict[str, int]
    histories: Path
    queue: str


@dataclass(frozen=True, slots=True)
class _ReleaseInterruptedCampaign:
    interrupted: _InterruptedCampaign
    release_backend: _TwoClaimBackend
    interrupted_releases: dict[str, bytes]


def _design_package() -> dict[str, Any]:
    classification = SourceClassification(
        sha256(CANDIDATE.encode()).hexdigest(),
        tuple(
            SourceCoverage(
                start_byte=item["start_byte"],
                end_byte=item["end_byte"],
                classification=item["classification"],
                owner=item.get("owner"),
                consumers=tuple(item.get("consumers", ())),
                reason=item.get("reason"),
            )
            for item in COVERAGE_SOURCE
        ),
    )
    verifier, observer, digest = b"verify\n", b"observe\n", "7" * 64

    def fixture(fixture_id: str, preferred: str) -> Fixture:
        alternate = "worse" if preferred == "better" else "different"
        manifest = {"fixture": fixture_id, "version": 1}

        def witness(code: str, result: str, verifier_passed: bool) -> ReachabilityWitness:
            return ReachabilityWitness(
                f"w-{code}",
                code,
                code.encode(),
                verifier_passed,
                (("result", result),),
                digest,
                (("python", digest),),
                (("observe.py", digest), ("verify.py", digest)),
                ("out.txt",),
            )

        return Fixture(
            fixture_id,
            "complete scenario task",
            manifest,
            canonical_hash(manifest),
            Verifier(verifier, sha256(verifier).hexdigest()),
            observer,
            sha256(observer).hexdigest(),
            {f"w-{preferred}": False, f"w-{alternate}": True},
            (EvidenceAxis("result", ("yes", "no")),),
            (Direction(preferred, "preferred result"), Direction(alternate, "alternate result")),
            {
                (False, "yes"): preferred,
                (True, "yes"): preferred,
                (False, "no"): alternate,
                (True, "no"): alternate,
            },
            ("out.txt",),
            (witness(preferred, "yes", False), witness(alternate, "no", True)),
            {"required": ["out.txt"]},
            classification,
        )

    design = ExperimentDesign(
        (
            fixture("core-1", "better"),
            fixture("core-2", "better"),
            fixture("negative-control", "same"),
        )
    )
    return json.loads(
        canonical_bytes(
            {
                "experiment_design": design.payload(),
                "preferred_directions": {
                    "core-1": "better",
                    "core-2": "better",
                    "negative-control": "same",
                },
            }
        )
    )


DESIGN_PACKAGE = _design_package()
DESIGN = canonical_hash(DESIGN_PACKAGE)
FIXTURE_MANIFEST_HASH = canonical_hash(
    {
        "fixtures": [
            {"fixture_id": fixture["fixture_id"], "manifest_sha256": fixture["manifest_sha256"]}
            for fixture in sorted(
                DESIGN_PACKAGE["experiment_design"]["fixtures"],
                key=lambda fixture: fixture["fixture_id"],
            )
        ]
    }
)


class _ProcessLoss(BaseException):
    """Escape in-process recovery exactly where the worker process disappears."""


class _PostCommitInterruptStore(CoordinationStore):
    """Inject process loss after one durable subject or release publication."""

    def __init__(
        self, database: Path, interrupt_subject: bool, interrupt_release_publish: bool
    ) -> None:
        super().__init__(database)
        self.interrupt_subject = interrupt_subject
        self.interrupt_release_publish = interrupt_release_publish
        self.committed_subjects: set[str] = set()
        self.recovered_subjects: set[str] = set()
        self.on_interruption: Callable[[], None] | None = None

    def reserve_invocation(self, invocation_key: str, input_bytes: bytes):
        reservation = super().reserve_invocation(invocation_key, input_bytes)
        if (
            reservation.disposition is InvocationDisposition.RESULT_RECOVERED
            and b'"purpose":"subject_trial"' in input_bytes
        ):
            self.recovered_subjects.add(invocation_key)
        return reservation

    def commit_private_subject_result(
        self, invocation_key: str, owner_epoch: int, result_bytes: bytes
    ):
        committed = super().commit_private_subject_result(invocation_key, owner_epoch, result_bytes)
        if self.interrupt_subject:
            self.interrupt_subject = False
            self.committed_subjects.add(invocation_key)
            if self.on_interruption is not None:
                self.on_interruption()
            raise _ProcessLoss("controlled process loss after durable subject result commit")
        return committed

    @override
    def publish_gate(
        self,
        workflow_id: str,
        run_id: str,
        ordinal: int,
        expected_revision_sha256: str,
        owner_epoch: int,
        final_artifact_path: str | Path,
        expected_bytes: bytes,
        expected_sha256: str,
    ):
        publication = super().publish_gate(
            workflow_id,
            run_id,
            ordinal,
            expected_revision_sha256,
            owner_epoch,
            final_artifact_path,
            expected_bytes,
            expected_sha256,
        )
        if self.interrupt_release_publish and Path(final_artifact_path).name.endswith(
            "-release.json"
        ):
            self.interrupt_release_publish = False
            if self.on_interruption is not None:
                self.on_interruption()
            raise _ProcessLoss("controlled process loss after durable release publication")
        return publication


class _TwoClaimBackend(baseline._ControlledBackend):
    """Controlled roles around the real durable backend boundary only."""

    def __init__(self, root: Path, campaign_id: str, options: _BackendOptions) -> None:
        self.campaign_id = campaign_id
        super().__init__(root)
        self.coordination = _PostCommitInterruptStore(
            root / "coordination.sqlite",
            options.interrupt_after_subject_commit,
            options.interrupt_after_release_publish,
        )
        self.treatment_hashes: dict[str, str] = {}
        self._coordination = self.coordination
        self.subject_requests: list[dict[str, Any]] = []
        self.subject_assignments: list[tuple[str, str]] = []
        self.subject_treatments: list[tuple[str, str, str | None]] = []
        self.subject_executor_calls: Counter[str] = Counter()
        self.treatment_texts: dict[str, str] = {}
        self.release_calls = 0
        self._claims = options.claims
        self._private_authority = ArtifactPrivateAuthority(self.artifacts)
        self.authorize_g6 = options.authorize_g6
        self.release_started = asyncio.Event()
        self.release_permit = asyncio.Event()
        self.subject_permit = asyncio.Event()
        if not options.interrupt_after_subject_commit:
            self.subject_permit.set()
        if not options.hold_release:
            self.release_permit.set()

    def _operation(self, name: str):
        parent = super()._operation(name)
        if name == "analysis":

            def analyze(
                request: Any, artifacts: Any, coordination: Any, runtime: Any
            ) -> GatePublication:
                if (
                    set(request.payload) != {"gate", "design_sha256", "release_sha256"}
                    or request.payload["gate"] != "G6"
                ):
                    raise AssertionError("G6 request is not exact")
                release_path = (
                    Path("releases")
                    / request.campaign_id
                    / request.experiment_id
                    / f"{request.payload['release_sha256']}.json"
                )
                release = json.loads(artifacts.path_for(release_path).read_bytes())
                if release["release_sha256"] != request.payload["release_sha256"]:
                    raise AssertionError("G6 is not bound to G5")
                payload = {
                    "schema": "instruct-eval-g6-analysis-v1",
                    "design_sha256": request.payload["design_sha256"],
                    "release_sha256": request.payload["release_sha256"],
                    "authorized": g6_authorized(
                        release["assignments"], release["preferred_directions"]
                    ),
                }
                raw = canonical_bytes(payload)
                relative = (
                    Path("gates") / request.experiment_id / f"analysis-{request.ordinal}.json"
                )
                return GatePublication(
                    payload,
                    artifacts.path_for(relative),
                    raw,
                    artifacts.publish_bytes(relative, raw),
                )

            return analyze
        if name == "proposal_decision":
            return concrete_domain_operations().proposal_decision
        return parent

    async def map_lifecycle(self, request: Any) -> Mapping[str, Any]:
        return await worker.InstructEvalActivityBackend.map_lifecycle(self, request)

    def _subject(self, **values: Any) -> Mapping[str, Any]:
        assignment = values["assignment"]
        treatment = values["treatment"]
        self.subject_executor_calls[assignment.token] += 1
        with closing(sqlite3.connect(self._private_maps.path)) as database:
            maps = database.execute("SELECT experiment, payload FROM private_maps").fetchall()
        experiment_id = next(
            str(experiment)
            for experiment, payload in maps
            if any(item["token"] == assignment.token for item in json.loads(payload)["assignments"])
        )
        self.subject_treatments.append((experiment_id, assignment.condition, treatment))
        self.subject_assignments.append((assignment.assignment_id, assignment.token))
        preferred = self.authorize_g6 and (
            assignment.scenario == "negative-control" or assignment.condition == "B"
        )
        verifier_passed = preferred
        observer_state = {"result": "yes" if preferred else "no"}
        observed = construct_outcome_tuple(
            values["frozen_design"], assignment.scenario, verifier_passed, observer_state
        )
        frozen_fixture = next(
            fixture
            for fixture in values["frozen_design"].fixtures
            if fixture.fixture_id == assignment.scenario
        )
        direction_code = frozen_fixture.outcome_table[
            (observed.verifier_passed, *observed.axis_values)
        ]
        return {
            "outcome": {
                "blind_id": assignment.blind_id,
                "fixture": assignment.scenario,
                "protocol_valid": True,
                "verifier_passed": verifier_passed,
                "observer_state": observer_state,
                "direction_code": direction_code,
                "changed_paths": [],
                "evidence_id": sha256(assignment.token.encode()).hexdigest(),
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

    async def subject_trial(self, request: Any) -> Mapping[str, Any]:
        await self.subject_permit.wait()
        self.subject_requests.append(dict(request.payload))
        result = await worker.InstructEvalActivityBackend.subject_trial(self, request)
        self._record("instruct_eval.subject_trial", request)
        return result

    async def finalize_subject_trial(self, request: Any, outcome: Mapping[str, Any]) -> None:
        await worker.InstructEvalActivityBackend.finalize_subject_trial(self, request, outcome)

    async def release(self, request: Any) -> Any:
        self.release_calls += 1
        self.release_started.set()
        await self.release_permit.wait()
        with closing(sqlite3.connect(self._private_maps.path)) as database:
            map_ref = database.execute(
                "SELECT map_ref FROM private_maps WHERE experiment = ?", (request.experiment_id,)
            ).fetchone()[0]
            inventory_count = database.execute(
                "SELECT COUNT(*) FROM private_artifacts WHERE map_ref = ?", (map_ref,)
            ).fetchone()[0]
        expected_inventory = 1 + 10 * len(worker.SUBJECT_ARTIFACT_KINDS)
        if inventory_count != expected_inventory:
            raise AssertionError(
                "release requires one map and the exact token-bound artifact inventory; "
                f"found {inventory_count}"
            )
        return await worker.InstructEvalActivityBackend.release(self, request)


def _history_text(history: Any) -> str:
    raw = history.to_json()
    decoded = [raw]

    def walk(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if key == "data" and isinstance(nested, str):
                    with suppress(ValueError, UnicodeDecodeError):
                        decoded.append(base64.b64decode(nested, validate=True).decode())
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(json.loads(raw))
    return "\n".join(decoded)


class PersistentTemporalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        address = os.environ.get("TEMPORAL_ADDRESS")
        temporal_cli = os.environ.get("TEMPORAL_CLI")
        temporal_database = os.environ.get("TEMPORAL_DATABASE")
        if not address or not temporal_cli or not temporal_database:
            self.skipTest("TEMPORAL_ADDRESS, TEMPORAL_CLI, and TEMPORAL_DATABASE are required")
        assert Path(temporal_cli).is_file()
        assert Path(temporal_database).is_file()
        version = subprocess.run(
            [temporal_cli, "--version"], check=True, text=True, capture_output=True
        ).stdout.rstrip("\n")
        assert version == TEMPORAL_CLI_VERSION_OUTPUT
        self.client = await Client.connect(address, namespace="instruct-eval")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.private_key = Ed25519PrivateKey.generate()
        self.suffix = f"{uuid4().int % 10**32:032d}"
        self.campaign_id = f"campaign-{self.suffix}"
        self._private_shutdown_tasks: list[asyncio.Task[Any]] = []
        baseline.CAMPAIGN_ID = self.campaign_id
        baseline.DESIGN = DESIGN

    async def asyncTearDown(self) -> None:
        await self._await_private_shutdowns()
        self.temp.cleanup()

    async def _await_private_shutdowns(self) -> None:
        tasks, self._private_shutdown_tasks = self._private_shutdown_tasks, []
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    raise result

    def _input(self) -> CampaignInput:
        public = {
            "candidate_instruction": "be exact",
            "permissions": {"network": False},
            "repository": "persistent-fixture",
            "fixture_manifest_hash": FIXTURE_MANIFEST_HASH,
            "operator_public_key": public_key_base64url(self.private_key.public_key()),
        }
        return CampaignInput(self.campaign_id, "model", "runtime", public, COVERAGE)

    def _wire(self, decision: _Decision, *, key: Ed25519PrivateKey | None = None) -> dict[str, Any]:
        return DecisionWire.sign(
            key or self.private_key,
            DecisionPayload(
                self.campaign_id,
                decision.target_kind,
                decision.target_id,
                decision.action,
                decision.proposal,
                decision.revision,
                decision.sequence,
            ),
        ).as_json()

    def _workers(self, backend: _TwoClaimBackend) -> tuple[Worker, Worker]:
        backend.bind_client(self.client)
        activities = InstructEvalActivities(backend.coordination, backend)
        public = Worker(
            self.client,
            task_queue=f"instruct-eval-public-{self.suffix}",
            workflows=[ExperimentCampaignWorkflow, InstructionExperimentWorkflow],
            activities=[getattr(activities, name) for name in worker.PUBLIC_ACTIVITY_METHODS],
            workflow_runner=worker.workflow_runner(),
            workflow_failure_exception_types=[WorkflowProtocolError],
        )
        private = Worker(
            self.client,
            task_queue="instruct-eval-private",
            activities=[getattr(activities, name) for name in worker.PRIVATE_ACTIVITY_METHODS],
        )
        return public, private

    async def _await_action(self, handle: Any, action: str) -> Mapping[str, Any]:
        for _ in range(200):
            try:
                status = await handle.query("status")
            except Exception as error:
                if "workflow not found" not in str(error).lower():
                    raise
                await asyncio.sleep(0.05)
                continue
            if status.get("outstanding_action") == action:
                return status
            await asyncio.sleep(0.05)
        self.fail(f"workflow did not reach {action}")

    def _stage_decomposition(self, backend: _TwoClaimBackend) -> tuple[str, tuple[str, ...]]:
        coverage = tuple(
            SourceCoverage(
                start_byte=item["start_byte"],
                end_byte=item["end_byte"],
                classification=item["classification"],
                owner=item.get("owner"),
                consumers=tuple(item.get("consumers", ())),
                reason=item.get("reason"),
            )
            for item in COVERAGE_SOURCE
        )
        claims = []
        treatment_hashes: dict[str, str] = {}
        treatment_texts: dict[str, str] = {}
        for index, _ in enumerate(backend._claims, 1):
            claim_id = f"claim-{index:04d}"
            treatment = derive_treatment(CANDIDATE, claim_id, coverage)
            claim = {
                "schema": "instruct-eval-claim-v1",
                "claim_id": claim_id,
                "triggering_event": claim_id,
                "preferred_behavior": claim_id,
                "competing_behaviors": ["other"],
                "observable_evidence": ["evidence"],
                "treatment_hash": treatment.hash,
                "coverage_sha256": COVERAGE,
            }
            claim_hash = canonical_hash(claim)
            claims.append(claim)
            treatment_hashes[claim_hash] = treatment.hash
            treatment_texts[claim_hash] = treatment.exact_instruction
        proposal = DecompositionProposal(
            f"{uuid4().int % 10**32:032d}",
            self.campaign_id,
            request_fingerprint(self._input().public_input, "model", "runtime"),
            COVERAGE_SOURCE,
            claims,
        )
        ProposalControl(backend.artifacts, backend.coordination).stage_decomposition(
            private_key=self.private_key,
            owner_public_key=public_key_base64url(self.private_key.public_key()),
            campaign_id=self.campaign_id,
            fingerprint=proposal.request_fingerprint,
            proposal=proposal,
        )
        backend.treatment_texts = treatment_texts
        backend.treatment_hashes = treatment_hashes
        return proposal.hash, tuple(treatment_hashes)

    async def _await_subjects(self, backend: _TwoClaimBackend, count: int) -> None:
        for _ in range(15000):
            if sum(backend.subject_executor_calls.values()) >= count:
                return
            await asyncio.sleep(0.001)
        self.fail(f"subject batch did not reach {count}")

    def _public_snapshot(self) -> dict[str, bytes]:
        public = self.root / "public"
        return {
            str(path.relative_to(public)): path.read_bytes()
            for path in sorted(public.rglob("*"))
            if path.is_file()
        }

    def _coordination_snapshot(self) -> dict[str, list[tuple[Any, ...]]]:
        with closing(sqlite3.connect(self.root / "coordination.sqlite")) as database:
            return {
                table: database.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                for table in ("child_authorizations", "gates", "invocations")
            }

    @staticmethod
    def _private_snapshot(root: Path) -> tuple[dict[str, list[tuple[Any, ...]]], dict[str, bytes]]:
        database = root / "private.sqlite"
        with closing(sqlite3.connect(database)) as connection:
            tables = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            rows = {
                table: connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
                for table in tables
            }
        private = root / "private"
        artifacts = {
            str(path.relative_to(private)): path.read_bytes()
            for path in sorted(private.rglob("*"))
            if path.is_file()
        }
        return rows, artifacts

    @staticmethod
    def _collect_all_private_values(value: Any, values: set[str]) -> None:
        if isinstance(value, Mapping):
            for nested in value.values():
                PersistentTemporalTests._collect_all_private_values(nested, values)
        elif isinstance(value, list):
            for nested in value:
                PersistentTemporalTests._collect_all_private_values(nested, values)
        elif isinstance(value, bytes):
            values.update((base64.b64encode(value).decode(), value.hex()))
        elif isinstance(value, str) and len(value) >= 8:
            values.add(value)

    @staticmethod
    def _collect_sensitive_private_values(
        value: Any, values: set[str], *, release_public: bool
    ) -> None:
        sensitive_keys = {
            "assignment_id",
            "assignment_order",
            "assignments",
            "seed",
            "k_map",
            "k_evidence",
            "k_artifact",
            "map_sha256",
        }
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if not release_public and key in {"assignment_order", "assignments"}:
                    values.add(
                        f'"{key}":{json.dumps(nested, sort_keys=True, separators=(",", ":"))}'
                    )
                    PersistentTemporalTests._collect_sensitive_private_values(
                        nested, values, release_public=release_public
                    )
                elif not release_public and key == "condition" and isinstance(nested, str):
                    values.add(f'"{key}":{json.dumps(nested, separators=(",", ":"))}')
                elif (
                    not release_public
                    and key == "preferred_directions"
                    and isinstance(nested, Mapping)
                ):
                    for scenario, direction in nested.items():
                        values.add(f"{json.dumps(scenario)}:{json.dumps(direction)}")
                elif key in sensitive_keys or "digest" in key:
                    PersistentTemporalTests._collect_all_private_values(nested, values)
                    values.add(
                        f'"{key}":{json.dumps(nested, sort_keys=True, separators=(",", ":"))}'
                    )
                else:
                    PersistentTemporalTests._collect_sensitive_private_values(
                        nested, values, release_public=release_public
                    )
        elif isinstance(value, list):
            for nested in value:
                PersistentTemporalTests._collect_sensitive_private_values(
                    nested, values, release_public=release_public
                )

    @staticmethod
    def _private_history_values(root: Path, *, release_public: bool = False) -> set[str]:
        rows, artifacts = PersistentTemporalTests._private_snapshot(root)
        values: set[str] = set()
        for row in rows.get("private_maps", []):
            PersistentTemporalTests._collect_all_private_values(row[7], values)
            for index in (8, 9, 10):
                PersistentTemporalTests._collect_all_private_values(row[index], values)
            PersistentTemporalTests._collect_sensitive_private_values(
                json.loads(row[7]), values, release_public=release_public
            )
        for row in rows.get("private_artifacts", []):
            PersistentTemporalTests._collect_all_private_values(row[5], values)
        for raw in artifacts.values():
            with suppress(UnicodeDecodeError, ValueError):
                PersistentTemporalTests._collect_sensitive_private_values(
                    json.loads(raw), values, release_public=release_public
                )
        return {value for value in values if value}

    def _stage_design(self, backend: _TwoClaimBackend, claim: str, g0_commit_hash: str) -> str:
        proposal = DesignProposal(
            f"{uuid4().int % 10**32:032d}",
            self.campaign_id,
            claim,
            g0_commit_hash,
            backend.treatment_hashes[claim],
            FIXTURE_MANIFEST_HASH,
            DESIGN_PACKAGE,
        )
        attestation = StageAttestation.sign(
            self.private_key,
            campaign_id=self.campaign_id,
            claim_hash=claim,
            proposal_nonce=proposal.proposal_nonce,
            proposal_hash=proposal.hash,
            g0_commit_hash=proposal.g0_commit_hash,
            treatment_hash=proposal.treatment_hash,
            fixture_manifest_hash=proposal.fixture_manifest_hash,
        )
        staged = ProposalControl(backend.artifacts, backend.coordination).stage_design(
            private_key=self.private_key,
            owner_public_key=public_key_base64url(self.private_key.public_key()),
            campaign_id=self.campaign_id,
            claim_hash=claim,
            g0_commit_hash=g0_commit_hash,
            treatment_hash=proposal.treatment_hash,
            fixture_manifest_hash=proposal.fixture_manifest_hash,
            proposal=proposal,
            attestation=attestation,
        )
        assert staged.proposal_hash == proposal.hash
        return proposal.hash

    def _interrupt_private_worker(self, private: Worker) -> None:
        self._private_shutdown_tasks.append(asyncio.create_task(private.shutdown()))

    async def _reject_forged_decomposition(
        self, campaign: Any, status_before: Mapping[str, Any]
    ) -> None:
        artifacts_before = self._public_snapshot()
        coordination_before = self._coordination_snapshot()
        private_before = self._private_snapshot(self.root)
        forged = self._wire(
            _Decision("campaign", self.campaign_id, "approve_decomposition", "7" * 64, ZERO, 1),
            key=Ed25519PrivateKey.generate(),
        )
        with pytest.raises(WorkflowUpdateFailedError):
            await campaign.execute_update("decision", forged)
        with pytest.raises(WorkflowUpdateFailedError):
            await campaign.execute_update(
                "decision",
                self._wire(
                    _Decision(
                        "campaign", self.campaign_id, "approve_decomposition", "7" * 64, "8" * 64, 1
                    )
                ),
            )
        assert await campaign.query("status") == status_before
        assert self._public_snapshot() == artifacts_before
        assert self._coordination_snapshot() == coordination_before
        assert self._private_snapshot(self.root) == private_before

    async def _approve_decomposition(
        self, campaign: Any, backend: _TwoClaimBackend
    ) -> tuple[tuple[Any, ...], tuple[str, ...]]:
        decomposition_hash, claims = self._stage_decomposition(backend)
        await campaign.execute_update(
            "decision",
            self._wire(
                _Decision(
                    "campaign",
                    self.campaign_id,
                    "approve_decomposition",
                    decomposition_hash,
                    ZERO,
                    1,
                )
            ),
        )
        for _ in range(200):
            if len(backend.issued) == 2:
                break
            await asyncio.sleep(0.05)
        assert len(backend.issued) == 2
        children = tuple(
            self.client.get_workflow_handle(str(item["experiment_id"])) for item in backend.issued
        )
        assert {item["claim_sha256"] for item in backend.issued} == set(claims)
        assert not list((self.root / "private" / "child-authorities").rglob("*.json"))
        return children, claims

    async def _submit_compound_designs(
        self, backend: _TwoClaimBackend, children: tuple[Any, ...], claims: tuple[str, ...]
    ) -> None:
        for child, claim in zip(children, sorted(claims), strict=False):
            status = await self._await_action(child, "submit_design")
            proposal_hash = self._stage_design(backend, claim, status["current_revision_sha256"])
            with pytest.raises(WorkflowUpdateFailedError):
                await child.execute_update(
                    "decision",
                    self._wire(
                        _Decision("claim", claim, "submit_design", proposal_hash, "f" * 64, 1)
                    ),
                )
            await child.execute_update(
                "decision",
                self._wire(
                    _Decision(
                        "claim",
                        claim,
                        "submit_design",
                        proposal_hash,
                        status["current_revision_sha256"],
                        1,
                    )
                ),
            )
            freeze = await self._await_action(child, "approve_freeze")
            await child.execute_update(
                "decision",
                self._wire(
                    _Decision(
                        "claim", claim, "approve_freeze", None, freeze["current_revision_sha256"], 2
                    )
                ),
            )

    async def _assert_child_authorities(self, backend: _TwoClaimBackend) -> None:
        authorities = self.root / "private" / "child-authorities"
        for _ in range(200):
            if len(list(authorities.rglob("*.json"))) == 2:
                break
            await asyncio.sleep(0.01)
        authority_files = list(authorities.rglob("*.json"))
        assert len(authority_files) == 2
        for path in authority_files:
            issued = json.loads(path.read_bytes())
            authority = issued["authority"]
            assert issued["campaign_id"] == self.campaign_id
            assert issued["experiment_id"] == issued["workflow_id"]
            assert issued["run_id"]
            assert authority["claim_hash"] == next(
                item["claim_sha256"]
                for item in backend.issued
                if item["experiment_id"] == issued["experiment_id"]
            )
            assert authority["design_hash"] == DESIGN
            assert authority["fixture_manifest_hash"] == FIXTURE_MANIFEST_HASH
            assert authority["preferred_directions"] == {
                "core-1": "better",
                "core-2": "better",
                "negative-control": "same",
            }

    async def _interrupt_after_subject_commit(self, backend: _TwoClaimBackend) -> None:
        backend.subject_permit.set()
        await self._await_subjects(backend, 1)
        for _ in range(200):
            if backend.coordination.committed_subjects:
                break
            await asyncio.sleep(0.01)
        assert len(backend.coordination.committed_subjects) == 1
        assert set(backend.subject_executor_calls.values()) == {1}
        assert len(list((self.root / "private" / "child-authorities").rglob("*.json"))) == 2

    async def _run_initial_compound_interruption(self) -> _InterruptedCampaign:
        backend = _TwoClaimBackend(
            self.root, self.campaign_id, _BackendOptions(interrupt_after_subject_commit=True)
        )
        public, private = self._workers(backend)
        queue = f"instruct-eval-public-{self.suffix}"
        histories = self.root / "histories"
        histories.mkdir()
        async with public, private:
            backend.coordination.on_interruption = lambda: self._interrupt_private_worker(private)
            campaign = await self.client.start_workflow(
                ExperimentCampaignWorkflow.run, self._input(), id=self.campaign_id, task_queue=queue
            )
            status_before = await self._await_action(campaign, "approve_decomposition")
            await self._reject_forged_decomposition(campaign, status_before)
            children, claims = await self._approve_decomposition(campaign, backend)
            await self._submit_compound_designs(backend, children, claims)
            await self._assert_child_authorities(backend)
            await self._interrupt_after_subject_commit(backend)
            assert len(backend.coordination.committed_subjects) == 1
            await self._await_private_shutdowns()
        assert not backend.coordination.recovered_subjects
        interrupted = _InterruptedCampaign(
            campaign,
            children,
            claims,
            backend,
            dict(backend.subject_executor_calls),
            histories,
            queue,
        )
        backend.close()
        return interrupted

    async def _assert_pre_release_privacy(self, interrupted: _InterruptedCampaign) -> None:
        private_values = self._private_history_values(self.root)
        assert private_values
        for handle in (interrupted.campaign, *interrupted.children):
            history = await handle.fetch_history()
            text = _history_text(history)
            for forbidden in private_values:
                assert forbidden not in text
        pre_release_public = self._public_snapshot()
        assert pre_release_public
        for forbidden in ("assignment", "condition", "preferred", "k_map", "private"):
            assert all(
                forbidden not in raw.decode(errors="ignore").lower()
                for raw in pre_release_public.values()
            )

    async def _interrupt_after_release_publish(
        self, interrupted: _InterruptedCampaign
    ) -> _ReleaseInterruptedCampaign:
        backend = _TwoClaimBackend(
            self.root,
            self.campaign_id,
            _BackendOptions(hold_release=True, interrupt_after_release_publish=True),
        )
        public, private = self._workers(backend)
        async with public, private:
            backend.coordination.on_interruption = lambda: self._interrupt_private_worker(private)
            await asyncio.wait_for(backend.release_started.wait(), timeout=30)
            await self._assert_pre_release_privacy(interrupted)
            backend.release_permit.set()
            for _ in range(200):
                if not backend.coordination.interrupt_release_publish:
                    break
                await asyncio.sleep(0.05)
            assert not backend.coordination.interrupt_release_publish
            await self._await_private_shutdowns()
        interrupted_releases = {
            path: raw
            for path, raw in self._public_snapshot().items()
            if Path(path).parts[0] == "releases"
        }
        assert len(interrupted_releases) == 1
        release_interrupted = _ReleaseInterruptedCampaign(
            interrupted, backend, interrupted_releases
        )
        backend.close()
        return release_interrupted

    async def _recover_campaign(
        self, release_interrupted: _ReleaseInterruptedCampaign
    ) -> tuple[_TwoClaimBackend, Any]:
        backend = _TwoClaimBackend(self.root, self.campaign_id, _BackendOptions())
        public, private = self._workers(backend)
        async with public, private:
            result = await release_interrupted.interrupted.campaign.result()
        recovered_releases = self._public_snapshot()
        assert {
            path: recovered_releases[path] for path in release_interrupted.interrupted_releases
        } == release_interrupted.interrupted_releases
        return backend, result

    def _assert_treatment_oracle(
        self, release_interrupted: _ReleaseInterruptedCampaign, backend: _TwoClaimBackend
    ) -> None:
        interrupted = release_interrupted.interrupted
        all_treatments = (
            interrupted.first_backend.subject_treatments
            + release_interrupted.release_backend.subject_treatments
            + backend.subject_treatments
        )
        claim_by_experiment = {
            str(item["experiment_id"]): str(item["claim_sha256"])
            for item in interrupted.first_backend.issued
        }
        assert Counter(
            (experiment_id, condition) for experiment_id, condition, _ in all_treatments
        ) == Counter(
            {
                (experiment_id, condition): 5
                for experiment_id in claim_by_experiment
                for condition in ("A", "B")
            }
        )
        for experiment_id, condition, treatment in all_treatments:
            expected = (
                None
                if condition == "A"
                else interrupted.first_backend.treatment_texts[claim_by_experiment[experiment_id]]
            )
            assert treatment == expected

    def _assert_release_visibility(self, result: Any) -> None:
        post_release_public = self._public_snapshot()
        joined = {
            path: raw
            for path, raw in post_release_public.items()
            if b'"assignments"' in raw or b'"preferred_directions"' in raw
        }
        assert {Path(path).parts[0] for path in joined} == {"releases"}
        assert all(json.loads(raw)["release_sha256"] for raw in joined.values())
        assert {claim.terminal_gate for claim in result.claims} == {"AUTHORIZED"}
        assert len(result.claims) == 2
        assert {claim.status for claim in result.claims} == {"AUTHORIZED"}

    def _assert_subject_invocations(
        self, release_interrupted: _ReleaseInterruptedCampaign, backend: _TwoClaimBackend
    ) -> None:
        interrupted = release_interrupted.interrupted
        assert (
            interrupted.first_backend.coordination.committed_subjects
            <= release_interrupted.release_backend.coordination.recovered_subjects
            | backend.coordination.recovered_subjects
        )
        combined_executor_calls = Counter(interrupted.first_executor_calls)
        combined_executor_calls.update(release_interrupted.release_backend.subject_executor_calls)
        combined_executor_calls.update(backend.subject_executor_calls)
        assert set(combined_executor_calls.values()) == {1}
        assert len(combined_executor_calls) == 20
        all_requests = (
            interrupted.first_backend.subject_requests
            + release_interrupted.release_backend.subject_requests
            + backend.subject_requests
        )
        assert all(
            set(request) == {"map_ref", "token", "design_sha256"}
            and request["design_sha256"] == DESIGN
            for request in all_requests
        )
        with closing(sqlite3.connect(self.root / "coordination.sqlite")) as database:
            rows = database.execute(
                "SELECT invocation_key, state, input_bytes, result_bytes FROM invocations"
            ).fetchall()
        subject_rows = [row for row in rows if json.loads(row[2])["purpose"] == "subject_trial"]
        assert len(subject_rows) == 20
        assert {row[1] for row in subject_rows} == {"RESULT_COMMITTED"}
        by_child: dict[str, list[str]] = {}
        for _, _, request_bytes, _ in subject_rows:
            request = json.loads(request_bytes)["request"]
            assert set(request["payload"]) == {"map_ref", "token", "design_sha256"}
            token = request["payload"]["token"]
            assert len(token) == 43
            by_child.setdefault(request["experiment_id"], []).append(token)
        assert set(by_child) == {
            str(item["experiment_id"]) for item in interrupted.first_backend.issued
        }
        assert all(len(tokens) == 10 and len(set(tokens)) == 10 for tokens in by_child.values())

    def _assert_gate_ledger(self) -> list[tuple[tuple[Any, ...], Mapping[str, Any]]]:
        with closing(sqlite3.connect(self.root / "coordination.sqlite")) as database:
            gates = database.execute(
                "SELECT workflow_id, ordinal, prior_record_sha256, record_input_sha256, "
                "state, publication_path, publication_sha256 FROM gates "
                "ORDER BY workflow_id, ordinal"
            ).fetchall()
        assert gates
        per_workflow: dict[str, list[tuple[Any, ...]]] = {}
        ledger_rows: list[tuple[tuple[Any, ...], Mapping[str, Any]]] = []
        for gate in gates:
            per_workflow.setdefault(gate[0], []).append(gate)
            assert gate[4] == "PUBLISHED"
            artifact = Path(gate[5])
            assert artifact.is_file()
            raw_ledger = artifact.read_bytes()
            assert sha256(raw_ledger).hexdigest() == gate[6]
            decoded = json.loads(raw_ledger)
            if set(decoded) == {"payload", "signature"}:
                DecisionWire.from_json(decoded)
                continue
            assert decoded["schema"] == "instruct-eval-ledger-v1"
            assert decoded["workflow_id"] == gate[0]
            assert decoded["ordinal"] == gate[1]
            public_artifact = Path(decoded["public_artifact_path"])
            assert (
                sha256(public_artifact.read_bytes()).hexdigest()
                == decoded["public_artifact_sha256"]
            )
            ledger_rows.append((gate, decoded))
            if decoded["gate"] == "analysis":
                g6 = json.loads(public_artifact.read_bytes())
                assert set(g6) == {"schema", "design_sha256", "release_sha256", "authorized"}
                assert g6["schema"] == "instruct-eval-g6-analysis-v1"
                assert g6["design_sha256"] == DESIGN
                assert g6["authorized"] is True
        for chain in per_workflow.values():
            assert [row[1] for row in chain] == list(range(len(chain)))
            assert all(
                row[2] == ZERO if row[1] == 0 else row[2] == chain[index - 1][6]
                for index, row in enumerate(chain)
            )
        return ledger_rows

    def _assert_releases(
        self, ledger_rows: list[tuple[tuple[Any, ...], Mapping[str, Any]]]
    ) -> Path:
        release_gates = [gate for gate, ledger in ledger_rows if ledger["gate"] == "release"]
        assert len(release_gates) == 2
        assert len({gate[5] for gate in release_gates}) == len(release_gates)
        release_files = list((self.root / "public" / "releases").rglob("*.json"))
        assert len(release_files) == 2
        for path in release_files:
            raw = path.read_bytes()
            release = json.loads(raw)
            assert set(release) == {
                "assignments",
                "preferred_directions",
                "authorization_rule",
                "release_sha256",
            }
            assert raw == canonical_bytes(release)
            unsigned = {key: value for key, value in release.items() if key != "release_sha256"}
            assert release["release_sha256"] == sha256(canonical_bytes(unsigned)).hexdigest()
            assert len(release["assignments"]) == 10
            assert len({item["blind_id"] for item in release["assignments"]}) == 10
            assert Counter(
                (item["scenario"], item["condition"]) for item in release["assignments"]
            ) == Counter(
                {
                    ("core-1", "A"): 2,
                    ("core-1", "B"): 2,
                    ("core-2", "A"): 2,
                    ("core-2", "B"): 2,
                    ("negative-control", "A"): 1,
                    ("negative-control", "B"): 1,
                }
            )
            assert g6_authorized(release["assignments"], release["preferred_directions"])
        return release_files[0]

    def _assert_release_conflict(
        self,
        backend: _TwoClaimBackend,
        ledger_rows: list[tuple[tuple[Any, ...], Mapping[str, Any]]],
        authoritative_release: Path,
    ) -> None:
        authoritative_bytes = authoritative_release.read_bytes()
        release_row = next(
            (
                gate
                for gate, ledger in ledger_rows
                if ledger["gate"] == "release"
                and ledger["public_artifact_path"] == str(authoritative_release)
            ),
            None,
        )
        assert release_row is not None
        if release_row is None:
            self.fail("authoritative release gate was not recorded")
        with closing(sqlite3.connect(self.root / "coordination.sqlite")) as database:
            release_gate = database.execute(
                "SELECT workflow_id, run_id, ordinal, expected_revision_sha256, "
                "owner_epoch FROM gates WHERE publication_path=?",
                (release_row[5],),
            ).fetchone()
        assert release_gate is not None
        if release_gate is None:
            self.fail("authoritative release gate identity was not recorded")
        competing_bytes = canonical_bytes({"competing_release": True})
        competing_path = self.root / "public" / "competing-release.json"
        competing_path.write_bytes(competing_bytes)
        with pytest.raises(CoordinationError):
            backend.coordination.publish_gate(
                release_gate[0],
                release_gate[1],
                release_gate[2],
                release_gate[3],
                release_gate[4],
                competing_path,
                competing_bytes,
                sha256(competing_bytes).hexdigest(),
            )
        assert authoritative_release.read_bytes() == authoritative_bytes

    async def _assert_late_update_and_adoption(
        self, backend: _TwoClaimBackend, interrupted: _InterruptedCampaign, result: Any
    ) -> None:
        query_public, query_private = self._workers(backend)
        async with query_public, query_private:
            child = interrupted.children[0]
            late_state = await child.query("status")
            late_artifacts = self._public_snapshot()
            late_coordination = self._coordination_snapshot()
            late_private = self._private_snapshot(self.root)
            with pytest.raises((WorkflowUpdateFailedError, RPCError)):
                await child.execute_update(
                    "decision",
                    self._wire(
                        _Decision(
                            "claim",
                            interrupted.claims[0],
                            "approve_freeze",
                            None,
                            late_state["current_revision_sha256"],
                            2,
                        )
                    ),
                )
            assert await child.query("status") == late_state
            assert self._public_snapshot() == late_artifacts
            assert self._coordination_snapshot() == late_coordination
            assert self._private_snapshot(self.root) == late_private
            adopted = await cli.start_campaign(
                self.client, self._input(), task_queue=interrupted.queue
            )
            assert adopted.state == "adopted"
            assert adopted.handle is not None
            if adopted.handle is None:
                self.fail("adopted campaign omitted workflow handle")
            assert await adopted.handle.result() == result
            mismatched = CampaignInput(
                self.campaign_id, "other-model", "runtime", self._input().public_input, COVERAGE
            )
            with pytest.raises(cli.CampaignStartError):
                await cli.start_campaign(self.client, mismatched, task_queue=interrupted.queue)

    async def _assert_private_history_and_replay(self, interrupted: _InterruptedCampaign) -> None:
        with closing(sqlite3.connect(self.root / "private.sqlite")) as database:
            private_rows = database.execute(
                "SELECT map_ref, payload, k_map, k_evidence, k_artifact FROM private_maps"
            ).fetchall()
            private_paths = [
                row[0]
                for row in database.execute(
                    "SELECT artifact_path FROM private_artifacts WHERE artifact_path IS NOT NULL"
                ).fetchall()
            ]
        assert len(private_rows) == 2
        private_values = set(private_paths)
        for _, payload, *keys in private_rows:
            mapping = json.loads(payload)
            assert len(mapping["assignment_order"]) == 10
            for value in [payload, *keys]:
                raw = bytes(value)
                private_values.update({base64.b64encode(raw).decode(), raw.hex()})
        for handle in (interrupted.campaign, *interrupted.children):
            history = await handle.fetch_history()
            text = _history_text(history)
            (interrupted.histories / f"{handle.id}.json").write_text(history.to_json())
            for forbidden in private_values:
                assert forbidden not in text
            replay = await Replayer(
                workflows=[ExperimentCampaignWorkflow, InstructionExperimentWorkflow],
                workflow_runner=worker.workflow_runner(),
            ).replay_workflow(history)
            assert replay.replay_failure is None

    async def test_signed_compound_campaign_recovers_without_private_history_or_replay_drift(
        self,
    ) -> None:
        backend: _TwoClaimBackend | None = None
        try:
            interrupted = await self._run_initial_compound_interruption()
            release_interrupted = await self._interrupt_after_release_publish(interrupted)
            backend, result = await self._recover_campaign(release_interrupted)
            self._assert_treatment_oracle(release_interrupted, backend)
            self._assert_release_visibility(result)
            self._assert_subject_invocations(release_interrupted, backend)
            ledger_rows = self._assert_gate_ledger()
            authoritative_release = self._assert_releases(ledger_rows)
            self._assert_release_conflict(backend, ledger_rows, authoritative_release)
            await self._assert_late_update_and_adoption(backend, interrupted, result)
            await self._assert_private_history_and_replay(interrupted)
        finally:
            if backend is not None:
                backend.close()

    async def test_atomic_campaign_persists_artifacts_and_replays(self) -> None:
        campaign_id = f"campaign-{uuid4().int % 10**32:032d}"
        original_campaign_id, baseline.CAMPAIGN_ID = self.campaign_id, campaign_id
        self.campaign_id = campaign_id
        backend = _TwoClaimBackend(
            self.root / "atomic",
            campaign_id,
            _BackendOptions(authorize_g6=False, claims=("atomic",)),
        )
        public, private = self._workers(backend)
        queue = f"instruct-eval-public-{self.suffix}"
        try:
            async with public, private:
                campaign = await self.client.start_workflow(
                    ExperimentCampaignWorkflow.run, self._input(), id=campaign_id, task_queue=queue
                )
                await self._await_action(campaign, "approve_decomposition")
                decomposition_hash, _ = self._stage_decomposition(backend)
                await campaign.execute_update(
                    "decision",
                    self._wire(
                        _Decision(
                            "campaign",
                            campaign_id,
                            "approve_decomposition",
                            decomposition_hash,
                            ZERO,
                            1,
                        )
                    ),
                )
                for _ in range(200):
                    if backend.issued:
                        break
                    await asyncio.sleep(0.05)
                assert len(backend.issued) == 1
                claim = str(backend.issued[0]["claim_sha256"])
                child = self.client.get_workflow_handle(str(backend.issued[0]["experiment_id"]))
                design = await self._await_action(child, "submit_design")
                proposal_hash = self._stage_design(
                    backend, claim, design["current_revision_sha256"]
                )
                await child.execute_update(
                    "decision",
                    self._wire(
                        _Decision(
                            "claim",
                            claim,
                            "submit_design",
                            proposal_hash,
                            design["current_revision_sha256"],
                            1,
                        )
                    ),
                )
                freeze = await self._await_action(child, "approve_freeze")
                await child.execute_update(
                    "decision",
                    self._wire(
                        _Decision(
                            "claim",
                            claim,
                            "approve_freeze",
                            None,
                            freeze["current_revision_sha256"],
                            2,
                        )
                    ),
                )
                result = await campaign.result()
            assert {claim.status for claim in result.claims} == {"COMPLETED_NOT_AUTHORIZED"}
            assert {claim.terminal_gate for claim in result.claims} == {"COMPLETED_NOT_AUTHORIZED"}
            assert len(result.claims) == 1
            assert list((self.root / "atomic" / "public").rglob("*.json"))
            analysis_files = list(
                (self.root / "atomic" / "public" / "gates").rglob("analysis-*.json")
            )
            assert len(analysis_files) == 1
            g6 = json.loads(analysis_files[0].read_bytes())
            assert set(g6) == {"schema", "design_sha256", "release_sha256", "authorized"}
            assert g6["schema"] == "instruct-eval-g6-analysis-v1"
            assert g6["design_sha256"] == DESIGN
            assert g6["authorized"] is False
            for handle in (campaign, child):
                history = await handle.fetch_history()
                replay = await Replayer(
                    workflows=[ExperimentCampaignWorkflow, InstructionExperimentWorkflow],
                    workflow_runner=worker.workflow_runner(),
                ).replay_workflow(history)
                assert replay.replay_failure is None
        finally:
            self.campaign_id, baseline.CAMPAIGN_ID = original_campaign_id, original_campaign_id
            backend.close()


if __name__ == "__main__":
    unittest.main()
