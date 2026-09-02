"""Contracts for named, exactly-once Temporal activity boundaries."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest
from temporalio.converter import DataConverter
from temporalio.exceptions import ApplicationError

from instruct_eval.activities import (
    ActivityBackend,
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
    GateResult,
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
from instruct_eval.artifacts import ArtifactStore
from instruct_eval.coordination import (
    CoordinationStore,
    GateCommitRequest,
    GateRequest,
    InvocationDisposition,
)
from instruct_eval.models import ProtocolError, canonical_bytes
from instruct_eval.trials import authorization_rule


def request(cls, payload=None, **gate):
    payload = payload if payload is not None else {"artifact": "public"}
    common = (
        "campaign",
        "experiment",
        "role",
        sha256(canonical_bytes(payload)).hexdigest(),
        "model",
        "runtime",
        payload,
    )
    if gate:
        return cls(*common, **gate)
    return cls(*common)


def release_payload() -> dict[str, Any]:
    preferred = {"core-1": "better", "core-2": "better", "negative-control": "same"}
    assignments = sorted(
        [
            {
                "blind_id": f"blind-{scenario}-{condition}-{index}",
                "scenario": scenario,
                "condition": condition,
                "direction": preferred[scenario],
            }
            for scenario, condition, count in (
                ("core-1", "A", 2),
                ("core-1", "B", 2),
                ("core-2", "A", 2),
                ("core-2", "B", 2),
                ("negative-control", "A", 1),
                ("negative-control", "B", 1),
            )
            for index in range(count)
        ],
        key=lambda record: record["blind_id"],
    )
    release = {
        "assignments": assignments,
        "preferred_directions": preferred,
        "authorization_rule": authorization_rule(),
    }
    return {**release, "release_sha256": sha256(canonical_bytes(release)).hexdigest()}


class FakeBackend(ActivityBackend):
    def __init__(self, root: Path) -> None:
        self._artifacts = ArtifactStore(root / "public", root / "private")
        self.root = root
        self.calls: list[str] = []

    def _result(self, name, value):
        self.calls.append(name)
        return {"endpoint": name, "artifact": value.payload["artifact"]}

    def _gate(self, name, value):
        self.calls.append(name)
        payload = {"endpoint": name, "artifact": value.payload["artifact"]}
        data = canonical_bytes(payload)
        path = self.root / f"{name}-{value.ordinal}.json"
        path.write_bytes(data)
        return GatePublication(payload, path, data, sha256(data).hexdigest())

    def fingerprint(self, request):
        return self._result("fingerprint", request)

    def proposal_decision(self, request):
        return self._result("proposal_decision", request)

    def decomposition(self, request):
        return self._result("decomposition", request)

    def eligibility(self, request):
        return self._result("eligibility", request)

    def child_authorization_issue(self, request):
        return self._result("child_authorization_issue", request)

    def child_authorization_claim(self, request):
        return self._result("child_authorization_claim", request)

    def design_draft(self, request):
        return self._result("design_draft", request)

    def design_commit(self, request):
        return self._gate("design_commit", request)

    def g0_commit(self, request):
        return self._gate("g0_commit", request)

    def pre_run_validity(self, request):
        return self._gate("pre_run_validity", request)

    def freeze(self, request):
        return self._gate("freeze", request)

    def execution_commit(self, request):
        return self._gate("execution_commit", request)

    def subject_trial(self, request):
        return self._result("subject_trial", request)

    def finalize_subject_trial(self, request, outcome):
        self.calls.append("finalize_subject_trial")

    def evidence_audit(self, request):
        return self._result("evidence_audit", request)

    def post_run_validity(self, request):
        return self._gate("post_run_validity", request)

    def map_lifecycle(self, request):
        return self._result("map_lifecycle", request)

    def release(self, request):
        self.calls.append("release")
        payload = release_payload()
        data = canonical_bytes(payload)
        path = self.root / f"release-{request.ordinal}.json"
        path.write_bytes(data)
        return ReleasePublication(payload, path, data, sha256(data).hexdigest())

    def analysis(self, request):
        return self._gate("analysis", request)

    def terminal_commit(self, request):
        return self._gate("terminal_commit", request)


class ActivityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.store = CoordinationStore(self.root / "coordination.sqlite")
        self.backend = FakeBackend(self.root)
        self.activities = InstructEvalActivities(self.store, self.backend)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_missing_or_abstract_backend_is_rejected(self) -> None:
        with pytest.raises(TypeError):
            InstructEvalActivities(self.store, cast(Any, object()))

        class Incomplete(ActivityBackend):
            pass

        with pytest.raises(TypeError):
            InstructEvalActivities(self.store, cast(Any, Incomplete))

    def test_payload_hash_binds_exact_canonical_bytes_key_and_request_snapshot(self) -> None:
        payload = {"artifact": "public", "nested": {"stable": "original"}}
        valid = request(FingerprintRequest, payload)
        key = valid.invocation_key("fingerprint")
        assert valid.frozen_input_sha256 == sha256(canonical_bytes(payload)).hexdigest()
        payload["artifact"] = "mutated"
        payload["nested"]["stable"] = "mutated"
        seen: list[bytes] = []
        self.backend.fingerprint = lambda value: (
            seen.append(canonical_bytes(value.payload))
            or {"endpoint": "fingerprint", "artifact": value.payload["artifact"]}
        )
        assert valid.invocation_key("fingerprint") == key
        result = asyncio.run(self.activities.fingerprint(valid))
        assert seen == [canonical_bytes({"artifact": "public", "nested": {"stable": "original"}})]
        assert result.payload == {"endpoint": "fingerprint", "artifact": "public"}
        with pytest.raises(ValueError, match="frozen input hash"):
            FingerprintRequest(
                "campaign",
                "experiment",
                "role",
                "a" * 64,
                "model",
                "runtime",
                {"artifact": "public"},
            )
        assert valid.invocation_key("fingerprint") != valid.invocation_key("analysis")

    def test_activity_request_transport_excludes_private_caches_and_round_trips(self) -> None:
        value = request(FingerprintRequest, {"artifact": "public"})
        assert "_payload_bytes" not in dataclasses.asdict(value)
        assert "_request_bytes" not in dataclasses.asdict(value)
        payloads = asyncio.run(DataConverter.default.encode([value]))
        decoded = asyncio.run(DataConverter.default.decode(payloads, [FingerprintRequest]))
        assert decoded == [value]

    def test_gate_result_transport_round_trips_with_string_path(self) -> None:
        value = GateResult("workflow", "run", 3, "/public/gate.json", "a" * 64, {"accepted": True})
        decoded = asyncio.run(
            DataConverter.default.decode(
                asyncio.run(DataConverter.default.encode([value])), [GateResult]
            )
        )
        assert decoded == [value]

    def test_release_publication_requires_exact_post_g5_packet(self) -> None:
        payload = release_payload()
        data = canonical_bytes(payload)
        ReleasePublication(payload, self.root / "release.json", data, sha256(data).hexdigest())
        with pytest.raises(ValueError, match="exactly ten assignments"):
            ReleasePublication(
                {**payload, "assignments": payload["assignments"][:-1]},
                self.root / "release.json",
                data,
                sha256(data).hexdigest(),
            )

    def test_role_and_subject_endpoints_use_invocation_cas(self) -> None:
        value = request(FingerprintRequest)
        first = asyncio.run(self.activities.fingerprint(value))
        second = asyncio.run(self.activities.fingerprint(value))
        assert first == second
        assert self.backend.calls == ["fingerprint"]
        subject = request(SubjectTrialRequest)
        asyncio.run(self.activities.subject_trial(subject))
        asyncio.run(self.activities.subject_trial(subject))
        assert self.backend.calls.count("subject_trial") == 1

    def test_subject_private_journal_supports_evidence_above_public_bound(self) -> None:
        value = request(SubjectTrialRequest)
        committed = {
            "outcome": {"endpoint": "subject_trial", "artifact": "public"},
            "private_artifacts": {"response": "x" * (2 * 1024 * 1024)},
        }
        with patch.object(self.backend, "subject_trial", return_value=committed):
            result = asyncio.run(self.activities.subject_trial(value))
        assert result.payload == committed["outcome"]
        assert (
            len(
                self.store.reserve_invocation(
                    value.invocation_key("subject_trial"),
                    canonical_bytes(
                        {"purpose": "subject_trial", "request": json.loads(value._request_bytes)}
                    ),
                ).result_bytes
                or b""
            )
            > 1048576
        )

    def test_recovered_subject_result_finalizes_without_reexecution(self) -> None:
        value = request(SubjectTrialRequest)
        canonical = self.activities._reconstruct(value)
        key = canonical.invocation_key("subject_trial")
        input_bytes = canonical_bytes(
            {"purpose": "subject_trial", "request": json.loads(canonical._request_bytes)}
        )
        reservation = self.store.reserve_invocation(key, input_bytes)
        owner_epoch = reservation.owner_epoch
        assert owner_epoch is not None
        assert owner_epoch is not None
        result = canonical_bytes({"endpoint": "subject_trial", "artifact": "public"})
        self.store.commit_result(key, owner_epoch, result)

        recovered = asyncio.run(self.activities.subject_trial(value))

        assert recovered.payload == json.loads(result)
        assert "subject_trial" not in self.backend.calls
        assert self.backend.calls == ["finalize_subject_trial"]

    def test_role_recovers_a_durable_result_when_commit_return_is_interrupted(self) -> None:
        value = request(FingerprintRequest)
        commit_result = self.store.commit_result
        interrupted = False

        def commit_then_interrupt(invocation_key: str, owner_epoch: int, result_bytes: bytes):
            nonlocal interrupted
            committed = commit_result(invocation_key, owner_epoch, result_bytes)
            if not interrupted:
                interrupted = True
                raise RuntimeError("interrupted after durable commit")
            return committed

        with patch.object(self.store, "commit_result", side_effect=commit_then_interrupt):
            recovered = asyncio.run(self.activities.fingerprint(value))
        assert recovered.payload == {"endpoint": "fingerprint", "artifact": "public"}
        assert self.backend.calls == ["fingerprint"]
        assert asyncio.run(self.activities.fingerprint(value)) == recovered
        assert self.backend.calls == ["fingerprint"]

    def test_every_named_endpoint_has_concrete_execution(self) -> None:
        role_endpoints = (
            ("fingerprint", FingerprintRequest),
            ("proposal_decision", ProposalDecisionRequest),
            ("decomposition", DecompositionRequest),
            ("eligibility", EligibilityRequest),
            ("child_authorization_issue", ChildAuthorizationIssueRequest),
            ("child_authorization_claim", ChildAuthorizationClaimRequest),
            ("design_draft", DesignDraftRequest),
            ("subject_trial", SubjectTrialRequest),
            ("evidence_audit", EvidenceAuditRequest),
            ("map_lifecycle", MapLifecycleRequest),
        )
        gate_endpoints = (
            ("design_commit", DesignCommitRequest),
            ("g0_commit", G0CommitRequest),
            ("pre_run_validity", PreRunValidityRequest),
            ("freeze", FreezeRequest),
            ("execution_commit", ExecutionCommitRequest),
            ("post_run_validity", PostRunValidityRequest),
            ("release", ReleaseRequest),
            ("analysis", AnalysisRequest),
            ("terminal_commit", TerminalCommitRequest),
        )
        for name, cls in role_endpoints:
            asyncio.run(getattr(self.activities, name)(request(cls)))
        for name, cls in gate_endpoints:
            value = request(
                cls,
                workflow_id=f"workflow-{name}",
                run_id="run",
                ordinal=0,
                prior_record_sha256="0" * 64,
                expected_revision_sha256=sha256(name.encode()).hexdigest(),
                branch_kind=name,
            )
            result = asyncio.run(getattr(self.activities, name)(value))
            assert result.payload == (
                release_payload() if name == "release" else {"endpoint": name, "artifact": "public"}
            )
        assert set(self.backend.calls) == {name for name, _ in role_endpoints + gate_endpoints} | {
            "finalize_subject_trial"
        }
        assert {item.__name__ for item in self.activities.registered()} == {
            name for name, _ in role_endpoints + gate_endpoints
        } | {"terminalize_invocation"}

    def test_release_recovers_committing_owner_epoch_and_publishes(self) -> None:
        payload = {"artifact": "public"}
        value = request(
            ReleaseRequest,
            payload,
            workflow_id="workflow",
            run_id="run",
            ordinal=0,
            prior_record_sha256="0" * 64,
            expected_revision_sha256="b" * 64,
            branch_kind="release",
        )
        payload["artifact"] = "mutated"
        record = canonical_bytes(
            {
                "purpose": "release",
                "request": {
                    "campaign_id": value.campaign_id,
                    "experiment_id": value.experiment_id,
                    "role_token": value.role_token,
                    "frozen_input_sha256": value.frozen_input_sha256,
                    "model_identity": value.model_identity,
                    "runtime_identity": value.runtime_identity,
                    "payload": {"artifact": "public"},
                    "workflow_id": value.workflow_id,
                    "run_id": value.run_id,
                    "ordinal": value.ordinal,
                    "prior_record_sha256": value.prior_record_sha256,
                    "expected_revision_sha256": value.expected_revision_sha256,
                    "branch_kind": value.branch_kind,
                },
            }
        )
        reserved = self.store.reserve_gate(
            GateRequest("workflow", "run", 0, "0" * 64, "b" * 64, "release", record)
        )
        self.store.begin_release_commit(
            GateCommitRequest("workflow", "run", 0, "b" * 64, reserved.owner_epoch or 0)
        )
        result = asyncio.run(self.activities.release(value))
        assert result.artifact_sha256 == sha256(Path(result.artifact_path).read_bytes()).hexdigest()
        assert self.backend.calls == ["release"]

    def test_gate_recovery_publishes_journaled_role_output_without_reexecution(self) -> None:
        value = request(
            PreRunValidityRequest,
            workflow_id="workflow",
            run_id="run",
            ordinal=0,
            prior_record_sha256="0" * 64,
            expected_revision_sha256="b" * 64,
            branch_kind="pre_run_validity",
        )
        with (
            patch.object(
                self.store, "publish_gate", side_effect=RuntimeError("crash before publication")
            ),
            pytest.raises(RuntimeError, match="crash before publication"),
        ):
            asyncio.run(self.activities.pre_run_validity(value))
        assert self.backend.calls == ["pre_run_validity"]
        recovered = asyncio.run(self.activities.pre_run_validity(value))
        expected = canonical_bytes({"endpoint": "pre_run_validity", "artifact": "public"})
        ledger = json.loads(Path(recovered.artifact_path).read_bytes())
        assert self.backend.calls == ["pre_run_validity"]
        assert Path(ledger["public_artifact_path"]).read_bytes() == expected
        assert canonical_bytes(recovered.payload) == expected

    def test_gate_publication_requires_exact_canonical_public_payload_bytes(self) -> None:
        payload = {"artifact": "public"}
        with pytest.raises(ValueError, match="artifact bytes do not match"):
            GatePublication(
                payload,
                self.root / "bad.json",
                canonical_bytes({"artifact": "other"}),
                sha256(canonical_bytes({"artifact": "other"})).hexdigest(),
            )
        with pytest.raises(ValueError, match="artifact bytes do not match"):
            GatePublication(
                payload, self.root / "bad.json", b"not-json", sha256(b"not-json").hexdigest()
            )

    def test_published_gate_recovery_returns_exact_canonical_decoded_payload(self) -> None:
        value = request(
            ReleaseRequest,
            workflow_id="workflow",
            run_id="run",
            ordinal=0,
            prior_record_sha256="0" * 64,
            expected_revision_sha256="b" * 64,
            branch_kind="release",
        )
        initial = asyncio.run(self.activities.release(value))
        recovered = asyncio.run(self.activities.release(value))
        ledger_bytes = Path(initial.artifact_path).read_bytes()
        ledger = json.loads(ledger_bytes)
        artifact_bytes = Path(ledger["public_artifact_path"]).read_bytes()
        assert canonical_bytes(initial.payload) == artifact_bytes
        assert canonical_bytes(recovered.payload) == artifact_bytes
        assert initial.payload == recovered.payload

    def test_private_condition_preference_and_split_joins_are_rejected(self) -> None:
        gate = {
            "workflow_id": "workflow",
            "run_id": "run",
            "ordinal": 0,
            "prior_record_sha256": "0" * 64,
            "expected_revision_sha256": "b" * 64,
            "branch_kind": "release",
        }
        for payload in (
            {"condition": "A"},
            {"preferred_direction": "D1"},
            {"blind_id": "blind-1", "condition": "A"},
            {"blind_id": "blind-1", "preferred_direction": "D1"},
            {"condition_by_assignment": {"opaque-1": "A"}},
            {"preferred-direction-by-scenario": {"core-1": "D1"}},
            {"private": {"evidence": "secret"}},
            {"quarantine": {"blind_id": "blind-1"}},
            {"opaque_id": "opaque-1"},
            {"authorization_id": "authorization-1"},
        ):
            with pytest.raises(ValueError, match="private joins or raw evidence"):
                request(ReleaseRequest, payload, **gate)

    def test_competing_gate_branch_and_private_payload_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="private joins or raw evidence"):
            request(
                ReleaseRequest,
                {"private_map": "secret"},
                workflow_id="workflow",
                run_id="run",
                ordinal=0,
                prior_record_sha256="0" * 64,
                expected_revision_sha256="b" * 64,
                branch_kind="release",
            )
        first = request(
            ReleaseRequest,
            workflow_id="workflow",
            run_id="run",
            ordinal=0,
            prior_record_sha256="0" * 64,
            expected_revision_sha256="b" * 64,
            branch_kind="release",
        )
        asyncio.run(self.activities.release(first))
        competing = request(
            ReleaseRequest,
            workflow_id="workflow",
            run_id="run",
            ordinal=0,
            prior_record_sha256="0" * 64,
            expected_revision_sha256="c" * 64,
            branch_kind="other",
        )
        with pytest.raises(ApplicationError):
            asyncio.run(self.activities.release(competing))

    def test_canonical_ordering_is_stable_and_identity_partitions_do_not_recover(self) -> None:
        ordered = request(FingerprintRequest, {"artifact": "public", "nested": {"a": 1, "b": 2}})
        reordered = request(FingerprintRequest, {"nested": {"b": 2, "a": 1}, "artifact": "public"})
        assert ordered.invocation_key("fingerprint") == reordered.invocation_key("fingerprint")
        assert asyncio.run(self.activities.fingerprint(ordered)) == asyncio.run(
            self.activities.fingerprint(reordered)
        )
        assert self.backend.calls == ["fingerprint"]

        identities = (
            ("campaign_id", "other-campaign"),
            ("experiment_id", "other-experiment"),
            ("role_token", "other-role"),
            ("model_identity", "other-model"),
            ("runtime_identity", "other-runtime"),
        )
        for field, replacement in identities:
            values = {
                "campaign_id": ordered.campaign_id,
                "experiment_id": ordered.experiment_id,
                "role_token": ordered.role_token,
                "model_identity": ordered.model_identity,
                "runtime_identity": ordered.runtime_identity,
                "payload": {"artifact": "public", "nested": {"a": 1, "b": 2}},
            }
            values[field] = replacement
            payload = values.pop("payload")
            candidate = FingerprintRequest(
                values["campaign_id"],
                values["experiment_id"],
                values["role_token"],
                sha256(canonical_bytes(payload)).hexdigest(),
                values["model_identity"],
                values["runtime_identity"],
                payload,
            )
            assert ordered.invocation_key("fingerprint") != candidate.invocation_key("fingerprint")
            asyncio.run(self.activities.fingerprint(candidate))
        assert self.backend.calls.count("fingerprint") == 1 + len(identities)

    def test_preflight_failure_is_retryable_before_role_or_gate_reservation(self) -> None:
        attempts = {"fingerprint": 0, "release": 0}

        def fail_once(endpoint):
            def check(_request):
                attempts[endpoint] += 1
                if attempts[endpoint] == 1:
                    raise RuntimeError("transient preflight failure")

            return check

        self.backend.preflight_fingerprint = fail_once("fingerprint")
        self.backend.preflight_release = fail_once("release")
        role = request(FingerprintRequest)
        gate = request(
            ReleaseRequest,
            workflow_id="workflow",
            run_id="run",
            ordinal=0,
            prior_record_sha256="0" * 64,
            expected_revision_sha256="b" * 64,
            branch_kind="release",
        )
        with pytest.raises(RuntimeError):
            asyncio.run(self.activities.fingerprint(role))
        with pytest.raises(RuntimeError):
            asyncio.run(self.activities.release(gate))
        asyncio.run(self.activities.fingerprint(role))
        asyncio.run(self.activities.release(gate))
        assert self.backend.calls == ["fingerprint", "release"]

    def test_stale_role_and_subject_reservations_terminalize_without_reexecution(self) -> None:
        for endpoint, cls in (
            ("fingerprint", FingerprintRequest),
            ("subject_trial", SubjectTrialRequest),
        ):
            with self.subTest(endpoint=endpoint):
                value = request(cls)
                canonical = self.activities._reconstruct(value)
                key = canonical.invocation_key(endpoint)
                input_bytes = canonical_bytes(
                    {"purpose": endpoint, "request": json.loads(canonical._request_bytes)}
                )
                assert (
                    self.store.reserve_invocation(key, input_bytes).disposition
                    == InvocationDisposition.ACQUIRED
                )
                with patch.object(
                    self.store,
                    "terminalize_indeterminate",
                    wraps=self.store.terminalize_indeterminate,
                ) as terminalize:
                    with pytest.raises(ApplicationError) as raised:
                        asyncio.run(getattr(self.activities, endpoint)(value))
                    assert (
                        self.store.reserve_invocation(key, input_bytes).disposition
                        == InvocationDisposition.INDETERMINATE
                    )
                    with pytest.raises(ApplicationError) as repeated:
                        asyncio.run(getattr(self.activities, endpoint)(value))
                assert raised.value.type == "InstructEvalIndeterminate"
                assert repeated.value.type == "InstructEvalIndeterminate"
                terminalize.assert_called_once_with(key, 1)
                assert self.backend.calls.count(endpoint) == 0

    def test_stale_gate_invocation_is_terminalized_without_reexecution(self) -> None:
        value = request(
            DesignCommitRequest,
            workflow_id="workflow",
            run_id="run",
            ordinal=0,
            prior_record_sha256="0" * 64,
            expected_revision_sha256="b" * 64,
            branch_kind="design",
        )
        canonical = self.activities._reconstruct(value)
        record = canonical_bytes(
            {"purpose": "design_commit", "request": json.loads(canonical._request_bytes)}
        )
        invocation = self.store.reserve_gate_invocation(record)
        assert invocation.disposition == InvocationDisposition.ACQUIRED

        with pytest.raises(ApplicationError) as raised:
            asyncio.run(self.activities.design_commit(value))

        assert raised.value.type == "InstructEvalIndeterminate"
        assert (
            self.store.reserve_gate_invocation(record).disposition
            == InvocationDisposition.INDETERMINATE
        )
        assert "design_commit" not in self.backend.calls

    def test_gate_crashes_recover_exact_published_artifact_without_reexecution(self) -> None:
        def value():
            return request(
                ReleaseRequest,
                workflow_id="workflow",
                run_id="run",
                ordinal=0,
                prior_record_sha256="0" * 64,
                expected_revision_sha256="b" * 64,
                branch_kind="release",
            )

        for boundary in ("reserve", "committing", "published"):
            with self.subTest(boundary=boundary):
                self.store = CoordinationStore(self.root / f"{boundary}.sqlite")
                self.backend = FakeBackend(self.root)
                self.activities = InstructEvalActivities(self.store, self.backend)
                original = getattr(
                    self.store,
                    {
                        "reserve": "reserve_gate",
                        "committing": "begin_release_commit",
                        "published": "publish_gate",
                    }[boundary],
                )
                crashed = False

                def crash_once(*args, original=original, boundary=boundary, **kwargs):
                    nonlocal crashed
                    outcome = original(*args, **kwargs)
                    if not crashed:
                        crashed = True
                        raise SystemExit(boundary)
                    return outcome

                with (
                    patch.object(self.store, original.__name__, side_effect=crash_once),
                    pytest.raises(SystemExit),
                ):
                    asyncio.run(self.activities.release(value()))
                recovered = asyncio.run(self.activities.release(value()))
                ledger_bytes = Path(recovered.artifact_path).read_bytes()
                ledger = json.loads(ledger_bytes)
                artifact_bytes = Path(ledger["public_artifact_path"]).read_bytes()
                assert canonical_bytes(recovered.payload) == artifact_bytes
                assert recovered.artifact_sha256 == sha256(ledger_bytes).hexdigest()
                assert self.backend.calls.count("release") == 1

    def test_gate_record_rejects_every_same_slot_request_identity_substitution(self) -> None:
        gate: dict[str, Any] = {
            "workflow_id": "workflow",
            "run_id": "run",
            "ordinal": 0,
            "prior_record_sha256": "0" * 64,
            "expected_revision_sha256": "b" * 64,
            "branch_kind": "release",
        }
        original = request(
            ReleaseRequest, {"artifact": "public", "nested": {"stable": True}}, **gate
        )
        self.store.reserve_gate(
            GateRequest(
                original.workflow_id,
                original.run_id,
                original.ordinal,
                original.prior_record_sha256,
                original.expected_revision_sha256,
                original.branch_kind,
                canonical_bytes(
                    {"purpose": "release", "request": json.loads(original._request_bytes)}
                ),
            )
        )
        for field, replacement in (
            ("campaign_id", "other-campaign"),
            ("experiment_id", "other-experiment"),
            ("role_token", "other-role"),
            ("model_identity", "other-model"),
            ("runtime_identity", "other-runtime"),
            ("payload", {"artifact": "other"}),
        ):
            values = {
                "campaign_id": original.campaign_id,
                "experiment_id": original.experiment_id,
                "role_token": original.role_token,
                "model_identity": original.model_identity,
                "runtime_identity": original.runtime_identity,
                "payload": {"artifact": "public", "nested": {"stable": True}},
            }
            values[field] = replacement
            payload = values["payload"]
            candidate = ReleaseRequest(
                values["campaign_id"],
                values["experiment_id"],
                values["role_token"],
                sha256(canonical_bytes(payload)).hexdigest(),
                values["model_identity"],
                values["runtime_identity"],
                payload,
                **gate,
            )
            with pytest.raises(ApplicationError):
                asyncio.run(self.activities.release(candidate))
        assert self.backend.calls == []

    def test_semantic_gate_failure_commits_recoverable_protocol_disposition(self) -> None:
        value = request(
            ReleaseRequest,
            workflow_id="workflow",
            run_id="run",
            ordinal=0,
            prior_record_sha256="0" * 64,
            expected_revision_sha256="b" * 64,
            branch_kind="release",
        )
        with patch.object(
            self.backend,
            "release",
            side_effect=ProtocolError("malformed private release"),
        ) as release:
            initial = asyncio.run(self.activities.release(value))
            recovered = asyncio.run(self.activities.release(value))
        assert release.call_count == 1
        assert initial.payload == {"accepted": False, "protocol_failure": True}
        assert recovered == initial
        ledger = json.loads(Path(initial.artifact_path).read_bytes())
        failure_path = Path(ledger["public_artifact_path"])
        assert failure_path.read_bytes() == canonical_bytes(
            {"accepted": False, "protocol_failure": True}
        )

    def test_invalid_gate_publication_never_becomes_a_published_result(self) -> None:
        value = request(
            ReleaseRequest,
            workflow_id="workflow",
            run_id="run",
            ordinal=0,
            prior_record_sha256="0" * 64,
            expected_revision_sha256="b" * 64,
            branch_kind="release",
        )
        real_release = self.backend.release

        def mismatched(request):
            publication = real_release(request)
            object.__setattr__(
                publication, "artifact_bytes", canonical_bytes({"artifact": "different"})
            )
            object.__setattr__(
                publication, "artifact_sha256", sha256(publication.artifact_bytes).hexdigest()
            )
            return publication

        with (
            patch.object(self.backend, "release", side_effect=mismatched),
            pytest.raises(ApplicationError),
        ):
            asyncio.run(self.activities.release(value))
        reservation = self.store.reserve_gate(
            GateRequest(
                value.workflow_id,
                value.run_id,
                value.ordinal,
                value.prior_record_sha256,
                value.expected_revision_sha256,
                value.branch_kind,
                canonical_bytes(
                    {"purpose": "release", "request": json.loads(value._request_bytes)}
                ),
            )
        )
        assert reservation.disposition.name != "PUBLISHED"
