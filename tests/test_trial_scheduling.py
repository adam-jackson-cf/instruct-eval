from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
import warnings
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import pytest

from instruct_eval.models import canonical_bytes
from instruct_eval.trials import (
    ASSIGNMENT_IDS,
    MAX_CHANNEL_BYTES,
    SUBJECT_ARTIFACT_KINDS,
    AhoMatcher,
    ClosedOutcomeParams,
    PrivateArtifactCommitmentParams,
    PrivateArtifactDescriptorParams,
    PrivateMapLifecycle,
    PrivateMapParams,
    TrialDispatcher,
    TrialProtocolError,
    TrustedActivityMetadataParams,
    closed_outcome,
    condition_disclosure,
    g6_authorized,
    prepare_private_map,
    private_artifact_commitment,
    private_artifact_descriptor,
    release_g5,
    scan_disclosure,
    trusted_activity_metadata,
    validate_allowed_paths,
)


class Info:
    workflow_namespace = "default"
    workflow_type = "InstructionExperimentWorkflow"
    task_queue = "queue"
    workflow_id = "workflow"
    workflow_run_id = "run"
    activity_type = "PreparePrivateMap"
    activity_id = "prepare"
    parent_workflow_id = "parent"
    parent_run_id = "parent-run"


def metadata():
    return trusted_activity_metadata(
        TrustedActivityMetadataParams(
            info=Info(),
            expected_namespace="default",
            expected_activity_type="PreparePrivateMap",
            expected_task_queue="queue",
            expected_activity_id="prepare",
            verified_parent_workflow_id="parent",
            verified_parent_run_id="parent-run",
            freeze_chain="f" * 64,
        )
    )


class TrialSchedulingTests(unittest.TestCase):
    def setUp(self):
        self.metadata = metadata()
        self.preferred = {"core-1": "D1", "core-2": "D2", "negative-control": "D3"}
        self.mapping = prepare_private_map(
            PrivateMapParams(
                campaign_id="campaign-" + "0" * 32,
                experiment_id="experiment-" + "1" * 32,
                metadata=self.metadata,
                pre_map_input_hash="a" * 64,
                preferred_directions=self.preferred,
                seed=b"x" * 32,
            )
        )

    def test_exact_matrix_and_bounded_dispatch(self):
        assert tuple(x.assignment_id for x in self.mapping.assignments) == ASSIGNMENT_IDS
        dispatcher = TrialDispatcher(self.mapping)
        assert len(dispatcher.dispatch()) == 4
        for assignment in tuple(x for x, v in dispatcher._state.items() if v == "started"):
            dispatcher.terminal(assignment, "result")
        assert len(dispatcher.dispatch()) == 4

    def test_metadata_rejects_untrusted_namespace(self):
        with pytest.raises(TrialProtocolError):
            trusted_activity_metadata(
                TrustedActivityMetadataParams(
                    info=Info(),
                    expected_namespace="wrong",
                    expected_activity_type="PreparePrivateMap",
                    expected_task_queue="queue",
                    expected_activity_id="prepare",
                    verified_parent_workflow_id="parent",
                    verified_parent_run_id="parent-run",
                    freeze_chain="f" * 64,
                )
            )

    def test_metadata_rejects_missing_freeze_chain(self):
        with pytest.raises(TrialProtocolError):
            trusted_activity_metadata(
                TrustedActivityMetadataParams(
                    info=Info(),
                    expected_namespace="default",
                    expected_activity_type="PreparePrivateMap",
                    expected_task_queue="queue",
                    expected_activity_id="prepare",
                    verified_parent_workflow_id="parent",
                    verified_parent_run_id="parent-run",
                    freeze_chain="",
                )
            )

    def test_sqlite_restart_stability_permissions_and_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            db = Path(tmp) / "private.db"
            private_root = Path(tmp) / "private-artifacts"
            with PrivateMapLifecycle(db, private_root) as first:
                one = first.prepare(
                    PrivateMapParams(
                        campaign_id="c",
                        experiment_id="e",
                        metadata=self.metadata,
                        pre_map_input_hash="a" * 64,
                        preferred_directions=self.preferred,
                        seed=b"x" * 32,
                    )
                )
                assert os.stat(db.parent).st_mode & 511 == 448
                assert os.stat(db).st_mode & 511 == 384
                assert os.stat(db.with_name("private.db-wal")).st_mode & 511 == 384
                assert os.stat(db.with_name("private.db-shm")).st_mode & 511 == 384
            with PrivateMapLifecycle(db, private_root) as second:
                two = second.prepare(
                    PrivateMapParams(
                        campaign_id="c",
                        experiment_id="e",
                        metadata=self.metadata,
                        pre_map_input_hash="a" * 64,
                        preferred_directions=self.preferred,
                    )
                )
            with PrivateMapLifecycle(db, private_root) as restored:
                resolved = restored.resolve(
                    map_ref=one.map_ref,
                    metadata=self.metadata,
                    token=one.mapping.assignments[0].token,
                )
            assert one.map_ref == two.map_ref
            assert os.stat(db).st_mode & 511 == 384
            assert resolved == one.mapping.assignments[0]
            with pytest.raises(sqlite3.ProgrammingError):
                restored._db.execute("SELECT 1")

    def test_sqlite_lifecycle_closes_after_prepare_error(self):
        with tempfile.TemporaryDirectory() as tmp, warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            lifecycle = PrivateMapLifecycle(Path(tmp) / "private.db")
            with pytest.raises(TrialProtocolError), lifecycle:
                lifecycle.prepare(
                    PrivateMapParams(
                        campaign_id="c",
                        experiment_id="e",
                        metadata=self.metadata,
                        pre_map_input_hash="a" * 64,
                        preferred_directions={},
                    )
                )
            with pytest.raises(sqlite3.ProgrammingError):
                lifecycle._db.execute("SELECT 1")

    def test_private_release_rejects_altered_or_deleted_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "private"
            for failure in ("altered", "deleted", "altered-map", "deleted-map"):
                with (
                    self.subTest(failure=failure),
                    PrivateMapLifecycle(Path(tmp) / f"{failure}.db", root) as lifecycle,
                ):
                    prepared = lifecycle.prepare(
                        PrivateMapParams(
                            campaign_id="c",
                            experiment_id="e",
                            metadata=self.metadata,
                            pre_map_input_hash="a" * 64,
                            preferred_directions=self.preferred,
                            seed=b"x" * 32,
                        )
                    )
                    for index in range(10):
                        assignment = lifecycle.resolve_index(metadata=self.metadata, index=index)
                        outcome = {
                            "blind_id": assignment.blind_id,
                            "fixture": assignment.scenario,
                            "protocol_valid": True,
                            "verifier_passed": False,
                            "observer_state": [],
                            "direction_code": "D",
                            "changed_paths": [],
                            "evidence_id": str(index),
                        }
                        path = root / f"quarantine/c/e/{index}.json"
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(canonical_bytes(outcome))
                        lifecycle.record_outcome_index(
                            metadata=self.metadata,
                            index=index,
                            outcome_sha256=sha256(canonical_bytes(outcome)).hexdigest(),
                        )
                    evidence = (
                        root / "quarantine/c/e/0.json"
                        if "map" not in failure
                        else root / f"private-maps/{prepared.map_ref}.json"
                    )
                    if "altered" in failure:
                        evidence.write_bytes(canonical_bytes({"altered": True}))
                    else:
                        evidence.unlink()
                    with pytest.raises(TrialProtocolError):
                        lifecycle.release(metadata=self.metadata)

    def test_dispatcher_accounts_terminal_and_cancellation(self):
        dispatcher = TrialDispatcher(self.mapping)
        started = dispatcher.dispatch()
        dispatcher.terminal(started[0], "terminal")
        for token in started[1:]:
            dispatcher.terminal(token, "canceled-before-invocation")
        accounting = dispatcher.accounting()
        assert set(accounting.values()) == {
            "terminal",
            "canceled-before-invocation",
            "UNSCHEDULED_DUE_TO_TERMINAL",
        }
        assert len(accounting) == 10
        dispatcher = TrialDispatcher(self.mapping)
        started = dispatcher.dispatch()
        dispatcher.cancel()
        for token in started:
            dispatcher.terminal(token, "canceled-before-invocation")
        assert "UNSCHEDULED_DUE_TO_CANCELLATION" in set(dispatcher.accounting().values())

    def test_linear_matcher_unicode_and_channel_limits(self):
        matcher = AhoMatcher(("aba", "bab"))
        assert set(matcher.matches("ababa")) == {"aba", "bab"}
        assert condition_disclosure("condition\u3000=\xa0A")
        assert not condition_disclosure("condition\x1c=A")
        assert scan_disclosure(raw=(b"Condition", b" = A"), treatment="other")
        with pytest.raises(TrialProtocolError):
            scan_disclosure(raw=b"x" * (MAX_CHANNEL_BYTES + 1), treatment="x")
        with pytest.raises(TrialProtocolError):
            scan_disclosure(raw=(b"x" * MAX_CHANNEL_BYTES,) * 5, treatment="x")

    def test_nfc_root_paths_and_closed_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "a" / "file").write_text("x")
            (root / "link").symlink_to(root / "a", target_is_directory=True)
            assert validate_allowed_paths(["a/file"], root) == ("a/file",)
            with pytest.raises(TrialProtocolError):
                validate_allowed_paths(["e\u0301"], root)
            with pytest.raises(TrialProtocolError):
                validate_allowed_paths(["link/file"], root)
            (root / "a" / "nested-link").symlink_to(root / "a", target_is_directory=True)
            with pytest.raises(TrialProtocolError):
                validate_allowed_paths(["a/nested-link/file"], root)
            with pytest.raises(TrialProtocolError):
                closed_outcome(
                    ClosedOutcomeParams(
                        blind_id="b",
                        fixture="core-1",
                        verifier_passed=cast(bool, "false"),
                        observer_state=[],
                        direction_code="D",
                        changed_paths=[],
                        token="t",
                        k_evidence=b"e" * 32,
                        fixture_paths={"core-1": ["a/file"]},
                        root=root,
                    )
                )
            outcome = closed_outcome(
                ClosedOutcomeParams(
                    blind_id="b",
                    fixture="core-1",
                    verifier_passed=False,
                    observer_state=[],
                    direction_code="D",
                    changed_paths=[],
                    token="t",
                    k_evidence=b"e" * 32,
                    fixture_paths={"core-1": ["a/file"]},
                    root=root,
                )
            )
            assert not outcome["verifier_passed"]

    def test_g5_inventory_tamper_replay_missing_extra_and_g6_exactness(self):
        key = b"k" * 32
        items = []
        artifact_rows = [(None, "map", self.mapping.map_sha256)] + [
            (assignment.token, kind, "b" * 64)
            for assignment in self.mapping.assignments
            for kind in SUBJECT_ARTIFACT_KINDS
        ]
        for token, kind, digest in artifact_rows:
            descriptor_params = PrivateArtifactDescriptorParams(
                campaign_id=self.mapping.campaign_id,
                experiment_id=self.mapping.experiment_id,
                token=token,
                artifact_kind=kind,
                artifact_sha256=digest,
            )
            descriptor = private_artifact_descriptor(descriptor_params)
            items.append(
                {
                    **descriptor,
                    "commitment": private_artifact_commitment(
                        PrivateArtifactCommitmentParams(
                            descriptor=descriptor_params,
                            k_artifact=key,
                        )
                    ),
                }
            )
        directions = {}
        scores = []
        for assignment in self.mapping.assignments:
            direction = (
                self.preferred[assignment.scenario]
                if assignment.condition == "B" or assignment.scenario == "negative-control"
                else "wrong"
            )
            directions[assignment.token] = direction
            scores.append(
                {
                    "blind_id": assignment.blind_id,
                    "scenario": assignment.scenario,
                    "condition": assignment.condition,
                    "direction": direction,
                }
            )
        release = release_g5(self.mapping, items, key, directions)
        assert set(release) == {
            "assignments",
            "preferred_directions",
            "authorization_rule",
            "release_sha256",
        }
        assert release["assignments"] == sorted(scores, key=lambda score: score["blind_id"])
        assert len(release["assignments"]) == 10
        assert (
            release["release_sha256"]
            == sha256(
                canonical_bytes(
                    {key: value for key, value in release.items() if key != "release_sha256"}
                )
            ).hexdigest()
        )
        for broken in (
            items[:-1],
            [*items, items[-1]],
            [{**items[0], "artifact_sha256": "c" * 64}, *items[1:]],
        ):
            with pytest.raises(TrialProtocolError):
                release_g5(self.mapping, broken, key, directions)
        for broken_directions in (
            dict(list(directions.items())[:-1]),
            {**directions, "foreign": "D"},
            {**directions, next(iter(directions)): ""},
        ):
            with pytest.raises(TrialProtocolError):
                release_g5(self.mapping, items, key, broken_directions)
        assert g6_authorized(scores, self.preferred)
        assert not g6_authorized(scores[:-1], self.preferred)
        assert not g6_authorized([*scores, {**scores[0], "blind_id": "extra"}], self.preferred)
        assert not g6_authorized([{**scores[0], "extra": "field"}, *scores[1:]], self.preferred)
        assert not g6_authorized(cast(Any, "malformed"), self.preferred)
        assert not g6_authorized(scores, cast(Any, {"core-1": "better"}))


if __name__ == "__main__":
    unittest.main()
