"""Durability contracts for invocation and gate coordination."""

from __future__ import annotations

import tempfile
import unittest
from contextlib import closing
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

import pytest

from instruct_eval.coordination import (
    ChildAuthorizationClaimRequest,
    ChildAuthorizationRequest,
    CoordinationError,
    CoordinationStore,
    GateCommitRequest,
    GateDisposition,
    GatePublicationRequest,
    GateRequest,
    InvocationDisposition,
)


class CoordinationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.store = CoordinationStore(
            self.root / "coordination.sqlite",
            max_invocation_input_bytes=4,
            max_invocation_result_bytes=5,
        )
        self.prior = "0" * 64
        self.revision = "b" * 64
        self.input = b'{"record":1}'

    def tearDown(self) -> None:
        self.directory.cleanup()

    def reserve(self):
        return self.store.reserve_gate(
            GateRequest(
                workflow_id="workflow",
                run_id="run",
                ordinal=0,
                prior_record_sha256=self.prior,
                expected_revision_sha256=self.revision,
                branch_kind="release",
                record_input_bytes=self.input,
            )
        )

    def test_invocation_payloads_are_bounded_before_persistence(self) -> None:
        with closing(self.store._connection()) as connection:
            assert (
                connection.execute(
                    "SELECT 1 FROM invocations WHERE invocation_key='too-large-input'"
                ).fetchone()
                is None
            )
        reservation = self.store.reserve_invocation("input", b"1234")
        with pytest.raises(CoordinationError):
            self.store.commit_result("input", reservation.owner_epoch or 0, b"123456")
        with closing(self.store._connection()) as connection:
            assert (
                connection.execute(
                    "SELECT state FROM invocations WHERE invocation_key='input'"
                ).fetchone()[0]
                == "STARTED"
            )

    def test_result_and_terminalizer_cas_preserve_the_first_terminal_outcome(self) -> None:
        terminal_first = self.store.reserve_invocation("terminal-first", b"seed")
        self.store.terminalize_indeterminate("terminal-first", terminal_first.owner_epoch or 0)
        with pytest.raises(CoordinationError):
            self.store.commit_result("terminal-first", terminal_first.owner_epoch or 0, b"done")
        terminal_recovery = self.store.reserve_invocation("terminal-first", b"seed")
        assert terminal_recovery.disposition == InvocationDisposition.INDETERMINATE

        result_first = self.store.reserve_invocation("result-first", b"seed")
        committed = self.store.commit_result("result-first", result_first.owner_epoch or 0, b"done")
        with pytest.raises(CoordinationError):
            self.store.terminalize_indeterminate("result-first", result_first.owner_epoch or 0)
        result_recovery = self.store.reserve_invocation("result-first", b"seed")
        assert result_recovery.disposition == InvocationDisposition.RESULT_RECOVERED
        assert result_recovery.result_bytes == committed.result_bytes

    def test_gate_invocation_journal_recovers_exact_committed_bytes(self) -> None:
        record = b"gate"
        first = self.store.reserve_gate_invocation(record)
        assert first.disposition == InvocationDisposition.ACQUIRED
        committed = self.store.commit_result(first.invocation_key, first.owner_epoch or 0, b"done")
        recovered = self.store.reserve_gate_invocation(record)
        assert recovered.disposition == InvocationDisposition.RESULT_RECOVERED
        assert recovered.invocation_key == committed.invocation_key
        assert recovered.result_bytes == b"done"

    def test_reserved_same_branch_recovery_requires_exact_provenance(self) -> None:
        first = self.reserve()
        recovered = self.reserve()
        assert recovered.disposition == GateDisposition.RECOVERED
        assert (recovered.owner_epoch or 0) > (first.owner_epoch or 0)
        with pytest.raises(CoordinationError):
            self.store.reserve_gate(
                GateRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=0,
                    prior_record_sha256=self.prior,
                    expected_revision_sha256=self.revision,
                    branch_kind="release",
                    record_input_bytes=b'{"record":2}',
                )
            )
        with pytest.raises(CoordinationError):
            self.store.reserve_gate(
                GateRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=0,
                    prior_record_sha256=self.prior,
                    expected_revision_sha256="c" * 64,
                    branch_kind="release",
                    record_input_bytes=self.input,
                )
            )
        with pytest.raises(CoordinationError):
            self.store.begin_release_commit(
                GateCommitRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=0,
                    expected_revision_sha256=self.revision,
                    owner_epoch=first.owner_epoch or 0,
                )
            )

    def test_release_committing_recovers_with_a_new_owner_epoch(self) -> None:
        reservation = self.reserve()
        release = self.store.begin_release_commit(
            GateCommitRequest(
                workflow_id="workflow",
                run_id="run",
                ordinal=0,
                expected_revision_sha256=self.revision,
                owner_epoch=reservation.owner_epoch or 0,
            )
        )
        assert release.disposition == GateDisposition.ACQUIRED
        recovered = self.reserve()
        assert recovered.disposition == GateDisposition.COMMITTING
        assert recovered.owner_epoch == (release.owner_epoch or 0) + 1
        with pytest.raises(CoordinationError):
            self.store.begin_release_commit(
                GateCommitRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=0,
                    expected_revision_sha256=self.revision,
                    owner_epoch=release.owner_epoch or 0,
                )
            )
        payload = b"durable artifact"
        digest = sha256(payload).hexdigest()
        artifact = self.root / "artifact.json"
        artifact.write_bytes(payload)
        with pytest.raises(CoordinationError):
            self.store.publish_gate(
                GatePublicationRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=0,
                    expected_revision_sha256=self.revision,
                    owner_epoch=release.owner_epoch or 0,
                    final_artifact_path=artifact,
                    expected_bytes=payload,
                    expected_sha256=digest,
                )
            )
        published = self.store.publish_gate(
            GatePublicationRequest(
                workflow_id="workflow",
                run_id="run",
                ordinal=0,
                expected_revision_sha256=self.revision,
                owner_epoch=recovered.owner_epoch or 0,
                final_artifact_path=artifact,
                expected_bytes=payload,
                expected_sha256=digest,
            )
        )
        assert published.disposition == GateDisposition.PUBLISHED
        assert self.reserve().disposition == GateDisposition.PUBLISHED

    def test_publication_requires_exact_regular_file_and_recovers_only_exact_artifact(self) -> None:
        reservation = self.reserve()
        self.store.begin_release_commit(
            GateCommitRequest(
                workflow_id="workflow",
                run_id="run",
                ordinal=0,
                expected_revision_sha256=self.revision,
                owner_epoch=reservation.owner_epoch or 0,
            )
        )
        payload = b"durable artifact"
        digest = sha256(payload).hexdigest()
        artifact = self.root / "artifact.json"
        with pytest.raises(CoordinationError):
            self.store.publish_gate(
                GatePublicationRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=0,
                    expected_revision_sha256=self.revision,
                    owner_epoch=reservation.owner_epoch or 0,
                    final_artifact_path=artifact,
                    expected_bytes=payload,
                    expected_sha256=digest,
                )
            )
        artifact.write_bytes(b"altered")
        with pytest.raises(CoordinationError):
            self.store.publish_gate(
                GatePublicationRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=0,
                    expected_revision_sha256=self.revision,
                    owner_epoch=reservation.owner_epoch or 0,
                    final_artifact_path=artifact,
                    expected_bytes=payload,
                    expected_sha256=digest,
                )
            )
        artifact.write_bytes(payload)
        published = self.store.publish_gate(
            GatePublicationRequest(
                workflow_id="workflow",
                run_id="run",
                ordinal=0,
                expected_revision_sha256=self.revision,
                owner_epoch=reservation.owner_epoch or 0,
                final_artifact_path=artifact,
                expected_bytes=payload,
                expected_sha256=digest,
            )
        )
        assert published.disposition == GateDisposition.PUBLISHED
        assert (
            self.store.publish_gate(
                GatePublicationRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=0,
                    expected_revision_sha256=self.revision,
                    owner_epoch=reservation.owner_epoch or 0,
                    final_artifact_path=artifact,
                    expected_bytes=payload,
                    expected_sha256=digest,
                )
            ).disposition
            == GateDisposition.PUBLISHED
        )
        artifact.write_bytes(b"forged")
        with pytest.raises(CoordinationError):
            self.store.publish_gate(
                GatePublicationRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=0,
                    expected_revision_sha256=self.revision,
                    owner_epoch=reservation.owner_epoch or 0,
                    final_artifact_path=artifact,
                    expected_bytes=payload,
                    expected_sha256=digest,
                )
            )

    def test_gate_chain_requires_published_exact_predecessor(self) -> None:
        with pytest.raises(CoordinationError):
            self.store.reserve_gate(
                GateRequest(
                    workflow_id="other-workflow",
                    run_id="run",
                    ordinal=0,
                    prior_record_sha256="a" * 64,
                    expected_revision_sha256=self.revision,
                    branch_kind="release",
                    record_input_bytes=self.input,
                )
            )
        with pytest.raises(CoordinationError):
            self.store.reserve_gate(
                GateRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=1,
                    prior_record_sha256="a" * 64,
                    expected_revision_sha256=self.revision,
                    branch_kind="release",
                    record_input_bytes=self.input,
                )
            )
        first = self.reserve()
        with pytest.raises(CoordinationError):
            self.store.reserve_gate(
                GateRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=1,
                    prior_record_sha256="a" * 64,
                    expected_revision_sha256=self.revision,
                    branch_kind="release",
                    record_input_bytes=self.input,
                )
            )
        artifact = self.root / "first.json"
        artifact.write_bytes(b"first")
        digest = sha256(b"first").hexdigest()
        self.store.begin_release_commit(
            GateCommitRequest(
                workflow_id="workflow",
                run_id="run",
                ordinal=0,
                expected_revision_sha256=self.revision,
                owner_epoch=first.owner_epoch or 0,
            )
        )
        self.store.publish_gate(
            GatePublicationRequest(
                workflow_id="workflow",
                run_id="run",
                ordinal=0,
                expected_revision_sha256=self.revision,
                owner_epoch=first.owner_epoch or 0,
                final_artifact_path=artifact,
                expected_bytes=b"first",
                expected_sha256=digest,
            )
        )
        assert (
            self.store.reserve_gate(
                GateRequest(
                    workflow_id="workflow",
                    run_id="run",
                    ordinal=1,
                    prior_record_sha256=digest,
                    expected_revision_sha256=self.revision,
                    branch_kind="release",
                    record_input_bytes=self.input,
                )
            ).disposition
            == GateDisposition.ACQUIRED
        )

    def test_initialize_closes_connection_on_success(self) -> None:
        class FakeConnection:
            def __init__(self) -> None:
                self.closed = False

            def executescript(self, script: str) -> None:
                self.script = script

            def execute(self, query: str):
                self.query = query
                if "child_authorizations" in query:
                    return [
                        (0, "campaign_id"),
                        (1, "parent_workflow_id"),
                        (2, "parent_run_id"),
                        (3, "claim_sha256"),
                        (4, "fingerprint_sha256"),
                        (5, "coverage_sha256"),
                        (6, "experiment_id"),
                        (7, "child_workflow_id"),
                        (8, "child_run_id"),
                        (9, "state"),
                        (10, "owner_epoch"),
                    ]
                return [
                    (0, "prior_record_sha256"),
                    (1, "expected_revision_sha256"),
                    (2, "branch_kind"),
                    (3, "record_input_bytes"),
                    (4, "record_input_sha256"),
                    (5, "publication_path"),
                ]

            def close(self) -> None:
                self.closed = True

        fake = FakeConnection()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite"
            path.touch()
            store = CoordinationStore.__new__(CoordinationStore)
            store.path = path
            store.max_invocation_input_bytes = 4
            store.max_invocation_result_bytes = 5
            with patch.object(CoordinationStore, "_connection", return_value=fake):
                store._initialize()
            assert fake.closed

    def test_initialize_closes_connection_when_schema_is_obsolete(self) -> None:
        class FakeConnection:
            def __init__(self) -> None:
                self.closed = False

            def executescript(self, script: str) -> None:
                self.script = script

            def execute(self, query: str):
                self.query = query
                return [(0, "workflow_id")]

            def close(self) -> None:
                self.closed = True

        fake = FakeConnection()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite"
            path.touch()
            store = CoordinationStore.__new__(CoordinationStore)
            store.path = path
            store.max_invocation_input_bytes = 4
            store.max_invocation_result_bytes = 5
            with (
                patch.object(CoordinationStore, "_connection", return_value=fake),
                pytest.raises(CoordinationError),
            ):
                store._initialize()
            assert fake.closed

    def test_child_authorization_claims_exact_issued_binding_once(self) -> None:
        with patch("instruct_eval.coordination.secrets.randbelow", return_value=11) as nonce:
            issued = self.store.issue_child_authorization(
                ChildAuthorizationRequest(
                    campaign_id="campaign",
                    parent_workflow_id="parent",
                    parent_run_id="parent-run",
                    claim_sha256="a" * 64,
                    fingerprint_sha256="b" * 64,
                    coverage_sha256="c" * 64,
                )
            )
        recovered = self.store.issue_child_authorization(
            ChildAuthorizationRequest(
                campaign_id="campaign",
                parent_workflow_id="parent",
                parent_run_id="parent-run",
                claim_sha256="a" * 64,
                fingerprint_sha256="b" * 64,
                coverage_sha256="c" * 64,
            )
        )
        assert nonce.call_count == 1
        assert issued == recovered
        assert issued.experiment_id == "experiment-00000000000000000000000000000011"
        with pytest.raises(CoordinationError, match="issued"):
            self.store.claim_child_authorization(
                ChildAuthorizationClaimRequest(
                    campaign_id="campaign",
                    parent_workflow_id="parent",
                    parent_run_id="parent-run",
                    claim_sha256="a" * 64,
                    fingerprint_sha256="b" * 64,
                    coverage_sha256="c" * 64,
                    experiment_id="experiment-" + "9" * 32,
                    child_workflow_id="child",
                    child_run_id="child-run",
                )
            )
        claimed = self.store.claim_child_authorization(
            ChildAuthorizationClaimRequest(
                campaign_id="campaign",
                parent_workflow_id="parent",
                parent_run_id="parent-run",
                claim_sha256="a" * 64,
                fingerprint_sha256="b" * 64,
                coverage_sha256="c" * 64,
                experiment_id=issued.experiment_id or "",
                child_workflow_id="child",
                child_run_id="child-run",
            )
        )
        assert claimed.experiment_id == issued.experiment_id
        with pytest.raises(CoordinationError, match="consumed"):
            self.store.claim_child_authorization(
                ChildAuthorizationClaimRequest(
                    campaign_id="campaign",
                    parent_workflow_id="parent",
                    parent_run_id="parent-run",
                    claim_sha256="a" * 64,
                    fingerprint_sha256="b" * 64,
                    coverage_sha256="c" * 64,
                    experiment_id=issued.experiment_id or "",
                    child_workflow_id="other-child",
                    child_run_id="child-run",
                )
            )


if __name__ == "__main__":
    unittest.main()
