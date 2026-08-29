import asyncio
import unittest
from unittest.mock import patch

import pytest

from instruct_eval.activities import ActivityResult, GateResult
from instruct_eval.models import canonical_hash
from instruct_eval.workflows import (
    ExperimentGate,
    ExperimentInput,
    InstructionExperimentWorkflow,
    WorkflowProtocolError,
    _g5_release,
)

DIGEST = "a" * 64
CLAIM = {"coverage_sha256": "c" * 64, "claim": "one"}
CLAIM_SHA256 = canonical_hash(CLAIM)


def activity(payload: dict[str, object]) -> ActivityResult:
    return ActivityResult(DIGEST, canonical_hash(payload), payload)


def gate(ordinal: int, payload: dict[str, object]) -> GateResult:
    return GateResult(
        "workflow", "run", ordinal, "/public/artifact.json", canonical_hash(payload), payload
    )


def input_() -> ExperimentInput:
    return ExperimentInput(
        "campaign-" + "1" * 32,
        "experiment-opaque",
        CLAIM_SHA256,
        CLAIM,
        "c" * 64,
        "model",
        "runtime",
        {
            "request_sha256": DIGEST,
            "candidate_instruction": "candidate",
            "fixture_manifest_hash": "f" * 64,
        },
        {
            "authorized": True,
            "campaign_id": "campaign-" + "1" * 32,
            "experiment_id": "experiment-opaque",
            "claim_sha256": CLAIM_SHA256,
            "coverage_sha256": "c" * 64,
            "fingerprint_sha256": "d" * 64,
        },
    )


def _subject_failure_trial_result(request: object, tokens: tuple[str, ...]) -> ActivityResult:
    if request.payload["token"] == tokens[0]:
        raise RuntimeError("subject failed")
    return activity({"protocol_valid": True})


def _subject_failure_pre_execution_gate(name: str) -> GateResult | None:
    if name == "instruct_eval.g0_commit":
        return gate(0, {"accepted": True})
    if name in {"instruct_eval.design_commit", "instruct_eval.pre_run_validity"}:
        return gate(1, {"accepted": True, "design_sha256": "d" * 64})
    if name == "instruct_eval.freeze":
        return gate(2, {"accepted": True, "design_sha256": "d" * 64})
    return None


def _subject_failure_trial_accounting(tokens: tuple[str, ...]) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "token": token,
            "disposition": "indeterminate"
            if index == 0
            else "result"
            if index < 4
            else "UNSCHEDULED_DUE_TO_TERMINAL",
        }
        for index, token in enumerate(tokens)
    )


def _subject_failure_subject_tokens(
    executed: list[tuple[str, object]],
) -> list[object]:
    return [
        request.payload["token"]
        for name, request in executed
        if name == "instruct_eval.subject_trial"
    ]


class _SubjectActivityFailureHarness:
    def __init__(
        self,
        workflow: InstructionExperimentWorkflow,
        experiment: ExperimentInput,
    ) -> None:
        self.workflow = workflow
        self.experiment = experiment
        self.executed: list[tuple[str, object]] = []
        self.committed: list[str] = []
        self.tokens = tuple(f"{index:043d}" for index in range(10))
        self.waits = 0

    async def execute(
        self,
        name: str,
        request: object,
        *,
        activity_id: str | None = None,
    ) -> ActivityResult:
        _ = activity_id
        self.executed.append((name, request))
        if name == "instruct_eval.child_authorization_claim":
            return activity(
                {
                    "authorized": True,
                    "campaign_id": self.experiment.campaign_id,
                    "experiment_id": self.experiment.experiment_id,
                    "claim_sha256": self.experiment.claim_sha256,
                    "coverage_sha256": self.experiment.coverage_sha256,
                    "fingerprint_sha256": "d" * 64,
                }
            )
        if name == "instruct_eval.eligibility":
            return activity({"accepted": True})
        if name == "instruct_eval.map_lifecycle":
            return activity(
                {
                    "map_ref": "map",
                    "map_commitment": "m" * 43,
                    "tokens": self.tokens,
                    "pre_map_input_hash": "e" * 64,
                    "authorization_rule_sha256": "f" * 64,
                }
            )
        if name == "instruct_eval.subject_trial":
            return _subject_failure_trial_result(request, self.tokens)
        raise AssertionError(name)

    async def execute_gate(
        self,
        name: str,
        request_type: object,
        payload: dict[str, object],
        *,
        activity_id: str | None = None,
    ) -> GateResult:
        _ = request_type, activity_id
        self.committed.append(name)
        pre_execution_gate = _subject_failure_pre_execution_gate(name)
        if pre_execution_gate is not None:
            return pre_execution_gate
        if name == "instruct_eval.execution_commit":
            assert payload["trial_accounting"] == _subject_failure_trial_accounting(self.tokens)
            return gate(3, {"accepted": False})
        if name == "instruct_eval.terminal_commit":
            return gate(4, {})
        raise AssertionError(name)

    async def wait_condition(self, condition: object) -> None:
        _ = condition
        self.waits += 1
        if self.waits == 1:
            self.workflow._frozen_design_sha256 = "d" * 64
            self.workflow._outstanding_proposal_sha256 = "p" * 64
        else:
            self.workflow._outstanding_action = None


class ExperimentWorkflowStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = InstructionExperimentWorkflow()
        self.workflow._initialize(input_())

    def test_authorization_precedes_g0_and_foreign_or_consumed_is_terminal(self) -> None:
        with pytest.raises(WorkflowProtocolError, match="authorization"):
            self.workflow._advance_gate(ExperimentGate.G0, activity({"accepted": True}))
        assert not self.workflow._claim_authorization(
            activity({"authorized": True, "campaign_id": "foreign"})
        )
        assert self.workflow.status().gate == "INITIALIZING"

    def test_rejected_or_preempted_authorization_makes_no_gate_transition(self) -> None:
        assert not self.workflow._claim_authorization(
            activity({"authorized": False, "preempted": True})
        )
        assert self.workflow.status().gate_artifact_sha256 == {}
        assert not self.workflow.status().terminal

    def test_rejected_gate_is_recorded_before_terminalization(self) -> None:
        assert self.workflow._claim_authorization(
            activity(
                {
                    "authorized": True,
                    "campaign_id": "campaign-" + "1" * 32,
                    "experiment_id": "experiment-opaque",
                    "claim_sha256": CLAIM_SHA256,
                    "coverage_sha256": "c" * 64,
                    "fingerprint_sha256": "d" * 64,
                }
            )
        )
        self.workflow._advance_gate(ExperimentGate.G0, gate(0, {"accepted": False}))
        assert self.workflow.status().gate == "G0"
        assert "G0" in self.workflow.status().gate_artifact_sha256

    def test_private_fields_are_rejected_recursively_before_input_is_retained(self) -> None:
        workflow = InstructionExperimentWorkflow()
        private = ExperimentInput(
            "campaign-" + "1" * 32,
            "experiment-opaque",
            CLAIM_SHA256,
            CLAIM,
            "c" * 64,
            "model",
            "runtime",
            {"nested": [{"preferred_direction": "D1"}]},
            {"authorization_id": "opaque"},
        )
        with pytest.raises(WorkflowProtocolError, match="private"):
            workflow._initialize(private)
        assert workflow.status().experiment_id == ""

    def test_gate_transitions_are_once_only_and_restart_safe(self) -> None:
        assert self.workflow._claim_authorization(
            activity(
                {
                    "authorized": True,
                    "campaign_id": "campaign-" + "1" * 32,
                    "experiment_id": "experiment-opaque",
                    "claim_sha256": CLAIM_SHA256,
                    "coverage_sha256": "c" * 64,
                    "fingerprint_sha256": "d" * 64,
                }
            )
        )
        self.workflow._advance_gate(ExperimentGate.G0, activity({"accepted": True}))
        assert self.workflow.status().gate == "G0"
        with pytest.raises(WorkflowProtocolError, match="expected G1"):
            self.workflow._advance_gate(ExperimentGate.G0, activity({"accepted": True}))
        self.workflow._commit_terminal(ExperimentGate.DESIGN_REJECTED)
        self.workflow._commit_terminal(ExperimentGate.DESIGN_REJECTED)
        with pytest.raises(WorkflowProtocolError, match="immutable"):
            self.workflow._commit_terminal(ExperimentGate.AUTHORIZED)

    def test_only_canonical_terminal_values_are_committable(self) -> None:
        for terminal in (
            ExperimentGate.DESIGN_REJECTED,
            ExperimentGate.AUTHORIZED,
            ExperimentGate.COMPLETED_NOT_AUTHORIZED,
            ExperimentGate.SCORING_REJECTED,
            ExperimentGate.PROTOCOL_FAILURE,
            ExperimentGate.CANCELED,
        ):
            workflow = InstructionExperimentWorkflow()
            workflow._initialize(input_())
            workflow._commit_terminal(terminal)
            assert workflow.status().gate == terminal.value

    def test_g1_and_g2_require_same_exact_design_bytes(self) -> None:
        assert self.workflow._claim_authorization(
            activity(
                {
                    "authorized": True,
                    "campaign_id": "campaign-" + "1" * 32,
                    "experiment_id": "experiment-opaque",
                    "claim_sha256": CLAIM_SHA256,
                    "coverage_sha256": "c" * 64,
                    "fingerprint_sha256": "d" * 64,
                }
            )
        )
        self.workflow._advance_gate(ExperimentGate.G0, activity({"accepted": True}))
        design = "d" * 64
        self.workflow._frozen_design_sha256 = design
        with pytest.raises(WorkflowProtocolError, match="G1 must bind"):
            self.workflow._advance_gate(
                ExperimentGate.G1, gate(1, {"accepted": True, "design_sha256": "e" * 64})
            )
        self.workflow._advance_gate(
            ExperimentGate.G1, gate(1, {"accepted": True, "design_sha256": design})
        )
        with pytest.raises(WorkflowProtocolError, match="exact staged"):
            self.workflow._advance_gate(
                ExperimentGate.G2, gate(2, {"accepted": True, "design_sha256": "e" * 64})
            )
        self.workflow._advance_gate(
            ExperimentGate.G2, gate(2, {"accepted": True, "design_sha256": design})
        )

    def test_public_status_contains_only_opaque_identifiers_and_hashes(self) -> None:
        status = self.workflow.status()
        rendered = repr(status)
        assert "authorization_id" not in rendered
        assert "request_sha256" not in rendered
        assert "experiment-opaque" in rendered

    def test_status_exposes_only_decision_reference_metadata(self) -> None:
        status = self.workflow.status()
        assert status.current_revision_sha256 == "0" * 64
        assert status.outstanding_action is None
        assert status.proposal_sha256 is None

    def test_subject_activity_failure_terminalizes_g3_without_later_trials(self) -> None:
        workflow = InstructionExperimentWorkflow()
        harness = _SubjectActivityFailureHarness(workflow, input_())

        with (
            patch.object(workflow, "_execute", harness.execute),
            patch.object(workflow, "_execute_gate", harness.execute_gate),
            patch(
                "instruct_eval.workflows.workflow.wait_condition",
                harness.wait_condition,
            ),
        ):
            result = asyncio.run(workflow.run(harness.experiment))

        assert _subject_failure_subject_tokens(harness.executed) == list(harness.tokens[:4])
        assert harness.committed[-2:] == [
            "instruct_eval.execution_commit",
            "instruct_eval.terminal_commit",
        ]
        assert result.status == "PROTOCOL_FAILURE"

    def test_canonical_g5_packet_and_non_authorized_g6_complete(self) -> None:
        blind_ids = {f"blind-{index}" for index in range(10)}
        released = {
            "assignments": [
                {
                    "blind_id": f"blind-{index}",
                    "scenario": "core-1",
                    "condition": "A",
                    "direction": "D",
                }
                for index in range(10)
            ],
            "preferred_directions": {"core-1": "D", "core-2": "D", "negative-control": "D"},
            "authorization_rule": {
                "schema": "instruct-eval-authorization-rule-v1",
                "core_scenarios": ["core-1", "core-2"],
                "negative_control_scenario": "negative-control",
                "core_comparison": "preferred_count_B_strictly_greater_than_A",
                "negative_control_comparison": "both_subjects_match_preferred_direction",
            },
        }
        packet = {**released, "release_sha256": canonical_hash(released)}
        assert _g5_release(packet, blind_ids) == packet
        assert self.workflow._claim_authorization(
            activity(
                {
                    "authorized": True,
                    "campaign_id": "campaign-" + "1" * 32,
                    "experiment_id": "experiment-opaque",
                    "claim_sha256": CLAIM_SHA256,
                    "coverage_sha256": "c" * 64,
                    "fingerprint_sha256": "d" * 64,
                }
            )
        )
        for ordinal, gate_name in enumerate(
            (
                ExperimentGate.G0,
                ExperimentGate.G1,
                ExperimentGate.G2,
                ExperimentGate.G3,
                ExperimentGate.G4,
                ExperimentGate.G5,
            )
        ):
            payload: dict[str, object] = (
                {"accepted": True, "design_sha256": "d" * 64}
                if gate_name in {ExperimentGate.G1, ExperimentGate.G2}
                else {"accepted": True}
            )
            if gate_name is ExperimentGate.G0:
                self.workflow._frozen_design_sha256 = "d" * 64
            self.workflow._advance_gate(gate_name, gate(ordinal, payload))
        self.workflow._advance_gate(ExperimentGate.G6, gate(6, {"authorized": False}))
        self.workflow._commit_terminal(ExperimentGate.COMPLETED_NOT_AUTHORIZED)
        assert self.workflow._result().status == "COMPLETED_NOT_AUTHORIZED"


if __name__ == "__main__":
    unittest.main()
