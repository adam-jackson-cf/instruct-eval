import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from instruct_eval.activities import ActivityResult, GateResult
from instruct_eval.messages import request_fingerprint
from instruct_eval.models import canonical_hash
from instruct_eval.signing import DecisionPayload, DecisionWire, public_key_base64url
from instruct_eval.workflows import (
    CampaignInput,
    ExperimentCampaignWorkflow,
    WorkflowProtocolError,
    _fingerprint_payload,
    _proposal_decision_payload,
)

DIGEST = "a" * 64


def result(payload: dict[str, object]) -> ActivityResult:
    return ActivityResult(DIGEST, canonical_hash(payload), payload)


def input_(campaign_id: str = "campaign-" + "1" * 32) -> CampaignInput:
    return CampaignInput(
        campaign_id,
        "model",
        "runtime",
        {
            "candidate_instruction": "be exact",
            "permissions": {"network": False},
            "repository": "repo",
            "fixture_manifest_hash": DIGEST,
            "operator_public_key": "operator",
        },
        "b" * 64,
    )


class FakeChildHandle:
    def __init__(self, gate: str = "G4") -> None:
        self.cancelled = False
        self.gate = gate

    def cancel(self) -> None:
        self.cancelled = True

    async def query(self, _name: str):
        return {"gate": self.gate}

    async def _complete(self) -> None:
        return None

    def __await__(self):
        return self._complete().__await__()


class CampaignWorkflowStateTests(unittest.TestCase):
    def test_campaign_id_grammar_and_immutable_input(self) -> None:
        workflow = ExperimentCampaignWorkflow()
        with pytest.raises(WorkflowProtocolError, match="campaign id"):
            workflow._initialize(input_("campaign-not-hex"))
        workflow._initialize(input_())
        workflow._initialize(input_())
        with pytest.raises(WorkflowProtocolError, match="immutable"):
            workflow._initialize(
                CampaignInput(
                    "campaign-" + "1" * 32,
                    "other",
                    "runtime",
                    {"manifest_sha256": DIGEST},
                    "b" * 64,
                )
            )

    def test_fingerprint_payload_is_the_exact_production_packet(self) -> None:
        campaign = input_()
        assert _fingerprint_payload(campaign) == {
            "candidate_instruction": "be exact",
            "model_identity": "model",
            "runtime_identity": "runtime",
            "request": campaign.public_input,
        }
        with pytest.raises(WorkflowProtocolError, match="exact public request"):
            _fingerprint_payload(
                CampaignInput(
                    campaign.campaign_id,
                    "model",
                    "runtime",
                    {"candidate_instruction": "extra"},
                    campaign.coverage_sha256,
                )
            )

    def test_proposal_decision_packet_binds_workflow_and_wire_metadata(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        campaign = input_()
        campaign = CampaignInput(
            campaign.campaign_id,
            campaign.model_identity,
            campaign.runtime_identity,
            {
                **campaign.public_input,
                "operator_public_key": public_key_base64url(private_key.public_key()),
            },
            campaign.coverage_sha256,
        )
        wire = DecisionWire.sign(
            private_key,
            DecisionPayload(
                campaign.campaign_id,
                "campaign",
                campaign.campaign_id,
                "approve_decomposition",
                "d" * 64,
                "0" * 64,
                1,
            ),
        )
        with patch(
            "instruct_eval.workflows.workflow.info",
            return_value=SimpleNamespace(workflow_id="workflow-id", run_id="run-id"),
        ):
            packet = _proposal_decision_payload(campaign, wire, "0" * 64)
        assert packet == {
            "wire": wire.as_json(),
            "workflow_id": "workflow-id",
            "run_id": "run-id",
            "prior_decision_sha256": "0" * 64,
            "target_kind": "campaign",
            "target_id": campaign.campaign_id,
            "action": "approve_decomposition",
            "proposal_hash": "d" * 64,
            "expected_revision_sha256": "0" * 64,
            "sequence": 1,
            "owner_public_key": campaign.public_input["operator_public_key"],
            "request_fingerprint": request_fingerprint(
                campaign.public_input, campaign.model_identity, campaign.runtime_identity
            ),
        }

    def test_initializing_fingerprint_is_stable_and_fail_closed(self) -> None:
        workflow = ExperimentCampaignWorkflow()
        workflow._initialize(input_())
        workflow._record_fingerprint(result({"fingerprint_sha256": "c" * 64}))
        assert workflow.status().state == "FINGERPRINT_READY"
        with pytest.raises(WorkflowProtocolError, match="fingerprint changed"):
            workflow._record_fingerprint(result({"fingerprint_sha256": "d" * 64}))

    def test_claims_are_coverage_bound_hashed_sorted_and_limited_to_32(self) -> None:
        workflow = ExperimentCampaignWorkflow()
        workflow._initialize(input_())
        claims = [{"coverage_sha256": "b" * 64, "claim": str(index)} for index in range(32)]
        extracted = workflow._extract_claims(result({"claims": list(reversed(claims))}))
        hashes = tuple(canonical_hash(claim) for claim in extracted)
        assert hashes == tuple(sorted(hashes))
        assert len(hashes) == 32
        with pytest.raises(WorkflowProtocolError, match="one to 32"):
            workflow._extract_claims(
                result({"claims": [*claims, {"coverage_sha256": "b" * 64, "claim": "extra"}]})
            )
        with pytest.raises(WorkflowProtocolError, match="coverage"):
            workflow._extract_claims(result({"claims": [{"coverage_sha256": "c" * 64}]}))

    def test_campaign_status_and_claims_are_opaque(self) -> None:
        workflow = ExperimentCampaignWorkflow()
        workflow._initialize(input_())
        workflow._claims = ({"coverage_sha256": "b" * 64, "claim": "opaque"},)
        shown = repr(workflow.status())
        assert "manifest_sha256" not in shown
        assert "d" * 64 not in shown
        assert workflow.status().claim_count == 1

    def test_campaign_status_has_no_proposal_material(self) -> None:
        workflow = ExperimentCampaignWorkflow()
        workflow._initialize(input_())
        status = workflow.status()
        assert status.current_revision_sha256 == "0" * 64
        assert status.outstanding_action is None
        assert status.proposal_sha256 is None

    def test_cancellation_cancels_and_drains_awaitable_child_handles(self) -> None:
        workflow = ExperimentCampaignWorkflow()
        handles = [FakeChildHandle(), FakeChildHandle()]
        workflow._children = handles
        asyncio.run(workflow._cancel_active_children())
        assert all(handle.cancelled for handle in handles)
        assert workflow._children == []

    def test_signed_cancellation_commits_before_draining_children(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        campaign = input_()
        campaign = CampaignInput(
            campaign.campaign_id,
            campaign.model_identity,
            campaign.runtime_identity,
            {
                **campaign.public_input,
                "operator_public_key": public_key_base64url(private_key.public_key()),
            },
            campaign.coverage_sha256,
        )
        workflow = ExperimentCampaignWorkflow()
        workflow._initialize(campaign)
        workflow._outstanding_action, workflow._outstanding_sequence = "cancel", 1
        events: list[str] = []

        async def execute(name: str, request: object) -> ActivityResult:
            events.append(name)
            return result(
                {
                    "accepted": True,
                    "decision_sha256": wire.hash,
                    "decision_artifact_sha256": wire.hash,
                    "decision_artifact_path": "/public/decision.json",
                }
            )

        async def execute_activity(name: str, request: object, **kwargs: object) -> GateResult:
            events.append(name)
            assert request.payload["reason"] == "operator_cancelled"  # type: ignore[attr-defined]
            assert request.payload["terminal_gate"] == "CANCELED"  # type: ignore[attr-defined]
            return GateResult("workflow-id", "run-id", 0, "/public/cancel.json", DIGEST, {})

        workflow._execute = execute  # type: ignore[method-assign]
        wire = DecisionWire.sign(
            private_key,
            DecisionPayload(
                campaign.campaign_id, "campaign", campaign.campaign_id, "cancel", None, "0" * 64, 1
            ),
        )

        async def submit_cancellation() -> str:
            return await ExperimentCampaignWorkflow.decision(workflow, wire.as_json())

        with (
            patch(
                "instruct_eval.workflows.workflow.info",
                return_value=SimpleNamespace(workflow_id="workflow-id", run_id="run-id"),
            ),
            patch("instruct_eval.workflows.workflow.execute_activity", execute_activity),
        ):
            asyncio.run(submit_cancellation())
        assert events == ["instruct_eval.proposal_decision", "instruct_eval.terminal_commit"]
        assert workflow.status().state == "CANCELED"
        assert workflow._cancelled

    def test_signed_cancellation_after_published_g5_returns_release_committed(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        campaign = input_()
        campaign = CampaignInput(
            campaign.campaign_id,
            campaign.model_identity,
            campaign.runtime_identity,
            {
                **campaign.public_input,
                "operator_public_key": public_key_base64url(private_key.public_key()),
            },
            campaign.coverage_sha256,
        )
        workflow = ExperimentCampaignWorkflow()
        workflow._initialize(campaign)
        workflow._outstanding_action, workflow._outstanding_sequence = "cancel", 1
        child = FakeChildHandle("G5")
        workflow._children = [child]
        wire = DecisionWire.sign(
            private_key,
            DecisionPayload(
                campaign.campaign_id,
                "campaign",
                campaign.campaign_id,
                "cancel",
                None,
                "0" * 64,
                1,
            ),
        )

        async def execute(_name: str, _request: object) -> ActivityResult:
            return result(
                {
                    "accepted": True,
                    "decision_sha256": wire.hash,
                    "decision_artifact_sha256": wire.hash,
                    "decision_artifact_path": "/public/decision.json",
                }
            )

        workflow._execute = execute  # type: ignore[method-assign]

        async def submit_cancellation() -> str:
            return await ExperimentCampaignWorkflow.decision(workflow, wire.as_json())

        with patch(
            "instruct_eval.workflows.workflow.info",
            return_value=SimpleNamespace(workflow_id="workflow-id", run_id="run-id"),
        ):
            decision = asyncio.run(submit_cancellation())
        assert decision == "release_committed"
        assert not workflow._cancelled
        assert not child.cancelled

    def test_validator_rejects_stale_cross_target_and_stale_cancel_before_handler(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        workflow = ExperimentCampaignWorkflow()
        campaign_id = "campaign-" + "1" * 32
        workflow._initialize(
            CampaignInput(
                campaign_id,
                "model",
                "runtime",
                {
                    "manifest_sha256": DIGEST,
                    "operator_public_key": public_key_base64url(private_key.public_key()),
                },
                "b" * 64,
            )
        )
        workflow._outstanding_action, workflow._outstanding_sequence = "approve_decomposition", 1
        stale = DecisionWire.sign(
            private_key,
            DecisionPayload(
                campaign_id, "campaign", campaign_id, "approve_decomposition", "d" * 64, "e" * 64, 1
            ),
        ).as_json()
        with pytest.raises(WorkflowProtocolError, match="invalid"):
            workflow.validate_decision_update(stale)
        foreign = DecisionWire.sign(
            private_key,
            DecisionPayload(
                campaign_id,
                "campaign",
                "campaign-" + "2" * 32,
                "approve_decomposition",
                "d" * 64,
                "0" * 64,
                1,
            ),
        ).as_json()
        with pytest.raises(WorkflowProtocolError, match="invalid"):
            workflow.validate_decision_update(foreign)
        cancel = DecisionWire.sign(
            private_key,
            DecisionPayload(campaign_id, "campaign", campaign_id, "cancel", None, "0" * 64, 2),
        ).as_json()
        with pytest.raises(WorkflowProtocolError, match="cancel sequence"):
            workflow.validate_decision_update(cancel)


if __name__ == "__main__":
    unittest.main()
