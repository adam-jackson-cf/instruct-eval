from __future__ import annotations

import json
import os
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from instruct_eval.artifacts import ArtifactMode, ArtifactStore
from instruct_eval.coordination import CoordinationStore
from instruct_eval.messages import (
    InspectDecompositionRequest,
    InspectDesignRequest,
    ProposalControl,
    ProposalControlError,
    PublishDecisionRequest,
    StageDecompositionRequest,
    StageDesignRequest,
    request_fingerprint,
)
from instruct_eval.signing import (
    DecisionValidationParameters,
    DecisionWire,
    DecompositionProposal,
    DesignProposal,
    DesignProposalValidationParameters,
    StageAttestation,
    StageAttestationSigningParameters,
    canonical_hash,
)

CAMPAIGN = "campaign-00000000000000000000000000000000"
H = "a" * 64
NONCE = "0" * 32


class ProposalControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.artifacts = ArtifactStore(root / "artifacts", root / "private")
        self.coordination = CoordinationStore(root / "coordination.sqlite")
        self.control = ProposalControl(self.artifacts, self.coordination)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.request = {
            "candidate_instruction": "be exact",
            "permissions": {"network": False},
            "repository": "repo",
            "fixture_manifest_hash": H,
            "operator_public_key": "operator",
        }
        self.fingerprint = request_fingerprint(self.request, "model", "runtime")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def decomposition(self) -> DecompositionProposal:
        return DecompositionProposal(
            proposal_nonce=NONCE,
            campaign_id=CAMPAIGN,
            request_fingerprint=self.fingerprint,
            source_coverage=[{"start_byte": 0, "end_byte": 1}],
            ordered_claims=[{"claim_id": "claim-1"}],
        )

    def design(self) -> tuple[DesignProposal, StageAttestation]:
        proposal = DesignProposal(
            proposal_nonce=NONCE,
            campaign_id=CAMPAIGN,
            claim_hash=H,
            g0_commit_hash="b" * 64,
            treatment_hash="c" * 64,
            fixture_manifest_hash="d" * 64,
            design={"fixtures": ["f"]},
        )
        parameters = StageAttestationSigningParameters(
            campaign_id=CAMPAIGN,
            claim_hash=H,
            proposal_nonce=NONCE,
            proposal_hash=proposal.hash,
            g0_commit_hash="b" * 64,
            treatment_hash="c" * 64,
            fixture_manifest_hash="d" * 64,
        )
        return proposal, StageAttestation.sign(
            private_key=self.private,
            parameters=parameters,
        )

    def test_request_fingerprint_is_exact_and_not_a_subset_hash(self) -> None:
        assert self.fingerprint == canonical_hash(
            {
                "schema": "instruct-eval-request-v1",
                "candidate_instruction": "be exact",
                "model": "model",
                "runtime": "runtime",
                "permissions": {"network": False},
                "repository": "repo",
                "fixture_manifest_hash": H,
                "operator_public_key": "operator",
            }
        )
        with pytest.raises(ProposalControlError):
            request_fingerprint({**self.request, "extra": True}, "model", "runtime")

    def test_decomposition_stage_replays_only_equal_bytes_and_is_private(self) -> None:
        proposal = self.decomposition()
        request = StageDecompositionRequest(
            private_key=self.private,
            owner_public_key=self.public,
            campaign_id=CAMPAIGN,
            fingerprint=self.fingerprint,
            proposal=proposal,
        )
        first = self.control.stage_decomposition(request)
        second = self.control.stage_decomposition(request)
        assert first == second
        path = self.artifacts.path_for(
            f"control/proposals/sha256/{proposal.hash}/record.json", ArtifactMode.PRIVATE
        )
        assert os.stat(path).st_mode & 511 == 384
        with pytest.raises(ProposalControlError):
            self.control.stage_decomposition(
                replace(request, fingerprint="e" * 64)
            )

    def test_authenticated_inspection_rejects_wrong_key_and_hash_path(self) -> None:
        proposal = self.decomposition()
        self.control.stage_decomposition(
            StageDecompositionRequest(
                private_key=self.private,
                owner_public_key=self.public,
                campaign_id=CAMPAIGN,
                fingerprint=self.fingerprint,
                proposal=proposal,
            )
        )
        request = InspectDecompositionRequest(
            private_key=self.private,
            owner_public_key=self.public,
            campaign_id=CAMPAIGN,
            fingerprint=self.fingerprint,
            proposal_hash=proposal.hash,
        )
        with pytest.raises(ProposalControlError):
            self.control.inspect_decomposition(
                replace(request, private_key=Ed25519PrivateKey.generate())
            )
        with pytest.raises(ProposalControlError):
            self.control.inspect_decomposition(
                replace(request, proposal_hash="../" + proposal.hash)
            )

    def test_design_inspection_rejects_altered_stale_and_cross_linked_records(self) -> None:
        proposal, attestation = self.design()
        parameters = DesignProposalValidationParameters(
            campaign_id=CAMPAIGN,
            claim_hash=H,
            g0_commit_hash="b" * 64,
            treatment_hash="c" * 64,
            fixture_manifest_hash="d" * 64,
        )
        self.control.stage_design(
            StageDesignRequest(
                private_key=self.private,
                owner_public_key=self.public,
                campaign_id=parameters.campaign_id,
                claim_hash=parameters.claim_hash,
                g0_commit_hash=parameters.g0_commit_hash,
                treatment_hash=parameters.treatment_hash,
                fixture_manifest_hash=parameters.fixture_manifest_hash,
                proposal=proposal,
                attestation=attestation,
            )
        )
        request = InspectDesignRequest(
            private_key=self.private,
            owner_public_key=self.public,
            campaign_id=parameters.campaign_id,
            claim_hash=parameters.claim_hash,
            g0_commit_hash=parameters.g0_commit_hash,
            treatment_hash=parameters.treatment_hash,
            fixture_manifest_hash=parameters.fixture_manifest_hash,
            proposal_hash=proposal.hash,
        )
        with pytest.raises(ProposalControlError):
            self.control.inspect_design(replace(request, claim_hash="e" * 64))
        path = self.artifacts.path_for(
            f"control/proposals/sha256/{proposal.hash}/record.json", ArtifactMode.PRIVATE
        )
        raw = json.loads(path.read_bytes())
        raw["attestation"]["payload"]["proposal_hash"] = "e" * 64
        path.unlink()
        path.write_bytes(json.dumps(raw).encode())
        with pytest.raises(ProposalControlError):
            self.control.inspect_design(request)

    def test_signed_decision_is_exact_public_artifact_and_recovers_after_gate_commit(self) -> None:
        parameters = DecisionValidationParameters(
            campaign_id=CAMPAIGN,
            target_kind="campaign",
            target_id=CAMPAIGN,
            action="approve_decomposition",
            proposal_hash=H,
            expected_revision_hash="b" * 64,
            sequence=1,
        )
        wire = DecisionWire.sign(
            private_key=self.private,
            payload=parameters.payload(),
        )
        request = PublishDecisionRequest(
            owner_public_key=self.public,
            wire=wire,
            workflow_id="workflow",
            run_id="run",
            prior_record_hash="c" * 64,
            campaign_id=parameters.campaign_id,
            target_kind=parameters.target_kind,
            target_id=parameters.target_id,
            action=parameters.action,
            proposal_hash=parameters.proposal_hash,
            expected_revision_hash=parameters.expected_revision_hash,
            sequence=parameters.sequence,
        )
        published = self.control.publish_decision(request)
        assert published.decision_sha256 == wire.hash
        assert published.decision_artifact_sha256 == wire.hash
        assert (
            published.decision_artifact_path.read_bytes()
            == json.dumps(wire.as_json(), sort_keys=True, separators=(",", ":")).encode()
        )
        assert self.control.publish_decision(request) == published
        assert self.private.private_bytes_raw() not in published.decision_artifact_path.read_bytes()

    def test_decision_rejects_malformed_wire_and_competing_branch(self) -> None:
        parameters = DecisionValidationParameters(
            campaign_id=CAMPAIGN,
            target_kind="campaign",
            target_id=CAMPAIGN,
            action="approve_decomposition",
            proposal_hash=H,
            expected_revision_hash="b" * 64,
            sequence=1,
        )
        wire = DecisionWire.sign(
            private_key=self.private,
            payload=parameters.payload(),
        )
        request = PublishDecisionRequest(
            owner_public_key=self.public,
            wire=wire.as_json(),
            workflow_id="workflow",
            run_id="run",
            prior_record_hash="c" * 64,
            campaign_id=parameters.campaign_id,
            target_kind=parameters.target_kind,
            target_id=parameters.target_id,
            action=parameters.action,
            proposal_hash=parameters.proposal_hash,
            expected_revision_hash=parameters.expected_revision_hash,
            sequence=parameters.sequence,
        )
        malformed = {"payload": wire.as_json()["payload"], "signature": "not-base64"}
        with pytest.raises(ProposalControlError):
            self.control.publish_decision(replace(request, wire=malformed))
        self.control.publish_decision(request)
        competing_parameters = replace(parameters, expected_revision_hash="d" * 64)
        competing = DecisionWire.sign(
            private_key=self.private,
            payload=competing_parameters.payload(),
        ).as_json()
        with pytest.raises(ProposalControlError):
            self.control.publish_decision(
                replace(
                    request,
                    wire=competing,
                    expected_revision_hash=competing_parameters.expected_revision_hash,
                )
            )


if __name__ == "__main__":
    unittest.main()
