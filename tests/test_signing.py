from __future__ import annotations

import unittest
from hashlib import sha256

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from instruct_eval.signing import (
    DecisionPayload,
    DecisionWire,
    DecompositionProposal,
    DesignProposal,
    DesignProposalValidationParameters,
    SigningError,
    StageAttestation,
    StageAttestationSigningParameters,
    canonical_bytes,
    canonical_hash,
    decode_base64url,
    encode_base64url,
    principal_id,
    public_key_base64url,
    sign,
    validate_design_proposal,
)

H = "a" * 64
CAMPAIGN = "campaign-00000000000000000000000000000001"
NONCE = "00000000000000000000000000000001"


def parse_and_verify_decision_wire(raw: object, public: object) -> None:
    DecisionWire.from_json(raw).verify(public)


def parse_and_verify_stage_attestation(raw: object, public: object) -> None:
    StageAttestation.from_json(raw).verify(public)


class SigningContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        )
        self.public = self.private.public_key()

    def _design(self) -> DesignProposal:
        return DesignProposal(
            NONCE, CAMPAIGN, H, "b" * 64, "c" * 64, "d" * 64, {"fixtures": ["one"], "version": 1}
        )

    def test_strict_unpadded_base64url_and_principal_vector(self) -> None:
        raw = bytes(range(32))
        encoded = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        assert encode_base64url(raw) == encoded
        assert decode_base64url(encoded, length=32) == raw
        assert decode_base64url(public_key_base64url(self.public), length=32) == bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        assert (
            principal_id(self.public)
            == sha256(
                bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            ).hexdigest()
        )
        for malformed in ("", "AA==", "AA=", "AA+_", "A", encoded + "=", encoded[:-1] + "!"):
            with self.subTest(malformed=malformed), pytest.raises(SigningError):
                decode_base64url(malformed)

    def test_exact_canonical_bytes_and_proposal_hashes(self) -> None:
        assert canonical_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
        assert canonical_hash({"b": 2, "a": 1}) == sha256(b'{"a":1,"b":2}').hexdigest()
        decomposition = DecompositionProposal(
            NONCE, CAMPAIGN, H, [{"end_byte": 1, "start_byte": 0}], [{"claim_id": "claim-0001"}]
        )
        assert decomposition.hash == sha256(canonical_bytes(decomposition.as_json())).hexdigest()
        design = self._design()
        assert design.hash == sha256(canonical_bytes(design.as_json())).hexdigest()
        assert design.design_hash == sha256(b'{"fixtures":["one"],"version":1}').hexdigest()
        assert design.hash != design.design_hash

    def test_decision_signature_vector_and_strict_wire_schema(self) -> None:
        payload = DecisionPayload(
            CAMPAIGN, "campaign", CAMPAIGN, "approve_decomposition", H, "b" * 64, 1
        )
        wire = DecisionWire.sign(self.private, payload)
        assert wire.signature == DecisionWire.sign(self.private, payload).signature
        assert wire.as_json()["payload"] == payload.as_json()
        wire.verify(self.public)
        assert DecisionWire.from_json(wire.as_json()) == wire
        for altered in (
            {
                "payload": wire.as_json()["payload"],
                "signature": wire.as_json()["signature"],
                "extra": None,
            },
            {
                "payload": {**wire.as_json()["payload"], "action": "submit_design"},
                "signature": wire.as_json()["signature"],
            },
            {
                "payload": {**wire.as_json()["payload"], "sequence": 0},
                "signature": wire.as_json()["signature"],
            },
        ):
            with self.subTest(altered=altered), pytest.raises(SigningError):
                parse_and_verify_decision_wire(altered, self.public)

    def test_decision_action_target_and_sequence_rules(self) -> None:
        valid_cancel = DecisionPayload(CAMPAIGN, "campaign", CAMPAIGN, "cancel", None, "b" * 64, 7)
        assert valid_cancel.sequence == 7
        invalid_payloads = (
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "claim",
                "target_id": H,
                "action": "approve_decomposition",
                "proposal_hash": H,
                "expected_revision_hash": "b" * 64,
                "sequence": 1,
            },
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "campaign",
                "target_id": CAMPAIGN,
                "action": "approve_decomposition",
                "proposal_hash": H,
                "expected_revision_hash": "b" * 64,
                "sequence": 2,
            },
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "campaign",
                "target_id": CAMPAIGN,
                "action": "submit_design",
                "proposal_hash": H,
                "expected_revision_hash": "b" * 64,
                "sequence": 1,
            },
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "claim",
                "target_id": H,
                "action": "submit_design",
                "proposal_hash": H,
                "expected_revision_hash": "b" * 64,
                "sequence": 2,
            },
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "campaign",
                "target_id": CAMPAIGN,
                "action": "approve_freeze",
                "proposal_hash": None,
                "expected_revision_hash": "b" * 64,
                "sequence": 2,
            },
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "claim",
                "target_id": H,
                "action": "approve_freeze",
                "proposal_hash": None,
                "expected_revision_hash": "b" * 64,
                "sequence": 1,
            },
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "claim",
                "target_id": H,
                "action": "cancel",
                "proposal_hash": None,
                "expected_revision_hash": "b" * 64,
                "sequence": 7,
            },
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "campaign",
                "target_id": CAMPAIGN,
                "action": "cancel",
                "proposal_hash": None,
                "expected_revision_hash": "b" * 64,
                "sequence": 0,
            },
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "campaign",
                "target_id": CAMPAIGN,
                "action": "cancel",
                "proposal_hash": H,
                "expected_revision_hash": "b" * 64,
                "sequence": 7,
            },
            {
                "campaign_id": CAMPAIGN,
                "target_kind": "campaign",
                "target_id": CAMPAIGN,
                "action": "cancel",
                "proposal_hash": None,
                "expected_revision_hash": None,
                "sequence": 7,
            },
        )
        for raw_payload in invalid_payloads:
            with self.subTest(raw_payload=raw_payload), pytest.raises(SigningError):
                DecisionPayload.from_json(raw_payload)
            signed_wire = {
                "payload": raw_payload,
                "signature": encode_base64url(sign(self.private, raw_payload)),
            }
            with self.subTest(signed_wire=signed_wire), pytest.raises(SigningError):
                DecisionWire.from_json(signed_wire)
            bypassed_payload = object.__new__(DecisionPayload)
            for field, value in raw_payload.items():
                object.__setattr__(bypassed_payload, field, value)
            with self.subTest(verification_payload=raw_payload), pytest.raises(SigningError):
                DecisionWire(bypassed_payload, sign(self.private, raw_payload)).verify(self.public)

    def test_proposals_reject_alternate_and_cross_linked_fields(self) -> None:
        design = self._design()
        valid = design.as_json()
        for altered in (
            {**valid, "extra": 1},
            {**valid, "proposal_nonce": "1"},
            {**valid, "campaign_id": "campaign-1"},
            {**valid, "claim_hash": "A" * 64},
            {**valid, "design": []},
        ):
            with self.subTest(altered=altered), pytest.raises(SigningError):
                DesignProposal.from_json(altered)
        with pytest.raises(SigningError):
            DecisionPayload(
                CAMPAIGN, "campaign", CAMPAIGN, "submit_design", design.hash, "b" * 64, 1
            )
        with pytest.raises(SigningError):
            DecisionPayload(CAMPAIGN, "claim", H, "approve_freeze", design.hash, "b" * 64, 2)

    def test_stage_attestation_binds_outer_and_inner_design_fields(self) -> None:
        design = self._design()
        attestation = StageAttestation.sign(
            self.private,
            StageAttestationSigningParameters(
                campaign_id=CAMPAIGN,
                claim_hash=design.claim_hash,
                proposal_nonce=design.proposal_nonce,
                proposal_hash=design.hash,
                g0_commit_hash=design.g0_commit_hash,
                treatment_hash=design.treatment_hash,
                fixture_manifest_hash=design.fixture_manifest_hash,
            ),
        )
        attestation.verify(self.public)
        assert StageAttestation.from_json(attestation.as_json()) == attestation
        validate_design_proposal(
            design,
            attestation,
            self.public,
            DesignProposalValidationParameters(
                campaign_id=CAMPAIGN,
                claim_hash=design.claim_hash,
                g0_commit_hash=design.g0_commit_hash,
                treatment_hash=design.treatment_hash,
                fixture_manifest_hash=design.fixture_manifest_hash,
                proposal_hash=design.hash,
                design_hash=design.design_hash,
            ),
        )
        substitutions = (
            {**attestation.payload(), "proposal_hash": design.design_hash},
            {**attestation.payload(), "claim_hash": "e" * 64},
            {**attestation.payload(), "proposal_nonce": "00000000000000000000000000000002"},
            {**attestation.payload(), "principal_id": "f" * 64},
        )
        for payload in substitutions:
            with self.subTest(payload=payload), pytest.raises(SigningError):
                parse_and_verify_stage_attestation(
                    {"payload": payload, "signature": attestation.as_json()["signature"]},
                    self.public,
                )


if __name__ == "__main__":
    unittest.main()
