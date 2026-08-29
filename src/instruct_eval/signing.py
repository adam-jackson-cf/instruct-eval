"""Strict signed control-plane envelopes for instruct-eval updates."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DOMAIN_SEPARATOR = b"instruct-eval-update-v1\0"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CAMPAIGN_ID = re.compile(r"campaign-[0-9]{32}\Z")
_EXPERIMENT_ID = re.compile(r"experiment-[0-9]{32}\Z")
_NONCE = re.compile(r"[0-9]{32}\Z")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*\Z")


class SigningError(ValueError):
    """Raised when an authority or signed protocol object is malformed."""


def _require_exact_mapping(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SigningError(f"{label} has invalid fields")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise SigningError(f"{label} must be a lowercase SHA-256 hash")
    return value


def _canonical_json(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise SigningError("value is not RFC 8785 canonicalizable") from error


def canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785 bytes, rejecting non-JSON and non-finite values."""
    return _canonical_json(value)


def canonical_hash(value: Any) -> str:
    """Return lowercase SHA-256 of RFC 8785 bytes."""
    return sha256(canonical_bytes(value)).hexdigest()


def encode_base64url(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise SigningError("base64url value must be bytes")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_base64url(value: str, *, length: int | None = None) -> bytes:
    """Decode canonical, unpadded base64url without accepting alternate spellings."""
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or _BASE64URL.fullmatch(value) is None
        or len(value) % 4 == 1
    ):
        raise SigningError("base64url must be unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise SigningError("base64url is malformed") from error
    if encode_base64url(decoded) != value:
        raise SigningError("base64url is not canonical")
    if length is not None and len(decoded) != length:
        raise SigningError(f"base64url must decode to exactly {length} bytes")
    return decoded


def public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    if not isinstance(public_key, Ed25519PublicKey):
        raise SigningError("public key must be Ed25519")
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key_base64url(public_key: Ed25519PublicKey) -> str:
    return encode_base64url(public_key_bytes(public_key))


def load_public_key(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(decode_base64url(value, length=32))


def principal_id(public_key: Ed25519PublicKey | bytes | str) -> str:
    if isinstance(public_key, Ed25519PublicKey):
        raw = public_key_bytes(public_key)
    elif isinstance(public_key, bytes):
        if len(public_key) != 32:
            raise SigningError("public key must be exactly 32 bytes")
        raw = public_key
    elif isinstance(public_key, str):
        raw = decode_base64url(public_key, length=32)
    else:
        raise SigningError("public key must be Ed25519 public-key bytes")
    return sha256(raw).hexdigest()


def signing_bytes(payload: Mapping[str, Any]) -> bytes:
    return DOMAIN_SEPARATOR + canonical_bytes(payload)


def sign(private_key: Ed25519PrivateKey, payload: Mapping[str, Any]) -> bytes:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SigningError("private key must be Ed25519")
    return private_key.sign(signing_bytes(payload))


def verify(
    public_key: Ed25519PublicKey | bytes | str,
    payload: Mapping[str, Any],
    signature: bytes | str,
) -> None:
    if isinstance(public_key, Ed25519PublicKey):
        key = public_key
    elif isinstance(public_key, bytes):
        if len(public_key) != 32:
            raise SigningError("public key must be exactly 32 bytes")
        key = Ed25519PublicKey.from_public_bytes(public_key)
    elif isinstance(public_key, str):
        key = load_public_key(public_key)
    else:
        raise SigningError("public key must be Ed25519 public-key bytes")
    raw_signature = (
        decode_base64url(signature, length=64) if isinstance(signature, str) else signature
    )
    if not isinstance(raw_signature, bytes) or len(raw_signature) != 64:
        raise SigningError("signature must be exactly 64 bytes")
    try:
        key.verify(raw_signature, signing_bytes(payload))
    except InvalidSignature as error:
        raise SigningError("signature does not verify") from error


def _validate_decision_campaign_id(campaign_id: str) -> None:
    if not isinstance(campaign_id, str) or _CAMPAIGN_ID.fullmatch(campaign_id) is None:
        raise SigningError("campaign_id is invalid")


def _validate_decision_target(target_kind: str, target_id: str) -> None:
    if target_kind not in {"campaign", "claim"}:
        raise SigningError("target_kind is invalid")
    expected_target = _CAMPAIGN_ID if target_kind == "campaign" else _HASH
    if not isinstance(target_id, str) or expected_target.fullmatch(target_id) is None:
        raise SigningError("target_id is invalid for target_kind")


def _validate_approve_decomposition(target_kind: str, sequence: int) -> None:
    if target_kind != "campaign":
        raise SigningError("approve_decomposition must target campaign")
    if sequence != 1:
        raise SigningError("approve_decomposition must use sequence 1")


def _validate_submit_design(target_kind: str, sequence: int) -> None:
    if target_kind != "claim":
        raise SigningError("submit_design must target claim")
    if sequence != 1:
        raise SigningError("submit_design must use sequence 1")


def _validate_approve_freeze(target_kind: str, sequence: int) -> None:
    if target_kind != "claim":
        raise SigningError("approve_freeze must target claim")
    if sequence != 2:
        raise SigningError("approve_freeze must use sequence 2")


def _validate_cancel(target_kind: str, _: int) -> None:
    if target_kind != "campaign":
        raise SigningError("cancel must target campaign")


def _validate_decision_action(action: str, target_kind: str, sequence: int) -> None:
    validators = {
        "approve_decomposition": _validate_approve_decomposition,
        "submit_design": _validate_submit_design,
        "approve_freeze": _validate_approve_freeze,
        "cancel": _validate_cancel,
    }
    if action not in validators:
        raise SigningError("action is invalid")
    validators[action](target_kind, sequence)


def _validate_decision_proposal(action: str, proposal_hash: str | None) -> None:
    if proposal_hash is not None:
        _hash(proposal_hash, "proposal_hash")
    if (action in {"approve_decomposition", "submit_design"}) != (proposal_hash is not None):
        raise SigningError("action has invalid proposal_hash")


def _validate_decision_sequence(sequence: int) -> None:
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise SigningError("sequence must be a positive integer")


@dataclass(frozen=True, slots=True)
class DecisionPayload:
    campaign_id: str
    target_kind: str
    target_id: str
    action: str
    proposal_hash: str | None
    expected_revision_hash: str
    sequence: int

    def __post_init__(self) -> None:
        _validate_decision_campaign_id(self.campaign_id)
        _validate_decision_target(self.target_kind, self.target_id)
        _validate_decision_action(self.action, self.target_kind, self.sequence)
        _validate_decision_proposal(self.action, self.proposal_hash)
        _hash(self.expected_revision_hash, "expected_revision_hash")
        _validate_decision_sequence(self.sequence)

    def as_json(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "action": self.action,
            "proposal_hash": self.proposal_hash,
            "expected_revision_hash": self.expected_revision_hash,
            "sequence": self.sequence,
        }

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> DecisionPayload:
        source = _require_exact_mapping(
            value,
            frozenset(
                {
                    "campaign_id",
                    "target_kind",
                    "target_id",
                    "action",
                    "proposal_hash",
                    "expected_revision_hash",
                    "sequence",
                }
            ),
            "decision payload",
        )
        return cls(**dict(source))


@dataclass(frozen=True, slots=True)
class DecisionWire:
    payload: DecisionPayload
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.payload, DecisionPayload):
            raise SigningError("wire payload must be DecisionPayload")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise SigningError("signature must be exactly 64 bytes")

    def as_json(self) -> dict[str, Any]:
        return {"payload": self.payload.as_json(), "signature": encode_base64url(self.signature)}

    @property
    def hash(self) -> str:
        return canonical_hash(self.as_json())

    @classmethod
    def sign(cls, private_key: Ed25519PrivateKey, payload: DecisionPayload) -> DecisionWire:
        return cls(payload, sign(private_key, payload.as_json()))

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> DecisionWire:
        source = _require_exact_mapping(
            value,
            frozenset({"payload", "signature"}),
            "decision wire",
        )
        return cls(
            DecisionPayload.from_json(source["payload"]),
            decode_base64url(source["signature"], length=64),
        )

    def verify(self, public_key: Ed25519PublicKey | bytes | str) -> None:
        DecisionPayload.from_json(self.payload.as_json())
        verify(public_key, self.payload.as_json(), self.signature)


@dataclass(frozen=True, slots=True)
class DecompositionProposal:
    proposal_nonce: str
    campaign_id: str
    request_fingerprint: str
    source_coverage: Any
    ordered_claims: Any
    schema: str = "instruct-eval-decomposition-v1"

    def __post_init__(self) -> None:
        if (
            self.schema != "instruct-eval-decomposition-v1"
            or not isinstance(self.proposal_nonce, str)
            or _NONCE.fullmatch(self.proposal_nonce) is None
        ):
            raise SigningError("decomposition proposal nonce or schema is invalid")
        if (
            not isinstance(self.campaign_id, str)
            or _CAMPAIGN_ID.fullmatch(self.campaign_id) is None
        ):
            raise SigningError("campaign_id is invalid")
        _hash(self.request_fingerprint, "request_fingerprint")
        if (
            not isinstance(self.source_coverage, list)
            or not self.source_coverage
            or not isinstance(self.ordered_claims, list)
            or not self.ordered_claims
        ):
            raise SigningError(
                "decomposition proposal requires nonempty source_coverage and ordered_claims"
            )
        canonical_bytes(self.as_json())

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "proposal_nonce": self.proposal_nonce,
            "campaign_id": self.campaign_id,
            "request_fingerprint": self.request_fingerprint,
            "source_coverage": self.source_coverage,
            "ordered_claims": self.ordered_claims,
        }

    @property
    def hash(self) -> str:
        return canonical_hash(self.as_json())

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> DecompositionProposal:
        source = _require_exact_mapping(
            value,
            frozenset(
                {
                    "schema",
                    "proposal_nonce",
                    "campaign_id",
                    "request_fingerprint",
                    "source_coverage",
                    "ordered_claims",
                }
            ),
            "decomposition proposal",
        )
        return cls(**dict(source))


@dataclass(frozen=True, slots=True)
class DesignProposal:
    proposal_nonce: str
    campaign_id: str
    claim_hash: str
    g0_commit_hash: str
    treatment_hash: str
    fixture_manifest_hash: str
    design: Any
    schema: str = "instruct-eval-design-v1"

    def __post_init__(self) -> None:
        if (
            self.schema != "instruct-eval-design-v1"
            or not isinstance(self.proposal_nonce, str)
            or _NONCE.fullmatch(self.proposal_nonce) is None
        ):
            raise SigningError("design proposal nonce or schema is invalid")
        if (
            not isinstance(self.campaign_id, str)
            or _CAMPAIGN_ID.fullmatch(self.campaign_id) is None
        ):
            raise SigningError("campaign_id is invalid")
        for value, label in (
            (self.claim_hash, "claim_hash"),
            (self.g0_commit_hash, "g0_commit_hash"),
            (self.treatment_hash, "treatment_hash"),
            (self.fixture_manifest_hash, "fixture_manifest_hash"),
        ):
            _hash(value, label)
        if not isinstance(self.design, Mapping):
            raise SigningError("design must be a mapping")
        canonical_bytes(self.as_json())

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "proposal_nonce": self.proposal_nonce,
            "campaign_id": self.campaign_id,
            "claim_hash": self.claim_hash,
            "g0_commit_hash": self.g0_commit_hash,
            "treatment_hash": self.treatment_hash,
            "fixture_manifest_hash": self.fixture_manifest_hash,
            "design": self.design,
        }

    @property
    def hash(self) -> str:
        return canonical_hash(self.as_json())

    @property
    def design_hash(self) -> str:
        return canonical_hash(self.design)

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> DesignProposal:
        source = _require_exact_mapping(
            value,
            frozenset(
                {
                    "schema",
                    "proposal_nonce",
                    "campaign_id",
                    "claim_hash",
                    "g0_commit_hash",
                    "treatment_hash",
                    "fixture_manifest_hash",
                    "design",
                }
            ),
            "design proposal",
        )
        return cls(**dict(source))


@dataclass(frozen=True, slots=True)
class StageAttestationSigningParameters:
    campaign_id: str
    claim_hash: str
    proposal_nonce: str
    proposal_hash: str
    g0_commit_hash: str
    treatment_hash: str
    fixture_manifest_hash: str

    def fields(self, principal: str) -> dict[str, str]:
        return {
            "campaign_id": self.campaign_id,
            "claim_hash": self.claim_hash,
            "proposal_nonce": self.proposal_nonce,
            "proposal_hash": self.proposal_hash,
            "g0_commit_hash": self.g0_commit_hash,
            "treatment_hash": self.treatment_hash,
            "fixture_manifest_hash": self.fixture_manifest_hash,
            "principal_id": principal,
        }


@dataclass(frozen=True, slots=True)
class StageAttestation:
    campaign_id: str
    claim_hash: str
    proposal_nonce: str
    proposal_hash: str
    g0_commit_hash: str
    treatment_hash: str
    fixture_manifest_hash: str
    principal_id: str
    signature: bytes
    schema: str = "instruct-eval-stage-attestation-v1"

    def __post_init__(self) -> None:
        if (
            self.schema != "instruct-eval-stage-attestation-v1"
            or not isinstance(self.campaign_id, str)
            or _CAMPAIGN_ID.fullmatch(self.campaign_id) is None
            or not isinstance(self.proposal_nonce, str)
            or _NONCE.fullmatch(self.proposal_nonce) is None
        ):
            raise SigningError("stage attestation schema, campaign_id, or nonce is invalid")
        for value, label in (
            (self.claim_hash, "claim_hash"),
            (self.proposal_hash, "proposal_hash"),
            (self.g0_commit_hash, "g0_commit_hash"),
            (self.treatment_hash, "treatment_hash"),
            (self.fixture_manifest_hash, "fixture_manifest_hash"),
            (self.principal_id, "principal_id"),
        ):
            _hash(value, label)
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise SigningError("signature must be exactly 64 bytes")

    def payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "campaign_id": self.campaign_id,
            "claim_hash": self.claim_hash,
            "proposal_nonce": self.proposal_nonce,
            "proposal_hash": self.proposal_hash,
            "g0_commit_hash": self.g0_commit_hash,
            "treatment_hash": self.treatment_hash,
            "fixture_manifest_hash": self.fixture_manifest_hash,
            "principal_id": self.principal_id,
        }

    def as_json(self) -> dict[str, Any]:
        return {"payload": self.payload(), "signature": encode_base64url(self.signature)}

    @property
    def hash(self) -> str:
        return canonical_hash(self.as_json())

    @classmethod
    def sign(
        cls,
        private_key: Ed25519PrivateKey,
        parameters: StageAttestationSigningParameters,
    ) -> StageAttestation:
        public = private_key.public_key()
        fields = parameters.fields(principal_id(public))
        unsigned = cls(**fields, signature=b"x" * 64)
        return cls(**fields, signature=sign(private_key, unsigned.payload()))

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> StageAttestation:
        source = _require_exact_mapping(
            value,
            frozenset({"payload", "signature"}),
            "stage attestation",
        )
        payload = _require_exact_mapping(
            source["payload"],
            frozenset(
                {
                    "schema",
                    "campaign_id",
                    "claim_hash",
                    "proposal_nonce",
                    "proposal_hash",
                    "g0_commit_hash",
                    "treatment_hash",
                    "fixture_manifest_hash",
                    "principal_id",
                }
            ),
            "stage attestation payload",
        )
        return cls(**dict(payload), signature=decode_base64url(source["signature"], length=64))

    def verify(self, public_key: Ed25519PublicKey | bytes | str) -> None:
        if principal_id(public_key) != self.principal_id:
            raise SigningError("stage attestation principal does not match public key")
        verify(public_key, self.payload(), self.signature)


@dataclass(frozen=True, slots=True)
class DecisionValidationParameters:
    campaign_id: str
    target_kind: str
    target_id: str
    action: str
    proposal_hash: str | None
    expected_revision_hash: str
    sequence: int

    def payload(self) -> DecisionPayload:
        return DecisionPayload(
            self.campaign_id,
            self.target_kind,
            self.target_id,
            self.action,
            self.proposal_hash,
            self.expected_revision_hash,
            self.sequence,
        )


@dataclass(frozen=True, slots=True)
class DesignProposalValidationParameters:
    campaign_id: str
    claim_hash: str
    g0_commit_hash: str
    treatment_hash: str
    fixture_manifest_hash: str
    proposal_hash: str | None = None
    design_hash: str | None = None


def validate_decision_wire(
    wire: DecisionWire,
    public_key: Ed25519PublicKey | bytes | str,
    parameters: DecisionValidationParameters,
) -> None:
    """Verify a signed decision and every state-derived linkage before use."""
    if not isinstance(wire, DecisionWire):
        raise SigningError("decision wire is invalid")
    wire.verify(public_key)
    if wire.payload != parameters.payload():
        raise SigningError("decision wire does not match the current target state")


def validate_decomposition_proposal(
    proposal: DecompositionProposal,
    *,
    campaign_id: str,
    request_fingerprint: str,
    proposal_hash: str | None = None,
) -> None:
    """Reject a proposal whose hash or campaign inputs are stale or cross-linked."""
    if not isinstance(proposal, DecompositionProposal):
        raise SigningError("decomposition proposal is invalid")
    if proposal.campaign_id != campaign_id or proposal.request_fingerprint != request_fingerprint:
        raise SigningError("decomposition proposal is cross-linked")
    if proposal_hash is not None and proposal.hash != _hash(proposal_hash, "proposal_hash"):
        raise SigningError("decomposition proposal hash does not match")


def _validate_design_proposal_linkage(
    proposal: DesignProposal,
    parameters: DesignProposalValidationParameters,
) -> None:
    for actual, expected, label in (
        (proposal.campaign_id, parameters.campaign_id, "campaign_id"),
        (proposal.claim_hash, parameters.claim_hash, "claim_hash"),
        (proposal.g0_commit_hash, parameters.g0_commit_hash, "g0_commit_hash"),
        (proposal.treatment_hash, parameters.treatment_hash, "treatment_hash"),
        (
            proposal.fixture_manifest_hash,
            parameters.fixture_manifest_hash,
            "fixture_manifest_hash",
        ),
    ):
        if actual != expected:
            raise SigningError(f"design proposal {label} is cross-linked")


def _validate_design_proposal_hashes(
    proposal: DesignProposal,
    parameters: DesignProposalValidationParameters,
) -> None:
    if parameters.proposal_hash is not None and proposal.hash != _hash(
        parameters.proposal_hash, "proposal_hash"
    ):
        raise SigningError("design proposal outer hash does not match")
    if parameters.design_hash is not None and proposal.design_hash != _hash(
        parameters.design_hash, "design_hash"
    ):
        raise SigningError("design proposal inner hash does not match")


def _validate_stage_attestation_linkage(
    proposal: DesignProposal,
    attestation: StageAttestation,
) -> None:
    if (
        attestation.campaign_id != proposal.campaign_id
        or attestation.claim_hash != proposal.claim_hash
        or attestation.proposal_nonce != proposal.proposal_nonce
        or attestation.proposal_hash != proposal.hash
        or attestation.g0_commit_hash != proposal.g0_commit_hash
        or attestation.treatment_hash != proposal.treatment_hash
        or attestation.fixture_manifest_hash != proposal.fixture_manifest_hash
    ):
        raise SigningError("stage attestation is cross-linked")


def validate_design_proposal(
    proposal: DesignProposal,
    attestation: StageAttestation,
    public_key: Ed25519PublicKey | bytes | str,
    parameters: DesignProposalValidationParameters,
) -> None:
    """Verify outer/inner hashes and every signed staging-attestation binding."""
    if not isinstance(proposal, DesignProposal) or not isinstance(attestation, StageAttestation):
        raise SigningError("design proposal or stage attestation is invalid")
    _validate_design_proposal_linkage(proposal, parameters)
    _validate_design_proposal_hashes(proposal, parameters)
    attestation.verify(public_key)
    _validate_stage_attestation_linkage(proposal, attestation)
