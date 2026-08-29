"""Durable, owner-bound proposal staging and decision publication."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .artifacts import (
    ArtifactConflictError,
    ArtifactError,
    ArtifactMode,
    ArtifactStore,
    canonical_bytes,
)
from .coordination import (
    CoordinationError,
    CoordinationStore,
    DecisionCommitRequest,
    DecisionPublicationRequest,
    DecisionRequest,
    GateDisposition,
)
from .signing import (
    DecisionValidationParameters,
    DecisionWire,
    DecompositionProposal,
    DesignProposal,
    DesignProposalValidationParameters,
    SigningError,
    StageAttestation,
    canonical_hash,
    principal_id,
    validate_decision_wire,
    validate_decomposition_proposal,
    validate_design_proposal,
)


class ProposalControlError(RuntimeError):
    """Raised when a durable proposal-control invariant is violated."""


_REQUEST_FIELDS = frozenset(
    {
        "candidate_instruction",
        "permissions",
        "repository",
        "fixture_manifest_hash",
        "operator_public_key",
    }
)


def request_fingerprint(
    public_input: Mapping[str, Any], model_identity: str, runtime_identity: str
) -> str:
    """Return the exact public campaign-request fingerprint used for proposals."""
    if not isinstance(public_input, Mapping) or set(public_input) != _REQUEST_FIELDS:
        raise ProposalControlError("public request has invalid fields")
    if (
        not isinstance(model_identity, str)
        or not model_identity
        or not isinstance(runtime_identity, str)
        or not runtime_identity
    ):
        raise ProposalControlError("model and runtime identities must be nonempty strings")
    return canonical_hash(
        {
            "schema": "instruct-eval-request-v1",
            "candidate_instruction": public_input["candidate_instruction"],
            "model": model_identity,
            "runtime": runtime_identity,
            "permissions": public_input["permissions"],
            "repository": public_input["repository"],
            "fixture_manifest_hash": public_input["fixture_manifest_hash"],
            "operator_public_key": public_input["operator_public_key"],
        }
    )


def _proposal_path(proposal_hash: str) -> str:
    if (
        not isinstance(proposal_hash, str)
        or len(proposal_hash) != 64
        or any(character not in "0123456789abcdef" for character in proposal_hash)
    ):
        raise ProposalControlError("proposal hash must be a lowercase SHA-256 digest")
    return f"control/proposals/sha256/{proposal_hash}/record.json"


def _decision_path(wire_hash: str) -> str:
    if (
        not isinstance(wire_hash, str)
        or len(wire_hash) != 64
        or any(character not in "0123456789abcdef" for character in wire_hash)
    ):
        raise ProposalControlError("wire hash must be a lowercase SHA-256 digest")
    return f"public/decisions/sha256/{wire_hash}.json"


def _owner_private_key(
    private_key: Ed25519PrivateKey,
    owner_public_key: Ed25519PublicKey | bytes | str,
) -> Ed25519PublicKey:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ProposalControlError("private key must be Ed25519")
    public_key = private_key.public_key()
    if principal_id(public_key) != principal_id(owner_public_key):
        raise ProposalControlError("private key does not match campaign principal")
    return public_key


@dataclass(frozen=True, slots=True)
class StageDecompositionRequest:
    """Parameters for staging an owner-bound decomposition proposal."""

    private_key: Ed25519PrivateKey
    owner_public_key: Ed25519PublicKey | bytes | str
    campaign_id: str
    fingerprint: str
    proposal: DecompositionProposal | Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class StageDesignRequest:
    """Parameters for staging an owner-bound design proposal."""

    private_key: Ed25519PrivateKey
    owner_public_key: Ed25519PublicKey | bytes | str
    campaign_id: str
    claim_hash: str
    g0_commit_hash: str
    treatment_hash: str
    fixture_manifest_hash: str
    proposal: DesignProposal | Mapping[str, Any]
    attestation: StageAttestation | Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class InspectDecompositionRequest:
    """Parameters for inspecting an owner-bound decomposition proposal."""

    private_key: Ed25519PrivateKey
    owner_public_key: Ed25519PublicKey | bytes | str
    campaign_id: str
    fingerprint: str
    proposal_hash: str


@dataclass(frozen=True, slots=True)
class InspectDesignRequest:
    """Parameters for inspecting an owner-bound design proposal."""

    private_key: Ed25519PrivateKey
    owner_public_key: Ed25519PublicKey | bytes | str
    campaign_id: str
    claim_hash: str
    g0_commit_hash: str
    treatment_hash: str
    fixture_manifest_hash: str
    proposal_hash: str
    design_hash: str | None = None


@dataclass(frozen=True, slots=True)
class PublishDecisionRequest:
    """Parameters for durably reserving and publishing a signed decision."""

    owner_public_key: Ed25519PublicKey | bytes | str
    wire: DecisionWire | Mapping[str, Any]
    workflow_id: str
    run_id: str
    prior_record_hash: str
    campaign_id: str
    target_kind: str
    target_id: str
    action: str
    proposal_hash: str | None
    expected_revision_hash: str
    sequence: int


@dataclass(frozen=True, slots=True)
class StagedProposal:
    """Authenticated private proposal material returned without key material."""

    proposal_hash: str
    proposal: DecompositionProposal | DesignProposal
    attestation: StageAttestation | None


@dataclass(frozen=True, slots=True)
class PublishedDecision:
    """Immutable public decision publication bound to the signed wire."""

    decision_sha256: str
    decision_artifact_sha256: str
    decision_artifact_path: Path


class ProposalControl:
    """Stages owner-signed proposals and publishes replay-safe signed decisions."""

    def __init__(self, artifacts: ArtifactStore, coordination: CoordinationStore) -> None:
        if not isinstance(artifacts, ArtifactStore) or not isinstance(
            coordination, CoordinationStore
        ):
            raise ProposalControlError(
                "proposal control requires ArtifactStore and CoordinationStore"
            )
        self._artifacts = artifacts
        self._coordination = coordination

    def stage_decomposition(self, request: StageDecompositionRequest) -> StagedProposal:
        _owner_private_key(request.private_key, request.owner_public_key)
        try:
            parsed = (
                request.proposal
                if isinstance(request.proposal, DecompositionProposal)
                else DecompositionProposal.from_json(request.proposal)
            )
            validate_decomposition_proposal(
                parsed,
                campaign_id=request.campaign_id,
                request_fingerprint=request.fingerprint,
            )
            payload = {
                "schema": "instruct-eval-staged-decomposition-v1",
                "owner_principal": principal_id(request.owner_public_key),
                "proposal": parsed.as_json(),
            }
            self._artifacts.publish_json(
                _proposal_path(parsed.hash),
                payload,
                ArtifactMode.PRIVATE,
            )
        except (ArtifactError, SigningError, TypeError, ValueError) as error:
            raise ProposalControlError("decomposition proposal staging failed") from error
        return StagedProposal(parsed.hash, parsed, None)

    def stage_design(self, request: StageDesignRequest) -> StagedProposal:
        public_key = _owner_private_key(
            request.private_key,
            request.owner_public_key,
        )
        try:
            parsed = (
                request.proposal
                if isinstance(request.proposal, DesignProposal)
                else DesignProposal.from_json(request.proposal)
            )
            signed = (
                request.attestation
                if isinstance(request.attestation, StageAttestation)
                else StageAttestation.from_json(request.attestation)
            )
            validate_design_proposal(
                parsed,
                signed,
                public_key,
                DesignProposalValidationParameters(
                    campaign_id=request.campaign_id,
                    claim_hash=request.claim_hash,
                    g0_commit_hash=request.g0_commit_hash,
                    treatment_hash=request.treatment_hash,
                    fixture_manifest_hash=request.fixture_manifest_hash,
                ),
            )
            payload = {
                "schema": "instruct-eval-staged-design-v1",
                "owner_principal": principal_id(public_key),
                "proposal": parsed.as_json(),
                "attestation": signed.as_json(),
            }
            self._artifacts.publish_json(
                _proposal_path(parsed.hash),
                payload,
                ArtifactMode.PRIVATE,
            )
        except (ArtifactError, SigningError, TypeError, ValueError) as error:
            raise ProposalControlError("design proposal staging failed") from error
        return StagedProposal(parsed.hash, parsed, signed)

    def inspect_decomposition(self, request: InspectDecompositionRequest) -> StagedProposal:
        public_key = _owner_private_key(
            request.private_key,
            request.owner_public_key,
        )
        try:
            record = self._read_record(
                request.proposal_hash,
                "instruct-eval-staged-decomposition-v1",
                public_key,
            )
            parsed = DecompositionProposal.from_json(record["proposal"])
            validate_decomposition_proposal(
                parsed,
                campaign_id=request.campaign_id,
                request_fingerprint=request.fingerprint,
                proposal_hash=request.proposal_hash,
            )
        except (ArtifactError, SigningError, TypeError, ValueError) as error:
            raise ProposalControlError("decomposition proposal inspection failed") from error
        return StagedProposal(request.proposal_hash, parsed, None)

    def inspect_design(self, request: InspectDesignRequest) -> StagedProposal:
        public_key = _owner_private_key(
            request.private_key,
            request.owner_public_key,
        )
        try:
            record = self._read_record(
                request.proposal_hash,
                "instruct-eval-staged-design-v1",
                public_key,
            )
            parsed = DesignProposal.from_json(record["proposal"])
            attestation = StageAttestation.from_json(record["attestation"])
            validate_design_proposal(
                parsed,
                attestation,
                public_key,
                DesignProposalValidationParameters(
                    campaign_id=request.campaign_id,
                    claim_hash=request.claim_hash,
                    g0_commit_hash=request.g0_commit_hash,
                    treatment_hash=request.treatment_hash,
                    fixture_manifest_hash=request.fixture_manifest_hash,
                    proposal_hash=request.proposal_hash,
                    design_hash=request.design_hash,
                ),
            )
        except (ArtifactError, SigningError, TypeError, ValueError) as error:
            raise ProposalControlError("design proposal inspection failed") from error
        return StagedProposal(request.proposal_hash, parsed, attestation)

    def publish_decision(self, request: PublishDecisionRequest) -> PublishedDecision:
        try:
            parsed = (
                request.wire
                if isinstance(request.wire, DecisionWire)
                else DecisionWire.from_json(request.wire)
            )
            validate_decision_wire(
                parsed,
                request.owner_public_key,
                DecisionValidationParameters(
                    campaign_id=request.campaign_id,
                    target_kind=request.target_kind,
                    target_id=request.target_id,
                    action=request.action,
                    proposal_hash=request.proposal_hash,
                    expected_revision_hash=request.expected_revision_hash,
                    sequence=request.sequence,
                ),
            )
            record = parsed.as_json()
            artifact_bytes = canonical_bytes(record)
            artifact_hash = parsed.hash
            path = self._artifacts.path_for(_decision_path(artifact_hash))
            reservation = self._coordination.reserve_decision(
                DecisionRequest(
                    request.workflow_id,
                    request.run_id,
                    request.target_kind,
                    request.target_id,
                    request.sequence,
                    request.prior_record_hash,
                    request.expected_revision_hash,
                    artifact_bytes,
                )
            )
            if reservation.disposition is GateDisposition.PUBLISHED:
                if (
                    reservation.publication_path != path
                    or reservation.publication_sha256 != artifact_hash
                ):
                    raise ProposalControlError("published decision conflicts")
                self._artifacts.read_bytes(_decision_path(artifact_hash))
                return PublishedDecision(artifact_hash, artifact_hash, path)
            epoch = reservation.owner_epoch
            if reservation.disposition is not GateDisposition.COMMITTING:
                committed = self._coordination.begin_decision_commit(
                    DecisionCommitRequest(
                        request.workflow_id,
                        request.run_id,
                        request.target_kind,
                        request.target_id,
                        request.sequence,
                        request.expected_revision_hash,
                        epoch or 0,
                    )
                )
                if committed.disposition is GateDisposition.PUBLISHED:
                    if (
                        committed.publication_path != path
                        or committed.publication_sha256 != artifact_hash
                    ):
                        raise ProposalControlError("published decision conflicts")
                    self._artifacts.read_bytes(_decision_path(artifact_hash))
                    return PublishedDecision(artifact_hash, artifact_hash, path)
                epoch = committed.owner_epoch
            if epoch is None:
                raise ProposalControlError("decision reservation has no owner epoch")
            self._artifacts.publish_bytes(_decision_path(artifact_hash), artifact_bytes)
            published = self._coordination.publish_decision(
                DecisionPublicationRequest(
                    request.workflow_id,
                    request.run_id,
                    request.target_kind,
                    request.target_id,
                    request.sequence,
                    request.expected_revision_hash,
                    epoch,
                    path,
                    artifact_bytes,
                    artifact_hash,
                )
            )
            if published.publication_path != path or published.publication_sha256 != artifact_hash:
                raise ProposalControlError("published decision conflicts")
            return PublishedDecision(artifact_hash, artifact_hash, path)
        except (
            ArtifactError,
            ArtifactConflictError,
            CoordinationError,
            SigningError,
            TypeError,
            ValueError,
        ) as error:
            if isinstance(error, ProposalControlError):
                raise
            raise ProposalControlError("decision publication failed") from error

    def _read_record(
        self,
        proposal_hash: str,
        schema: str,
        owner_public_key: Ed25519PublicKey | bytes | str,
    ) -> Mapping[str, Any]:
        import json

        raw = self._artifacts.read_bytes(
            _proposal_path(proposal_hash),
            ArtifactMode.PRIVATE,
        )
        try:
            record = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProposalControlError("staged proposal record is malformed") from error
        if (
            not isinstance(record, Mapping)
            or record.get("schema") != schema
            or record.get("owner_principal") != principal_id(owner_public_key)
        ):
            raise ProposalControlError("staged proposal record is not owned by campaign principal")
        expected = (
            {"schema", "owner_principal", "proposal"}
            if schema.endswith("decomposition-v1")
            else {"schema", "owner_principal", "proposal", "attestation"}
        )
        if set(record) != expected:
            raise ProposalControlError("staged proposal record has invalid fields")
        return record
