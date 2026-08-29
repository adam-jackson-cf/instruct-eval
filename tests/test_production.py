from __future__ import annotations

import json
import sys
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from instruct_eval.activities import ActivityRequest, GatePublication, GateRequest
from instruct_eval.artifacts import ArtifactError, ArtifactMode, ArtifactStore
from instruct_eval.coordination import (
    ChildAuthorizationClaimRequest,
    ChildAuthorizationRequest,
    CoordinationStore,
)
from instruct_eval.messages import (
    ProposalControl,
    PublishDecisionRequest,
    StageDecompositionRequest,
    StageDesignRequest,
    request_fingerprint,
)
from instruct_eval.models import (
    Direction,
    EvidenceAxis,
    ExperimentDesign,
    Fixture,
    ProtocolError,
    ReachabilityWitness,
    SourceClassification,
    SourceCoverage,
    Verifier,
    canonical_bytes,
    canonical_hash,
    derive_treatment,
)
from instruct_eval.production import (
    ArtifactPrivateAuthority,
    DurableAuthoritySlots,
    ProductionConfig,
    ProductionConfigurationError,
    PublicProductionConfig,
    RuntimeSubjectExecutor,
    build_public_production_backend,
    concrete_domain_operations,
)
from instruct_eval.role_runtime import run_witness
from instruct_eval.signing import (
    DecisionValidationParameters,
    DecisionWire,
    DecompositionProposal,
    DesignProposal,
    StageAttestation,
    StageAttestationSigningParameters,
    public_key_base64url,
)
from instruct_eval.trials import PrivateAssignment, authorization_rule


@dataclass(frozen=True)
class _ApprovedClaim:
    campaign: str
    child: str
    child_run: str
    experiment_id: str
    candidate: str
    claim_hash: str
    treatment_hash: str
    key: Ed25519PrivateKey
    public_key: str
    classification: SourceClassification


class ProductionOperationsTest(unittest.TestCase):
    def request(self, payload: Mapping[str, object]) -> ActivityRequest:
        from instruct_eval.models import canonical_bytes

        return ActivityRequest(
            "campaign",
            "experiment",
            "role",
            sha256(canonical_bytes(payload)).hexdigest(),
            "model",
            "runtime",
            payload,
        )

    @staticmethod
    def runtime(result: Mapping[str, object]) -> SimpleNamespace:
        return SimpleNamespace(invoke_role=lambda contract, payload, role_request: result)

    @staticmethod
    def complete_package(classification: SourceClassification) -> tuple[dict[str, object], str]:
        verifier, observer = b"verify\n", b"observe\n"
        unchanged = (
            ("verify.py", sha256(verifier).hexdigest()),
            ("observe.py", sha256(observer).hexdigest()),
        )
        fixtures = []
        for fixture_id in ("core-1", "core-2", "negative-control"):
            manifest = {
                "schema": "instruct-eval-fixture-manifest-v1",
                "files": [
                    {"path": "observe.py", "sha256": sha256(observer).hexdigest()},
                    {"path": "out.txt", "sha256": "a" * 64},
                    {"path": "verify.py", "sha256": sha256(verifier).hexdigest()},
                ],
            }
            witnesses = tuple(
                ReachabilityWitness(
                    f"{fixture_id}-{direction}",
                    direction,
                    canonical_bytes(
                        {
                            "schema": "instruct-eval-witness-input-v1",
                            "changes": [{"path": "out.txt", "content": result}],
                        }
                    ),
                    passed,
                    (("result", result),),
                    "b" * 64,
                    (("python", "c" * 64),),
                    unchanged,
                    ("out.txt",),
                )
                for direction, result, passed in (("good", "yes", True), ("bad", "no", False))
            )
            fixtures.append(
                Fixture(
                    fixture_id,
                    "scenario",
                    manifest,
                    canonical_hash(manifest),
                    Verifier(verifier, sha256(verifier).hexdigest()),
                    observer,
                    sha256(observer).hexdigest(),
                    {w.witness_id: w.expected_verifier_passed for w in witnesses},
                    (EvidenceAxis("result", ("yes", "no")),),
                    (Direction("good", "good"), Direction("bad", "bad")),
                    {
                        (False, "yes"): "good",
                        (True, "yes"): "good",
                        (False, "no"): "bad",
                        (True, "no"): "bad",
                    },
                    ("out.txt",),
                    witnesses,
                    {
                        "schema": "instruct-eval-evidence-contract-v1",
                        "verifier_path": "verify.py",
                        "observer_path": "observe.py",
                        "verifier_command": ["python", "verify.py"],
                        "observer_command": ["python", "observe.py"],
                    },
                    classification,
                )
            )
        design = ExperimentDesign(tuple(fixtures))
        package = json.loads(
            canonical_bytes(
                {
                    "experiment_design": design.payload(),
                    "preferred_directions": {
                        "core-1": "good",
                        "core-2": "good",
                        "negative-control": "bad",
                    },
                }
            )
        )
        return package, canonical_hash(
            {
                "fixtures": [
                    {"fixture_id": fixture.fixture_id, "manifest_sha256": fixture.manifest_sha256}
                    for fixture in fixtures
                ]
            }
        )

    @staticmethod
    def _prepare_approved_claim(
        artifacts: ArtifactStore,
        coordination: CoordinationStore,
    ) -> _ApprovedClaim:
        campaign, parent_run, child, child_run = (
            "campaign-" + "1" * 32,
            "campaign-run",
            "child",
            "child-run",
        )
        candidate = "Follow the signed instruction."
        coverage = (SourceCoverage(0, len(candidate.encode()), "claim_normative", "claim-0001"),)
        coverage_payload = [item.as_json() for item in coverage]
        coverage_sha256 = canonical_hash({"source_coverage": coverage_payload})
        treatment = derive_treatment(candidate, "claim-0001", coverage)
        claim = {
            "schema": "instruct-eval-claim-v1",
            "claim_id": "claim-0001",
            "triggering_event": "instruction",
            "preferred_behavior": "follow",
            "competing_behaviors": ["ignore"],
            "observable_evidence": ["output"],
            "treatment_hash": treatment.hash,
            "coverage_sha256": coverage_sha256,
        }
        key = Ed25519PrivateKey.generate()
        public_key = public_key_base64url(key.public_key())
        decomposition = DecompositionProposal(
            "1" * 32, campaign, "b" * 64, coverage_payload, [claim]
        )
        control = ProposalControl(artifacts, coordination)
        control.stage_decomposition(
            StageDecompositionRequest(
                private_key=key,
                owner_public_key=public_key,
                campaign_id=campaign,
                fingerprint="b" * 64,
                proposal=decomposition,
            )
        )
        campaign_wire = DecisionWire.sign(
            key,
            DecisionValidationParameters(
                campaign_id=campaign,
                target_kind="campaign",
                target_id=campaign,
                action="approve_decomposition",
                proposal_hash=decomposition.hash,
                expected_revision_hash="0" * 64,
                sequence=1,
            ).payload(),
        )
        control.publish_decision(
            PublishDecisionRequest(
                owner_public_key=public_key,
                wire=campaign_wire,
                workflow_id=campaign,
                run_id=parent_run,
                prior_record_hash="0" * 64,
                campaign_id=campaign,
                target_kind="campaign",
                target_id=campaign,
                action="approve_decomposition",
                proposal_hash=decomposition.hash,
                expected_revision_hash="0" * 64,
                sequence=1,
            )
        )
        claim_hash = canonical_hash(claim)
        issued = coordination.issue_child_authorization(
            ChildAuthorizationRequest(
                campaign,
                campaign,
                parent_run,
                claim_hash,
                "b" * 64,
                coverage_sha256,
            )
        )
        coordination.claim_child_authorization(
            ChildAuthorizationClaimRequest(
                campaign,
                campaign,
                parent_run,
                claim_hash,
                "b" * 64,
                coverage_sha256,
                str(issued.experiment_id),
                child,
                child_run,
            )
        )
        classification = SourceClassification(sha256(candidate.encode()).hexdigest(), coverage)
        return _ApprovedClaim(
            campaign,
            child,
            child_run,
            str(issued.experiment_id),
            candidate,
            claim_hash,
            treatment.hash,
            key,
            public_key,
            classification,
        )

    @patch("instruct_eval.production.activity.info")
    def test_canonical_production_gates_bind_the_complete_signed_design_package(
        self,
        activity_info: MagicMock,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            artifacts = ArtifactStore(Path(root) / "public", Path(root) / "private")
            coordination = CoordinationStore(Path(root) / "coord.sqlite")
            context = self._prepare_approved_claim(artifacts, coordination)
            activity_info.return_value = SimpleNamespace(
                workflow_id=context.child,
                workflow_run_id=context.child_run,
            )
            fixture_roots: dict[str, Path] = {}
            fixtures = []
            for fixture_id in ("core-1", "core-2", "negative-control"):
                fixture_root = Path(root) / fixture_id
                fixture_root.mkdir()
                verifier = (
                    b"import pathlib, sys\n"
                    b'sys.exit(0 if pathlib.Path("out.txt").read_text() == "yes" else 1)\n'
                )
                observer = (
                    b"import json, pathlib\n"
                    b'print(json.dumps({"result": pathlib.Path("out.txt").read_text()}))\n'
                )
                files = {
                    "TASK.txt": b"scenario",
                    "verify.py": verifier,
                    "observe.py": observer,
                    "out.txt": b"base",
                }
                for path, content in files.items():
                    (fixture_root / path).write_bytes(content)
                manifest = {
                    "schema": "instruct-eval-fixture-manifest-v1",
                    "files": [
                        {"path": path, "sha256": sha256(content).hexdigest()}
                        for path, content in sorted(files.items())
                    ],
                }
                witnesses = tuple(
                    ReachabilityWitness(
                        f"{fixture_id}-{direction}",
                        direction,
                        canonical_bytes(
                            {
                                "schema": "instruct-eval-witness-input-v1",
                                "changes": [{"path": "out.txt", "content": result}],
                            }
                        ),
                        verifier_passed,
                        (("result", result),),
                        "0" * 64,
                        (("python", "0" * 64),),
                        (
                            ("verify.py", sha256(verifier).hexdigest()),
                            ("observe.py", sha256(observer).hexdigest()),
                        ),
                        ("out.txt",),
                    )
                    for direction, result, verifier_passed in (
                        ("good", "yes", True),
                        ("bad", "no", False),
                    )
                )
                provisional = Fixture(
                    fixture_id,
                    "scenario",
                    manifest,
                    canonical_hash(manifest),
                    Verifier(verifier, sha256(verifier).hexdigest()),
                    observer,
                    sha256(observer).hexdigest(),
                    {w.witness_id: w.expected_verifier_passed for w in witnesses},
                    (EvidenceAxis("result", ("yes", "no")),),
                    (Direction("good", "good"), Direction("bad", "bad")),
                    {
                        (False, "yes"): "good",
                        (True, "yes"): "good",
                        (False, "no"): "bad",
                        (True, "no"): "bad",
                    },
                    ("out.txt",),
                    witnesses,
                    {
                        "schema": "instruct-eval-evidence-contract-v1",
                        "verifier_path": "verify.py",
                        "observer_path": "observe.py",
                        "verifier_command": [sys.executable, "verify.py"],
                        "observer_command": [sys.executable, "observe.py"],
                    },
                    context.classification,
                )
                fixtures.append(
                    replace(
                        provisional,
                        witnesses=tuple(
                            replace(
                                witness,
                                expected_evidence_sha256=(
                                    result := run_witness(provisional, witness, fixture_root)
                                ).evidence_sha256,
                                expected_tool_hashes=tuple(result.tool_hashes.items()),
                            )
                            for witness in witnesses
                        ),
                    )
                )
                fixture_roots[fixture_id] = fixture_root
            design = ExperimentDesign(tuple(fixtures))
            operations = concrete_domain_operations({"role": "request"}, fixture_roots)

            def gate(payload: Mapping[str, object]) -> GateRequest:
                return GateRequest(
                    context.campaign,
                    context.experiment_id,
                    "role",
                    sha256(canonical_bytes(payload)).hexdigest(),
                    "model",
                    "runtime",
                    payload,
                    context.child,
                    context.child_run,
                    0,
                    "0" * 64,
                    "0" * 64,
                    "child",
                )

            g0_payload = {"gate": "G0", "eligibility": {"accepted": True}, "accepted": True}
            g0 = cast(
                GatePublication,
                operations.g0_commit(gate(g0_payload), artifacts, coordination, object()),
            )
            package = json.loads(
                canonical_bytes(
                    {
                        "experiment_design": design.payload(),
                        "preferred_directions": {
                            "core-1": "good",
                            "core-2": "good",
                            "negative-control": "bad",
                        },
                    }
                )
            )
            manifest_hash = canonical_hash(
                {
                    "fixtures": [
                        {
                            "fixture_id": fixture.fixture_id,
                            "manifest_sha256": fixture.manifest_sha256,
                        }
                        for fixture in sorted(design.fixtures, key=lambda item: item.fixture_id)
                    ]
                }
            )
            proposal = DesignProposal(
                "2" * 32,
                context.campaign,
                context.claim_hash,
                g0.artifact_sha256,
                context.treatment_hash,
                manifest_hash,
                package,
            )
            attestation = StageAttestation.sign(
                context.key,
                StageAttestationSigningParameters(
                    campaign_id=context.campaign,
                    claim_hash=context.claim_hash,
                    proposal_nonce=proposal.proposal_nonce,
                    proposal_hash=proposal.hash,
                    g0_commit_hash=proposal.g0_commit_hash,
                    treatment_hash=proposal.treatment_hash,
                    fixture_manifest_hash=proposal.fixture_manifest_hash,
                ),
            )
            control = ProposalControl(artifacts, coordination)
            control.stage_design(
                StageDesignRequest(
                    private_key=context.key,
                    owner_public_key=context.public_key,
                    campaign_id=context.campaign,
                    claim_hash=context.claim_hash,
                    g0_commit_hash=proposal.g0_commit_hash,
                    treatment_hash=proposal.treatment_hash,
                    fixture_manifest_hash=proposal.fixture_manifest_hash,
                    proposal=proposal,
                    attestation=attestation,
                )
            )
            wire = DecisionWire.sign(
                context.key,
                DecisionValidationParameters(
                    campaign_id=context.campaign,
                    target_kind="claim",
                    target_id=context.claim_hash,
                    action="submit_design",
                    proposal_hash=proposal.hash,
                    expected_revision_hash=g0.artifact_sha256,
                    sequence=1,
                ).payload(),
            )
            control.publish_decision(
                PublishDecisionRequest(
                    owner_public_key=context.public_key,
                    wire=wire,
                    workflow_id=context.child,
                    run_id=context.child_run,
                    prior_record_hash="0" * 64,
                    campaign_id=context.campaign,
                    target_kind="claim",
                    target_id=context.claim_hash,
                    action="submit_design",
                    proposal_hash=proposal.hash,
                    expected_revision_hash=g0.artifact_sha256,
                    sequence=1,
                )
            )
            public_input = {
                "candidate_instruction": context.candidate,
                "fixture_manifest_hash": manifest_hash,
                "operator_public_key": context.public_key,
            }
            base = {
                "input": public_input,
                "design_sha256": proposal.design_hash,
                "proposal_sha256": proposal.hash,
                "g0_record_sha256": g0.artifact_sha256,
            }
            g1 = cast(
                GatePublication,
                operations.design_commit(
                    gate({**base, "gate": "G1", "staged_design_sha256": proposal.design_hash}),
                    artifacts,
                    coordination,
                    object(),
                ),
            )
            assert g1.payload["experiment_design_sha256"] == design.hash
            packets: list[Mapping[str, object]] = []
            runtime = SimpleNamespace(
                run_witness=run_witness,
                invoke_role=lambda _contract, packet, _role_request: (
                    packets.append(packet)
                    or {
                        "adversary_decision": {
                            "accepted": True,
                            "packet_sha256": packet["packet_sha256"],
                        },
                        "rejections": [],
                        "stress_review": None,
                    }
                ),
            )
            g2 = cast(
                GatePublication,
                operations.pre_run_validity(
                    gate({**base, "gate": "G2"}), artifacts, coordination, runtime
                ),
            )
            assert g2.payload["accepted"]
            assert g2.payload["adversary_decision"]["packet_sha256"] == canonical_hash(
                {key: value for key, value in packets[0].items() if key != "packet_sha256"}
            )
            freeze = cast(
                GatePublication,
                operations.freeze(
                    gate(
                        {
                            **base,
                            "commit": "freeze",
                            "map_ref": "opaque-map",
                            "map_commitment": "opaque-commitment",
                            "tokens": [f"token-{index}" for index in range(10)],
                            "pre_map_input_hash": "c" * 64,
                            "authorization_rule_sha256": "d" * 64,
                            "authorization_sha256": "e" * 64,
                        }
                    ),
                    artifacts,
                    coordination,
                    object(),
                ),
            )
            assert freeze.payload["accepted"]
            with pytest.raises(ProtocolError):
                operations.design_commit(
                    gate({**base, "gate": "G1", "staged_design_sha256": "f" * 64}),
                    artifacts,
                    coordination,
                    object(),
                )
            with pytest.raises(ProtocolError):
                operations.pre_run_validity(
                    gate(
                        {
                            "input": public_input,
                            "gate": "G2",
                            "design_sha256": proposal.design_hash,
                            "g0_record_sha256": g0.artifact_sha256,
                        }
                    ),
                    artifacts,
                    coordination,
                    runtime,
                )

    def test_scorer_uses_exact_blind_scores_schema(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            operations = concrete_domain_operations({"role": "request"})
            artifacts = ArtifactStore(Path(root) / "public", Path(root) / "private")
            scores = [{"blind_id": f"blind-{index}", "direction": "better"} for index in range(10)]
            result = cast(
                Mapping[str, object],
                operations.evidence_audit(
                    self.request({"design_sha256": "d" * 64, "outcomes": [{} for _ in range(10)]}),
                    artifacts,
                    CoordinationStore(Path(root) / "coord.sqlite"),
                    self.runtime({"blind_scores": scores}),
                ),
            )
            assert result == {"blind_scores": scores}
            with pytest.raises(ProtocolError):
                operations.evidence_audit(
                    self.request({"design_sha256": "d" * 64, "outcomes": [{} for _ in range(10)]}),
                    artifacts,
                    CoordinationStore(Path(root) / "coord.sqlite"),
                    self.runtime({"scores": {}}),
                )

    def test_fingerprint_is_canonical_and_operation_set_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            operations = concrete_domain_operations()
            assert set(operations.__dataclass_fields__) == set(
                type(operations).__dataclass_fields__
            )
            request_payload: Mapping[str, object] = {
                "candidate_instruction": "do work",
                "permissions": {},
                "repository": {},
                "fixture_manifest_hash": "a" * 64,
                "operator_public_key": "operator",
            }
            payload: Mapping[str, object] = {
                "candidate_instruction": "do work",
                "model_identity": "model",
                "runtime_identity": "runtime",
                "request": request_payload,
            }
            outcome = operations.fingerprint(
                self.request(payload),
                ArtifactStore(Path(root) / "public", Path(root) / "private"),
                CoordinationStore(Path(root) / "coord.sqlite"),
                object(),
            )
            assert isinstance(outcome, Mapping)
            public = cast(Mapping[str, object], outcome)
            assert public["fingerprint_sha256"] == request_fingerprint(
                request_payload, "model", "runtime"
            )

    def test_g6_uses_the_exact_canonical_g5_release_identity(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            artifacts = ArtifactStore(Path(root) / "public", Path(root) / "private")
            assignments = [
                {
                    "blind_id": f"blind-{index:02d}",
                    "scenario": scenario,
                    "condition": condition,
                    "direction": "better"
                    if condition == "B" and scenario != "negative-control"
                    else "same",
                }
                for index, (scenario, condition) in enumerate(
                    [
                        ("core-1", "A"),
                        ("core-1", "A"),
                        ("core-1", "B"),
                        ("core-1", "B"),
                        ("core-2", "A"),
                        ("core-2", "A"),
                        ("core-2", "B"),
                        ("core-2", "B"),
                        ("negative-control", "A"),
                        ("negative-control", "B"),
                    ]
                )
            ]
            unsigned = {
                "assignments": assignments,
                "preferred_directions": {
                    "core-1": "better",
                    "core-2": "better",
                    "negative-control": "same",
                },
                "authorization_rule": authorization_rule(),
            }
            release_sha256 = canonical_hash(unsigned)
            release = {**unsigned, "release_sha256": release_sha256}
            artifacts.publish_json(
                f"releases/campaign/experiment/{release_sha256}.json", release, ArtifactMode.PUBLIC
            )
            operations = concrete_domain_operations()
            payload = {"gate": "G6", "design_sha256": "d" * 64, "release_sha256": release_sha256}
            result = operations.analysis(
                self.request(payload),
                artifacts,
                CoordinationStore(Path(root) / "coord.sqlite"),
                object(),
            )
            assert isinstance(result, GatePublication)
            assert cast(GatePublication, result).payload["authorized"] is True

            mismatched_sha256 = "e" * 64
            artifacts.publish_json(
                f"releases/campaign/experiment/{mismatched_sha256}.json",
                release,
                ArtifactMode.PUBLIC,
            )
            mismatched = {**payload, "release_sha256": mismatched_sha256}
            with pytest.raises(ProtocolError, match="exact public G5 packet"):
                operations.analysis(
                    self.request(mismatched),
                    artifacts,
                    CoordinationStore(Path(root) / "coord.sqlite"),
                    object(),
                )

    def test_startup_configuration_fails_closed_for_relative_storage(self) -> None:
        with pytest.raises(ProductionConfigurationError):
            ProductionConfig(
                "127.0.0.1:7233",
                Path("public"),
                Path("/private"),
                Path("/coord.sqlite"),
                Path("/maps.sqlite"),
                "authority.json",
                {},
                {},
                b"x" * 32,
                {},
            )

    def test_private_authority_is_read_from_bound_private_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            artifacts = ArtifactStore(Path(root) / "public", Path(root) / "private")
            package, _ = self.complete_package(
                SourceClassification(
                    "1" * 64, (SourceCoverage(0, 1, "claim_normative", "claim-0001"),)
                )
            )
            authority = {
                "parent_workflow_id": "campaign",
                "parent_run_id": "run",
                "freeze_chain": "a" * 64,
                "claim_hash": "b" * 64,
                "g0_record_hash": "c" * 64,
                "design_proposal_hash": "d" * 64,
                "design_hash": canonical_hash(package),
                "treatment_hash": "f" * 64,
                "fixture_manifest_hash": "0" * 64,
                "preferred_directions": package["preferred_directions"],
                "treatments": {"core-1-A-1": None},
                "experiment_design": package["experiment_design"],
            }
            relative = "authorities/campaign/experiment/workflow/run.json"
            artifacts.publish_json(
                relative,
                {
                    "campaign_id": "campaign",
                    "experiment_id": "experiment",
                    "workflow_id": "workflow",
                    "run_id": "run",
                    "authority": authority,
                },
                ArtifactMode.PRIVATE,
            )
            resolved = ArtifactPrivateAuthority(artifacts, "authorities").authority_for(
                campaign_id="campaign",
                experiment_id="experiment",
                workflow_id="workflow",
                run_id="run",
            )
            assert resolved.design_hash == canonical_hash(package)

    def test_proposal_decision_reads_private_staging_and_projects_only_claims(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            campaign = "campaign-" + "1" * 32
            key = Ed25519PrivateKey.generate()
            public_key = public_key_base64url(key.public_key())
            artifacts = ArtifactStore(Path(root) / "public", Path(root) / "private")
            coordination = CoordinationStore(Path(root) / "coord.sqlite")
            fingerprint = "a" * 64
            claim = {"coverage_sha256": "b" * 64, "claim": "public"}
            proposal = DecompositionProposal("1" * 32, campaign, fingerprint, ["source"], [claim])
            ProposalControl(artifacts, coordination).stage_decomposition(
                StageDecompositionRequest(
                    private_key=key,
                    owner_public_key=public_key,
                    campaign_id=campaign,
                    fingerprint=fingerprint,
                    proposal=proposal,
                )
            )
            wire = DecisionWire.sign(
                key,
                DecisionValidationParameters(
                    campaign_id=campaign,
                    target_kind="campaign",
                    target_id=campaign,
                    action="approve_decomposition",
                    proposal_hash=proposal.hash,
                    expected_revision_hash="0" * 64,
                    sequence=1,
                ).payload(),
            )
            payload = {
                "wire": wire.as_json(),
                "workflow_id": campaign,
                "run_id": "run",
                "prior_decision_sha256": "0" * 64,
                "target_kind": "campaign",
                "target_id": campaign,
                "action": "approve_decomposition",
                "proposal_hash": proposal.hash,
                "expected_revision_sha256": "0" * 64,
                "sequence": 1,
                "owner_public_key": public_key,
                "request_fingerprint": fingerprint,
            }
            request = ActivityRequest(
                campaign,
                "experiment",
                "role",
                sha256(canonical_bytes(payload)).hexdigest(),
                "model",
                "runtime",
                payload,
            )
            result = cast(
                Mapping[str, object],
                concrete_domain_operations().proposal_decision(
                    request, artifacts, coordination, object()
                ),
            )
            assert result["claims"] == [claim]
            assert result["proposal_sha256"] == proposal.hash
            assert "source_coverage" not in result

    def test_private_authority_issue_is_bound_and_public_store_has_no_private_capability(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            artifacts = ArtifactStore(Path(root) / "public", Path(root) / "private")
            package, _ = self.complete_package(
                SourceClassification(
                    "1" * 64, (SourceCoverage(0, 1, "claim_normative", "claim-0001"),)
                )
            )
            authority = {
                "parent_workflow_id": "campaign",
                "parent_run_id": "run",
                "freeze_chain": "a" * 64,
                "claim_hash": "b" * 64,
                "g0_record_hash": "c" * 64,
                "design_proposal_hash": "d" * 64,
                "design_hash": canonical_hash(package),
                "treatment_hash": "f" * 64,
                "fixture_manifest_hash": "0" * 64,
                "preferred_directions": package["preferred_directions"],
                "treatments": {},
                "experiment_design": package["experiment_design"],
            }
            resolver = ArtifactPrivateAuthority(artifacts, "authorities")
            from instruct_eval.worker import PrivateMapAuthority

            resolver.issue_for(
                campaign_id="campaign",
                experiment_id="experiment",
                workflow_id="workflow",
                run_id="run",
                authority=PrivateMapAuthority(**authority),
            )
            assert (
                resolver.authority_for(
                    campaign_id="campaign",
                    experiment_id="experiment",
                    workflow_id="workflow",
                    run_id="run",
                ).freeze_chain
                == "a" * 64
            )
            public = ArtifactStore.public_only(Path(root) / "public-only")
            backend = build_public_production_backend(
                PublicProductionConfig(
                    "127.0.0.1:7233",
                    Path(root) / "public-process",
                    Path(root) / "public.sqlite",
                    {"role": "request"},
                )
            )
            assert not hasattr(backend._artifacts, "private_root")

            assert not hasattr(public, "private_root")
            with pytest.raises(ArtifactError):
                public.read_bytes("secret.json", ArtifactMode.PRIVATE)

    def test_private_authority_issues_only_claim_specific_treatments_from_signed_decomposition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            artifacts = ArtifactStore(Path(root) / "public", Path(root) / "private")
            coordination = CoordinationStore(Path(root) / "coord.sqlite")
            campaign, parent_run = "campaign-" + "1" * 32, "campaign-run"
            key = Ed25519PrivateKey.generate()
            public_key = public_key_base64url(key.public_key())
            candidate = "First behavior.\nSecond behavior."
            first_end = len(b"First behavior.\n")
            coverage = [
                SourceCoverage(0, first_end, "claim_normative", "claim-0001").as_json(),
                SourceCoverage(
                    first_end, len(candidate.encode()), "claim_normative", "claim-0002"
                ).as_json(),
            ]
            coverage_sha256 = canonical_hash({"source_coverage": coverage})
            claims = []
            for claim_id in ("claim-0001", "claim-0002"):
                treatment = derive_treatment(
                    candidate,
                    claim_id,
                    tuple(
                        SourceCoverage(
                            start_byte=item["start_byte"],
                            end_byte=item["end_byte"],
                            classification=item["classification"],
                            owner=item.get("owner"),
                            consumers=tuple(item.get("consumers", ())),
                            reason=item.get("reason"),
                        )
                        for item in coverage
                    ),
                )
                claims.append(
                    {
                        "schema": "instruct-eval-claim-v1",
                        "claim_id": claim_id,
                        "triggering_event": claim_id,
                        "preferred_behavior": claim_id,
                        "competing_behaviors": ["other"],
                        "observable_evidence": ["evidence"],
                        "treatment_hash": treatment.hash,
                        "coverage_sha256": coverage_sha256,
                    }
                )
            decomposition = DecompositionProposal(
                "1" * 32,
                campaign,
                "b" * 64,
                coverage,
                claims,
            )
            control = ProposalControl(artifacts, coordination)
            control.stage_decomposition(
                StageDecompositionRequest(
                    private_key=key,
                    owner_public_key=public_key,
                    campaign_id=campaign,
                    fingerprint="b" * 64,
                    proposal=decomposition,
                )
            )
            campaign_wire = DecisionWire.sign(
                key,
                DecisionValidationParameters(
                    campaign_id=campaign,
                    target_kind="campaign",
                    target_id=campaign,
                    action="approve_decomposition",
                    proposal_hash=decomposition.hash,
                    expected_revision_hash="0" * 64,
                    sequence=1,
                ).payload(),
            )
            control.publish_decision(
                PublishDecisionRequest(
                    owner_public_key=public_key,
                    wire=campaign_wire,
                    workflow_id=campaign,
                    run_id=parent_run,
                    prior_record_hash="0" * 64,
                    campaign_id=campaign,
                    target_kind="campaign",
                    target_id=campaign,
                    action="approve_decomposition",
                    proposal_hash=decomposition.hash,
                    expected_revision_hash="0" * 64,
                    sequence=1,
                )
            )
            resolver = ArtifactPrivateAuthority(artifacts, "authorities")
            authorities = []
            for index, claim in enumerate(claims, 1):
                claim_hash = canonical_hash(claim)
                issued = coordination.issue_child_authorization(
                    ChildAuthorizationRequest(
                        campaign,
                        campaign,
                        parent_run,
                        claim_hash,
                        "b" * 64,
                        coverage_sha256,
                    )
                )
                child, child_run = f"child-{index}", f"child-run-{index}"
                coordination.claim_child_authorization(
                    ChildAuthorizationClaimRequest(
                        campaign,
                        campaign,
                        parent_run,
                        claim_hash,
                        "b" * 64,
                        coverage_sha256,
                        str(issued.experiment_id),
                        child,
                        child_run,
                    )
                )
                treatment = derive_treatment(
                    candidate,
                    claim["claim_id"],
                    tuple(
                        SourceCoverage(
                            start_byte=item["start_byte"],
                            end_byte=item["end_byte"],
                            classification=item["classification"],
                            owner=item.get("owner"),
                            consumers=tuple(item.get("consumers", ())),
                            reason=item.get("reason"),
                        )
                        for item in coverage
                    ),
                )
                source_classification = SourceClassification(
                    sha256(candidate.encode()).hexdigest(),
                    tuple(
                        SourceCoverage(
                            start_byte=item["start_byte"],
                            end_byte=item["end_byte"],
                            classification=item["classification"],
                            owner=item.get("owner"),
                            consumers=tuple(item.get("consumers", ())),
                            reason=item.get("reason"),
                        )
                        for item in coverage
                    ),
                )
                package, fixture_manifest_hash = self.complete_package(source_classification)
                proposal = DesignProposal(
                    str(index) * 32,
                    campaign,
                    claim_hash,
                    "d" * 64,
                    treatment.hash,
                    fixture_manifest_hash,
                    package,
                )
                attestation = StageAttestation.sign(
                    key,
                    StageAttestationSigningParameters(
                        campaign_id=campaign,
                        claim_hash=claim_hash,
                        proposal_nonce=proposal.proposal_nonce,
                        proposal_hash=proposal.hash,
                        g0_commit_hash=proposal.g0_commit_hash,
                        treatment_hash=proposal.treatment_hash,
                        fixture_manifest_hash=proposal.fixture_manifest_hash,
                    ),
                )
                control.stage_design(
                    StageDesignRequest(
                        private_key=key,
                        owner_public_key=public_key,
                        campaign_id=campaign,
                        claim_hash=claim_hash,
                        g0_commit_hash=proposal.g0_commit_hash,
                        treatment_hash=proposal.treatment_hash,
                        fixture_manifest_hash=proposal.fixture_manifest_hash,
                        proposal=proposal,
                        attestation=attestation,
                    )
                )
                wire = DecisionWire.sign(
                    key,
                    DecisionValidationParameters(
                        campaign_id=campaign,
                        target_kind="claim",
                        target_id=claim_hash,
                        action="submit_design",
                        proposal_hash=proposal.hash,
                        expected_revision_hash=proposal.g0_commit_hash,
                        sequence=1,
                    ).payload(),
                )
                control.publish_decision(
                    PublishDecisionRequest(
                        owner_public_key=public_key,
                        wire=wire,
                        workflow_id=child,
                        run_id=child_run,
                        prior_record_hash="0" * 64,
                        campaign_id=campaign,
                        target_kind="claim",
                        target_id=claim_hash,
                        action="submit_design",
                        proposal_hash=proposal.hash,
                        expected_revision_hash=proposal.g0_commit_hash,
                        sequence=1,
                    )
                )
                resolver.issue_from_durable_records(
                    DurableAuthoritySlots(
                        coordination=coordination,
                        campaign_id=campaign,
                        experiment_id=str(issued.experiment_id),
                        workflow_id=child,
                        run_id=child_run,
                        parent_workflow_id=campaign,
                        parent_run_id=parent_run,
                        candidate_instruction=candidate,
                    )
                )
                authorities.append(
                    resolver.authority_for(
                        campaign_id=campaign,
                        experiment_id=str(issued.experiment_id),
                        workflow_id=child,
                        run_id=child_run,
                    )
                )
            assert [authority.treatments["core-1-B-1"] for authority in authorities] == [
                "First behavior.\n",
                "Second behavior.",
            ]
            assert all(authority.treatments["core-1-A-1"] is None for authority in authorities)
            with pytest.raises(ProductionConfigurationError):
                resolver.issue_from_durable_records(
                    DurableAuthoritySlots(
                        coordination=coordination,
                        campaign_id=campaign,
                        experiment_id="experiment-" + "9" * 32,
                        workflow_id="wrong",
                        run_id="wrong",
                        parent_workflow_id=campaign,
                        parent_run_id=parent_run,
                        candidate_instruction=candidate,
                    )
                )

    def test_runtime_subject_uses_blind_condition_and_treatment_request(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            package, _ = self.complete_package(
                SourceClassification(
                    "1" * 64, (SourceCoverage(0, 1, "claim_normative", "claim-0001"),)
                )
            )
            frozen_design = ExperimentDesign.from_payload(
                cast(Mapping[str, object], package["experiment_design"])
            )
            executor = RuntimeSubjectExecutor(
                {"core-1": Path(root)}, {"candidate_instruction": "original"}, b"k" * 32, {}
            )
            outcome = SimpleNamespace(
                protocol_valid=True,
                verifier_passed=True,
                observer_output={"result": "yes"},
                changes="",
                response="completed",
                tool_outputs=(),
                runtime_stdout="",
                runtime_stderr="",
                verifier_stdout="",
                verifier_stderr="",
                unchanged_hashes={},
                reason=None,
            )
            with (
                patch(
                    "instruct_eval.production.role_runtime.run_subject", return_value=outcome
                ) as run,
                patch("instruct_eval.production.closed_outcome", return_value={"closed": True}),
            ):
                for condition in ("A", "B"):
                    assignment = PrivateAssignment("id", "core-1", condition, "blind", "x" * 64)
                    result = executor(
                        assignment=assignment,
                        treatment="treatment",
                        disclosure_treatment="treatment",
                        frozen_design=frozen_design,
                    )
                    assert result["outcome"] == {"closed": True}
            assert [call.args[1] for call in run.call_args_list] == ["A", "B"]
            assert all(
                call.args[3]["candidate_instruction"] == "treatment" for call in run.call_args_list
            )


if __name__ == "__main__":
    unittest.main()
