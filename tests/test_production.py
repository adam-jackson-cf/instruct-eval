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
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from instruct_eval import production
from instruct_eval.activities import (
    ActivityRequest,
    GatePublication,
    GateRequest,
    InstructEvalActivities,
)
from instruct_eval.artifacts import ArtifactError, ArtifactMode, ArtifactStore
from instruct_eval.behavior import OBSERVATION_CONTRACT
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
from instruct_eval.trials import (
    ASSIGNMENT_IDS,
    MAX_NORMALIZED_SCALARS,
    SUBJECT_ARTIFACT_KINDS,
    PrivateAssignment,
    authorization_rule,
    normalize,
    scan_disclosure,
)
from instruct_eval.worker import DurableAuthoritySlots


def _assert_retained_invalid_subject(result) -> None:
    assert result["outcome"] == {"protocol_valid": False}
    private_artifacts = result["private_artifacts"]
    assert set(private_artifacts) == SUBJECT_ARTIFACT_KINDS - {"outcome"}
    assert isinstance(private_artifacts["trusted_logs"]["reason"], str)
    events = [
        json.loads(line) for line in private_artifacts["runtime_streams"]["stdout"].splitlines()
    ]
    terminal = next(event for event in events if event["type"] == "agent_end")
    assert private_artifacts["response"] == "".join(
        block["text"] for block in terminal["messages"][-1]["content"] if block["type"] == "text"
    )


def _assert_valid_subject_artifacts(result: Mapping[str, Any], treatment: str | None) -> None:
    private_artifacts = result["private_artifacts"]
    assert set(private_artifacts) == SUBJECT_ARTIFACT_KINDS - {"outcome"}
    outcome = result["outcome"]
    assert outcome["protocol_valid"]
    assert outcome["verifier_passed"]
    assert outcome["observer_state"] == ["yes"]
    assert private_artifacts["tool_outputs"] == ([] if treatment is None else [treatment])
    assert "disclosure_tool_outputs" not in private_artifacts
    if treatment is None:
        return
    raw_events = [
        json.loads(line) for line in private_artifacts["runtime_streams"]["stdout"].splitlines()
    ]
    projected_events = [
        json.loads(line)
        for line in private_artifacts["runtime_streams"]["output_events"].splitlines()
    ]
    raw_read = next(event for event in raw_events if event["type"] == "tool_execution_end")
    projected_read = next(
        event for event in projected_events if event["type"] == "tool_execution_end"
    )
    assert raw_read["result"]["content"][0]["text"] == treatment
    assert not scan_disclosure(raw=json.dumps(projected_read).encode(), treatment=treatment)


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
                "public_files": {},
            }
            witnesses = tuple(
                ReachabilityWitness(
                    f"{fixture_id}-{direction}",
                    direction,
                    canonical_bytes(
                        {
                            "schema": "instruct-eval-witness-input-v1",
                            "actions": [
                                {"tool": "write", "path": "out.txt", "content": result},
                                {
                                    "tool": "respond",
                                    "response": {
                                        "completion": "complete" if passed else "incomplete",
                                        "summary": result,
                                    },
                                },
                            ],
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
                        "observation_contract": OBSERVATION_CONTRACT,
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
                    "public_files": {},
                }
                witnesses = tuple(
                    ReachabilityWitness(
                        f"{fixture_id}-{direction}",
                        direction,
                        canonical_bytes(
                            {
                                "schema": "instruct-eval-witness-input-v1",
                                "actions": [
                                    {"tool": "write", "path": "out.txt", "content": result},
                                    {
                                        "tool": "respond",
                                        "response": {
                                            "completion": (
                                                "complete" if verifier_passed else "incomplete"
                                            ),
                                            "summary": result,
                                        },
                                    },
                                ],
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
                        "observation_contract": OBSERVATION_CONTRACT,
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

            g0_payload = {"gate": "G0", "eligibility": {"eligible": True}, "accepted": True}
            g0 = cast(
                GatePublication,
                operations.g0_commit(gate(g0_payload), artifacts, coordination, object()),
            )
            backend = build_public_production_backend(
                PublicProductionConfig(
                    "127.0.0.1:7233",
                    Path(root) / "public",
                    Path(root) / "coord.sqlite",
                    {"role": "request"},
                )
            )
            _, _, g0_record_hash = InstructEvalActivities(coordination, backend)._publish_ledger(
                gate(g0_payload), "g0_commit", canonical_bytes(g0_payload), g0
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
                g0_record_hash,
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
                    expected_revision_hash=g0_record_hash,
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
                    expected_revision_hash=g0_record_hash,
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
                "g0_record_sha256": g0_record_hash,
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
            runtime = SimpleNamespace(
                run_witness=run_witness,
                invoke_role=lambda _contract, packet, _role_request: {
                    "adversary_decision": {
                        "accepted": True,
                        "packet_sha256": packet["packet_sha256"],
                    },
                    "rejections": [],
                    "stress_review": None,
                },
            )
            assert cast(
                GatePublication,
                operations.pre_run_validity(
                    gate({**base, "gate": "G2"}), artifacts, coordination, runtime
                ),
            ).payload["accepted"]
            freeze = cast(
                GatePublication,
                operations.freeze(
                    gate(
                        {
                            **base,
                            "commit": "freeze",
                            "map_ref": "opaque-map",
                            "map_commitment": "opaque-commitment",
                            "tokens": [f"token-{index}" for index in range(len(ASSIGNMENT_IDS))],
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
            outcome_hashes = [
                canonical_hash({"index": index}) for index in range(len(ASSIGNMENT_IDS))
            ]
            execution_payload = {
                "input": public_input,
                "gate": "G3",
                "design_sha256": proposal.design_hash,
                "outcome_sha256s": outcome_hashes,
                "outcomes_sha256": canonical_hash({"outcome_sha256s": outcome_hashes}),
                "trial_accounting": [
                    {"token": token, "disposition": "result"} for token in freeze.payload["tokens"]
                ],
                "protocol_valid": True,
                "verifier_passed": [True] * len(ASSIGNMENT_IDS),
                "accepted": True,
            }
            assert cast(
                GatePublication,
                operations.execution_commit(
                    gate(execution_payload), artifacts, coordination, object()
                ),
            ).payload["accepted"]
            for private_field in ("private", "treatment"):
                with pytest.raises(ProtocolError):
                    operations.execution_commit(
                        gate(
                            {
                                **execution_payload,
                                "input": {**public_input, "nested": {private_field: "hidden"}},
                            }
                        ),
                        artifacts,
                        coordination,
                        object(),
                    )
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
            fixture_ids = ("core-1", "core-2", "negative-control")
            fixtures = [
                {
                    "fixture_id": fixture_id,
                    "axes": [{"name": "result", "values": ["yes", "no"]}],
                    "directions": [
                        {"code": "better", "description": "yes"},
                        {"code": "worse", "description": "no"},
                    ],
                    "outcome_table": [
                        {"outcome": [passed, value], "direction": direction}
                        for passed in (False, True)
                        for value, direction in (("yes", "better"), ("no", "worse"))
                    ],
                }
                for fixture_id in fixture_ids
            ]
            artifacts.publish_json(
                f"scoring/campaign/experiment/{'d' * 64}.json",
                {"design_sha256": "d" * 64, "fixtures": fixtures},
            )
            outcomes = [
                {
                    "blind_id": f"blind-{index}",
                    "fixture": fixture_ids[index % 3],
                    "protocol_valid": True,
                    "verifier_passed": index % 2 == 0,
                    "observer_state": ["yes" if index % 2 == 0 else "no"],
                    "direction_code": "must-not-reach-scorer",
                    "changed_paths": ["out.txt"],
                    "evidence_id": "opaque-evidence",
                }
                for index in range(len(ASSIGNMENT_IDS))
            ]
            scores = [
                {"blind_id": f"blind-{index}", "direction": "better" if index % 2 == 0 else "worse"}
                for index in range(len(ASSIGNMENT_IDS))
            ]

            def score(contract, packet, request):
                assert set(packet) == {"fixtures", "outcomes"}
                scored = []
                for outcome in packet["outcomes"]:
                    assert set(outcome) == {
                        "blind_id",
                        "fixture",
                        "verifier_passed",
                        "observer_state",
                    }
                    fixture = next(
                        item
                        for item in packet["fixtures"]
                        if item["fixture_id"] == outcome["fixture"]
                    )
                    row = next(
                        item
                        for item in fixture["outcome_table"]
                        if item["outcome"]
                        == [outcome["verifier_passed"], *outcome["observer_state"]]
                    )
                    scored.append({"blind_id": outcome["blind_id"], "direction": row["direction"]})
                return {"blind_scores": scored}

            result = cast(
                Mapping[str, object],
                operations.evidence_audit(
                    self.request({"design_sha256": "d" * 64, "outcomes": outcomes}),
                    artifacts,
                    CoordinationStore(Path(root) / "coord.sqlite"),
                    SimpleNamespace(invoke_role=score),
                ),
            )
            assert result == {"blind_scores": scores}
            with pytest.raises(ProtocolError):
                operations.evidence_audit(
                    self.request({"design_sha256": "d" * 64, "outcomes": outcomes}),
                    artifacts,
                    CoordinationStore(Path(root) / "coord.sqlite"),
                    self.runtime({"scores": {}}),
                )

    def test_fingerprint_is_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            operations = concrete_domain_operations()
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
                for index, assignment_id in enumerate(ASSIGNMENT_IDS)
                for scenario, condition, _ in [assignment_id.rsplit("-", 2)]
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
            public.publish_json("gates/G0.json", {"accepted": True})
            assert json.loads(public.read_bytes("gates/G0.json")) == {"accepted": True}
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
            placeholder_design = ExperimentDesign.from_payload(
                cast(Mapping[str, object], package["experiment_design"])
            )
            fixture_root = Path(root) / "core-1"
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
                "out.txt": b"base",
                "observe.py": observer,
                "verify.py": verifier,
            }
            for path, content in files.items():
                (fixture_root / path).write_bytes(content)
            manifest = {
                "schema": "instruct-eval-fixture-manifest-v1",
                "files": [
                    {"path": path, "sha256": sha256(content).hexdigest()}
                    for path, content in sorted(files.items())
                ],
                "public_files": {},
            }
            placeholder_fixture = next(
                fixture for fixture in placeholder_design.fixtures if fixture.fixture_id == "core-1"
            )
            frozen_fixture = replace(
                placeholder_fixture,
                manifest=manifest,
                manifest_sha256=canonical_hash(manifest),
                verifier=Verifier(verifier, sha256(verifier).hexdigest()),
                observe_source=observer,
                observe_sha256=sha256(observer).hexdigest(),
                witnesses=tuple(
                    replace(
                        witness,
                        expected_unchanged_hashes=(
                            ("observe.py", sha256(observer).hexdigest()),
                            ("verify.py", sha256(verifier).hexdigest()),
                        ),
                    )
                    for witness in placeholder_fixture.witnesses
                ),
                evidence_contract={
                    "schema": "instruct-eval-evidence-contract-v1",
                    "verifier_path": "verify.py",
                    "observer_path": "observe.py",
                    "verifier_command": [sys.executable, "verify.py"],
                    "observer_command": [sys.executable, "observe.py"],
                    "observation_contract": OBSERVATION_CONTRACT,
                },
            )
            frozen_design = ExperimentDesign(
                tuple(
                    frozen_fixture if fixture.fixture_id == "core-1" else fixture
                    for fixture in placeholder_design.fixtures
                )
            )
            executor = RuntimeSubjectExecutor(
                {"core-1": fixture_root},
                {
                    "candidate_instruction": "original",
                    "permissions": {"tools": []},
                },
                b"k" * 32,
                {"core-1": ("out.txt",)},
            )
            executions = []
            contexts = []
            fault = None
            expanded = "\ufdfa" * (MAX_NORMALIZED_SCALARS // len(normalize("\ufdfa")) + 1)
            native_treatment = "treatment"

            def execute_omp(execution):
                (execution.workspace / "out.txt").write_text(
                    "unknown" if fault == "frozen" else "yes", encoding="utf-8"
                )
                agents = execution.workspace / ".omp" / "AGENTS.md"
                contexts.append(agents.read_text() if agents.is_file() else None)
                if fault == "observer":
                    (execution.workspace / "observe.py").write_text("changed", encoding="utf-8")
                if fault == "paths":
                    (execution.workspace / "extra.txt").write_text("unexpected", encoding="utf-8")
                executions.append(execution)
                input_path = str(agents.resolve())
                native_read = {
                    "content": [{"type": "text", "text": native_treatment}],
                    "details": {
                        "totalLines": 1,
                        "displayContent": {
                            "text": native_treatment,
                            "startLine": 1,
                            "lineNumbers": [1],
                        },
                        "fileSize": len(native_treatment.encode("utf-8")),
                        "meta": {"source": {"type": "path", "value": input_path}},
                    },
                }
                user = {
                    "role": "user",
                    "content": [{"type": "text", "text": execution.prompt}],
                }
                response = {"completion": "complete", "summary": "completed"}
                assistant = {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(response, separators=(",", ":")),
                        }
                    ],
                    "stopReason": "stop",
                }
                events = [
                    {"type": "message_start", "message": user},
                    {"type": "message_end", "message": user},
                    {"type": "instruct_eval_observer_ready", "origin": "runtime_observer"},
                    {"type": "message_end", "message": assistant},
                    {
                        "type": "agent_end",
                        "stopReason": "stop",
                        "messages": [user, assistant],
                    },
                ]
                if agents.is_file():
                    events[3:3] = [
                        {
                            "type": "tool_execution_start",
                            "toolCallId": "context-read",
                            "toolName": "read",
                            "args": {"path": input_path},
                        },
                        {
                            "type": "tool_execution_end",
                            "toolCallId": "context-read",
                            "toolName": "read",
                            "isError": False,
                            "result": native_read,
                        },
                    ]
                if fault == "disclosure":
                    events.insert(
                        3,
                        {
                            "type": "tool_execution_update",
                            "partialResult": {"content": [{"type": "text", "text": "treatment"}]},
                        },
                    )
                return production.role_runtime._terminal_output(
                    "".join(json.dumps(event) + "\n" for event in events),
                    expanded if fault == "scan_limit" else "",
                    prompt=execution.prompt,
                    required=False,
                    context=production.role_runtime._TerminalContext(
                        input_file=(input_path, native_treatment) if agents.is_file() else None
                    ),
                )

            with patch(
                "instruct_eval.production.role_runtime.execute_omp",
                side_effect=execute_omp,
            ):
                results = [
                    executor(
                        assignment=PrivateAssignment(
                            condition, "core-1", condition, "blind", "x" * 64
                        ),
                        treatment="treatment",
                        disclosure_treatment="treatment",
                        frozen_design=frozen_design,
                    )
                    for condition in ("A", "B")
                ]
                invalid_results = []
                for fault in ("observer", "disclosure", "frozen", "paths", "scan_limit"):
                    invalid_results.append(
                        executor(
                            assignment=PrivateAssignment(fault, "core-1", "A", "blind", "x" * 64),
                            treatment="treatment",
                            disclosure_treatment="treatment",
                            frozen_design=frozen_design,
                        )
                    )
            for result, input_treatment in zip(results, (None, native_treatment), strict=True):
                _assert_valid_subject_artifacts(result, input_treatment)
            for result in invalid_results:
                _assert_retained_invalid_subject(result)
            control, treatment = executions[:2]
            assert "candidate_instruction" not in control.request
            assert control.prompt == treatment.prompt == "scenario"
            assert treatment.request["candidate_instruction"] == "treatment"
            assert contexts[:2] == [None, "treatment"]

    def test_decomposer_packet_hash_is_host_bound_and_response_is_verified(self) -> None:
        instruction = "café"
        source_sha256 = sha256(instruction.encode("utf-8")).hexdigest()
        classification = {
            "source_sha256": source_sha256,
            "coverage": [
                {
                    "start_byte": 0,
                    "end_byte": len(instruction.encode("utf-8")),
                    "classification": "claim_normative",
                    "owner": "p1",
                }
            ],
        }
        captured: dict[str, Mapping[str, object]] = {}

        def invoke(contract, payload, request):
            captured["payload"] = payload
            return {
                "provisional_groups": [{"group_id": "p1"}],
                "source_classification": classification,
            }

        result = production._role_output(
            "decomposition",
            {"instruction": instruction},
            SimpleNamespace(invoke_role=invoke),
            {},
        )
        assert result["source_classification"] == classification
        assert captured["payload"] == {
            "instruction": instruction,
            "source_sha256": source_sha256,
            "source_byte_length": len(instruction.encode("utf-8")),
        }
        classification["source_sha256"] = "0" * 64
        with pytest.raises(ProtocolError, match="source hash"):
            production._role_output(
                "decomposition",
                {"instruction": instruction},
                SimpleNamespace(invoke_role=invoke),
                {},
            )
        classification["source_sha256"] = source_sha256
        classification["coverage"][0]["end_byte"] = len(instruction)
        with pytest.raises(ProtocolError):
            production._role_output(
                "decomposition",
                {"instruction": instruction},
                SimpleNamespace(invoke_role=invoke),
                {},
            )


if __name__ == "__main__":
    unittest.main()
