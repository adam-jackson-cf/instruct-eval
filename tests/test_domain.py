from __future__ import annotations

import json
import unittest
from dataclasses import replace
from hashlib import sha256
from types import MappingProxyType

import pytest

from instruct_eval.models import (
    AdversaryDecision,
    Direction,
    EvidenceAxis,
    ExperimentDesign,
    Fixture,
    ProtocolError,
    ProvisionalGroup,
    ReachabilityWitness,
    SourceClassification,
    SourceCoverage,
    Verifier,
    WitnessExecutionResult,
    adversary_packet_hash,
    canonical_bytes,
    canonical_hash,
    construct_outcome_tuple,
    derive_claims,
    validate_adversary_decision,
    validate_experiment_design,
)


def hash_hex(value):
    return sha256(value).hexdigest()


D = "a" * 64


class DomainContractTest(unittest.TestCase):
    def _source_inputs(self):
        source = "\u03b1A | B\n"
        groups = (
            ProvisionalGroup("first", "event one", "prefer one", ("other",), ("proof",)),
            ProvisionalGroup("second", "event two", "prefer two", ("other",), ("proof",)),
        )
        return source, groups

    @staticmethod
    def _span(source: str, start: int, end: int) -> tuple[int, int]:
        return len(source[:start].encode("utf-8")), len(source[:end].encode("utf-8"))

    def test_canonical_hash_handles_nested_immutable_containers(self) -> None:
        immutable = MappingProxyType({"nested": MappingProxyType({"values": ("\u03b1", "β")})})
        assert canonical_hash(immutable) == canonical_hash({"nested": {"values": ["\u03b1", "β"]}})

    def test_source_classification_partitions_utf8_and_ownership(self) -> None:
        source, groups = self._source_inputs()
        valid = (
            SourceCoverage(*self._span(source, 0, 2), "claim_normative", "first"),
            SourceCoverage(*self._span(source, 2, 3), "non_normative", reason="separator"),
            SourceCoverage(
                *self._span(source, 3, 4), "shared_context", consumers=("first", "second")
            ),
            SourceCoverage(*self._span(source, 4, 5), "non_normative", reason="separator"),
            SourceCoverage(*self._span(source, 5, 6), "claim_normative", "second"),
            SourceCoverage(*self._span(source, 6, 7), "non_normative", reason="formatting"),
        )
        claims, treatments, coverage = derive_claims(source, groups, valid)
        assert len(claims) == len(treatments)
        assert coverage[2].consumers == ("claim-0001", "claim-0002")
        invalid = (
            (),
            valid[:1] + valid[2:],
            (SourceCoverage(*self._span(source, 0, 1), "claim_normative", "first"), *valid[1:]),
            (
                *valid[:2],
                SourceCoverage(
                    *self._span(source, 3, 4), "shared_context", consumers=("first", "foreign")
                ),
                *valid[3:],
            ),
        )
        for case in invalid:
            with self.subTest(case=case), pytest.raises(ProtocolError):
                derive_claims(source, groups, case)

    def test_source_roots_hash_vectors_reorder_and_ties(self) -> None:
        source, groups = self._source_inputs()
        coverage = (
            SourceCoverage(*self._span(source, 0, 2), "claim_normative", "first"),
            SourceCoverage(*self._span(source, 2, 5), "non_normative", reason="separator"),
            SourceCoverage(*self._span(source, 5, 6), "claim_normative", "second"),
            SourceCoverage(*self._span(source, 6, 7), "non_normative", reason="formatting"),
        )
        claims, treatments, _ = derive_claims(source, groups, coverage)
        assert claims[0].hash != treatments[0].hash
        assert derive_claims(source, tuple(reversed(groups)), coverage)[0] == claims
        with pytest.raises(ProtocolError):
            derive_claims(
                "AB",
                groups,
                (
                    SourceCoverage(0, 1, "claim_normative", "first"),
                    SourceCoverage(1, 2, "claim_normative", "first"),
                ),
            )

    def _fixture(self, fixture_id: str) -> Fixture:
        verifier, observer = b"verify\n", b"observe\n"
        axes = (EvidenceAxis("result", ("yes", "no")),)
        directions = (Direction("good", "good result"), Direction("bad", "bad result"))
        table = {
            (False, "yes"): "good",
            (True, "yes"): "good",
            (False, "no"): "bad",
            (True, "no"): "bad",
        }

        def witness(name, code, result, verifier_result):
            return ReachabilityWitness(
                name,
                code,
                name.encode(),
                verifier_result,
                (("result", result),),
                D,
                (("python", D),),
                (("verify.py", D), ("observe.py", D)),
                ("out.txt",),
            )

        witnesses = (witness("w-good", "good", "yes", False), witness("w-bad", "bad", "no", True))
        manifest = {"fixture": fixture_id, "version": 1}
        source_classification = SourceClassification(
            D,
            (SourceCoverage(0, 1, "claim_normative", "claim"),),
        )
        return Fixture(
            fixture_id,
            "complete scenario task",
            manifest,
            canonical_hash(manifest),
            Verifier(verifier, hash_hex(verifier)),
            observer,
            hash_hex(observer),
            {"w-good": False, "w-bad": True},
            axes,
            directions,
            table,
            ("out.txt",),
            witnesses,
            {"required": ["out.txt"]},
            source_classification,
        )

    def _design(self) -> ExperimentDesign:
        return ExperimentDesign(tuple(self._fixture(f"scenario-{index}") for index in range(3)))

    def test_three_fixture_packages_are_local_total_and_score_verifier_false(self) -> None:
        design = self._design()
        validate_experiment_design(design)
        outcome = construct_outcome_tuple(design, "scenario-0", False, {"result": "yes"})
        assert ExperimentDesign.from_payload(design.payload()) == design
        assert not outcome.verifier_passed
        with pytest.raises(ProtocolError):
            construct_outcome_tuple(design, "scenario-0", False, {"result": "yes", "foreign": "no"})

    def test_complete_design_parser_rejects_omitted_altered_and_duplicate_owned_fields(
        self,
    ) -> None:
        payload = self._design().payload()
        mutations = []
        missing_verifier = json.loads(canonical_bytes(payload))
        del missing_verifier["fixtures"][0]["verifier"]["source"]
        mutations.append(missing_verifier)
        altered_observer = json.loads(canonical_bytes(payload))
        altered_observer["fixtures"][0]["observer"]["source"] = "different"
        mutations.append(altered_observer)
        missing_witness_input = json.loads(canonical_bytes(payload))
        del missing_witness_input["fixtures"][0]["witnesses"][0]["input"]
        mutations.append(missing_witness_input)
        missing_classification = json.loads(canonical_bytes(payload))
        del missing_classification["fixtures"][0]["source_classification"]
        mutations.append(missing_classification)
        duplicate_table_row = json.loads(canonical_bytes(payload))
        duplicate_table_row["fixtures"][0]["outcome_table"].append(
            dict(duplicate_table_row["fixtures"][0]["outcome_table"][0]),
        )
        mutations.append(duplicate_table_row)
        foreign_field = json.loads(canonical_bytes(payload))
        foreign_field["fixtures"][0]["approval"] = True
        mutations.append(foreign_field)
        for mutation in mutations:
            with self.subTest(mutation=mutation), pytest.raises(ProtocolError):
                ExperimentDesign.from_payload(mutation)

    def test_g2_adversary_review_binds_design_and_source_classification(self) -> None:
        source, groups = self._source_inputs()
        false_coverage = (
            SourceCoverage(*self._span(source, 0, 2), "claim_normative", "first"),
            SourceCoverage(*self._span(source, 2, 3), "non_normative", reason="separator"),
            SourceCoverage(
                *self._span(source, 3, 4), "non_normative", reason="descriptive_context"
            ),
            SourceCoverage(*self._span(source, 4, 5), "non_normative", reason="separator"),
            SourceCoverage(*self._span(source, 5, 6), "claim_normative", "second"),
            SourceCoverage(*self._span(source, 6, 7), "non_normative", reason="formatting"),
        )
        derive_claims(source, groups, false_coverage)
        source_classification = SourceClassification(hash_hex(source.encode()), false_coverage)
        design = ExperimentDesign(tuple(self._fixture(f"scenario-{index}") for index in range(3)))
        packet = adversary_packet_hash(design, source_classification)
        accepted = AdversaryDecision(True, packet)
        validate_adversary_decision(design, source_classification, accepted)
        with pytest.raises(ProtocolError):
            validate_adversary_decision(
                design, source_classification, AdversaryDecision(False, packet)
            )
        different_classification = SourceClassification(D, false_coverage)
        with pytest.raises(ProtocolError):
            validate_adversary_decision(design, different_classification, accepted)

    def test_axis_and_table_rejections_include_257th_and_reward_hacking_collapse(self) -> None:
        fixture = self._fixture("scenario-x")
        oversized = replace(
            fixture, axes=tuple(EvidenceAxis(f"a{i}", ("0", "1")) for i in range(8))
        )
        collapsed = replace(fixture, outcome_table=dict.fromkeys(fixture.outcome_table, "good"))
        with pytest.raises(ProtocolError):
            EvidenceAxis("result", ("yes", "yes"))
        bad_fixtures = (
            oversized,
            collapsed,
            replace(fixture, directions=(Direction("good", "x"), Direction("good", "y"))),
        )
        for bad in bad_fixtures:
            with self.subTest(bad=bad), pytest.raises(ProtocolError):
                validate_experiment_design(
                    ExperimentDesign(
                        (bad, self._fixture("scenario-y"), self._fixture("scenario-z"))
                    )
                )

    def test_witness_execution_rejects_all_tampering(self) -> None:
        design = self._design()
        fixture = design.fixtures[0]
        witness = fixture.witnesses[0]
        good = WitnessExecutionResult(
            dict(witness.expected_unchanged_hashes),
            witness.expected_changed_paths,
            True,
            False,
            witness.expected_verifier_passed,
            dict(witness.expected_observer),
            witness.expected_evidence_sha256,
            dict(witness.expected_tool_hashes),
        )
        with pytest.raises(ProtocolError):
            WitnessExecutionResult(
                {"verify.py": D},
                ("out.txt",),
                True,
                False,
                False,
                {"result": object()},
                D,
                {"python": D},
            )
        validate_experiment_design(
            design,
            lambda _f, w: (
                good
                if w.witness_id == witness.witness_id
                else WitnessExecutionResult(
                    dict(w.expected_unchanged_hashes),
                    w.expected_changed_paths,
                    True,
                    False,
                    w.expected_verifier_passed,
                    dict(w.expected_observer),
                    w.expected_evidence_sha256,
                    dict(w.expected_tool_hashes),
                )
            ),
        )
        mutations = (
            replace(good, protocol_valid=False),
            replace(good, contaminated=True),
            replace(good, changed_paths=("escape.txt",)),
            replace(good, verifier_passed=True),
            replace(good, observer_output={"result": "no"}),
            replace(good, evidence_sha256="b" * 64),
            replace(good, tool_hashes={"python": "b" * 64}),
            replace(good, unchanged_hashes={"verify.py": D}),
        )
        for mutated in mutations:
            with self.subTest(mutated=mutated), pytest.raises(ProtocolError):
                validate_experiment_design(design, lambda _f, _w, mutated=mutated: mutated)


if __name__ == "__main__":
    unittest.main()
