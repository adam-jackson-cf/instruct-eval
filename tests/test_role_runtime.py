from __future__ import annotations

import json
import re
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from instruct_eval import role_runtime as runtime
from instruct_eval.models import (
    Direction,
    EvidenceAxis,
    Fixture,
    ReachabilityWitness,
    SourceClassification,
    SourceCoverage,
    Verifier,
    canonical_hash,
)


class RoleRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.request = {
            "candidate_instruction": "private treatment",
            "model": {"provider": "openai-codex", "identifier": "test", "thinking": "low"},
            "runtime": {"version": "18.0.1", "timeout_seconds": 10},
            "permissions": {
                "approval_mode": "auto",
                "tools": ["read", "edit", "write", "glob", "grep"],
            },
        }

    def assert_timestamped_workspace(
        self,
        workspace: Path,
        experiments: Path,
        kind: str,
        identity: str,
    ) -> Path:
        assert workspace.name == "workspace"
        experiment = workspace.parent
        assert experiment.parent == experiments
        assert re.fullmatch(
            rf"\d{{8}}T\d{{6}}\.\d{{6}}Z-{kind}-{identity}-[A-Za-z0-9_-]+",
            experiment.name,
        )
        return experiment

    def test_credential_gateway_receives_only_isolated_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            (home / ".omp").mkdir(parents=True)
            credential = home / ".omp" / "token"
            credential.write_text("ephemeral")
            broker, gateway = MagicMock(), MagicMock()
            with (
                patch.object(runtime, "_port", side_effect=[1111, 2222]),
                patch.object(runtime, "_wait_for"),
                patch.object(runtime.subprocess, "Popen", side_effect=[broker, gateway]) as popen,
                patch.object(
                    runtime.subprocess,
                    "run",
                    side_effect=[
                        MagicMock(returncode=0, stdout=json.dumps({"token": "broker-secret"})),
                        MagicMock(
                            returncode=0,
                            stdout=json.dumps({"token": "child-token", "path": str(credential)}),
                        ),
                    ],
                ),
            ):
                result = runtime._start_gateway(Path("/bin/echo"), home)
            assert (result.url, result.client_token) == (
                "http://127.0.0.1:2222",
                "child-token",
            )
            gateway_environment = popen.call_args_list[1].kwargs["env"]
            assert gateway_environment["HOME"] == str(home)
            assert "OPENAI_API_KEY" not in gateway_environment
            assert stat.S_IMODE(credential.stat().st_mode) == 384

    def test_gateway_failure_stops_broker(self) -> None:
        broker = MagicMock()
        with (
            patch.object(runtime, "_wait_for"),
            patch.object(runtime.subprocess, "Popen", return_value=broker),
            patch.object(
                runtime.subprocess,
                "run",
                side_effect=runtime.subprocess.TimeoutExpired(["omp"], 15),
            ),
            patch.object(runtime, "_stop") as stop,
            pytest.raises(runtime.CredentialGatewayError, match="broker token issuance timed out"),
        ):
            runtime._start_gateway(Path("/bin/echo"), Path(tempfile.gettempdir()))
        stop.assert_called_once_with(broker)

    def test_role_json_requires_one_compact_object(self) -> None:
        assert dict(runtime._role_json('```json\n{"approved":true}\n```')) == {"approved": True}
        with pytest.raises(runtime.RoleRuntimeError, match="exactly one JSON"):
            runtime._role_json('{"approved":true} trailing')

    def test_sandbox_mounts_only_workspace_home_and_readonly_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, home, binary = root / "workspace", root / "home", root / "omp"
            workspace.mkdir()
            home.mkdir()
            binary.write_text("")
            command = runtime._sandbox(["omp"], workspace, home, (binary,))
        profile = command[2]
        assert str(workspace) in profile
        assert str(home) in profile
        assert str(binary) in profile
        assert 'network-outbound (remote ip "localhost:*")' in profile
        assert 'subpath "/Users' not in profile

    def test_execute_omp_places_child_tmpdir_under_project_experiments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            experiments = root / "experiments"
            workspace = root / "external-workspace"
            workspace.mkdir()
            native = root / "native"
            native.write_text("runtime")
            credential = root / "credential"
            credential.write_text("ephemeral")
            child = MagicMock(returncode=0)
            child.communicate.return_value = ('{"type":"agent_end"}\n', "")
            gateway = runtime._Gateway(
                MagicMock(),
                MagicMock(),
                "http://127.0.0.1:1",
                "client-token",
                credential,
            )
            with (
                patch.object(runtime, "_EXPERIMENTS_ROOT", experiments),
                patch.object(runtime, "_omp", return_value=Path("/bin/echo")),
                patch.object(
                    runtime,
                    "_runtime_native",
                    return_value=("18.0.1", native),
                ),
                patch.object(runtime, "_start_gateway", return_value=gateway),
                patch.object(runtime, "_sandbox", return_value=["omp"]),
                patch.object(runtime.subprocess, "Popen", return_value=child) as popen,
            ):
                runtime.execute_omp(
                    runtime.OmpExecutionRequest(
                        workspace,
                        "prompt",
                        self.request,
                        "system",
                        (),
                        False,
                    )
                )
                external_environment = popen.call_args.kwargs["env"]
                experiment = experiments / "20260831T142530.123456Z-subject-core-1-A-1-unique"
                experiment_workspace = experiment / "workspace"
                experiment_workspace.mkdir(parents=True)
                credential.write_text("ephemeral")
                runtime.execute_omp(
                    runtime.OmpExecutionRequest(
                        experiment_workspace,
                        "prompt",
                        self.request,
                        "system",
                        (),
                        False,
                    )
                )
                experiment_environment = popen.call_args.kwargs["env"]
            child_environment = external_environment
            child_tmpdir = Path(child_environment["TMPDIR"])
            runtime_directory = child_tmpdir.parent
            assert runtime_directory.parent == experiments
            assert re.fullmatch(
                r"\d{8}T\d{6}\.\d{6}Z-runtime-[A-Za-z0-9_-]+",
                runtime_directory.name,
            )
            assert not runtime_directory.exists()
            experiment_tmpdir = Path(experiment_environment["TMPDIR"])
            experiment_runtime_directory = experiment_tmpdir.parent
            assert experiment_runtime_directory.parent == experiment
            assert re.fullmatch(
                r"runtime-[A-Za-z0-9_-]+",
                experiment_runtime_directory.name,
            )
            assert not experiment_runtime_directory.exists()

    def test_snapshot_and_diff_include_empty_directories_and_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "empty").mkdir()
            (root / "value.txt").write_text("before\n")
            before = runtime.snapshot_workspace(root)
            (root / "empty").rmdir()
            (root / "created").mkdir()
            (root / "value.txt").write_text("after\n")
            changes = runtime.workspace_diff(before, runtime.snapshot_workspace(root))
        assert "removed directory/empty" in changes
        assert "created directory/created" in changes
        assert "before/value.txt" in changes
        assert "after/value.txt" in changes

    def _witness_fixture(
        self,
        root: Path,
        *,
        change_path: str = "result.txt",
        content: str | None = "yes",
    ) -> tuple[Fixture, ReachabilityWitness]:
        task = "produce one observable result"
        verifier = (
            b"from pathlib import Path\n"
            b"raise SystemExit(0 if Path('result.txt').read_text() == 'yes' else 1)\n"
        )
        observer = (
            b"import json\nfrom pathlib import Path\n"
            b"print(json.dumps({'result': Path('result.txt').read_text()}))\n"
        )
        root.mkdir()
        (root / "TASK.txt").write_text(task)
        (root / "verify.py").write_bytes(verifier)
        (root / "observe.py").write_bytes(observer)
        manifest = {
            "schema": "instruct-eval-fixture-manifest-v1",
            "files": [
                {
                    "path": path.name,
                    "sha256": runtime._sha256_file(path),
                }
                for path in sorted(root.iterdir())
            ],
        }
        witness = ReachabilityWitness(
            "witness-yes",
            "preferred",
            json.dumps(
                {
                    "schema": "instruct-eval-witness-input-v1",
                    "changes": [{"path": change_path, "content": content}],
                },
                separators=(",", ":"),
            ).encode(),
            True,
            (("result", "yes"),),
            "a" * 64,
            (("python3", "a" * 64),),
            (
                ("verify.py", runtime._sha256_file(root / "verify.py")),
                ("observe.py", runtime._sha256_file(root / "observe.py")),
            ),
            (change_path,),
        )
        fixture = Fixture(
            "core-1",
            task,
            manifest,
            canonical_hash(manifest),
            Verifier(verifier, runtime._sha256_file(root / "verify.py")),
            observer,
            runtime._sha256_file(root / "observe.py"),
            {"witness-yes": True},
            (EvidenceAxis("result", ("yes", "no")),),
            (Direction("preferred", "preferred result"), Direction("other", "other result")),
            {
                (False, "yes"): "preferred",
                (True, "yes"): "preferred",
                (False, "no"): "other",
                (True, "no"): "other",
            },
            (change_path,),
            (witness,),
            {
                "schema": "instruct-eval-evidence-contract-v1",
                "verifier_path": "verify.py",
                "observer_path": "observe.py",
                "verifier_command": ["python3", "verify.py"],
                "observer_command": ["python3", "observe.py"],
            },
            SourceClassification(
                "b" * 64,
                (SourceCoverage(0, 1, "claim_normative", "claim"),),
            ),
        )
        return fixture, witness

    def test_witness_execution_uses_clean_frozen_fixture_and_complete_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            experiments = root / "experiments"
            fixture, witness = self._witness_fixture(root / "fixture")
            with (
                patch.object(runtime, "_EXPERIMENTS_ROOT", experiments),
                patch.object(
                    runtime,
                    "_run_witness_commands",
                    wraps=runtime._run_witness_commands,
                ) as commands,
            ):
                result = runtime.run_witness(fixture, witness, root / "fixture")
            workspace = commands.call_args.args[1]
            experiment = self.assert_timestamped_workspace(
                workspace,
                experiments,
                "witness",
                witness.witness_id,
            )
            assert not experiment.exists()
        assert result.protocol_valid
        assert not result.contaminated
        assert result.verifier_passed
        assert result.observer_output == {"result": "yes"}
        assert result.changed_paths == ("result.txt",)
        assert set(result.unchanged_hashes) == {"verify.py", "observe.py"}
        assert set(result.tool_hashes) == {"python3"}

    def test_witness_execution_rejects_escape_symlink_and_manifest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fixture"
            fixture, witness = self._witness_fixture(
                root,
                change_path="../escape.txt",
            )
            with pytest.raises(runtime.RoleRuntimeError, match="escapes"):
                runtime.run_witness(fixture, witness, root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fixture"
            fixture, witness = self._witness_fixture(root)
            (root / "foreign-link").symlink_to(root / "TASK.txt")
            with pytest.raises(runtime.RoleRuntimeError, match="symlink"):
                runtime.run_witness(fixture, witness, root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fixture"
            fixture, witness = self._witness_fixture(root)
            (root / "TASK.txt").write_text("altered")
            with pytest.raises(runtime.RoleRuntimeError, match=r"frozen task|frozen manifest"):
                runtime.run_witness(fixture, witness, root)

    def test_witness_execution_reports_modified_frozen_evidence_as_contamination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fixture"
            fixture, _ = self._witness_fixture(
                root, change_path="verify.py", content="raise SystemExit(1)\n"
            )
            witness = ReachabilityWitness(
                "witness-yes",
                "preferred",
                json.dumps(
                    {
                        "schema": "instruct-eval-witness-input-v1",
                        "changes": [
                            {"path": "verify.py", "content": "raise SystemExit(1)\n"},
                            {"path": "result.txt", "content": "yes"},
                        ],
                    },
                    separators=(",", ":"),
                ).encode(),
                False,
                (("result", "yes"),),
                "a" * 64,
                (("python3", "a" * 64),),
                (
                    ("verify.py", runtime._sha256_file(root / "verify.py")),
                    ("observe.py", runtime._sha256_file(root / "observe.py")),
                ),
                ("result.txt", "verify.py"),
            )
            fixture = Fixture(
                fixture.fixture_id,
                fixture.task,
                fixture.manifest,
                fixture.manifest_sha256,
                fixture.verifier,
                fixture.observe_source,
                fixture.observe_sha256,
                {"witness-yes": False},
                fixture.axes,
                fixture.directions,
                fixture.outcome_table,
                ("verify.py", "result.txt"),
                (witness,),
                fixture.evidence_contract,
                fixture.source_classification,
            )
            result = runtime.run_witness(fixture, witness, root)
        assert result.contaminated
        assert not result.verifier_passed

    def test_workspace_diff_explicitly_marks_empty_file_additions_and_deletions(self) -> None:
        before = runtime.WorkspaceSnapshot({"removed-empty.txt": ""}, ())
        after = runtime.WorkspaceSnapshot({"created-empty.txt": ""}, ())
        changes = runtime.workspace_diff(before, after)
        assert "removed file/removed-empty.txt" in changes
        assert "created file/created-empty.txt" in changes

    def test_workspace_snapshot_and_diff_reject_evidence_overflow(self) -> None:
        oversized = "x" * (runtime._MAX_EVIDENCE_BYTES + 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "oversized.txt").write_text(oversized)
            with pytest.raises(
                runtime.RoleRuntimeError, match="snapshot exceeds the evidence bound"
            ):
                runtime.snapshot_workspace(root)
        diff_sized = "x" * (runtime._MAX_EVIDENCE_BYTES // 2 + 1)
        before = runtime.WorkspaceSnapshot({"value.txt": diff_sized}, ())
        after = runtime.WorkspaceSnapshot({"value.txt": "y" * len(diff_sized)}, ())
        with pytest.raises(runtime.RoleRuntimeError, match="diff exceeds the evidence bound"):
            runtime.workspace_diff(before, after)

    def test_subject_control_removes_treatment_from_runtime_request_and_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            experiments = root / "experiments"
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "TASK.txt").write_text("task")
            (fixture / "verify.py").write_text("raise SystemExit(0)\n")
            executions: list[runtime.OmpExecutionRequest] = []

            def capture(execution: runtime.OmpExecutionRequest) -> runtime.ExecutionResult:
                executions.append(execution)
                return runtime.ExecutionResult("done", None, ())

            with (
                patch.object(runtime, "_EXPERIMENTS_ROOT", experiments),
                patch.object(runtime, "execute_omp", side_effect=capture),
            ):
                runtime.run_subject("core-1-A-1", "A", fixture, self.request)
                runtime.run_subject("core-1-B-1", "B", fixture, self.request)

        control, treatment = executions
        assert "candidate_instruction" not in control.request
        assert control.prompt == "task"
        assert treatment.request["candidate_instruction"] == "private treatment"
        assert treatment.prompt.endswith(
            "Apply this additional instruction while completing the task:\nprivate treatment"
        )

    def test_subject_rejects_modified_verifier_or_observer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            experiments = root / "experiments"
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "TASK.txt").write_text("task")
            (fixture / "verify.py").write_text("raise SystemExit(0)\n")
            (fixture / "observer.py").write_text("raise SystemExit(0)\n")
            workspaces: list[Path] = []

            def mutate(execution: runtime.OmpExecutionRequest) -> runtime.ExecutionResult:
                workspaces.append(execution.workspace)
                (execution.workspace / "verify.py").write_text("changed")
                return runtime.ExecutionResult("done", None, ())

            with (
                patch.object(runtime, "_EXPERIMENTS_ROOT", experiments),
                patch.object(runtime, "execute_omp", side_effect=mutate),
            ):
                result = runtime.run_subject(
                    "core-1-A-1",
                    "A",
                    fixture,
                    self.request,
                    observer_paths=("observer.py",),
                )
            experiment = self.assert_timestamped_workspace(
                workspaces[0],
                experiments,
                "subject",
                "core-1-A-1",
            )
            assert not experiment.exists()
        assert not result.protocol_valid
        assert not result.verifier_passed
        assert result.reason == "public verifier or observer was modified"
        assert "valid" not in result.as_json()
        assert "verify.py" in result.unchanged_hashes
        assert "observer.py" in result.unchanged_hashes

    def test_subject_retains_observer_evidence_when_verifier_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"
            fixture.mkdir()
            (fixture / "TASK.txt").write_text("task")
            (fixture / "verify.py").write_text("raise SystemExit(1)\n")
            (fixture / "observer.py").write_text("print('evidence')\n")
            with patch.object(
                runtime, "execute_omp", return_value=runtime.ExecutionResult("done", None, ())
            ):
                result = runtime.run_subject(
                    "core-1-A-1", "A", fixture, self.request, observer_paths=("observer.py",)
                )
        assert result.protocol_valid
        assert not result.verifier_passed
        assert result.reason == "public fixture verifier failed"
        assert result.observer_output == {"observer.py": "evidence\n"}
        assert not result.as_json()["verifier_passed"]

    def test_subject_rejects_observer_stdout_overflow_without_retaining_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"
            fixture.mkdir()
            (fixture / "TASK.txt").write_text("task")
            (fixture / "verify.py").write_text("raise SystemExit(0)\n")
            (fixture / "observer.py").write_text(
                f"print('x' * {runtime._MAX_EVIDENCE_BYTES + 1})\n"
            )
            with patch.object(
                runtime, "execute_omp", return_value=runtime.ExecutionResult("done", None, ())
            ):
                result = runtime.run_subject(
                    "core-1-A-1", "A", fixture, self.request, observer_paths=("observer.py",)
                )
        assert not result.protocol_valid
        assert result.verifier_passed
        assert result.observer_output == {}
        assert "observer stdout exceeds the evidence bound" in (result.reason or "")

    def test_subject_preserves_verifier_result_when_observer_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"
            fixture.mkdir()
            (fixture / "TASK.txt").write_text("task")
            (fixture / "verify.py").write_text("raise SystemExit(0)\n")
            (fixture / "observer.py").write_text("raise SystemExit(1)\n")
            with patch.object(
                runtime, "execute_omp", return_value=runtime.ExecutionResult("done", None, ())
            ):
                result = runtime.run_subject(
                    "core-1-A-1", "A", fixture, self.request, observer_paths=("observer.py",)
                )
        assert not result.protocol_valid
        assert result.verifier_passed
        assert result.reason == "public fixture observer failed"

    def test_subject_marks_malformed_runtime_output_protocol_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"
            fixture.mkdir()
            (fixture / "TASK.txt").write_text("task")
            (fixture / "verify.py").write_text("raise SystemExit(0)\n")
            with patch.object(
                runtime,
                "execute_omp",
                side_effect=runtime.RoleRuntimeError("OMP JSON stream is malformed"),
            ):
                result = runtime.run_subject("core-1-A-1", "A", fixture, self.request)
        assert not result.protocol_valid
        assert not result.verifier_passed
        assert result.reason == "subject execution failed: OMP JSON stream is malformed"

    def test_role_packet_does_not_include_private_request_data(self) -> None:
        captured: dict[str, str | Path] = {}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            experiments = root / "experiments"
            contract = root / "role.md"
            contract.write_text("contract")

            def execute(execution: runtime.OmpExecutionRequest) -> runtime.ExecutionResult:
                captured["prompt"] = execution.prompt
                captured["system"] = execution.system_prompt
                captured["workspace"] = execution.workspace
                return runtime.ExecutionResult('{"approved":true}', {"approved": True}, ())

            private_request = {**self.request, "private_maps": {"join": "do-not-leak"}}
            with (
                patch.object(runtime, "_EXPERIMENTS_ROOT", experiments),
                patch.object(runtime, "execute_omp", side_effect=execute),
            ):
                result = runtime.invoke_role(contract, {"public": "packet"}, private_request)
            workspace = captured["workspace"]
            assert isinstance(workspace, Path)
            experiment = self.assert_timestamped_workspace(
                workspace,
                experiments,
                "role",
                "role",
            )
            assert not experiment.exists()
        assert dict(result) == {"approved": True}
        prompt = captured["prompt"]
        system_prompt = captured["system"]
        assert isinstance(prompt, str)
        assert isinstance(system_prompt, str)
        assert "do-not-leak" not in prompt
        assert "do-not-leak" not in system_prompt


if __name__ == "__main__":
    unittest.main()
