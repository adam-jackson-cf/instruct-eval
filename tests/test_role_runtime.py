from __future__ import annotations

import json
import re
import socket
import stat
import tempfile
import unittest
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from instruct_eval import role_runtime as runtime
from instruct_eval.behavior import OBSERVATION_CONTRACT
from instruct_eval.models import (
    Direction,
    EvidenceAxis,
    Fixture,
    ReachabilityWitness,
    SourceClassification,
    SourceCoverage,
    Verifier,
    canonical_bytes,
    canonical_hash,
)
from instruct_eval.trials import scan_disclosure


def _generated_disclosures(prompt: str, treatment: str) -> list[dict[str, object]]:
    return [
        {
            "type": "message_update",
            "partial": {
                "role": "assistant",
                "content": [{"type": "thinking", "thinking": treatment}],
            },
        },
        {
            "type": "tool_execution_start",
            "toolCallId": "generated-read",
            "toolName": "read",
            "args": {"path": ".omp/AGENTS.md"},
        },
        {
            "type": "tool_execution_end",
            "toolCallId": "generated-read",
            "toolName": "read",
            "isError": False,
            "result": {
                "content": [{"type": "text", "text": treatment}],
                "details": {"role": "user", "content": [{"type": "text", "text": prompt}]},
            },
        },
        {"type": "runtime_diagnostic", "message": treatment},
    ]


def _native_input_result(input_path: str, treatment: str) -> dict[str, Any]:
    lines = treatment.count("\n") + 1
    return {
        "content": [{"type": "text", "text": treatment}],
        "details": {
            "totalLines": lines,
            "displayContent": {
                "text": treatment,
                "startLine": 1,
                "lineNumbers": list(range(1, lines + 1)),
            },
            "fileSize": len(treatment.encode("utf-8")),
            "meta": {"source": {"type": "path", "value": input_path}},
        },
    }


def _native_input_events(
    input_path: str, treatment: str, fault: str = ""
) -> list[dict[str, object]]:
    result = _native_input_result(input_path, treatment)
    message = {
        "role": "toolResult",
        "toolCallId": "context-read",
        "toolName": "read",
        "isError": False,
        **_native_input_result(input_path, treatment),
    }
    faults: dict[str, tuple[dict[str, Any], str, Any]] = {
        "altered": (result, "content", [{"type": "text", "text": treatment + " altered"}]),
        "partial": (result["details"]["displayContent"], "lineNumbers", []),
        "wrong_provenance": (
            result["details"]["meta"],
            "source",
            {"type": "path", "value": input_path + ".untrusted"},
        ),
        "missing_provenance": (result["details"], "meta", {}),
        "forged_call_id": (message, "toolCallId", "forged-read"),
        "forged_metadata": (message["details"], "fileSize", 0),
        "boolean_file_size": (result["details"], "fileSize", True),
        "floating_file_size": (
            result["details"],
            "fileSize",
            float(len(treatment.encode("utf-8"))),
        ),
        "boolean_line_numbers": (result["details"]["displayContent"], "lineNumbers", [True]),
    }
    if fault:
        target, key, value = faults[fault]
        target[key] = value
    return [
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
            "result": result,
        },
        {"type": "message_start", "message": message},
        {"type": "message_end", "message": message},
        {"type": "turn_end", "toolResults": [message]},
    ]


class RoleRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.request = {
            "candidate_instruction": "private treatment",
            "model": {"provider": "openai-codex", "identifier": "test", "thinking": "low"},
            "runtime": {"version": "18.1.10", "timeout_seconds": 10},
            "permissions": {
                "approval_mode": "auto",
                "tools": ["read", "edit", "write", "glob", "grep", "bash"],
            },
        }

    @staticmethod
    def omp_stream(
        prompt: str,
        generated: list[dict[str, object]],
        response: dict[str, str] | None = None,
    ) -> str:
        user = {"role": "user", "content": [{"type": "text", "text": prompt}]}
        response = response or {"completion": "complete", "summary": "done"}
        assistant = {
            "role": "assistant",
            "content": [{"type": "text", "text": json.dumps(response, separators=(",", ":"))}],
            "stopReason": "stop",
        }
        events = [
            {"type": "message_start", "message": user},
            {"type": "message_end", "message": user},
            {"type": "instruct_eval_observer_ready", "origin": "runtime_observer"},
            *generated,
            {"type": "message_end", "message": assistant},
            {
                "type": "agent_end",
                "stopReason": "stop",
                "messages": [
                    user,
                    *[
                        event["message"]
                        for event in generated
                        if event.get("type") == "message_end"
                    ],
                    assistant,
                ],
            },
        ]
        return "".join(json.dumps(event) + "\n" for event in events)

    def subject_execution(self, prompt: str = "task") -> runtime.ExecutionResult:
        output_events = self.omp_stream(prompt, [])
        return runtime._terminal_output(output_events, "", prompt=prompt, required=False)

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
            child = MagicMock()
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
                    return_value=("18.1.10", native),
                ),
                patch.object(runtime, "_start_gateway", return_value=gateway),
                patch.object(runtime, "_sandbox", return_value=["omp"]),
                patch.object(
                    runtime,
                    "_communicate_omp",
                    return_value=runtime.ExecutionResult("", None, (), "", True),
                ) as communicate,
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
                assert communicate.call_count == 2
                assert all(call.args[0] is child for call in communicate.call_args_list)
            child_environment = external_environment
            child_tmpdir = Path(child_environment["TMPDIR"])
            runtime_home = Path(child_environment["HOME"])
            assert child_tmpdir.is_relative_to(runtime_home)
            runtime_directory = runtime_home.parent
            assert runtime_directory.parent == experiments
            assert re.fullmatch(
                r"\d{8}T\d{6}\.\d{6}Z-runtime-[A-Za-z0-9_-]+",
                runtime_directory.name,
            )
            assert not runtime_directory.exists()
            experiment_tmpdir = Path(experiment_environment["TMPDIR"])
            experiment_home = Path(experiment_environment["HOME"])
            assert experiment_tmpdir.is_relative_to(experiment_home)
            experiment_runtime_directory = experiment_home.parent
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
        completion: str = "complete",
    ) -> tuple[Fixture, ReachabilityWitness]:
        task = "produce one observable result"
        verifier = (
            b"from pathlib import Path\n"
            b"raise SystemExit(0 if Path('result.txt').read_text() == 'yes' else 1)\n"
        )
        observer = (
            b"import json\nfrom pathlib import Path\n"
            b"observation = json.load(__import__('sys').stdin)\n"
            b"print(json.dumps({'result': Path('result.txt').read_text(), "
            b"'completion': observation['response']['completion']}))\n"
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
            "public_files": {},
        }
        witness = ReachabilityWitness(
            "witness-yes",
            "preferred",
            canonical_bytes(
                {
                    "schema": "instruct-eval-witness-input-v1",
                    "actions": [
                        {"tool": "write", "path": change_path, "content": content},
                        {
                            "tool": "respond",
                            "response": {"completion": completion, "summary": "yes"},
                        },
                    ],
                }
            ),
            True,
            (("result", "yes"), ("completion", completion)),
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
                "observation_contract": OBSERVATION_CONTRACT,
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
            assert commands.call_args.args[2] == {
                "origin": "witness",
                "terminal": "witness_return",
                "response": {"completion": "complete", "summary": "yes"},
                "events": [
                    {
                        "tool": "write",
                        "arguments": {"path": "result.txt", "content": "yes"},
                        "is_error": False,
                        "exit_code": None,
                        "gate_snapshots": [],
                        "changed_paths": ["result.txt"],
                    },
                ],
            }
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
        assert result.observer_output == {"result": "yes", "completion": "complete"}
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
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fixture"
            fixture, witness = self._witness_fixture(root)
            manifest = {
                **fixture.manifest,
                "public_files": {"verify.py": "raise SystemExit(0)\n"},
            }
            malformed_fixture = replace(
                fixture,
                manifest=manifest,
                manifest_sha256=canonical_hash(manifest),
            )
            with pytest.raises(runtime.RoleRuntimeError):
                runtime.run_witness(malformed_fixture, witness, root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fixture"
            fixture, witness = self._witness_fixture(root, completion="incomplete")
            result = runtime.run_witness(fixture, witness, root)
            assert result.observer_output["completion"] == "incomplete"
            malformed_actions = json.loads(witness.input_bytes)["actions"]
            malformed_actions.append({"tool": "write", "path": "later.txt", "content": "no"})
            malformed_witness = replace(
                witness,
                input_bytes=canonical_bytes(
                    {"schema": "instruct-eval-witness-input-v1", "actions": malformed_actions}
                ),
            )
            with pytest.raises(runtime.RoleRuntimeError, match=r"respond|malformed"):
                runtime.run_witness(fixture, malformed_witness, root)

    def test_witness_execution_reports_modified_frozen_evidence_as_contamination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "fixture"
            fixture, _ = self._witness_fixture(
                root, change_path="verify.py", content="raise SystemExit(1)\n"
            )
            witness = ReachabilityWitness(
                "witness-yes",
                "preferred",
                canonical_bytes(
                    {
                        "schema": "instruct-eval-witness-input-v1",
                        "actions": [
                            {
                                "tool": "write",
                                "path": "verify.py",
                                "content": "raise SystemExit(1)\n",
                            },
                            {"tool": "write", "path": "result.txt", "content": "yes"},
                            {
                                "tool": "respond",
                                "response": {
                                    "completion": "incomplete",
                                    "summary": "contaminated",
                                },
                            },
                        ],
                    }
                ),
                False,
                (("result", "yes"), ("completion", "incomplete")),
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

    def test_gate_snapshot_server_records_actual_changes_since_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "result.txt").write_text("before")
            with runtime._gate_snapshot_server(workspace) as server:
                with socket.create_connection(("127.0.0.1", server.port)) as client:
                    client.sendall(b'{"script":"check.py"}\n')
                    assert client.recv(3) == b"ok\n"
                (workspace / "result.txt").write_text("after")
                snapshots = server.changed_paths(runtime.snapshot_workspace(workspace))
        assert snapshots == [{"script": "check.py", "changed_paths": ["result.txt"]}]

    def test_subject_control_removes_treatment_from_runtime_request_and_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            experiments = root / "experiments"
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "TASK.txt").write_text("task")
            (fixture / "verify.py").write_text("raise SystemExit(0)\n")
            injected = root / "fixture-with-agents"
            injected.mkdir()
            (injected / "TASK.txt").write_text("task")
            (injected / "verify.py").write_text("raise SystemExit(0)\n")
            (injected / "AGENTS.md").write_text("untrusted context")
            with pytest.raises(
                runtime.RoleRuntimeError, match="frozen fixture contains runtime context files"
            ):
                runtime.run_subject("core-1-A-2", "A", injected, self.request)
            executions: list[runtime.OmpExecutionRequest] = []
            contexts: list[str | None] = []

            def capture(execution: runtime.OmpExecutionRequest) -> runtime.ExecutionResult:
                executions.append(execution)
                agents = execution.workspace / ".omp" / "AGENTS.md"
                contexts.append(agents.read_text() if agents.is_file() else None)
                stdout = self.omp_stream(execution.prompt, [])
                return runtime._terminal_output(stdout, "", prompt=execution.prompt, required=False)

            with (
                patch.object(runtime, "_EXPERIMENTS_ROOT", experiments),
                patch.object(runtime, "execute_omp", side_effect=capture),
            ):
                results = [
                    runtime.run_subject("core-1-A-1", "A", fixture, self.request),
                    runtime.run_subject("core-1-B-1", "B", fixture, self.request),
                ]

        control, treatment = executions
        assert "candidate_instruction" not in control.request
        assert control.prompt == treatment.prompt == "task"
        assert treatment.request["candidate_instruction"] == "private treatment"
        assert contexts == [None, "private treatment"]
        for execution in executions:
            assert not scan_disclosure(
                raw=str(execution.workspace).encode(),
                treatment=self.request["candidate_instruction"],
            )
        assert all(result.protocol_valid for result in results)
        assert not scan_disclosure(
            raw=results[1].runtime_stdout.encode(),
            treatment=self.request["candidate_instruction"],
        )
        assert all(
            not scan_disclosure(
                raw=result.runtime_output_events.encode(),
                treatment=self.request["candidate_instruction"],
            )
            for result in results
        )

    def test_tool_free_rpc_does_not_issue_subject_control(self) -> None:
        capture = runtime._RpcCapture()
        pipe = BytesIO()
        for method in ("notify", "setTitle", "select"):
            capture.respond({"type": "extension_ui_request", "id": method, "method": method}, pipe)
        assert pipe.getvalue() == b""
        assert capture.approvals.failure is None

    def test_native_approvals_wait_for_observation_and_execution_end(self) -> None:
        def event(kind: str, identity: str, **values: object) -> dict[str, object]:
            return {"type": kind, "toolCallId": identity, "toolName": "bash", **values}

        for first_completion in ("instruct_eval_tool_observation", "tool_execution_end"):
            approvals = runtime._NativeApprovals(True)
            for identity in ("first", "second"):
                assert approvals.commands(event("tool_execution_start", identity)) == ()
                assert (
                    approvals.commands(
                        event(
                            "instruct_eval_tool_admission",
                            identity,
                            origin="runtime_observer",
                            phase="requested",
                        )
                    )
                    == ()
                )
            first = approvals.commands(
                {
                    "type": "extension_ui_request",
                    "id": "dialog-first",
                    "method": "select",
                    "options": ["Approve", "Deny"],
                }
            )
            assert first == (
                {
                    "type": "extension_ui_response",
                    "id": "dialog-first",
                    "value": "Approve",
                },
            )
            assert (
                approvals.commands(
                    {
                        "type": "extension_ui_request",
                        "id": "dialog-second",
                        "method": "select",
                        "options": ["Approve", "Deny"],
                    }
                )
                == ()
            )
            for method in ("notify", "setStatus", "setWidget", "setTitle", "set_editor_text"):
                assert (
                    approvals.commands(
                        {
                            "type": "extension_ui_request",
                            "id": method,
                            "method": method,
                        }
                    )
                    == ()
                )
            # UI identity does not encode the call: native resolution establishes that join.
            assert (
                approvals.commands(
                    event(
                        "instruct_eval_tool_admission",
                        "second",
                        origin="runtime_observer",
                        phase="admitted",
                    )
                )
                == ()
            )
            second_completion = (
                "tool_execution_end"
                if first_completion == "instruct_eval_tool_observation"
                else "instruct_eval_tool_observation"
            )
            assert (
                approvals.commands(
                    event(
                        first_completion,
                        "second",
                        origin="runtime_observer",
                    )
                )
                == ()
            )
            released = approvals.commands(
                event(
                    second_completion,
                    "second",
                    origin="runtime_observer",
                )
            )
            assert released == (
                {
                    "type": "extension_ui_response",
                    "id": "dialog-second",
                    "value": "Approve",
                },
            )
            assert (
                approvals.commands(
                    event(
                        "instruct_eval_tool_admission",
                        "first",
                        origin="runtime_observer",
                        phase="admitted",
                    )
                )
                == ()
            )
            assert (
                approvals.commands(
                    event(
                        "instruct_eval_tool_observation",
                        "first",
                        origin="runtime_observer",
                    )
                )
                == ()
            )
            assert approvals.commands(event("tool_execution_end", "first")) == ()
            assert approvals.commands({"type": "agent_end"}) == ()
            assert approvals.failure is None

    def test_native_approvals_cancel_instead_of_authorizing_uncorrelated_work(self) -> None:
        for fault in ("unmatched_resolution", "duplicate_dialog", "missing_completion"):
            approvals = runtime._NativeApprovals(True)
            for identity in ("first", "second"):
                approvals.commands(
                    {
                        "type": "tool_execution_start",
                        "toolCallId": identity,
                        "toolName": "write",
                    }
                )
                approvals.commands(
                    {
                        "type": "instruct_eval_tool_admission",
                        "origin": "runtime_observer",
                        "phase": "requested",
                        "toolCallId": identity,
                        "toolName": "write",
                    }
                )
                approvals.commands(
                    {
                        "type": "extension_ui_request",
                        "id": identity,
                        "method": "select",
                        "options": ["Approve", "Deny"],
                    }
                )
            faults = {
                "unmatched_resolution": {
                    "type": "instruct_eval_tool_admission",
                    "origin": "runtime_observer",
                    "phase": "admitted",
                    "toolCallId": "unknown",
                    "toolName": "write",
                },
                "duplicate_dialog": {
                    "type": "extension_ui_request",
                    "id": "second",
                    "method": "select",
                    "options": ["Approve", "Deny"],
                },
                "missing_completion": {"type": "agent_end"},
            }
            rejected = approvals.commands(faults[fault])
            assert rejected == (
                {"type": "abort", "id": "native-approval-abort"},
                {"type": "extension_ui_response", "id": "second", "cancelled": True},
            )
            assert approvals.failure is not None
            assert approvals.commands(
                {
                    "type": "extension_ui_request",
                    "id": "later",
                    "method": "select",
                    "options": ["Approve", "Deny"],
                }
            ) == ({"type": "extension_ui_response", "id": "later", "cancelled": True},)

    def test_subject_verifies_input_and_preserves_generated_disclosure_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "fixture"
            fixture.mkdir()
            (fixture / "TASK.txt").write_text("task")
            (fixture / "verify.py").write_text("raise SystemExit(0)\n")
            treatment = self.request["candidate_instruction"]
            mode = "generated"
            streams: list[str] = []

            def capture(execution: runtime.OmpExecutionRequest) -> runtime.ExecutionResult:
                prompt = execution.prompt + (" altered" if mode == "mismatch" else "")
                stdout = self.omp_stream(
                    prompt, _generated_disclosures(execution.prompt, treatment)
                )
                if mode == "missing":
                    stdout = "\n".join(stdout.splitlines()[1:]) + "\n"
                elif mode == "duplicate":
                    stdout = stdout.splitlines(keepends=True)[0] + stdout
                failure = None
                if mode in ("approval", "approval_unfinished"):
                    failure = "OMP native approval resolution is uncorrelated"
                    if mode == "approval_unfinished":
                        stdout = "\n".join(stdout.splitlines()[:-1]) + "\n"
                streams.append(stdout)
                return runtime._terminal_output(
                    stdout,
                    "",
                    prompt=execution.prompt,
                    required=False,
                    context=runtime._TerminalContext(
                        protocol_failure=failure,
                        input_file=(str(execution.workspace / ".omp" / "AGENTS.md"), treatment),
                    ),
                )

            with (
                patch.object(runtime, "_EXPERIMENTS_ROOT", Path(temporary) / "experiments"),
                patch.object(runtime, "execute_omp", side_effect=capture),
            ):
                result = runtime.run_subject("core-1-B-1", "B", fixture, self.request)
                assert result.protocol_valid
                assert result.runtime_stdout == streams[-1]
                assert result.tool_outputs == result.disclosure_tool_outputs == (treatment,)
                assert scan_disclosure(raw=result.runtime_stdout.encode(), treatment=treatment)
                events = [json.loads(line) for line in result.runtime_output_events.splitlines()]
                for kind in ("message_update", "runtime_diagnostic", "tool_execution_end"):
                    event = next(event for event in events if event["type"] == kind)
                    assert scan_disclosure(raw=json.dumps(event).encode(), treatment=treatment)
                for mode in ("mismatch", "missing", "duplicate", "approval", "approval_unfinished"):
                    rejected = runtime.run_subject("core-1-B-1", "B", fixture, self.request)
                    assert not rejected.protocol_valid, mode
                    assert rejected.runtime_stdout == streams[-1]

    def test_subject_projects_only_verified_native_input_reads(self) -> None:
        treatment = self.request["candidate_instruction"]
        input_path = "/workspace/.omp/AGENTS.md"
        context = runtime._TerminalContext(input_file=(input_path, treatment))
        for fault in (
            "",
            "altered",
            "partial",
            "wrong_provenance",
            "missing_provenance",
            "forged_call_id",
            "forged_metadata",
            "boolean_file_size",
            "floating_file_size",
            "boolean_line_numbers",
        ):
            stdout = self.omp_stream("task", _native_input_events(input_path, treatment, fault))
            result = runtime._terminal_output(
                stdout, "", prompt="task", required=False, context=context
            )
            assert result.stdout == stdout
            assert scan_disclosure(raw=result.stdout.encode(), treatment=treatment)
            assert scan_disclosure(raw=result.output_events.encode(), treatment=treatment) is bool(
                fault
            ), fault
        generated = [
            *_native_input_events(input_path, treatment),
            *_generated_disclosures("task", treatment),
        ]
        stdout = self.omp_stream("task", generated)
        result = runtime._terminal_output(
            stdout, "", prompt="task", required=False, context=context
        )
        assert result.stdout == stdout
        assert result.tool_outputs == (treatment, treatment)
        assert len(result.disclosure_tool_outputs) == 2
        assert not scan_disclosure(
            raw=result.disclosure_tool_outputs[0].encode(), treatment=treatment
        )
        assert result.disclosure_tool_outputs[1] == treatment
        events = [json.loads(line) for line in result.output_events.splitlines()]
        for kind in ("message_update", "runtime_diagnostic"):
            event = next(event for event in events if event["type"] == kind)
            assert scan_disclosure(raw=json.dumps(event).encode(), treatment=treatment)

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
                return self.subject_execution(execution.prompt)

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
            experiment = workspaces[0].parent
            assert experiment.parent == experiments
            assert not experiment.exists()
        assert not result.protocol_valid
        assert not result.verifier_passed
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
                runtime,
                "execute_omp",
                return_value=self.subject_execution(),
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
                runtime,
                "execute_omp",
                return_value=self.subject_execution(),
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
                runtime,
                "execute_omp",
                return_value=self.subject_execution(),
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
                return runtime.ExecutionResult(
                    '{"approved":true}', {"approved": True}, (), "", True
                )

            private_request = {**self.request, "private_maps": {"join": "do-not-leak"}}
            with (
                patch.object(runtime, "_EXPERIMENTS_ROOT", experiments),
                patch.object(runtime, "execute_omp", side_effect=execute),
            ):
                result = runtime.invoke_role(
                    contract,
                    {"sources": (runtime.prepare_decomposition_packet("public packet"),)},
                    private_request,
                )
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
        assert json.loads(prompt.split("\n", 1)[1])["sources"][0]["instruction"] == "public packet"
        assert "do-not-leak" not in prompt
        assert "do-not-leak" not in system_prompt


if __name__ == "__main__":
    unittest.main()
