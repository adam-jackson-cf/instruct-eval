from __future__ import annotations

import json

import pytest

from instruct_eval.behavior import BehaviorError, project_subject_evidence

_RESPONSE = json.dumps({"completion": "complete", "summary": "Finished"})


def _terminal(response: str = _RESPONSE) -> dict[str, object]:
    return {
        "type": "agent_end",
        "messages": [
            {
                "role": "assistant",
                "stopReason": "stop",
                "content": [{"type": "text", "text": response}],
            }
        ],
    }


def _events(*events: dict[str, object]) -> str:
    return "".join(json.dumps(event) + "\n" for event in events)


def _start(call_id: str, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
    return {
        "type": "tool_execution_start",
        "toolCallId": call_id,
        "toolName": tool_name,
        "args": arguments,
    }


def _observer_ready() -> dict[str, object]:
    return {"type": "instruct_eval_observer_ready", "origin": "runtime_observer"}


def _observation(
    call_id: str,
    tool_name: str,
    changed_paths: object,
    gate_snapshots: object = (),
) -> dict[str, object]:
    return {
        "type": "instruct_eval_tool_observation",
        "origin": "runtime_observer",
        "toolCallId": call_id,
        "toolName": tool_name,
        "changed_paths": changed_paths,
        "gate_snapshots": (
            list(gate_snapshots) if isinstance(gate_snapshots, tuple) else gate_snapshots
        ),
    }


def _end(
    call_id: str,
    tool_name: str,
    *,
    is_error: bool = False,
    result: object = None,
) -> dict[str, object]:
    return {
        "type": "tool_execution_end",
        "toolCallId": call_id,
        "toolName": tool_name,
        "isError": is_error,
        "result": result,
    }


def test_projects_truthful_edit_and_command_order() -> None:
    output_events = _events(
        _observer_ready(),
        _start("read", "read", {"path": "TASK.txt"}),
        _end("read", "read", result={}),
        _start("edit", "edit", {"patch": "*** Begin Patch"}),
        _observation("edit", "edit", []),
        _end("edit", "edit", result={}),
        _start("bash", "bash", {"command": "python3 verify.py"}),
        _observation("bash", "bash", [], [{"script": "check.py", "changed_paths": ["service.py"]}]),
        _end("bash", "bash", is_error=True, result={"details": {"exitCode": 1}}),
        _start("repair", "write", {"path": "service.py", "content": "repaired"}),
        _observation("repair", "write", ["service.py"]),
        _end("repair", "write", result={}),
        _start("retry", "bash", {"command": "python3 verify.py"}),
        _observation("retry", "bash", []),
        _end("retry", "bash", result={"details": {"timeoutSeconds": 300, "wallTimeMs": 18.4}}),
        _terminal(),
    )

    evidence = project_subject_evidence(output_events, _RESPONSE)
    assert evidence["origin"] == "subject"
    assert evidence["terminal"] == "agent_end"
    assert evidence["response"] == json.loads(_RESPONSE)
    assert evidence["events"] == [
        {
            "tool": "edit",
            "arguments": {"patch": "*** Begin Patch"},
            "is_error": False,
            "exit_code": None,
            "changed_paths": [],
            "gate_snapshots": [],
        },
        {
            "tool": "bash",
            "arguments": {"command": "python3 verify.py"},
            "is_error": True,
            "exit_code": 1,
            "changed_paths": [],
            "gate_snapshots": [{"script": "check.py", "changed_paths": ["service.py"]}],
        },
        {
            "tool": "write",
            "arguments": {"path": "service.py", "content": "repaired"},
            "is_error": False,
            "exit_code": None,
            "changed_paths": ["service.py"],
            "gate_snapshots": [],
        },
        {
            "tool": "bash",
            "arguments": {"command": "python3 verify.py"},
            "is_error": False,
            "exit_code": 0,
            "changed_paths": [],
            "gate_snapshots": [],
        },
    ]


def test_reports_command_failure_from_structured_result() -> None:
    output_events = _events(
        _observer_ready(),
        _start("command", "bash", {"command": "python3 verify.py"}),
        _observation("command", "bash", []),
        _end(
            "command",
            "bash",
            is_error=True,
            result={"details": {"exitCode": 17}},
        ),
        _terminal(),
    )

    assert project_subject_evidence(output_events, _RESPONSE)["events"] == [
        {
            "tool": "bash",
            "arguments": {"command": "python3 verify.py"},
            "is_error": True,
            "exit_code": 17,
            "changed_paths": [],
            "gate_snapshots": [],
        }
    ]


@pytest.mark.parametrize(
    "output_events",
    [
        _events(
            _observer_ready(),
            _start("call", "write", {"path": "result.txt", "content": "done"}),
            _observation("call", "write", ["result.txt"]),
            _end("call", "edit", result={}),
            _terminal(),
        ),
        _events(
            _observer_ready(),
            _start("call", "write", {"path": "result.txt", "content": "done"}),
            _terminal(),
        ),
    ],
)
def test_rejects_mismatched_or_missing_completion(output_events: str) -> None:
    with pytest.raises(BehaviorError):
        project_subject_evidence(output_events, _RESPONSE)


@pytest.mark.parametrize(
    "output_events",
    [
        _events(
            _observer_ready(),
            _start("call", "read", {"path": "result.txt"}),
            _start("call", "read", {"path": "result.txt"}),
            _end("call", "read", result={}),
            _terminal(),
        ),
        _events(
            _observer_ready(),
            _start("call", "write", {"path": "result.txt", "content": "done"}),
            _observation("call", "write", ["result.txt"]),
            _end("call", "write", result={}),
            _end("call", "write", result={}),
            _terminal(),
        ),
        _events(
            _observer_ready(),
            _start("call", "write", {"path": "result.txt", "content": "done"}),
            _observation("call", "write", ["result.txt"]),
            _end("call", "write", result={}),
            _start("call", "write", {"path": "result.txt", "content": "again"}),
            _observation("call", "write", ["result.txt"]),
            _end("call", "write", result={}),
            _terminal(),
        ),
    ],
)
def test_rejects_duplicate_tool_event_records(output_events: str) -> None:
    with pytest.raises(BehaviorError):
        project_subject_evidence(output_events, _RESPONSE)


def test_rejects_observations_after_native_completion() -> None:
    output_events = _events(
        _observer_ready(),
        _start("write", "write", {"path": "result.txt", "content": "done"}),
        _end("write", "write", result={}),
        _observation("write", "write", ["result.txt"]),
        _terminal(),
    )

    with pytest.raises(BehaviorError):
        project_subject_evidence(output_events, _RESPONSE)


def test_projects_mutators_in_observer_completion_order() -> None:
    output_events = _events(
        _observer_ready(),
        _start("first", "write", {"path": "first.txt", "content": "first"}),
        _start("second", "edit", {"patch": "*** Begin Patch"}),
        _observation("first", "write", ["first.txt"]),
        _observation("second", "edit", ["second.txt"]),
        _end("second", "edit", result={}),
        _end("first", "write", result={}),
        _terminal(),
    )

    assert [
        event["tool"] for event in project_subject_evidence(output_events, _RESPONSE)["events"]
    ] == ["write", "edit"]


@pytest.mark.parametrize(
    "details",
    [
        {},
        {"timeoutSeconds": 30, "wallTimeMs": 1, "timedOut": True},
        {"timeoutSeconds": 30, "wallTimeMs": 1, "async": {"state": "running"}},
        {"exitCode": False},
    ],
)
def test_rejects_bash_without_native_exit_code(details: dict[str, object]) -> None:
    output_events = _events(
        _observer_ready(),
        _start("command", "bash", {"command": "python3 verify.py"}),
        _observation("command", "bash", []),
        _end(
            "command",
            "bash",
            result={"content": [{"text": "looks successful"}], "details": details},
        ),
        _terminal(),
    )

    with pytest.raises(BehaviorError):
        project_subject_evidence(output_events, _RESPONSE)


@pytest.mark.parametrize(
    "observation",
    [
        (
            _observation(
                "write", "write", ["result.txt"], [{"script": "check.py", "changed_paths": []}]
            ),
        ),
        (
            _observation(
                "write", "write", ["result.txt"], [{"script": "other.py", "changed_paths": []}]
            ),
        ),
        (
            _observation(
                "bash", "bash", [], [{"script": "check.py", "changed_paths": ["../result.txt"]}]
            ),
        ),
        (
            {
                "type": "instruct_eval_tool_observation",
                "origin": "runtime_observer",
                "toolCallId": "write",
                "toolName": "write",
                "changed_paths": ["result.txt"],
            },
        ),
        (_observation("write", "write", ["result.txt"]),) * 2,
        (_observation("other", "write", ["result.txt"]),),
        (_observation("write", "bash", ["result.txt"]),),
        (_observation("write", "write", ["../result.txt"]),),
        (_observation("write", "write", ["result.txt", 1]),),
    ],
)
def test_rejects_invalid_runtime_observations(observation: tuple[dict[str, object], ...]) -> None:
    output_events = _events(
        _observer_ready(),
        _start("write", "write", {"path": "result.txt", "content": "done"}),
        *observation,
        _end("write", "write", result={}),
        _terminal(),
    )

    with pytest.raises(BehaviorError):
        project_subject_evidence(output_events, _RESPONSE)


@pytest.mark.parametrize(
    "ready_events",
    [
        (),
        (_observer_ready(), _observer_ready()),
    ],
)
def test_requires_one_observer_lifecycle_before_tool_activity(
    ready_events: tuple[dict[str, object], ...],
) -> None:
    output_events = _events(
        *ready_events,
        _start("write", "write", {"path": "result.txt", "content": "done"}),
        _observation("write", "write", ["result.txt"]),
        _end("write", "write", result={}),
        _terminal(),
    )

    with pytest.raises(BehaviorError):
        project_subject_evidence(output_events, _RESPONSE)


def test_projects_observed_changes_for_partial_error_and_noop() -> None:
    output_events = _events(
        _observer_ready(),
        _start("failed", "write", {"path": "result.txt", "content": "done"}),
        _observation("failed", "write", ["result.txt"]),
        _end("failed", "write", is_error=True, result={}),
        _start("noop", "edit", {"patch": "*** Begin Patch"}),
        _observation("noop", "edit", []),
        _end("noop", "edit", result={}),
        _terminal(),
    )

    assert [
        event["changed_paths"]
        for event in project_subject_evidence(output_events, _RESPONSE)["events"]
    ] == [["result.txt"], []]


def test_binds_the_completion_decision_to_the_final_native_response() -> None:
    response = json.dumps({"completion": "incomplete", "summary": "Cannot finish"})
    output_events = _events(_observer_ready(), _terminal(response))
    assert (
        project_subject_evidence(output_events, response)["response"]["completion"] == "incomplete"
    )
    with pytest.raises(BehaviorError):
        project_subject_evidence(output_events, _RESPONSE)


@pytest.mark.parametrize(
    "output_events",
    [
        _events(_observer_ready()),
        _events(_observer_ready(), _terminal(), _terminal()),
        _events(
            _observer_ready(),
            _terminal(),
            _start("late", "write", {"path": "result.txt", "content": "late"}),
        ),
        _events(_observer_ready(), _start("pending", "read", {"path": "result.txt"}), _terminal()),
    ],
)
def test_requires_one_terminal_boundary_after_all_tool_activity(output_events: str) -> None:
    with pytest.raises(BehaviorError):
        project_subject_evidence(output_events, _RESPONSE)


def test_rejects_an_ambiguous_completion_decision() -> None:
    response = '{"completion":"incomplete","completion":"complete","summary":"Finished"}'
    with pytest.raises(BehaviorError):
        project_subject_evidence(_events(_observer_ready(), _terminal(response)), response)
