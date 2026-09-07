"""Project factual subject actions and its explicit terminal completion decision."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any


class BehaviorError(ValueError):
    """The OMP transport cannot support a truthful behavior projection."""


_MUTATING_TOOLS = frozenset({"bash", "edit", "write"})
_SUBJECT_TOOLS = _MUTATING_TOOLS | {"read", "glob", "grep"}

OBSERVATION_CONTRACT = {
    "subject_origin": "subject",
    "subject_terminal": "agent_end",
    "witness_origin": "witness",
    "witness_terminal": "witness_return",
    "tool_events": ["write", "edit", "bash"],
    "changed_paths": "actual_file_content_changes",
    "gate_snapshots": "actual_file_content_changes_since_gate_start",
    "mutating_tool_execution": "serialized",
    "terminal_order": "after_all_tool_completions",
    "completion": {"field": "completion", "values": ["complete", "incomplete"]},
    "coordinator_verification": "excluded",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BehaviorError("completion response contains a duplicate key")
        result[key] = value
    return result


def decode_completion_response(response: str) -> dict[str, Any]:
    """Require an explicit decision without guessing from completion prose."""
    try:
        value = json.loads(response, object_pairs_hook=_unique_object)
    except (TypeError, json.JSONDecodeError) as error:
        raise BehaviorError("completion response is not one JSON object") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"completion", "summary"}
        or value["completion"] not in ("complete", "incomplete")
        or not isinstance(value["summary"], str)
    ):
        raise BehaviorError("completion response is not canonical")
    return value


def _validate_terminal_response(event: dict[str, Any], response: str) -> None:
    messages = event.get("messages")
    last = messages[-1] if isinstance(messages, list) and messages else None
    if (
        not isinstance(last, dict)
        or last.get("role") != "assistant"
        or last.get("stopReason") != "stop"
        or not isinstance(last.get("content"), list)
    ):
        raise BehaviorError("terminal event lacks a final assistant response")
    fragments: list[str] = []
    for block in last["content"]:
        if not isinstance(block, dict):
            raise BehaviorError("terminal assistant content is malformed")
        if block.get("type") == "text":
            text = block.get("text")
            if not isinstance(text, str):
                raise BehaviorError("terminal assistant text is malformed")
            fragments.append(text)
    if "".join(fragments) != response:
        raise BehaviorError("terminal response differs from the retained final response")


def _event_lines(output_events: str) -> Iterator[dict[str, Any]]:
    if not isinstance(output_events, str):
        raise BehaviorError("OMP output events must be text")
    for line in re.finditer(r"[^\n]+", output_events):
        try:
            event = json.loads(line[0])
        except json.JSONDecodeError as error:
            raise BehaviorError("OMP output event is not JSON") from error
        if not isinstance(event, dict):
            raise BehaviorError("OMP output event is not an object")
        yield event


def _call_id(event: dict[str, Any]) -> str:
    call_id = event.get("toolCallId")
    if not isinstance(call_id, str) or not call_id:
        raise BehaviorError("relevant tool event lacks a call identifier")
    return call_id


def _tool_name(event: dict[str, Any]) -> str | None:
    tool_name = event.get("toolName")
    if tool_name is not None and not isinstance(tool_name, str):
        raise BehaviorError("tool event has an invalid tool name")
    return tool_name


def _arguments(event: dict[str, Any]) -> dict[str, Any]:
    arguments = event.get("args")
    if not isinstance(arguments, dict):
        raise BehaviorError("relevant tool start lacks object arguments")
    return arguments


def _is_error(event: dict[str, Any]) -> bool:
    is_error = event.get("isError", False)
    if not isinstance(is_error, bool):
        raise BehaviorError("tool completion has an invalid error state")
    return is_error


def _bash_exit_code(event: dict[str, Any]) -> int:
    result = event.get("result")
    if not isinstance(result, dict):
        raise BehaviorError("completed bash call lacks a definite exit code")
    details = result.get("details")
    if not isinstance(details, dict) or details.get("async") or details.get("timedOut"):
        raise BehaviorError("completed bash call lacks a definite exit code")
    exit_code = details.get("exitCode")
    if isinstance(exit_code, int) and not isinstance(exit_code, bool):
        return exit_code
    # OMP 18.1.10 #buildCompletedResult omits exitCode only for zero exits.
    # Unfinished calls throw; timeouts and async starts are separate result branches.
    if (
        "exitCode" not in details
        and event.get("isError") is False
        and result.get("isError") is not True
        and "wallTimeMs" in details
        and ("timeoutSeconds" in details or details.get("timeoutDisabled") is True)
    ):
        return 0
    raise BehaviorError("completed bash call lacks a definite exit code")


def _subject_events(output_events: str) -> Iterator[dict[str, Any]]:
    ready = False
    observed_kinds = {
        "tool_execution_start",
        "tool_execution_end",
        "instruct_eval_tool_observation",
        "agent_end",
    }
    for event in _event_lines(output_events):
        if event.get("type") == "instruct_eval_observer_ready":
            if ready or event != {
                "type": "instruct_eval_observer_ready",
                "origin": "runtime_observer",
            }:
                raise BehaviorError("workspace observer readiness is malformed or repeated")
            ready = True
        else:
            if event.get("type") in observed_kinds and not ready:
                raise BehaviorError("subject activity precedes workspace observer readiness")
            yield event
    if not ready:
        raise BehaviorError("subject evidence lacks workspace observer readiness")


def _valid_changed_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\0" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and value != "." and str(path) == value


def _valid_gate_snapshots(value: Any, tool_name: str) -> bool:
    if not isinstance(value, list):
        return False
    if tool_name in {"write", "edit"}:
        return not value
    return all(
        isinstance(snapshot, dict)
        and set(snapshot) == {"script", "changed_paths"}
        and snapshot["script"] == "check.py"
        and isinstance(snapshot["changed_paths"], list)
        and all(_valid_changed_path(path) for path in snapshot["changed_paths"])
        and snapshot["changed_paths"] == sorted(set(snapshot["changed_paths"]))
        for snapshot in value
    )


@dataclass(slots=True)
class _ProjectionState:
    calls: dict[str, tuple[str, dict[str, Any]]] = field(default_factory=dict)
    pending: set[str] = field(default_factory=set)
    seen: set[str] = field(default_factory=set)
    observations: dict[str, tuple[list[str], list[dict[str, Any]]]] = field(default_factory=dict)
    completed: dict[str, dict[str, Any]] = field(default_factory=dict)


def _record_observation(event: dict[str, Any], state: _ProjectionState) -> None:
    if set(event) != {
        "type",
        "origin",
        "toolCallId",
        "toolName",
        "changed_paths",
        "gate_snapshots",
    }:
        raise BehaviorError("workspace observation is malformed")
    call_id = _call_id(event)
    tool_name = _tool_name(event)
    paths = event["changed_paths"]
    gate_snapshots = event["gate_snapshots"]
    if (
        event["origin"] != "runtime_observer"
        or tool_name not in _MUTATING_TOOLS
        or call_id not in state.pending
        or state.calls[call_id][0] != tool_name
        or call_id in state.observations
    ):
        raise BehaviorError("workspace observation is repeated or has no matching start")
    if (
        not isinstance(paths, list)
        or any(not _valid_changed_path(path) for path in paths)
        or paths != sorted(set(paths))
        or not _valid_gate_snapshots(gate_snapshots, tool_name)
    ):
        raise BehaviorError("workspace observation has malformed source-state measurements")
    state.observations[call_id] = (paths, gate_snapshots)


def _project_tool_event(event: dict[str, Any], state: _ProjectionState) -> None:
    tool_name = _tool_name(event)
    if tool_name not in _SUBJECT_TOOLS:
        raise BehaviorError("tool event does not identify a permitted subject tool")
    call_id = _call_id(event)
    if event["type"] == "tool_execution_start":
        if call_id in state.seen:
            raise BehaviorError("tool call started more than once")
        state.calls[call_id] = (tool_name, _arguments(event))
        state.pending.add(call_id)
        state.seen.add(call_id)
        return
    if call_id not in state.pending:
        raise BehaviorError("tool completion has no matching start")
    started_name, _ = state.calls[call_id]
    if tool_name != started_name:
        raise BehaviorError("tool completion does not match its start")
    state.pending.remove(call_id)
    if tool_name in _MUTATING_TOOLS:
        state.completed[call_id] = event


def _normalized_records(state: _ProjectionState) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for call_id in state.observations:
        tool_name, arguments = state.calls[call_id]
        event = state.completed[call_id]
        records.append(
            {
                "tool": tool_name,
                "arguments": arguments,
                "is_error": _is_error(event),
                "exit_code": _bash_exit_code(event) if tool_name == "bash" else None,
                "changed_paths": state.observations[call_id][0],
                "gate_snapshots": state.observations[call_id][1],
            }
        )
    return records


def project_subject_evidence(output_events: str, response: str) -> dict[str, Any]:
    """Bind observer-ordered native tool facts to the same completion decision."""
    state = _ProjectionState()
    terminal = False

    for event in _subject_events(output_events):
        kind = event.get("type")
        if kind == "agent_end":
            if terminal or state.pending:
                raise BehaviorError("terminal event is repeated or precedes tool completion")
            _validate_terminal_response(event, response)
            terminal = True
            continue
        if kind not in {
            "tool_execution_start",
            "tool_execution_end",
            "instruct_eval_tool_observation",
        }:
            continue
        if terminal:
            raise BehaviorError("tool activity follows terminal completion")
        if kind == "instruct_eval_tool_observation":
            _record_observation(event, state)
            continue
        _project_tool_event(event, state)

    if state.pending:
        raise BehaviorError("relevant tool call has no completion")
    if set(state.observations) != set(state.completed):
        raise BehaviorError("mutating tool completion lacks workspace observation")
    if not terminal:
        raise BehaviorError("subject evidence lacks a terminal event")
    return {
        "origin": "subject",
        "terminal": "agent_end",
        "response": decode_completion_response(response),
        "events": _normalized_records(state),
    }
