"""Fresh, credential-isolated OMP execution for instruct-eval roles and subjects."""

from __future__ import annotations

import contextlib
import difflib
import json
import os
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from collections.abc import Generator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import IO, Any
from urllib.error import URLError
from urllib.request import urlopen

from .behavior import (
    OBSERVATION_CONTRACT,
    BehaviorError,
    decode_completion_response,
    project_subject_evidence,
)
from .models import (
    Fixture,
    ProtocolError,
    ReachabilityWitness,
    WitnessExecutionResult,
    canonical_bytes,
    canonical_hash,
)

_PERMITTED_TOOLS = frozenset({"read", "edit", "write", "glob", "grep", "bash"})
_MUTATING_TOOLS = ("write", "edit", "bash")
_SYSTEM_READS = (
    "/System",
    "/usr/lib",
    "/usr/bin",
    "/usr/share",
    "/bin",
    "/sbin",
    "/private/var/db/timezone",
)
_MAX_EVIDENCE_BYTES = 2 << 20
_MAX_STREAM_BYTES = 1 << 20
# RPC includes repeated partial-message snapshots, unlike terminal result streams.
_MAX_TRANSPORT_BYTES = 64 << 20
_MAX_RESULT_TEXT_BYTES = 1 << 18
_EXPERIMENTS_ROOT = Path(__file__).parents[2] / "experiments"
_VERIFIED_RUNTIME_INPUT = "[verified runtime input]"


def _experiment_prefix(kind: str, identity: str = "") -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    safe_identity = re.sub(r"[^A-Za-z0-9._-]+", "-", identity).strip("._-")[:64]
    identity_segment = f"-{safe_identity}" if safe_identity else ""
    return f"{timestamp}-{kind}{identity_segment}-"


@contextlib.contextmanager
def _experiment_directory(kind: str, identity: str = "") -> Generator[Path]:
    _EXPERIMENTS_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=_experiment_prefix(kind, identity),
        dir=_EXPERIMENTS_ROOT,
    ) as temporary:
        yield Path(temporary)


class RoleRuntimeError(ProtocolError):
    """A fresh OMP runtime boundary could not safely complete."""


class CredentialGatewayError(RoleRuntimeError):
    """The credential broker or isolated gateway failed."""


class SandboxError(RoleRuntimeError):
    """A child process could not be constrained to its permitted mounts."""


def prepare_decomposition_packet(
    instruction: str,
) -> Mapping[str, Any]:
    """Bind an instruction's exact UTF-8 bytes before tool-free decomposition."""
    if not isinstance(instruction, str) or not instruction:
        raise RoleRuntimeError("decomposition instruction must be a nonempty string")
    source_bytes = instruction.encode("utf-8")
    return MappingProxyType(
        {
            "instruction": instruction,
            "source_sha256": sha256(source_bytes).hexdigest(),
            "source_byte_length": len(source_bytes),
        }
    )


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Complete private transport and input-verified output evidence."""

    text: str
    payload: Mapping[str, Any] | None
    tool_outputs: tuple[str, ...]
    output_events: str
    input_verified: bool
    stdout: str = ""
    stderr: str = ""
    protocol_failure: str | None = None
    disclosure_tool_outputs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.input_verified, bool):
            raise RoleRuntimeError("OMP input verification is malformed")
        if self.protocol_failure is not None and (
            not isinstance(self.protocol_failure, str)
            or len(self.protocol_failure.encode("utf-8")) > _MAX_RESULT_TEXT_BYTES
        ):
            raise RoleRuntimeError("OMP protocol failure exceeds the runtime bound")
        if (
            not isinstance(self.text, str)
            or len(self.text.encode("utf-8")) > _MAX_RESULT_TEXT_BYTES
        ):
            raise RoleRuntimeError("OMP result text exceeds the runtime bound")
        if self.payload is not None and not isinstance(self.payload, Mapping):
            raise RoleRuntimeError("OMP role payload must be an object")
        if len(self.tool_outputs) != len(self.disclosure_tool_outputs):
            raise RoleRuntimeError("OMP disclosure tool output projection is incomplete")
        if any(
            not isinstance(item, str) or len(item.encode("utf-8")) > _MAX_RESULT_TEXT_BYTES
            for outputs in (self.tool_outputs, self.disclosure_tool_outputs)
            for item in outputs
        ):
            raise RoleRuntimeError("OMP tool output exceeds the runtime bound")
        if any(
            not isinstance(stream, str) or len(stream.encode("utf-8")) > _MAX_TRANSPORT_BYTES
            for stream in (self.stdout, self.stderr, self.output_events)
        ):
            raise RoleRuntimeError("OMP process stream exceeds the runtime bound")
        object.__setattr__(
            self,
            "payload",
            MappingProxyType(dict(self.payload)) if self.payload is not None else None,
        )


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    """Complete text-only workspace state, including empty directories."""

    files: Mapping[str, str]
    directories: tuple[str, ...]

    def __post_init__(self) -> None:
        if any(
            not isinstance(path, str)
            or not path
            or Path(path).is_absolute()
            or ".." in Path(path).parts
            or not isinstance(content, str)
            for path, content in self.files.items()
        ):
            raise RoleRuntimeError("workspace snapshot has an unsafe file path")
        if tuple(sorted(set(self.directories))) != self.directories:
            raise RoleRuntimeError("workspace snapshot directories must be unique and sorted")
        retained = sum(
            len(path.encode("utf-8")) + len(content.encode("utf-8"))
            for path, content in self.files.items()
        ) + sum(len(directory.encode("utf-8")) for directory in self.directories)
        if retained > _MAX_EVIDENCE_BYTES:
            raise RoleRuntimeError("workspace snapshot exceeds the evidence bound")
        object.__setattr__(self, "files", MappingProxyType(dict(self.files)))


@dataclass(frozen=True, slots=True)
class SubjectResult:
    assignment: str
    protocol_valid: bool
    verifier_passed: bool
    reason: str | None
    response: str
    changes: str
    unchanged_hashes: Mapping[str, str]
    observer_output: Mapping[str, str]
    tool_outputs: tuple[str, ...] = ()
    runtime_stdout: str = ""
    runtime_stderr: str = ""
    verifier_stdout: str = ""
    verifier_stderr: str = ""
    runtime_output_events: str = ""
    disclosure_tool_outputs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.assignment, str)
            or not self.assignment
            or not isinstance(self.protocol_valid, bool)
            or not isinstance(self.verifier_passed, bool)
        ):
            raise RoleRuntimeError("subject result is malformed")
        if self.reason is not None and not isinstance(self.reason, str):
            raise RoleRuntimeError("subject result reason is malformed")
        if (
            not isinstance(self.response, str)
            or len(self.response.encode("utf-8")) > _MAX_RESULT_TEXT_BYTES
        ):
            raise RoleRuntimeError("subject response exceeds the runtime bound")
        if (
            not isinstance(self.changes, str)
            or len(self.changes.encode("utf-8")) > _MAX_EVIDENCE_BYTES
        ):
            raise RoleRuntimeError("subject changes exceed the evidence bound")
        if any(len(value) != 64 for value in self.unchanged_hashes.values()):
            raise RoleRuntimeError("subject unchanged hashes are malformed")
        if any(
            not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_EVIDENCE_BYTES
            for value in self.observer_output.values()
        ):
            raise RoleRuntimeError("subject observer output exceeds the evidence bound")
        if len(self.tool_outputs) != len(self.disclosure_tool_outputs):
            raise RoleRuntimeError("subject disclosure tool output projection is incomplete")
        streams = (
            *self.tool_outputs,
            *self.disclosure_tool_outputs,
            self.verifier_stdout,
            self.verifier_stderr,
        )
        if any(
            not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_STREAM_BYTES
            for value in streams
        ):
            raise RoleRuntimeError("subject raw stream exceeds the evidence bound")
        if any(
            not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_TRANSPORT_BYTES
            for value in (
                self.runtime_stdout,
                self.runtime_stderr,
                self.runtime_output_events,
            )
        ):
            raise RoleRuntimeError("subject transport exceeds the evidence bound")
        object.__setattr__(
            self,
            "unchanged_hashes",
            MappingProxyType(dict(self.unchanged_hashes)),
        )
        object.__setattr__(
            self,
            "observer_output",
            MappingProxyType(dict(self.observer_output)),
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "assignment": self.assignment,
            "protocol_valid": self.protocol_valid,
            "verifier_passed": self.verifier_passed,
            "reason": self.reason,
            "response": self.response,
            "changes": self.changes,
            "unchanged_hashes": dict(self.unchanged_hashes),
            "observer_output": dict(self.observer_output),
            "tool_outputs": list(self.tool_outputs),
            "runtime_stdout": self.runtime_stdout,
            "runtime_stderr": self.runtime_stderr,
            "verifier_stdout": self.verifier_stdout,
            "verifier_stderr": self.verifier_stderr,
            "runtime_output_events": self.runtime_output_events,
        }


@dataclass(frozen=True, slots=True)
class OmpExecutionRequest:
    """The complete, canonical input for one isolated OMP execution."""

    workspace: Path
    prompt: str
    request: Mapping[str, Any]
    system_prompt: str
    tools: Sequence[str]
    expect_json: bool
    observe_tools: bool = False


@dataclass(frozen=True, slots=True)
class _Gateway:
    broker: subprocess.Popen[str]
    gateway: subprocess.Popen[str]
    url: str
    client_token: str
    credential: Path


@dataclass(frozen=True, slots=True)
class _OmpSettings:
    model: str
    thinking: str
    approval: str
    timeout: int


@dataclass(frozen=True, slots=True)
class _WitnessContract:
    expected_files: Mapping[str, str]
    verifier_path: str
    observer_path: str
    commands: tuple[tuple[str, ...], tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class _WitnessEvidence:
    results: tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str]]
    tool_hashes: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _SubjectEvidence:
    changes: str
    unchanged: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _SubjectCapture:
    assignment: str
    execution: ExecutionResult

    def result(
        self,
        outcome: _SubjectOutcome,
    ) -> SubjectResult:
        return SubjectResult(
            self.assignment,
            outcome.protocol_valid,
            outcome.verifier_passed,
            outcome.reason,
            outcome.response,
            outcome.changes,
            outcome.unchanged_hashes,
            outcome.observer_output,
            self.execution.tool_outputs,
            self.execution.stdout,
            self.execution.stderr,
            outcome.verifier_stdout,
            outcome.verifier_stderr,
            runtime_output_events=self.execution.output_events,
            disclosure_tool_outputs=self.execution.disclosure_tool_outputs,
        )


@dataclass(frozen=True, slots=True)
class _SubjectOutcome:
    protocol_valid: bool
    verifier_passed: bool
    reason: str | None
    response: str
    changes: str
    unchanged_hashes: Mapping[str, str]
    observer_output: Mapping[str, str]
    verifier_stdout: str = ""
    verifier_stderr: str = ""


@dataclass(frozen=True, slots=True)
class _SubjectOutcomeRequest:
    protocol_valid: bool
    verifier_passed: bool
    reason: str | None
    response: str
    evidence: _SubjectEvidence
    observer_output: Mapping[str, str]
    verifier: subprocess.CompletedProcess[str] | None = None


@dataclass(frozen=True, slots=True)
class _SubjectRequest:
    assignment: str
    condition: str
    fixture: Path
    request: Mapping[str, Any]
    observer_paths: Sequence[str]


@dataclass(frozen=True, slots=True)
class _SubjectRun:
    subject: _SubjectRequest
    workspace: Path
    before: WorkspaceSnapshot
    protected: Mapping[str, str]
    prompt: str


@dataclass(frozen=True, slots=True)
class _SubjectObserverRequest:
    workspace: Path
    observer_paths: Sequence[str]
    protected: Mapping[str, str]
    evidence: _SubjectEvidence
    capture: _SubjectCapture
    verifier: subprocess.CompletedProcess[str]


def _omp() -> Path:
    executable = shutil.which("omp")
    if executable is None:
        raise RoleRuntimeError("omp executable is unavailable")
    return Path(executable).resolve(strict=True)


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _stop(process: subprocess.Popen[Any] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise RoleRuntimeError("isolated OMP process did not terminate") from error


def _wait_for(url: str, process: subprocess.Popen[str], endpoint: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CredentialGatewayError("credential boundary exited before becoming ready")
        try:
            with urlopen(f"{url}{endpoint}", timeout=0.2) as response:
                if response.status == 200:
                    return
        except (OSError, URLError):
            time.sleep(0.05)
    raise CredentialGatewayError("credential boundary did not become ready")


def _broker_environment() -> dict[str, str]:
    names = (
        "HOME",
        "LANG",
        "LC_ALL",
        "PI_CONFIG_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    )
    return {name: os.environ[name] for name in names if name in os.environ}


def _credential_process(
    executable: Path,
    command: Sequence[str],
    environment: Mapping[str, str],
    timeout_message: str,
    failure_message: str,
) -> str:
    try:
        issued = subprocess.run(
            [str(executable), *command],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(environment),
            timeout=15,
        )
    except subprocess.TimeoutExpired as error:
        raise CredentialGatewayError(timeout_message) from error
    if issued.returncode:
        raise CredentialGatewayError(failure_message)
    return issued.stdout


def _credential_json(stdout: str, message: str) -> Mapping[str, Any]:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise CredentialGatewayError(message) from error
    if not isinstance(value, Mapping):
        raise CredentialGatewayError(message)
    return value


def _broker_token(executable: Path) -> str:
    stdout = _credential_process(
        executable,
        ("auth-broker", "token", "--json"),
        _broker_environment(),
        "credential broker token issuance timed out",
        "credential broker did not issue a token",
    )
    token = _credential_json(
        stdout,
        "credential broker returned invalid JSON",
    ).get("token")
    if not isinstance(token, str) or not token:
        raise CredentialGatewayError("credential broker returned an invalid token")
    return token


def _gateway_environment(home: Path, broker_url: str, token: str) -> dict[str, str]:
    return {
        "HOME": str(home),
        "OMP_HOME": str(home / ".omp"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "OMP_AUTH_BROKER_URL": broker_url,
        "OMP_AUTH_BROKER_TOKEN": token,
    }


def _gateway_client(
    executable: Path,
    home: Path,
    environment: Mapping[str, str],
) -> tuple[str, Path]:
    stdout = _credential_process(
        executable,
        ("auth-gateway", "token", "--regenerate", "--json"),
        environment,
        "credential gateway token issuance timed out",
        "credential gateway did not issue an ephemeral token",
    )
    client = _credential_json(stdout, "credential gateway returned invalid JSON")
    client_token, token_path = client.get("token"), client.get("path")
    if not isinstance(client_token, str) or not client_token or not isinstance(token_path, str):
        raise CredentialGatewayError("credential gateway returned invalid client data")
    credential = Path(token_path).resolve(strict=True)
    isolated_home = (home / ".omp").resolve(strict=True)
    if not credential.is_relative_to(isolated_home):
        raise CredentialGatewayError("gateway credential escaped isolated home")
    credential.chmod(0o600)
    return client_token, credential


def _start_gateway(executable: Path, home: Path) -> _Gateway:
    """Give a child an ephemeral loopback credential, never provider credentials."""
    broker_url = f"http://127.0.0.1:{_port()}"
    broker = subprocess.Popen(
        [
            str(executable),
            "auth-broker",
            "serve",
            f"--bind={broker_url.removeprefix('http://')}",
        ],
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_broker_environment(),
        start_new_session=True,
    )
    try:
        _wait_for(broker_url, broker, "/v1/healthz")
        environment = _gateway_environment(home, broker_url, _broker_token(executable))
        client_token, credential = _gateway_client(executable, home, environment)
        gateway_url = f"http://127.0.0.1:{_port()}"
        gateway = subprocess.Popen(
            [
                str(executable),
                "auth-gateway",
                "serve",
                f"--bind={gateway_url.removeprefix('http://')}",
            ],
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        )
        try:
            _wait_for(gateway_url, gateway, "/healthz")
            return _Gateway(broker, gateway, gateway_url, client_token, credential)
        except BaseException:
            _stop(gateway)
            raise
    except BaseException:
        _stop(broker)
        raise


@dataclass(frozen=True, slots=True)
class _SandboxNetwork:
    outbound_ports: tuple[int, ...] = ()
    gate_port: int | None = None


def _sandbox(
    argv: Sequence[str],
    workspace: Path,
    home: Path,
    read_only: Sequence[Path],
    network: _SandboxNetwork,
) -> list[str]:
    def escaped(path: Path) -> str:
        return str(path.resolve(strict=True)).replace("\\", "\\\\").replace('"', '\\"')

    gate_port = network.gate_port

    if (
        not workspace.is_dir()
        or not home.is_dir()
        or any(
            not isinstance(port, int) or not 1 <= port <= 65535 for port in network.outbound_ports
        )
        or (
            gate_port is not None
            and (not isinstance(gate_port, int) or not 1 <= gate_port <= 65535)
        )
    ):
        raise SandboxError("sandbox mount or endpoint is unavailable")
    paths = " ".join(
        f'(subpath "{escaped(path.parent)}") (literal "{escaped(path)}")' for path in read_only
    )
    systems = " ".join(f'(subpath "{path}")' for path in _SYSTEM_READS)
    outbound = " ".join(f'(remote ip "localhost:{port}")' for port in network.outbound_ports)
    inbound = ""
    if gate_port is not None:
        outbound += f' (remote ip "localhost:{gate_port}")'
        inbound = f' (allow network-inbound (local ip "localhost:{gate_port}"))'
    profile = (
        "(version 1) (deny default) "
        + (
            f'(allow file-read* (literal "/") {systems} '
            f'(literal "/dev/null") (literal "/dev/random") '
            f'(literal "/dev/urandom") (subpath "{escaped(workspace)}") '
            f'(subpath "{escaped(home)}") {paths}) '
        )
        + '(allow file-read-metadata (subpath "/usr") (subpath "/var")) '
        + f'(allow file-write* (literal "/dev/null") (subpath "{escaped(workspace)}") '
        f'(subpath "{escaped(home)}")) '
        + "(allow process*) (allow sysctl-read) (allow mach-lookup) "
        + f"(allow network-outbound {outbound}){inbound}"
    )
    return ["/usr/bin/sandbox-exec", "-p", profile, *argv]


def _content_text(content: list[Any]) -> str:
    fragments: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("text"), str):
            fragments.append(item["text"])
        elif isinstance(item.get("json"), (dict, list)):
            fragments.append(json.dumps(item["json"], sort_keys=True))
        elif isinstance(item.get("content"), str):
            fragments.append(item["content"])
    return "".join(fragments)


def _terminal_event(line: str) -> dict[str, Any]:
    try:
        event = json.loads(line)
    except json.JSONDecodeError as error:
        raise RoleRuntimeError("OMP JSON stream is malformed") from error
    if not isinstance(event, dict):
        raise RoleRuntimeError("OMP JSON stream event is malformed")
    return event


def _assistant_message_text(event: Mapping[str, Any]) -> str | None:
    if event.get("type") != "message_end":
        return None
    message = event.get("message")
    if (
        not isinstance(message, dict)
        or message.get("role") != "assistant"
        or not isinstance(message.get("content"), list)
    ):
        return None
    return _content_text(message["content"])


def _tool_execution_text(event: Mapping[str, Any]) -> str | None:
    if event.get("type") != "tool_execution_end":
        return None
    result = event.get("result")
    content = result.get("content") if isinstance(result, dict) else None
    return _content_text(content) if isinstance(content, list) else None


def _project_input_echo(event: dict[str, Any], prompt: str) -> tuple[int, bool]:
    """Remove only exact supplied input content from known transport locations."""
    kind = event.get("type")
    if kind in ("message_start", "message_end"):
        messages = [event.get("message")]
    elif kind == "agent_end" and isinstance(event.get("messages"), list):
        messages = event["messages"]
    else:
        return 0, True
    count, verified = 0, True
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        count += 1
        if message.get("content") == [{"type": "text", "text": prompt}]:
            message["content"] = []
        else:
            verified = False
    return count, verified


@dataclass
class _InputReadProjection:
    """Project only native copies proven to contain the complete supplied input."""

    input_file: tuple[str, str] | None
    expected: tuple[object, ...] = field(init=False, default=())
    started: dict[str, str] = field(default_factory=dict)
    ended: set[str] = field(default_factory=set)
    proven: set[str] = field(default_factory=set)
    valid: bool = True

    def __post_init__(self) -> None:
        if self.input_file is not None:
            path, text = self.input_file
            lines = text.count("\n") + 1
            self.expected = (
                [{"type": "text", "text": text}],
                len(text.encode("utf-8")),
                lines,
                {"text": text, "startLine": 1, "lineNumbers": list(range(1, lines + 1))},
                {"type": "path", "value": path},
            )

    def _matches(self, result: dict[str, Any]) -> bool:
        details = result.get("details")
        if not isinstance(details, dict) or not isinstance(details.get("meta"), dict):
            return False
        matches = (
            result.get("content"),
            details.get("fileSize"),
            details.get("totalLines"),
            details.get("displayContent"),
            details["meta"].get("source"),
        ) == self.expected
        return matches and all(
            type(value) is int
            for value in (
                details["fileSize"],
                details["totalLines"],
                details["displayContent"]["startLine"],
                *details["displayContent"]["lineNumbers"],
            )
        )

    def _call(self, event: Mapping[str, Any]) -> str | None:
        call_id = event.get("toolCallId")
        if (
            isinstance(call_id, str)
            and self.started.get(call_id) == "read"
            and event.get("toolName") == "read"
            and event.get("isError") is False
        ):
            return call_id
        return None

    @staticmethod
    def _replace(result: dict[str, Any]) -> None:
        result["content"][0]["text"] = _VERIFIED_RUNTIME_INPUT
        result["details"]["displayContent"]["text"] = _VERIFIED_RUNTIME_INPUT

    def _start(self, event: Mapping[str, Any]) -> None:
        call_id, name = event.get("toolCallId"), event.get("toolName")
        if isinstance(call_id, str) and call_id and isinstance(name, str):
            if call_id in self.started:
                self.valid = False
            self.started[call_id] = name

    def _end(self, event: dict[str, Any]) -> bool:
        call_id = event.get("toolCallId")
        if not isinstance(call_id, str) or self.started.get(call_id) != "read":
            return False
        if call_id in self.ended:
            self.valid = False
            return False
        self.ended.add(call_id)
        result = event.get("result")
        if not isinstance(result, dict) or self._call(event) is None or not self._matches(result):
            return False
        self.proven.add(call_id)
        self._replace(result)
        return True

    def _copy(self, message: Any) -> bool:
        if not isinstance(message, dict) or message.get("role") != "toolResult":
            return False
        call_id = self._call(message)
        if call_id not in self.proven or not self._matches(message):
            return False
        self._replace(message)
        return True

    def project(self, event: dict[str, Any]) -> bool:
        if self.input_file is None or not self.valid:
            return False
        kind = event.get("type")
        if kind == "tool_execution_start":
            self._start(event)
        elif kind == "tool_execution_end":
            return self._end(event)
        elif kind in ("message_start", "message_end"):
            return self._copy(event.get("message"))
        elif kind in ("turn_end", "agent_end"):
            messages = event.get("toolResults" if kind == "turn_end" else "messages")
            if isinstance(messages, list):
                changed = False
                for message in messages:
                    changed |= self._copy(message)
                return changed
        return False


@dataclass(frozen=True, slots=True)
class _TerminalContext:
    response: Mapping[str, Any] | None = None
    protocol_failure: str | None = None
    input_file: tuple[str, str] | None = None


def _terminal_output(
    stdout: str,
    stderr: str,
    *,
    prompt: str,
    required: bool,
    context: _TerminalContext | None = None,
) -> ExecutionResult:
    context_response = context.response if context is not None else None
    protocol_failure = context.protocol_failure if context is not None else None
    input_reads = _InputReadProjection(context.input_file if context is not None else None)
    if len(stdout.encode("utf-8")) > _MAX_TRANSPORT_BYTES:
        raise RoleRuntimeError("OMP JSON stream exceeds the runtime bound")
    text = ""
    tool_output: list[str] = []
    disclosure_tool_output: list[str] = []
    output_events: list[str] = []
    echoes = {"message_start": 0, "message_end": 0, "agent_end": 0}
    verified, ended = True, False
    for line in stdout.splitlines(keepends=True):
        event = _terminal_event(line)
        message = _assistant_message_text(event)
        tool_result = _tool_execution_text(event)
        read_projected = input_reads.project(event)
        if message:
            text = message
        if tool_result is not None:
            tool_output.append(tool_result)
            disclosure_tool_output.append(
                _VERIFIED_RUNTIME_INPUT if read_projected else tool_result
            )
        count, matches = _project_input_echo(event, prompt)
        context_echo = context_response is not None and event == context_response
        if context_echo:
            event = {**event, "data": {"systemPrompt": _VERIFIED_RUNTIME_INPUT}}
        if count:
            echoes[event["type"]] += count
        verified = verified and matches
        output_events.append(
            json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
            if count or context_echo or read_projected
            else line
        )
        ended = ended or event.get("type") == "agent_end"
    if protocol_failure is None and (not ended or (required and not text)):
        raise RoleRuntimeError("OMP JSON stream is incomplete")
    return ExecutionResult(
        text,
        _role_json(text) if required and protocol_failure is None else None,
        tuple(tool_output),
        "".join(output_events),
        verified and input_reads.valid and all(count == 1 for count in echoes.values()),
        stdout,
        stderr,
        protocol_failure,
        tuple(disclosure_tool_output),
    )


def _execution_settings(
    request: Mapping[str, Any],
    tools: Sequence[str],
) -> _OmpSettings:
    model_value, permissions_value, runtime_value = (
        request.get("model"),
        request.get("permissions"),
        request.get("runtime"),
    )
    if (
        not isinstance(model_value, Mapping)
        or not isinstance(permissions_value, Mapping)
        or not isinstance(runtime_value, Mapping)
    ):
        raise RoleRuntimeError("execution request is invalid")
    provider, identifier, thinking = (
        model_value.get("provider"),
        model_value.get("identifier"),
        model_value.get("thinking"),
    )
    if (
        not isinstance(provider, str)
        or not provider
        or not isinstance(identifier, str)
        or not identifier
        or not isinstance(thinking, str)
        or not thinking
    ):
        raise RoleRuntimeError("model configuration is invalid")
    approval, allowed_tools, timeout = (
        permissions_value.get("approval_mode"),
        permissions_value.get("tools"),
        runtime_value.get("timeout_seconds"),
    )
    if not isinstance(approval, str) or not isinstance(allowed_tools, list):
        raise RoleRuntimeError("permission configuration is invalid")
    if not isinstance(timeout, int) or timeout <= 0:
        raise RoleRuntimeError("runtime timeout is invalid")
    if not set(tools).issubset(_PERMITTED_TOOLS) or not set(tools).issubset(set(allowed_tools)):
        raise RoleRuntimeError("requested tools exceed frozen permissions")
    return _OmpSettings(f"{provider}/{identifier}", thinking, approval, timeout)


def _role_json(text: str) -> Mapping[str, Any]:
    candidates = [text.strip()]
    stripped = candidates[0]
    if stripped.startswith("```") and stripped.endswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3:
            candidates.append("\n".join(lines[1:-1]).strip())
    decoder = json.JSONDecoder()
    for candidate in candidates:
        start = candidate.find("{")
        if start < 0:
            continue
        try:
            value, end = decoder.raw_decode(candidate[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and not candidate[start + end :].strip():
            return value
    raise RoleRuntimeError("OMP role output must contain exactly one JSON object")


def _runtime_native(request: Mapping[str, Any]) -> tuple[str, Path]:
    runtime = request["runtime"]
    runtime_version = runtime.get("version")
    if not isinstance(runtime_version, str) or not runtime_version:
        raise RoleRuntimeError("runtime version is required")
    architecture = "arm64" if os.uname().machine in {"arm64", "aarch64"} else "x64"
    native = (
        Path.home()
        / ".omp"
        / "natives"
        / runtime_version
        / f"pi_natives.darwin-{architecture}.node"
    )
    if not native.is_file() or native.is_symlink():
        raise RoleRuntimeError("OMP native runtime is unavailable")
    return runtime_version, native


def _prepare_runtime_home(root: Path, profile: str, observe_tools: bool = False) -> Path:
    home = root / "home"
    directories = (
        home,
        home / ".config",
        home / ".local" / "share",
        home / "tmp",
        home / ".omp" / "profiles" / profile / "agent",
    )
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    (directories[-1] / "config.yml").write_text(
        json.dumps(
            {
                "disabledProviders": [
                    "claude",
                    "codex",
                    "gemini",
                    "opencode",
                    "github",
                    "agents",
                    "agents-md",
                    "claude-md",
                    "omp-plugins",
                    "agent-plugins",
                    "claude-plugins",
                    "cursor",
                    "windsurf",
                    "cline",
                    "vscode",
                    "mcp-json",
                    "ssh-json",
                    "builtin-defaults",
                ],
                "disabledExtensions": ["context-file:user:AGENTS.md"],
                "async": {"enabled": False},
                "bash": {"autoBackground": {"enabled": False}},
                **(
                    {"tools": {"approval": dict.fromkeys(_MUTATING_TOOLS, "prompt")}}
                    if observe_tools
                    else {}
                ),
            }
        ),
        encoding="utf-8",
    )
    return home


def _write_gateway_model(
    home: Path,
    profile: str,
    gateway: _Gateway,
) -> None:
    models = home / ".omp" / "profiles" / profile / "agent" / "models.yml"
    models.write_text(
        "providers:\n  openai-codex:\n    baseUrl: "
        + gateway.url
        + "\n    apiKey: "
        + json.dumps(gateway.client_token)
        + "\n    transport: pi-native\n",
        encoding="utf-8",
    )


def _omp_argv(
    executable: Path,
    profile: str,
    settings: _OmpSettings,
    execution: OmpExecutionRequest,
    observer: Path | None,
) -> list[str]:
    argv = [
        str(executable),
        "--mode",
        "rpc",
        "--model",
        settings.model,
        "--thinking",
        settings.thinking,
        "--approval-mode",
        settings.approval,
    ]
    argv.extend(["--tools", ",".join(execution.tools)] if execution.tools else ["--no-tools"])
    argv.extend(
        [
            "--profile",
            profile,
            "--no-session",
            "--no-rules",
            "--no-skills",
            "--no-extensions",
            "--no-prewalk",
            "--no-lsp",
            "--no-pty",
            "--system-prompt",
            execution.system_prompt,
        ]
    )
    if observer is not None:
        argv.extend(["--hook", str(observer)])
    return argv


def _runtime_environment(home: Path, gate_port: int | None = None) -> dict[str, str]:
    environment = {
        name: os.environ[name] for name in ("LANG", "LC_ALL", "TERM") if name in os.environ
    }
    environment.update(
        {
            "HOME": str(home),
            "OMP_HOME": str(home / ".omp"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "TMPDIR": str(home / "tmp"),
            "PATH": f"{Path(sys.executable).resolve().parent}:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "INSTRUCT_EVAL_EVIDENCE_BYTES": str(_MAX_EVIDENCE_BYTES),
        }
    )
    if gate_port is not None:
        if not 1 <= gate_port <= 65535:
            raise RoleRuntimeError("gate snapshot endpoint is unavailable")
        environment["INSTRUCT_EVAL_GATE_PORT"] = str(gate_port)
    return environment


def _python_runtime_reads() -> tuple[Path, ...]:
    library = (
        Path(sys.base_prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    )
    return Path(sys.executable).resolve(), library


def _supplied_input_file(execution: OmpExecutionRequest) -> tuple[str, str] | None:
    treatment = execution.request.get("candidate_instruction")
    if treatment is None:
        return None
    if not isinstance(treatment, str):
        raise RoleRuntimeError("OMP supplied treatment is malformed")
    return str(execution.workspace / ".omp" / "AGENTS.md"), treatment


def _validate_runtime_context(response: Mapping[str, Any], execution: OmpExecutionRequest) -> None:
    data = response.get("data")
    prompts = data.get("systemPrompt") if isinstance(data, Mapping) else None
    if (
        response.get("success") is not True
        or not isinstance(data, Mapping)
        or not isinstance(prompts, list)
        or not prompts
        or any(not isinstance(prompt, str) for prompt in prompts)
    ):
        raise RoleRuntimeError("OMP runtime input context is unavailable")
    files = re.findall(r'<file path="([^"]+)">\n(.*?)\n</file>', "\n".join(prompts), re.DOTALL)
    input_file = _supplied_input_file(execution)
    expected = [input_file] if input_file is not None else []
    expected_prompt = execution.system_prompt
    if expected:
        path, content = expected[0]
        expected_prompt += (
            f'\n<project>\n## Context\n<instructions>\n<file path="{path}">\n'
            f"{content}\n</file>\n</instructions>\n</project>"
        )
    if files != expected or prompts[0] != expected_prompt:
        raise RoleRuntimeError("OMP loaded context differs from the isolated treatment")
    tools = data.get("dumpTools")
    if not isinstance(tools, list) or {
        tool.get("name") for tool in tools if isinstance(tool, Mapping)
    } != set(execution.tools):
        raise RoleRuntimeError("OMP loaded tools differ from frozen permissions")


@dataclass(slots=True)
class _NativeApprovals:
    """Serialize native approval responses, never preparation or capped hook handlers."""

    enabled: bool
    failure: str | None = None
    started: dict[str, str] = field(default_factory=dict)
    requested: dict[str, str] = field(default_factory=dict)
    seen_requests: set[str] = field(default_factory=set)
    dialogs: deque[str] = field(default_factory=deque)
    seen_dialogs: set[str] = field(default_factory=set)
    completed: set[str] = field(default_factory=set)
    active_dialog: str | None = None
    active_call: str | None = None
    observed: bool = False
    ended: bool = False
    abort_sent: bool = False

    @staticmethod
    def _call(event: Mapping[str, Any]) -> tuple[str, str]:
        identity, name = event.get("toolCallId"), event.get("toolName")
        if not isinstance(identity, str) or not identity or name not in _MUTATING_TOOLS:
            raise RoleRuntimeError("OMP native admission has malformed call identity")
        return identity, name

    def _admission(self, event: Mapping[str, Any]) -> None:
        if not self.enabled or event.get("origin") != "runtime_observer":
            raise RoleRuntimeError("OMP native admission has an unexpected origin")
        identity, name = self._call(event)
        phase = event.get("phase")
        if phase == "requested":
            if identity in self.seen_requests:
                raise RoleRuntimeError("OMP native admission request was repeated")
            self.seen_requests.add(identity)
            self.requested[identity] = name
        elif phase == "admitted":
            if (
                self.active_dialog is None
                or self.active_call is not None
                or self.requested.get(identity) != name
                or self.started.get(identity) != name
            ):
                raise RoleRuntimeError("OMP native approval resolution is uncorrelated")
            del self.requested[identity]
            self.active_call = identity
        else:
            raise RoleRuntimeError("OMP native mutator admission was rejected")

    def _dialog(self, event: Mapping[str, Any]) -> None:
        if event.get("method") in (
            "notify",
            "setStatus",
            "setWidget",
            "setTitle",
            "set_editor_text",
        ):
            return
        identity = event.get("id")
        if (
            not self.enabled
            or event.get("method") != "select"
            or event.get("options") != ["Approve", "Deny"]
            or not isinstance(identity, str)
            or not identity
            or identity in self.seen_dialogs
        ):
            raise RoleRuntimeError("OMP native approval dialog is unexpected")
        unbound = self.active_dialog is not None and self.active_call is None
        if len(self.dialogs) + int(unbound) >= len(self.requested):
            raise RoleRuntimeError("OMP native approval dialog lacks a request")
        self.seen_dialogs.add(identity)
        self.dialogs.append(identity)

    def _start(self, event: Mapping[str, Any]) -> None:
        if event.get("toolName") not in _MUTATING_TOOLS:
            return
        identity, name = self._call(event)
        if identity in self.started:
            raise RoleRuntimeError("OMP native mutator execution start was repeated")
        self.started[identity] = name

    def _completion(self, event: Mapping[str, Any]) -> None:
        identity, name = self._call(event)
        if identity != self.active_call or self.started.get(identity) != name:
            raise RoleRuntimeError("OMP native mutator completion is uncorrelated")
        if event.get("type") == "instruct_eval_tool_observation":
            if self.observed or event.get("origin") != "runtime_observer":
                raise RoleRuntimeError("OMP native workspace observation is uncorrelated")
            self.observed = True
        else:
            if self.ended:
                raise RoleRuntimeError("OMP native mutator execution end was repeated")
            self.ended = True

    def _next(self) -> tuple[dict[str, Any], ...]:
        if self.active_call is not None and self.observed and self.ended:
            self.completed.add(self.active_call)
            self.active_call = self.active_dialog = None
            self.observed = self.ended = False
        if self.active_dialog is not None or not self.dialogs:
            return ()
        if any(self.started.get(identity) != name for identity, name in self.requested.items()):
            return ()
        self.active_dialog = self.dialogs.popleft()
        return ({"type": "extension_ui_response", "id": self.active_dialog, "value": "Approve"},)

    def _cancel(self, event: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
        if self.abort_sent and event.get("type") != "extension_ui_request":
            return ()
        identities = list(self.dialogs)
        self.dialogs.clear()
        identity = event.get("id")
        if (
            event.get("type") == "extension_ui_request"
            and isinstance(identity, str)
            and identity not in identities
            and identity != self.active_dialog
        ):
            identities.append(identity)
        commands: list[dict[str, Any]] = []
        if not self.abort_sent:
            commands.append({"type": "abort", "id": "native-approval-abort"})
            self.abort_sent = True
        commands.extend(
            {"type": "extension_ui_response", "id": identity, "cancelled": True}
            for identity in identities
        )
        return tuple(commands)

    def _observe(self, event: Mapping[str, Any]) -> None:
        match event.get("type"):
            case "instruct_eval_tool_admission":
                self._admission(event)
            case "extension_ui_request":
                self._dialog(event)
            case "tool_execution_start":
                self._start(event)
            case "instruct_eval_tool_observation":
                self._completion(event)
            case "tool_execution_end":
                if event.get("toolName") in _MUTATING_TOOLS:
                    self._completion(event)
            case "extension_error":
                raise RoleRuntimeError("OMP native observer reported an extension error")
            case "agent_end":
                if (
                    self.active_dialog
                    or self.dialogs
                    or self.requested
                    or (set(self.started) != self.completed)
                ):
                    raise RoleRuntimeError("OMP native admission evidence is incomplete")

    def commands(self, event: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
        if self.failure is not None:
            return self._cancel(event)
        try:
            self._observe(event)
            return self._next()
        except RoleRuntimeError as error:
            self.failure = str(error)
            return self._cancel(event)


@dataclass(slots=True)
class _RpcCapture:
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    pending: bytearray = field(default_factory=bytearray)
    observer_ready: bool = False
    approvals: _NativeApprovals = field(default_factory=lambda: _NativeApprovals(False))

    def observe_readiness(self, event: Mapping[str, Any]) -> None:
        if event.get("type") == "instruct_eval_observer_ready":
            if self.observer_ready or event != {
                "type": "instruct_eval_observer_ready",
                "origin": "runtime_observer",
            }:
                raise RoleRuntimeError("OMP workspace observer readiness is malformed")
            self.observer_ready = True

    def respond(self, event: Mapping[str, Any], pipe: IO[bytes]) -> None:
        self.observe_readiness(event)
        if not self.approvals.enabled:
            return
        commands = self.approvals.commands(event)
        if commands:
            pipe.write("".join(json.dumps(command) + "\n" for command in commands).encode("utf-8"))
            pipe.flush()


def _read_rpc_event(
    child: subprocess.Popen[bytes], deadline: float, expected: str, capture: _RpcCapture
) -> Mapping[str, Any]:
    if child.stdin is None or child.stdout is None or child.stderr is None:
        raise RoleRuntimeError("OMP RPC pipes are unavailable")
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ, capture.stdout)
        selector.register(child.stderr, selectors.EVENT_READ, capture.stderr)
        while selector.get_map():
            while b"\n" in capture.pending:
                end = capture.pending.index(b"\n")
                event = _terminal_event(capture.pending[:end].decode("utf-8"))
                del capture.pending[: end + 1]
                capture.respond(event, child.stdin)
                if event.get("type") == expected or (
                    event.get("type") == "response" and event.get("id") == expected
                ):
                    return event
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("OMP context", 0)
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                key.data.extend(chunk)
                if len(capture.stdout) + len(capture.stderr) > _MAX_TRANSPORT_BYTES:
                    raise RoleRuntimeError("OMP transport exceeds the runtime bound")
                if key.data is capture.stdout:
                    capture.pending.extend(chunk)
    raise RoleRuntimeError("OMP exited before the expected RPC event")


def _communicate_omp(
    child: subprocess.Popen[bytes], execution: OmpExecutionRequest, timeout: int
) -> ExecutionResult:
    if child.stdin is None:
        raise RoleRuntimeError("OMP RPC input pipe is unavailable")
    deadline = time.monotonic() + timeout
    capture = _RpcCapture(approvals=_NativeApprovals(execution.observe_tools))
    child.stdin.write(b'{"id":"input-context","type":"get_state"}\n')
    child.stdin.flush()
    context = _read_rpc_event(child, deadline, "input-context", capture)
    _validate_runtime_context(context, execution)
    if capture.observer_ready != execution.observe_tools:
        raise RoleRuntimeError("OMP workspace observer was not loaded as requested")
    command = json.dumps({"id": "subject-task", "type": "prompt", "message": execution.prompt})
    child.stdin.write((command + "\n").encode("utf-8"))
    child.stdin.flush()
    try:
        _read_rpc_event(child, deadline, "agent_end", capture)
        stdout, stderr = child.communicate(timeout=max(0, deadline - time.monotonic()))
    except (subprocess.TimeoutExpired, RoleRuntimeError):
        if capture.approvals.failure is None:
            raise
        _stop(child)
        stdout, stderr = child.communicate(timeout=5)
    if child.returncode and capture.approvals.failure is None:
        raise RoleRuntimeError(f"OMP call failed with exit code {child.returncode}")
    return _terminal_output(
        (bytes(capture.stdout) + stdout).decode("utf-8"),
        (bytes(capture.stderr) + stderr).decode("utf-8"),
        prompt=execution.prompt,
        required=execution.expect_json,
        context=_TerminalContext(
            context, capture.approvals.failure, _supplied_input_file(execution)
        ),
    )


def execute_omp(execution: OmpExecutionRequest) -> ExecutionResult:
    """Execute one fresh OMP context without mounting run roots or private maps."""
    settings = _execution_settings(execution.request, execution.tools)
    executable = _omp()
    profile = f"instruct-eval-{uuid.uuid4().hex}"
    runtime_version, native = _runtime_native(execution.request)
    inside_experiment = _EXPERIMENTS_ROOT in execution.workspace.parents
    runtime_parent = execution.workspace.parent if inside_experiment else _EXPERIMENTS_ROOT
    runtime_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="runtime-" if inside_experiment else _experiment_prefix("runtime"),
        dir=runtime_parent,
    ) as temporary:
        root = Path(temporary)
        home = _prepare_runtime_home(root, profile, execution.observe_tools)
        observer = root / "observer.mjs" if execution.observe_tools else None
        if observer is not None:
            observer.write_bytes(Path(__file__).with_name("native_observer.mjs").read_bytes())
        destination = home / ".omp" / "natives" / runtime_version / native.name
        destination.parent.mkdir(parents=True)
        shutil.copy2(native, destination)
        broker = gateway = child = None
        credential: Path | None = None
        gate_port = _port() if execution.observe_tools else None
        try:
            boundary = _start_gateway(executable, home)
            broker = boundary.broker
            gateway = boundary.gateway
            credential = boundary.credential
            _write_gateway_model(home, profile, boundary)
            child = subprocess.Popen(
                _sandbox(
                    _omp_argv(executable, profile, settings, execution, observer),
                    execution.workspace,
                    home,
                    (
                        executable,
                        destination,
                        *_python_runtime_reads(),
                        *((observer,) if observer is not None else ()),
                    ),
                    _SandboxNetwork(
                        outbound_ports=(int(boundary.url.rsplit(":", 1)[1]),),
                        gate_port=gate_port,
                    ),
                ),
                cwd=execution.workspace,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_runtime_environment(home, gate_port),
                start_new_session=True,
            )
            try:
                return _communicate_omp(child, execution, settings.timeout)
            except subprocess.TimeoutExpired as error:
                _stop(child)
                raise RoleRuntimeError("OMP call timed out") from error
        finally:
            _stop(child)
            if credential is not None:
                credential.unlink(missing_ok=True)
            _stop(gateway)
            _stop(broker)


def invoke_role(
    contract: Path,
    payload: Mapping[str, Any],
    request: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Route one compact packet into a fresh, tool-free role context."""
    try:
        contract_text = contract.read_text(encoding="utf-8")
    except OSError as error:
        raise RoleRuntimeError(f"role contract is unreadable: {contract.name}") from error
    prompt = "Return the required JSON object for this complete packet:\n" + canonical_bytes(
        payload
    ).decode("utf-8")
    system_prompt = (
        "You are an internal machine function. Return only the requested JSON object; "
        "do not use a completion-response format.\n\n"
        + contract_text.rstrip()
        + "\n\nThe supplied packet is complete. Return one JSON object now; do not ask "
        "for more data, describe your reasoning, or use a code fence."
    )
    with _experiment_directory("role", contract.stem) as experiment:
        workspace = experiment / "workspace"
        workspace.mkdir()
        result = execute_omp(
            OmpExecutionRequest(
                workspace,
                prompt,
                request,
                system_prompt,
                (),
                True,
            )
        )
    if result.protocol_failure is not None:
        raise RoleRuntimeError(result.protocol_failure)
    if not result.input_verified:
        raise RoleRuntimeError("OMP input echoes do not match the supplied prompt")
    assert result.payload is not None
    return result.payload


def _bounded_evidence(value: str, label: str) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_EVIDENCE_BYTES:
        raise RoleRuntimeError(f"{label} exceeds the evidence bound")
    return value


def snapshot_workspace(root: Path) -> WorkspaceSnapshot:
    if not root.is_dir():
        raise RoleRuntimeError("subject workspace is unavailable")
    files: dict[str, str] = {}
    directories: list[str] = []
    retained = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RoleRuntimeError("subject workspace contains a symlink")
        relative = str(path.relative_to(root))
        retained += len(relative.encode("utf-8"))
        if path.is_dir():
            directories.append(relative)
        elif path.is_file():
            retained += path.stat().st_size
            if retained > _MAX_EVIDENCE_BYTES:
                raise RoleRuntimeError("workspace snapshot exceeds the evidence bound")
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError as error:
                raise RoleRuntimeError("subject workspace contains non-text evidence") from error
            if len(content.encode("utf-8")) != path.stat().st_size:
                raise RoleRuntimeError("workspace changed while snapshotting")
            files[relative] = content
        else:
            raise RoleRuntimeError("subject workspace contains an unsupported entry")
        if retained > _MAX_EVIDENCE_BYTES:
            raise RoleRuntimeError("workspace snapshot exceeds the evidence bound")
    return WorkspaceSnapshot(files, tuple(directories))


def workspace_diff(before: WorkspaceSnapshot, after: WorkspaceSnapshot) -> str:
    lines: list[str] = []
    retained = 0

    def append(line: str) -> None:
        nonlocal retained
        retained += len(line.encode("utf-8"))
        if retained > _MAX_EVIDENCE_BYTES:
            raise RoleRuntimeError("workspace diff exceeds the evidence bound")
        lines.append(line)

    for directory in sorted(set(before.directories) | set(after.directories)):
        if (directory in before.directories) != (directory in after.directories):
            change = "+++ created" if directory in after.directories else "--- removed"
            append(f"{change} directory/{directory}\n")
    for path in sorted(set(before.files) | set(after.files)):
        before_exists, after_exists = path in before.files, path in after.files
        if before.files.get(path) != after.files.get(path) or before_exists != after_exists:
            if not before_exists:
                append(f"+++ created file/{path}\n")
            elif not after_exists:
                append(f"--- removed file/{path}\n")
            for line in difflib.unified_diff(
                before.files.get(path, "").splitlines(keepends=True),
                after.files.get(path, "").splitlines(keepends=True),
                fromfile=f"before/{path}",
                tofile=f"after/{path}",
                n=3,
            ):
                append(line)
    return "".join(lines)


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_public_fixture_files(public_files: Any, expected_files: Mapping[str, str]) -> None:
    if not isinstance(public_files, Mapping) or any(
        not isinstance(content, str)
        or sha256(content.encode("utf-8")).hexdigest() != expected_files.get(path)
        for path, content in public_files.items()
    ):
        raise RoleRuntimeError("public fixture files differ from the frozen manifest")


def _witness_contract(fixture: Fixture) -> _WitnessContract:
    manifest = fixture.manifest
    evidence = fixture.evidence_contract
    if (
        set(manifest) != {"schema", "files", "public_files"}
        or manifest["schema"] != "instruct-eval-fixture-manifest-v1"
    ):
        raise RoleRuntimeError("fixture manifest is not canonical")
    if (
        set(evidence)
        != {
            "schema",
            "verifier_path",
            "observer_path",
            "verifier_command",
            "observer_command",
            "observation_contract",
        }
        or evidence["schema"] != "instruct-eval-evidence-contract-v1"
        or evidence["observation_contract"] != OBSERVATION_CONTRACT
    ):
        raise RoleRuntimeError("fixture evidence contract is not canonical")
    files = manifest["files"]
    if not isinstance(files, list):
        raise RoleRuntimeError("fixture manifest files are malformed")
    expected_files: dict[str, str] = {}
    for item in files:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"path", "sha256"}
            or not isinstance(item["path"], str)
            or not isinstance(item["sha256"], str)
            or item["path"] in expected_files
        ):
            raise RoleRuntimeError("fixture manifest entry is malformed")
        expected_files[item["path"]] = item["sha256"]
    _validate_public_fixture_files(manifest["public_files"], expected_files)
    verifier_path = evidence["verifier_path"]
    observer_path = evidence["observer_path"]
    commands = (evidence["verifier_command"], evidence["observer_command"])
    if (
        not isinstance(verifier_path, str)
        or not isinstance(observer_path, str)
        or any(
            not isinstance(command, list)
            or not command
            or any(not isinstance(part, str) or not part for part in command)
            for command in commands
        )
    ):
        raise RoleRuntimeError("fixture evidence execution is malformed")
    return _WitnessContract(
        expected_files,
        verifier_path,
        observer_path,
        (tuple(commands[0]), tuple(commands[1])),
    )


def _witness_actions(witness: ReachabilityWitness) -> list[Any]:
    try:
        actions = json.loads(witness.input_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RoleRuntimeError("witness input is not canonical JSON") from error
    if (
        not isinstance(actions, Mapping)
        or set(actions) != {"schema", "actions"}
        or actions["schema"] != "instruct-eval-witness-input-v1"
        or not isinstance(actions["actions"], list)
        or canonical_bytes(actions) != witness.input_bytes
    ):
        raise RoleRuntimeError("witness action sequence is malformed")
    return actions["actions"]


def _validate_frozen_fixture(
    before: WorkspaceSnapshot,
    fixture: Fixture,
    contract: _WitnessContract,
) -> None:
    actual_files = {
        path: sha256(content.encode("utf-8")).hexdigest() for path, content in before.files.items()
    }
    if before.files.get("TASK.txt") != fixture.task:
        raise RoleRuntimeError("fixture task differs from frozen task")
    if actual_files != contract.expected_files:
        raise RoleRuntimeError("fixture root differs from frozen manifest")
    if (
        before.files.get(contract.verifier_path, "").encode() != fixture.verifier.source
        or before.files.get(contract.observer_path, "").encode() != fixture.observe_source
    ):
        raise RoleRuntimeError("fixture verifier or observer differs from frozen source")


def _apply_witness_change(
    workspace: Path,
    fixture: Fixture,
    raw: Any,
) -> None:
    if (
        not isinstance(raw, Mapping)
        or set(raw) != {"tool", "path", "content"}
        or raw["tool"] != "write"
        or not isinstance(raw["path"], str)
        or raw["path"] not in fixture.allowed_changed_paths
        or (raw["content"] is not None and not isinstance(raw["content"], str))
    ):
        raise RoleRuntimeError("witness change is malformed or outside policy")
    relative = PurePosixPath(raw["path"])
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise RoleRuntimeError("witness change path escapes the fixture")
    path = workspace.joinpath(*relative.parts)
    workspace_root = workspace.resolve()
    parent = path.parent.resolve()
    if parent != workspace_root and workspace_root not in parent.parents:
        raise RoleRuntimeError("witness change path escapes the fixture")
    if raw["content"] is None:
        path.unlink()
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw["content"], encoding="utf-8")


def _actual_changed_paths(
    before: WorkspaceSnapshot,
    after: WorkspaceSnapshot,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            path
            for path in set(before.files) | set(after.files)
            if before.files.get(path) != after.files.get(path)
        )
    )


@dataclass(slots=True)
class _GateSnapshotServer:
    workspace: Path
    listener: socket.socket = field(init=False)
    snapshots: list[WorkspaceSnapshot] = field(default_factory=list)
    error: BaseException | None = None
    _closed: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread = field(init=False)
    _retained: int = 0

    def __post_init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(("127.0.0.1", 0))
            self.listener.listen()
            self.listener.settimeout(0.1)
        except OSError as error:
            self.listener.close()
            raise RoleRuntimeError("gate snapshot server could not bind") from error
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def port(self) -> int:
        return int(self.listener.getsockname()[1])

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._closed.set()
        self.listener.close()
        self._thread.join(timeout=1)
        if self._thread.is_alive():
            raise RoleRuntimeError("gate snapshot server did not terminate")

    def changed_paths(self, final: WorkspaceSnapshot) -> list[dict[str, Any]]:
        if self.error is not None:
            raise RoleRuntimeError("gate snapshot server failed") from self.error
        return [
            {
                "script": "check.py",
                "changed_paths": list(_actual_changed_paths(snapshot, final)),
            }
            for snapshot in self.snapshots
        ]

    def _observe_connection(self, connection: socket.socket) -> None:
        connection.settimeout(1)
        payload = bytearray()
        while not payload.endswith(b"\n"):
            chunk = connection.recv(4096)
            if not chunk:
                raise RoleRuntimeError("gate snapshot request is incomplete")
            payload.extend(chunk)
            if len(payload) > _MAX_RESULT_TEXT_BYTES:
                raise RoleRuntimeError("gate snapshot request exceeds the runtime bound")
        if payload != b'{"script":"check.py"}\n':
            raise RoleRuntimeError("gate snapshot request is malformed")
        snapshot = snapshot_workspace(self.workspace)
        retained = sum(
            len(path.encode("utf-8")) + len(content.encode("utf-8"))
            for path, content in snapshot.files.items()
        ) + sum(len(path.encode("utf-8")) for path in snapshot.directories)
        self._retained += retained
        if self._retained > _MAX_EVIDENCE_BYTES:
            raise RoleRuntimeError("gate snapshots exceed the evidence bound")
        self.snapshots.append(snapshot)
        connection.sendall(b"ok\n")

    def _serve(self) -> None:
        try:
            while not self._closed.is_set():
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if not self._closed.is_set():
                        raise
                    return
                with connection:
                    self._observe_connection(connection)
        except BaseException as error:
            self.error = error


@contextlib.contextmanager
def _gate_snapshot_server(workspace: Path) -> Generator[_GateSnapshotServer]:
    server = _GateSnapshotServer(workspace)
    server.start()
    try:
        yield server
    finally:
        server.close()


def _witness_bash(
    workspace: Path,
    home: Path,
    command: str,
    gate_port: int,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            _sandbox(
                ["/bin/bash", "--noprofile", "--norc", "-c", command],
                workspace,
                home,
                _python_runtime_reads(),
                _SandboxNetwork(outbound_ports=(gate_port,)),
            ),
            cwd=workspace,
            env=_runtime_environment(home, gate_port),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        raise RoleRuntimeError("witness action timed out") from error
    _bounded_evidence(result.stdout, "witness action stdout")
    _bounded_evidence(result.stderr, "witness action stderr")
    return result


def _execute_witness_actions(
    workspace: Path, fixture: Fixture, actions: Sequence[Any]
) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="runtime-", dir=workspace.parent) as temporary:
        home = _prepare_runtime_home(Path(temporary), "witness")
        for index, action in enumerate(actions):
            if not isinstance(action, Mapping):
                raise RoleRuntimeError("witness action is malformed")
            if action.get("tool") == "write":
                before = snapshot_workspace(workspace)
                _apply_witness_change(workspace, fixture, action)
                events.append(
                    {
                        "tool": "write",
                        "arguments": {"path": action["path"], "content": action["content"]},
                        "is_error": False,
                        "exit_code": None,
                        "gate_snapshots": [],
                    }
                )
            elif (
                set(action) == {"tool", "command"}
                and action["tool"] == "bash"
                and isinstance(action["command"], str)
                and action["command"]
            ):
                before = snapshot_workspace(workspace)
                with _gate_snapshot_server(workspace) as snapshots:
                    result = _witness_bash(workspace, home, action["command"], snapshots.port)
                    gate_snapshots = snapshots.changed_paths(snapshot_workspace(workspace))
                events.append(
                    {
                        "tool": "bash",
                        "arguments": {"command": action["command"]},
                        "is_error": result.returncode != 0,
                        "exit_code": result.returncode,
                        "gate_snapshots": gate_snapshots,
                    }
                )
            elif set(action) == {"tool", "response"} and action["tool"] == "respond":
                if index != len(actions) - 1:
                    raise RoleRuntimeError("witness respond action must be last")
                response_bytes = canonical_bytes(action["response"])
                if len(response_bytes) > _MAX_RESULT_TEXT_BYTES:
                    raise RoleRuntimeError("witness response exceeds the runtime bound")
                try:
                    response = decode_completion_response(response_bytes.decode("utf-8"))
                except BehaviorError as error:
                    raise RoleRuntimeError(f"witness response is malformed: {error}") from error
                return {
                    "origin": "witness",
                    "terminal": "witness_return",
                    "response": response,
                    "events": events,
                }
            else:
                raise RoleRuntimeError("witness action is malformed")
            events[-1]["changed_paths"] = list(
                _actual_changed_paths(before, snapshot_workspace(workspace))
            )
    raise RoleRuntimeError("witness requires one final respond action")


def _run_witness_commands(
    commands: Sequence[Sequence[str]],
    workspace: Path,
    observation: Mapping[str, Any],
) -> _WitnessEvidence:
    tool_hashes: dict[str, str] = {}
    results: list[subprocess.CompletedProcess[str]] = []
    for index, command in enumerate(commands):
        executable = shutil.which(command[0])
        if executable is None:
            raise RoleRuntimeError("witness evidence tool is unavailable")
        tool_hashes[command[0]] = _sha256_file(Path(executable))
        try:
            result = subprocess.run(
                command,
                cwd=workspace,
                input=json.dumps(observation) if index == 1 else "",
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as error:
            raise RoleRuntimeError("witness evidence execution timed out") from error
        _bounded_evidence(result.stdout, "witness stdout")
        _bounded_evidence(result.stderr, "witness stderr")
        results.append(result)
    return _WitnessEvidence((results[0], results[1]), tool_hashes)


def _witness_observer(stdout: str) -> Mapping[str, Any]:
    try:
        observer = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RoleRuntimeError("witness observer output is malformed") from error
    if not isinstance(observer, Mapping):
        raise RoleRuntimeError("witness observer output must be an object")
    return observer


def _witness_evidence_hash(
    changed_paths: tuple[str, ...],
    before: WorkspaceSnapshot,
    after: WorkspaceSnapshot,
    evidence: _WitnessEvidence,
) -> str:
    verifier, observer = evidence.results
    return canonical_hash(
        {
            "changed_paths": changed_paths,
            "diff_sha256": sha256(workspace_diff(before, after).encode()).hexdigest(),
            "verifier_returncode": verifier.returncode,
            "verifier_stdout": verifier.stdout,
            "verifier_stderr": verifier.stderr,
            "observer_returncode": observer.returncode,
            "observer_stdout": observer.stdout,
            "observer_stderr": observer.stderr,
        }
    )


def run_witness(
    fixture: Fixture,
    witness: ReachabilityWitness,
    fixture_root: Path,
) -> WitnessExecutionResult:
    """Execute one condition-independent witness against a clean frozen fixture."""
    contract = _witness_contract(fixture)
    actions = _witness_actions(witness)
    with _experiment_directory("witness", witness.witness_id) as experiment:
        workspace = experiment / "workspace"
        shutil.copytree(fixture_root, workspace, symlinks=True)
        before = snapshot_workspace(workspace)
        _validate_frozen_fixture(before, fixture, contract)
        observation = _execute_witness_actions(workspace, fixture, actions)
        after = snapshot_workspace(workspace)
        actual_changed = _actual_changed_paths(before, after)
        protected = {
            contract.verifier_path: fixture.verifier.sha256,
            contract.observer_path: fixture.observe_sha256,
        }
        unchanged = {
            path: _sha256_file(workspace / path)
            for path in protected
            if (workspace / path).is_file()
        }
        evidence = _run_witness_commands(contract.commands, workspace, observation)
        if any(event["tool"] == "bash" for event in observation["events"]):
            evidence = _WitnessEvidence(
                evidence.results,
                {**evidence.tool_hashes, "/bin/bash": _sha256_file(Path("/bin/bash"))},
            )
        observer = (
            _witness_observer(evidence.results[1].stdout)
            if evidence.results[1].returncode == 0
            else {}
        )
        return WitnessExecutionResult(
            unchanged,
            actual_changed,
            evidence.results[1].returncode == 0,
            unchanged != protected,
            evidence.results[0].returncode == 0,
            observer,
            _witness_evidence_hash(actual_changed, before, after, evidence),
            evidence.tool_hashes,
        )


def _subject_evidence(
    workspace: Path,
    before: WorkspaceSnapshot,
    protected: Mapping[str, str],
) -> _SubjectEvidence:
    after = snapshot_workspace(workspace)
    return _SubjectEvidence(
        workspace_diff(before, after),
        {name: _sha256_file(workspace / name) for name in protected},
    )


def _subject_outcome(request: _SubjectOutcomeRequest) -> _SubjectOutcome:
    verifier = request.verifier
    return _SubjectOutcome(
        request.protocol_valid,
        request.verifier_passed,
        request.reason,
        request.response,
        request.evidence.changes,
        request.evidence.unchanged,
        request.observer_output,
        "" if verifier is None else verifier.stdout,
        "" if verifier is None else verifier.stderr,
    )


def _run_subject_verifier(
    workspace: Path,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["python3", "verify.py"],
            cwd=workspace,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return None


def _run_subject_observers(
    observation: _SubjectObserverRequest,
) -> SubjectResult | Mapping[str, str]:
    observer_output: dict[str, str] = {}
    verifier_passed = observation.verifier.returncode == 0
    try:
        observer_input = json.dumps(
            project_subject_evidence(
                observation.capture.execution.output_events,
                observation.capture.execution.text,
            )
        )
    except BehaviorError as error:
        return observation.capture.result(
            _subject_outcome(
                _SubjectOutcomeRequest(
                    False,
                    verifier_passed,
                    f"subject behavior evidence failed: {error}",
                    observation.capture.execution.text,
                    observation.evidence,
                    observer_output,
                    observation.verifier,
                )
            )
        )
    for item in observation.observer_paths:
        try:
            observed = subprocess.run(
                ["python3", item],
                cwd=observation.workspace,
                input=observer_input,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            return observation.capture.result(
                _subject_outcome(
                    _SubjectOutcomeRequest(
                        False,
                        verifier_passed,
                        "public fixture observer timed out",
                        observation.capture.execution.text,
                        observation.evidence,
                        observer_output,
                        observation.verifier,
                    )
                )
            )
        if observed.returncode:
            return observation.capture.result(
                _subject_outcome(
                    _SubjectOutcomeRequest(
                        False,
                        verifier_passed,
                        "public fixture observer failed",
                        observation.capture.execution.text,
                        observation.evidence,
                        observer_output,
                        observation.verifier,
                    )
                )
            )
        try:
            observer_output[item] = _bounded_evidence(
                observed.stdout,
                "public fixture observer stdout",
            )
        except RoleRuntimeError as error:
            return observation.capture.result(
                _subject_outcome(
                    _SubjectOutcomeRequest(
                        False,
                        verifier_passed,
                        f"subject evidence failed: {error}",
                        observation.capture.execution.text,
                        observation.evidence,
                        observer_output,
                        observation.verifier,
                    )
                )
            )
        unchanged = {
            name: _sha256_file(observation.workspace / name) for name in observation.protected
        }
        if unchanged != observation.protected:
            modified = _SubjectEvidence(observation.evidence.changes, unchanged)
            return observation.capture.result(
                _subject_outcome(
                    _SubjectOutcomeRequest(
                        False,
                        verifier_passed,
                        "public verifier or observer was modified",
                        observation.capture.execution.text,
                        modified,
                        observer_output,
                        observation.verifier,
                    )
                )
            )
    return observer_output


def _prepare_subject_run(
    workspace: Path,
    subject: _SubjectRequest,
) -> _SubjectRun | SubjectResult:
    if any(
        path.name in {"AGENTS.md", "CLAUDE.md", "GEMINI.md", "RULES.md", "SYSTEM.md"}
        or ".omp" in path.relative_to(workspace).parts
        for path in workspace.rglob("*")
    ):
        raise RoleRuntimeError("frozen fixture contains runtime context files")
    if subject.condition == "B":
        context_file = workspace / ".omp" / "AGENTS.md"
        context_file.parent.mkdir()
        context_file.write_text(str(subject.request["candidate_instruction"]), encoding="utf-8")
    try:
        before = snapshot_workspace(workspace)
    except RoleRuntimeError as error:
        return SubjectResult(
            subject.assignment,
            False,
            False,
            f"subject evidence failed: {error}",
            "",
            "",
            {},
            {},
        )
    verifier_path = workspace / "verify.py"
    if not verifier_path.is_file():
        raise RoleRuntimeError("public fixture verifier is unavailable")
    protected = {"verify.py": _sha256_file(verifier_path)}
    if subject.condition == "B":
        protected[".omp/AGENTS.md"] = _sha256_file(workspace / ".omp" / "AGENTS.md")
    for item in subject.observer_paths:
        path = workspace / item
        if not path.is_file():
            raise RoleRuntimeError("public fixture observer is unavailable")
        protected[item] = _sha256_file(path)
    task = (workspace / "TASK.txt").read_text(encoding="utf-8")
    return _SubjectRun(subject, workspace, before, protected, task)


def _execute_subject(run: _SubjectRun) -> _SubjectCapture | SubjectResult:
    try:
        execution = execute_omp(
            OmpExecutionRequest(
                run.workspace,
                run.prompt,
                run.subject.request,
                "Complete the supplied task in the workspace. Do not describe an "
                "experiment. Use only the permitted tools. Your final response must be one "
                'JSON object with exactly "completion" ("complete" or "incomplete") and '
                '"summary" (a string describing the outcome). Do not use a code fence.',
                run.subject.request["permissions"]["tools"],
                False,
                observe_tools=True,
            )
        )
    except RoleRuntimeError as error:
        try:
            evidence = _subject_evidence(run.workspace, run.before, run.protected)
        except RoleRuntimeError as evidence_error:
            return SubjectResult(
                run.subject.assignment,
                False,
                False,
                f"subject evidence failed: {evidence_error}",
                "",
                "",
                {},
                {},
            )
        return SubjectResult(
            run.subject.assignment,
            False,
            False,
            f"subject execution failed: {error}",
            "",
            evidence.changes,
            evidence.unchanged,
            {},
        )
    return _SubjectCapture(run.subject.assignment, execution)


def _capture_subject_evidence(
    run: _SubjectRun,
    capture: _SubjectCapture,
) -> _SubjectEvidence | SubjectResult:
    try:
        return _subject_evidence(run.workspace, run.before, run.protected)
    except RoleRuntimeError as error:
        return capture.result(
            _subject_outcome(
                _SubjectOutcomeRequest(
                    False,
                    False,
                    f"subject evidence failed: {error}",
                    capture.execution.text,
                    _SubjectEvidence("", {}),
                    {},
                )
            )
        )


def _finalize_subject(
    run: _SubjectRun,
    capture: _SubjectCapture,
    evidence: _SubjectEvidence,
) -> SubjectResult:
    failure = capture.execution.protocol_failure
    if failure is None and not capture.execution.input_verified:
        failure = "OMP input echoes do not match the supplied prompt"
    if failure is not None:
        return capture.result(
            _subject_outcome(
                _SubjectOutcomeRequest(
                    False,
                    False,
                    failure,
                    capture.execution.text,
                    evidence,
                    {},
                )
            )
        )
    if evidence.unchanged != run.protected:
        return capture.result(
            _subject_outcome(
                _SubjectOutcomeRequest(
                    False,
                    False,
                    "public verifier or observer was modified",
                    capture.execution.text,
                    evidence,
                    {},
                )
            )
        )
    verifier = _run_subject_verifier(run.workspace)
    if verifier is None:
        return capture.result(
            _subject_outcome(
                _SubjectOutcomeRequest(
                    False,
                    False,
                    "public fixture verifier timed out",
                    capture.execution.text,
                    evidence,
                    {},
                )
            )
        )
    verifier_passed = verifier.returncode == 0
    unchanged = {name: _sha256_file(run.workspace / name) for name in run.protected}
    if unchanged != run.protected:
        modified = _SubjectEvidence(evidence.changes, unchanged)
        return capture.result(
            _subject_outcome(
                _SubjectOutcomeRequest(
                    False,
                    verifier_passed,
                    "public verifier or observer was modified",
                    capture.execution.text,
                    modified,
                    {},
                    verifier,
                )
            )
        )
    observer_result = _run_subject_observers(
        _SubjectObserverRequest(
            run.workspace,
            run.subject.observer_paths,
            run.protected,
            evidence,
            capture,
            verifier,
        )
    )
    if isinstance(observer_result, SubjectResult):
        return observer_result
    return capture.result(
        _subject_outcome(
            _SubjectOutcomeRequest(
                True,
                verifier_passed,
                None if verifier_passed else "public fixture verifier failed",
                capture.execution.text,
                evidence,
                observer_result,
                verifier,
            )
        )
    )


def run_subject(
    assignment: str,
    condition: str,
    fixture: Path,
    request: Mapping[str, Any],
    *,
    observer_paths: Sequence[str] = (),
) -> SubjectResult:
    """Run a fresh subject and unchanged public verifier/observers in its fixture."""
    if condition not in {"A", "B"}:
        raise RoleRuntimeError("subject condition is invalid")
    isolated_request = dict(request)
    if condition == "A":
        isolated_request.pop("candidate_instruction", None)
    else:
        treatment = isolated_request.get("candidate_instruction")
        if not isinstance(treatment, str) or not treatment:
            raise RoleRuntimeError("treatment instruction is unavailable")
    subject = _SubjectRequest(
        assignment,
        condition,
        fixture,
        isolated_request,
        observer_paths,
    )
    with _experiment_directory("subject") as experiment:
        workspace = experiment / "workspace"
        shutil.copytree(subject.fixture, workspace, symlinks=True)
        prepared = _prepare_subject_run(workspace, subject)
        if isinstance(prepared, SubjectResult):
            return prepared
        executed = _execute_subject(prepared)
        if isinstance(executed, SubjectResult):
            return executed
        evidence = _capture_subject_evidence(prepared, executed)
        if isinstance(evidence, SubjectResult):
            return evidence
        return _finalize_subject(prepared, executed, evidence)
