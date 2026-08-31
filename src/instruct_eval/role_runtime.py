"""Fresh, credential-isolated OMP execution for instruct-eval roles and subjects."""

from __future__ import annotations

import contextlib
import difflib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid
from collections.abc import Generator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

from .models import (
    Fixture,
    ProtocolError,
    ReachabilityWitness,
    WitnessExecutionResult,
    canonical_hash,
)

_FILESYSTEM_TOOLS = frozenset({"read", "edit", "write", "glob", "grep"})
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
_MAX_RESULT_TEXT_BYTES = 1 << 18
_EXPERIMENTS_ROOT = Path(__file__).parents[2] / "experiments"


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


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Bounded, child-safe output retained by a runtime caller."""

    text: str
    payload: Mapping[str, Any] | None
    tool_outputs: tuple[str, ...]
    stdout: str = ""
    stderr: str = ""

    def __post_init__(self) -> None:
        if (
            not isinstance(self.text, str)
            or len(self.text.encode("utf-8")) > _MAX_RESULT_TEXT_BYTES
        ):
            raise RoleRuntimeError("OMP result text exceeds the runtime bound")
        if self.payload is not None and not isinstance(self.payload, Mapping):
            raise RoleRuntimeError("OMP role payload must be an object")
        if any(
            not isinstance(item, str) or len(item.encode("utf-8")) > _MAX_RESULT_TEXT_BYTES
            for item in self.tool_outputs
        ):
            raise RoleRuntimeError("OMP tool output exceeds the runtime bound")
        if (
            not isinstance(self.stdout, str)
            or len(self.stdout.encode("utf-8")) > _MAX_STREAM_BYTES
            or not isinstance(self.stderr, str)
            or len(self.stderr.encode("utf-8")) > _MAX_STREAM_BYTES
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
        streams = (
            *self.tool_outputs,
            self.runtime_stdout,
            self.runtime_stderr,
            self.verifier_stdout,
            self.verifier_stderr,
        )
        if any(
            not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_STREAM_BYTES
            for value in streams
        ):
            raise RoleRuntimeError("subject raw stream exceeds the evidence bound")
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


def _stop(process: subprocess.Popen[str] | None) -> None:
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


def _sandbox(
    argv: Sequence[str],
    workspace: Path,
    home: Path,
    read_only: Sequence[Path],
) -> list[str]:
    def escaped(path: Path) -> str:
        return str(path.resolve(strict=True)).replace("\\", "\\\\").replace('"', '\\"')

    if not workspace.is_dir() or not home.is_dir():
        raise SandboxError("sandbox mount is unavailable")
    paths = " ".join(
        f'(subpath "{escaped(path.parent)}") (literal "{escaped(path)}")' for path in read_only
    )
    systems = " ".join(f'(subpath "{path}")' for path in _SYSTEM_READS)
    profile = (
        "(version 1) (deny default) "
        + (
            f'(allow file-read* (literal "/") {systems} '
            f'(literal "/dev/null") (literal "/dev/random") '
            f'(literal "/dev/urandom") (subpath "{escaped(workspace)}") '
            f'(subpath "{escaped(home)}") {paths}) '
        )
        + '(allow file-read-metadata (subpath "/usr") (subpath "/var")) '
        + f'(allow file-write* (subpath "{escaped(workspace)}") '
        f'(subpath "{escaped(home)}")) '
        + "(allow process*) (allow sysctl-read) (allow mach-lookup) "
        '(allow network-outbound (remote ip "localhost:*"))'
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


def _terminal_text(stdout: str, *, required: bool) -> tuple[str, tuple[str, ...]]:
    if len(stdout.encode("utf-8")) > _MAX_STREAM_BYTES:
        raise RoleRuntimeError("OMP JSON stream exceeds the runtime bound")
    messages: list[str] = []
    tool_output: list[str] = []
    ended = False
    for line in stdout.splitlines():
        event = _terminal_event(line)
        message = _assistant_message_text(event)
        tool_result = _tool_execution_text(event)
        if message:
            messages.append(message)
        if tool_result is not None:
            tool_output.append(tool_result)
        ended = ended or event.get("type") == "agent_end"
    text = "\n".join(messages)
    if not ended or (required and not text):
        raise RoleRuntimeError("OMP JSON stream is incomplete")
    return text, tuple(tool_output)


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
    if not set(tools).issubset(_FILESYSTEM_TOOLS) or not set(tools).issubset(set(allowed_tools)):
        raise RoleRuntimeError("requested tools exceed frozen filesystem permissions")
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


def _prepare_runtime_home(root: Path, profile: str) -> Path:
    home = root / "home"
    directories = (
        home,
        home / ".config",
        home / ".local" / "share",
        home / ".omp" / "profiles" / profile / "agent",
    )
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
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
) -> list[str]:
    argv = [
        str(executable),
        "--mode",
        "json",
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
            "--system-prompt",
            execution.system_prompt,
            "-p",
            execution.prompt,
        ]
    )
    return argv


def _runtime_environment(home: Path, root: Path) -> dict[str, str]:
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
            "TMPDIR": str(root / "tmp"),
        }
    )
    return environment


def execute_omp(execution: OmpExecutionRequest) -> ExecutionResult:
    """Execute one fresh OMP context without mounting run roots or private maps."""
    settings = _execution_settings(execution.request, execution.tools)
    executable = _omp()
    profile = f"instruct-eval-{uuid.uuid4().hex}"
    runtime_version, native = _runtime_native(execution.request)
    runtime_parent = (
        execution.workspace.parent
        if _EXPERIMENTS_ROOT in execution.workspace.parents
        else _EXPERIMENTS_ROOT
    )
    runtime_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=_experiment_prefix("runtime"),
        dir=runtime_parent,
    ) as temporary:
        root = Path(temporary)
        home = _prepare_runtime_home(root, profile)
        destination = home / ".omp" / "natives" / runtime_version / native.name
        destination.parent.mkdir(parents=True)
        shutil.copy2(native, destination)
        broker = gateway = child = None
        credential: Path | None = None
        try:
            boundary = _start_gateway(executable, home)
            broker = boundary.broker
            gateway = boundary.gateway
            credential = boundary.credential
            _write_gateway_model(home, profile, boundary)
            (root / "tmp").mkdir()
            child = subprocess.Popen(
                _sandbox(
                    _omp_argv(executable, profile, settings, execution),
                    execution.workspace,
                    home,
                    (executable, destination),
                ),
                cwd=execution.workspace,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_runtime_environment(home, root),
                start_new_session=True,
            )
            try:
                stdout, stderr = child.communicate(timeout=settings.timeout)
            except subprocess.TimeoutExpired as error:
                _stop(child)
                raise RoleRuntimeError("OMP call timed out") from error
            if child.returncode:
                raise RoleRuntimeError(f"OMP call failed with exit code {child.returncode}")
            text, outputs = _terminal_text(stdout, required=execution.expect_json)
            return ExecutionResult(
                text,
                _role_json(text) if execution.expect_json else None,
                outputs,
                stdout,
                stderr,
            )
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
    prompt = "Return the required JSON object for this complete packet:\n" + json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )
    system_prompt = (
        "You are an internal machine function. Return only the requested JSON object; "
        "do not use a completion-response format.\n\n"
        + contract_text
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


def _witness_contract(fixture: Fixture) -> _WitnessContract:
    manifest = fixture.manifest
    evidence = fixture.evidence_contract
    if (
        set(manifest) != {"schema", "files"}
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
        }
        or evidence["schema"] != "instruct-eval-evidence-contract-v1"
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


def _witness_changes(witness: ReachabilityWitness) -> list[Any]:
    try:
        changes = json.loads(witness.input_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RoleRuntimeError("witness input is not canonical JSON") from error
    if (
        not isinstance(changes, Mapping)
        or set(changes) != {"schema", "changes"}
        or changes["schema"] != "instruct-eval-witness-input-v1"
        or not isinstance(changes["changes"], list)
    ):
        raise RoleRuntimeError("witness change-set is malformed")
    return changes["changes"]


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
    changed_paths: list[str],
) -> None:
    if (
        not isinstance(raw, Mapping)
        or set(raw) != {"path", "content"}
        or not isinstance(raw["path"], str)
        or raw["path"] in changed_paths
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
    changed_paths.append(raw["path"])


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


def _run_witness_commands(
    commands: Sequence[Sequence[str]],
    workspace: Path,
) -> _WitnessEvidence:
    tool_hashes: dict[str, str] = {}
    results: list[subprocess.CompletedProcess[str]] = []
    for command in commands:
        executable = shutil.which(command[0])
        if executable is None:
            raise RoleRuntimeError("witness evidence tool is unavailable")
        tool_hashes[command[0]] = _sha256_file(Path(executable))
        try:
            result = subprocess.run(
                command,
                cwd=workspace,
                stdin=subprocess.DEVNULL,
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
    changes = _witness_changes(witness)
    with _experiment_directory("witness", witness.witness_id) as experiment:
        workspace = experiment / "workspace"
        shutil.copytree(fixture_root, workspace, symlinks=True)
        before = snapshot_workspace(workspace)
        _validate_frozen_fixture(before, fixture, contract)
        changed_paths: list[str] = []
        for raw in changes:
            _apply_witness_change(workspace, fixture, raw, changed_paths)
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
        evidence = _run_witness_commands(contract.commands, workspace)
        observer = _witness_observer(evidence.results[1].stdout)
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
    for item in observation.observer_paths:
        try:
            observed = subprocess.run(
                ["python3", item],
                cwd=observation.workspace,
                stdin=subprocess.DEVNULL,
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
    for item in subject.observer_paths:
        path = workspace / item
        if not path.is_file():
            raise RoleRuntimeError("public fixture observer is unavailable")
        protected[item] = _sha256_file(path)
    task = (workspace / "TASK.txt").read_text(encoding="utf-8")
    prompt = task + (
        "\n\nApply this additional instruction while completing the task:\n"
        + str(subject.request["candidate_instruction"])
        if subject.condition == "B"
        else ""
    )
    return _SubjectRun(subject, workspace, before, protected, prompt)


def _execute_subject(run: _SubjectRun) -> _SubjectCapture | SubjectResult:
    try:
        execution = execute_omp(
            OmpExecutionRequest(
                run.workspace,
                run.prompt,
                run.subject.request,
                "Complete the supplied task in the workspace. Do not describe an "
                "experiment. Use only the permitted tools.",
                run.subject.request["permissions"]["tools"],
                False,
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
    subject = _SubjectRequest(assignment, condition, fixture, request, observer_paths)
    with _experiment_directory("subject", assignment) as experiment:
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
