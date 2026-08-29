"""Fail-closed provisioning for the pinned Temporal CLI development server."""

from __future__ import annotations

import ipaddress
import os
import platform as host_platform
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlparse
from urllib.request import Request, urlopen

TEMPORAL_CLI_VERSION = "1.8.2"
TEMPORAL_CLI_VERSION_OUTPUT = "temporal version 1.8.2 (Server 1.31.2, UI 2.50.1)"
TEMPORAL_NAMESPACE = "instruct-eval"
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
_CHUNK_BYTES = 64 * 1024
_RELEASE_BASE = "https://github.com/temporalio/cli/releases/download/v1.8.2"
_EXPECTED_CHECKSUMS = {
    "temporal_cli_1.8.2_darwin_arm64.tar.gz": (
        "dacdc3587682c04cf27e67c8878ca2d755230b6ad63c0c6ebddd7348ae90ed94"
    ),
    "temporal_cli_1.8.2_linux_amd64.tar.gz": (
        "d8421bda989e6514b4bdb4d63a9012a8a05a806892e881a5aad8510496349a94"
    ),
}


class ProvisionError(RuntimeError):
    """A provisioning invariant was not satisfied."""


class ServicePrerequisiteError(ProvisionError):
    """The local Temporal development server configuration is unsafe."""


@dataclass(frozen=True, slots=True)
class PlatformArtifact:
    system: str
    machine: str
    filename: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ProvisionOperations:
    """Injectable side-effect boundaries for Temporal CLI provisioning."""

    downloader: Callable[[str, BinaryIO], str] | None = None
    runner: Callable[..., object] = subprocess.run


_DEFAULT_PROVISION_OPERATIONS = ProvisionOperations()


def _reference_path() -> Path:
    return Path(__file__).resolve().parents[2] / "references" / "temporal-cli-v1.8.2-checksums.txt"


def select_platform(system: str | None = None, machine: str | None = None) -> PlatformArtifact:
    """Return the only supported host artifact; reject every other host."""
    system = system if system is not None else host_platform.system()
    machine = machine if machine is not None else host_platform.machine()
    mapping = {
        ("Darwin", "arm64"): "temporal_cli_1.8.2_darwin_arm64.tar.gz",
        ("Linux", "x86_64"): "temporal_cli_1.8.2_linux_amd64.tar.gz",
        ("Linux", "amd64"): "temporal_cli_1.8.2_linux_amd64.tar.gz",
    }
    try:
        filename = mapping[(system, machine)]
    except KeyError as error:
        raise ProvisionError(
            f"unsupported Temporal CLI platform: {system!r}/{machine!r}"
        ) from error
    return PlatformArtifact(system, machine, filename, _EXPECTED_CHECKSUMS[filename])


def release_url(artifact: PlatformArtifact) -> str:
    if (
        artifact.filename not in _EXPECTED_CHECKSUMS
        or artifact.sha256 != _EXPECTED_CHECKSUMS[artifact.filename]
    ):
        raise ProvisionError("unrecognized Temporal CLI artifact")
    return f"{_RELEASE_BASE}/{artifact.filename}"


def _regular_nonsymlink(path: Path, *, required: bool = True) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        if required:
            raise ProvisionError(f"required path is absent: {path}") from None
        return
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise ProvisionError(f"path must be a regular non-symlink file: {path}")


def parse_checksums(path: str | Path | None = None) -> Mapping[str, str]:
    """Parse precisely the checked-in two-artifact checksum manifest."""
    reference = Path(path) if path is not None else _reference_path()
    _regular_nonsymlink(reference)
    parsed: dict[str, str] = {}
    with reference.open("rt", encoding="ascii", newline="") as manifest:
        for raw in manifest:
            line = raw.rstrip("\n")
            if not line or line.endswith("\r"):
                raise ProvisionError("checksum manifest contains an invalid line")
            pieces = line.split("  ")
            if (
                len(pieces) != 2
                or len(pieces[0]) != 64
                or any(char not in "0123456789abcdef" for char in pieces[0])
            ):
                raise ProvisionError("checksum manifest has invalid syntax")
            digest, filename = pieces
            if not filename or "/" in filename or "\\" in filename or filename in parsed:
                raise ProvisionError("checksum manifest has duplicate or unsafe filename")
            parsed[filename] = digest
    if parsed != _EXPECTED_CHECKSUMS:
        raise ProvisionError("checksum manifest must exactly match pinned artifacts")
    return dict(parsed)


def _download_https(url: str, output: BinaryIO, *, max_bytes: int) -> str:
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ProvisionError("download URL must be a clean HTTPS URL")
    request = Request(url, headers={"User-Agent": "instruct-eval-provisioner"})
    with urlopen(request, timeout=30) as response:
        final = urlparse(response.geturl())
        if final.scheme != "https":
            raise ProvisionError("download was redirected away from HTTPS")
        length = response.headers.get("Content-Length")
        if length is not None:
            try:
                if int(length) > max_bytes:
                    raise ProvisionError("download exceeds configured byte limit")
            except ValueError as error:
                raise ProvisionError("download has invalid Content-Length") from error
        digest = sha256()
        total = 0
        while chunk := response.read(_CHUNK_BYTES):
            total += len(chunk)
            if total > max_bytes:
                raise ProvisionError("download exceeds configured byte limit")
            digest.update(chunk)
            output.write(chunk)
        return digest.hexdigest()


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        while chunk := source.read(_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_binary(archive: Path, staging: Path) -> Path:
    with tarfile.open(archive, mode="r:gz") as contents:
        members = contents.getmembers()
        candidates = [member for member in members if member.name == "temporal"]
        if (
            len(candidates) != 1
            or not candidates[0].isfile()
            or candidates[0].issym()
            or candidates[0].islnk()
        ):
            raise ProvisionError("archive must contain exactly one regular temporal binary")
        source = contents.extractfile(candidates[0])
        if source is None:
            raise ProvisionError("archive temporal binary cannot be read")
        binary = staging / "temporal"
        with source, binary.open("xb") as target:
            while chunk := source.read(_CHUNK_BYTES):
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
    os.chmod(binary, 0o755)
    return binary


def assert_temporal_version(
    binary: str | Path, *, runner: Callable[..., object] = subprocess.run
) -> None:
    binary_path = Path(binary)
    _regular_nonsymlink(binary_path)
    try:
        completed = runner(
            [str(binary_path), "--version"], check=False, capture_output=True, text=True
        )
    except OSError as error:
        raise ProvisionError("installed Temporal CLI cannot be executed") from error
    output = getattr(completed, "stdout", "")
    if (
        getattr(completed, "returncode", 1) != 0
        or output.rstrip("\n") != TEMPORAL_CLI_VERSION_OUTPUT
    ):
        raise ProvisionError(
            "installed Temporal CLI version does not exactly match the pinned release"
        )


def _has_symlink_component(path: Path) -> bool:
    current = path
    while current != current.parent:
        if (current.exists() or current.is_symlink()) and stat.S_ISLNK(current.lstat().st_mode):
            return True
        current = current.parent
    return False


def provision_temporal_cli(
    destination: str | Path,
    *,
    system: str | None = None,
    machine: str | None = None,
    max_download_bytes: int = MAX_DOWNLOAD_BYTES,
    operations: ProvisionOperations = _DEFAULT_PROVISION_OPERATIONS,
) -> Path:
    """Verify then atomically install the pinned CLI to ``destination``."""
    if not isinstance(max_download_bytes, int) or max_download_bytes <= 0:
        raise ValueError("max_download_bytes must be positive")
    destination = Path(destination)
    artifact = select_platform(system, machine)
    checksums = parse_checksums()
    if destination.exists() or destination.is_symlink():
        _regular_nonsymlink(destination, required=False)
        try:
            assert_temporal_version(destination, runner=operations.runner)
        except ProvisionError:
            pass
        else:
            return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    if _has_symlink_component(destination.parent):
        raise ProvisionError("installation parent must not contain a symlink")
    url = release_url(artifact)
    with tempfile.TemporaryDirectory(prefix=".temporal-", dir=destination.parent) as temporary:
        staging = Path(temporary)
        archive = staging / artifact.filename
        with archive.open("xb") as downloaded:
            if operations.downloader:
                operations.downloader(url, downloaded)
            else:
                _download_https(url, downloaded, max_bytes=max_download_bytes)
            downloaded.flush()
            os.fsync(downloaded.fileno())
        if archive.stat().st_size > max_download_bytes:
            raise ProvisionError("download exceeds configured byte limit")
        if _file_sha256(archive) != checksums[artifact.filename]:
            raise ProvisionError("Temporal CLI checksum mismatch")
        binary = _extract_binary(archive, staging)
        assert_temporal_version(binary, runner=operations.runner)
        os.replace(binary, destination)
        os.chmod(destination, 0o755)
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return destination


def validate_service_prerequisites(
    address: str, namespace: str, database_path: str | Path, *, run_roots: Iterable[str | Path] = ()
) -> Path:
    try:
        if not ipaddress.ip_address(address).is_loopback:
            raise ValueError
    except ValueError as error:
        raise ServicePrerequisiteError(
            "Temporal service address must be a loopback IP address"
        ) from error
    if namespace != TEMPORAL_NAMESPACE:
        raise ServicePrerequisiteError("Temporal service namespace must be instruct-eval")
    database = Path(database_path)
    if (
        not database.is_absolute()
        or database.suffix != ".sqlite"
        or _has_symlink_component(database)
    ):
        raise ServicePrerequisiteError(
            "Temporal SQLite database must be an absolute non-symlink .sqlite path"
        )
    if database.exists() and not stat.S_ISREG(database.lstat().st_mode):
        raise ServicePrerequisiteError("Temporal SQLite database must be a regular file")
    resolved = database.resolve(strict=False)
    for root in run_roots:
        candidate = Path(root).resolve(strict=False)
        try:
            resolved.relative_to(candidate)
        except ValueError:
            continue
        raise ServicePrerequisiteError(
            "Temporal SQLite database must be outside ephemeral run roots"
        )
    return database


def server_start_dev_argv(
    binary: str | Path,
    *,
    address: str,
    database_path: str | Path,
    namespace: str = TEMPORAL_NAMESPACE,
    run_roots: Iterable[str | Path] = (),
) -> tuple[str, ...]:
    database = validate_service_prerequisites(
        address, namespace, database_path, run_roots=run_roots
    )
    binary = Path(binary)
    _regular_nonsymlink(binary)
    return (
        str(binary),
        "server",
        "start-dev",
        "--ip",
        address,
        "--namespace",
        namespace,
        "--db-filename",
        str(database),
    )
