"""Durable, write-once artifact publication primitives."""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

from .models import canonical_bytes as _canonical_bytes


class ArtifactError(RuntimeError):
    """Raised when an artifact cannot be safely published."""


class ArtifactConflictError(ArtifactError):
    """Raised when a write-once artifact already has different bytes."""


class ArtifactMode(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


def canonical_bytes(value: Any) -> bytes:
    """Return the RFC 8785 representation used for durable JSON artifacts."""
    return _canonical_bytes(value)


def canonical_hash(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def safe_relative_path(path: str | Path) -> PurePosixPath:
    """Validate an artifact name before it is joined to a store root."""
    if not isinstance(path, (str, Path)):
        raise ArtifactError("artifact path must be a relative path")
    text = str(path)
    if not text or "\x00" in text or "\\" in text:
        raise ArtifactError("artifact path is unsafe")
    candidate = PurePosixPath(text)
    if (
        candidate.is_absolute()
        or not candidate.parts
        or any(part in ("", ".", "..") for part in candidate.parts)
    ):
        raise ArtifactError("artifact path is unsafe")
    return candidate


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _bytes_equal(left: Path, payload: bytes) -> bool:
    try:
        with left.open("rb") as stream:
            while payload:
                chunk = stream.read(min(len(payload), 1024 * 1024))
                if not chunk or chunk != payload[: len(chunk)]:
                    return False
                payload = payload[len(chunk) :]
            return not stream.read(1)
    except FileNotFoundError:
        return False


class ArtifactStore:
    """Publishes byte-identical files once, recovering safely after a crash.

    A staging file is always created beside its final name, making ``link`` an
    atomic publication operation on the same filesystem.
    """

    def __init__(self, root: str | Path, private_root: str | Path | None = None) -> None:
        self.root = Path(root)
        self.private_root = (
            Path(private_root) if private_root is not None else self.root / "private"
        )
        self._public_only = False
        self._prepare_directory(self.root)
        if self.private_root == self.root:
            raise ArtifactError("private artifact root must be separate")
        self._prepare_directory(self.private_root)

    @classmethod
    def public_only(cls, root: str | Path) -> ArtifactStore:
        """Create a public-process store with no private-root capability."""
        store = object.__new__(cls)
        store.root = Path(root)
        store._public_only = True
        cls._prepare_directory(store.root)
        return store

    @staticmethod
    def _prepare_directory(directory: Path) -> None:
        missing: list[Path] = []
        current = directory
        while True:
            try:
                status = current.lstat()
            except FileNotFoundError:
                missing.append(current)
                parent = current.parent
                if parent == current:
                    raise ArtifactError("artifact root cannot be created") from None
                current = parent
                continue
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                raise ArtifactError("artifact root is not a directory")
            break
        for current in reversed(missing):
            os.mkdir(current, 0o700)
            os.chmod(current, 0o700)
            _fsync_directory(current)
            _fsync_directory(current.parent)
        os.chmod(directory, 0o700)
        _fsync_directory(directory)
        _fsync_directory(directory.parent)

    def path_for(self, relative_path: str | Path, mode: ArtifactMode = ArtifactMode.PUBLIC) -> Path:
        relative = safe_relative_path(relative_path)
        if mode is ArtifactMode.PRIVATE and self._public_only:
            raise ArtifactError("public artifact store cannot access private storage")
        root = self.private_root if mode is ArtifactMode.PRIVATE else self.root
        destination = root.joinpath(*relative.parts)
        if (
            mode is ArtifactMode.PUBLIC
            and not self._public_only
            and self.private_root.is_relative_to(self.root)
            and destination.is_relative_to(self.private_root)
        ):
            raise ArtifactError("public artifact path overlaps private storage")
        # The lexical check above, plus refusing a symlink at every created
        # directory, prevents an artifact name from escaping the configured root.
        return destination

    def publish_json(
        self, relative_path: str | Path, value: Any, mode: ArtifactMode = ArtifactMode.PUBLIC
    ) -> str:
        return self.publish_bytes(relative_path, canonical_bytes(value), mode)

    def publish_bytes(
        self, relative_path: str | Path, payload: bytes, mode: ArtifactMode = ArtifactMode.PUBLIC
    ) -> str:
        if not isinstance(payload, bytes):
            raise ArtifactError("artifact payload must be bytes")
        destination = self.path_for(relative_path, mode)
        expected_mode = 0o600 if mode is ArtifactMode.PRIVATE else 0o644
        self._make_parent(destination.parent)
        try:
            destination.lstat()
        except FileNotFoundError:
            pass
        else:
            self._recover_equal(destination, payload, expected_mode)
            return sha256(payload).hexdigest()

        stage = destination.parent / f".{destination.name}.stage-{secrets.token_hex(16)}"
        try:
            fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL, expected_mode)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fchmod(fd, expected_mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(stage, destination, follow_symlinks=False)
            except FileExistsError:
                self._recover_equal(destination, payload, expected_mode)
            else:
                _fsync_directory(destination.parent)
            return sha256(payload).hexdigest()
        finally:
            with contextlib.suppress(FileNotFoundError):
                stage.unlink()

    def read_bytes(
        self, relative_path: str | Path, mode: ArtifactMode = ArtifactMode.PUBLIC
    ) -> bytes:
        destination = self.path_for(relative_path, mode)
        if destination.is_symlink() or not destination.is_file():
            raise ArtifactError("artifact is not a regular file")
        return destination.read_bytes()

    def _recover_equal(self, destination: Path, payload: bytes, expected_mode: int) -> None:
        status = destination.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise ArtifactConflictError("artifact destination is not a regular file")
        if not _bytes_equal(destination, payload):
            raise ArtifactConflictError("write-once artifact bytes conflict")
        if stat.S_IMODE(status.st_mode) != expected_mode:
            os.chmod(destination, expected_mode)
        fd = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            status = os.fstat(fd)
            if not stat.S_ISREG(status.st_mode):
                raise ArtifactConflictError("artifact destination is not a regular file")
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(destination.parent)

    def _make_parent(self, parent: Path) -> None:
        root = (
            self.private_root
            if self.private_root == parent or self.private_root in parent.parents
            else self.root
        )
        current = root
        for part in parent.relative_to(root).parts:
            current = current / part
            try:
                status = current.lstat()
            except FileNotFoundError:
                os.mkdir(current, 0o700)
                os.chmod(current, 0o700)
                _fsync_directory(current)
                _fsync_directory(current.parent)
                continue
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                raise ArtifactError("artifact parent is not a directory")
            if stat.S_IMODE(status.st_mode) != 0o700:
                os.chmod(current, 0o700)
            _fsync_directory(current)
            _fsync_directory(current.parent)
