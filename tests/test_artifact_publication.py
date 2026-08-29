from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from instruct_eval import artifacts
from instruct_eval.artifacts import ArtifactConflictError, ArtifactMode, ArtifactStore


class ArtifactPublicationDurabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = ArtifactStore(Path(self.directory.name) / "artifacts")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_public_and_private_recovery_restores_final_modes(self) -> None:
        for mode, expected in ((ArtifactMode.PUBLIC, 0o644), (ArtifactMode.PRIVATE, 0o600)):
            self.store.publish_bytes(f"{mode.value}.bin", b"payload", mode)
            destination = self.store.path_for(f"{mode.value}.bin", mode)
            os.chmod(destination, 0o777)
            self.store.publish_bytes(f"{mode.value}.bin", b"payload", mode)
            assert stat.S_IMODE(destination.stat().st_mode) == expected

    def test_recovery_after_stage_sync_and_mode_application_failures(self) -> None:
        original_fsync = os.fsync
        original_fchmod = os.fchmod

        def sync_then_crash(fd: int) -> None:
            original_fsync(fd)
            raise OSError("crash after stage sync")

        def chmod_then_crash(fd: int, permissions: int) -> None:
            original_fchmod(fd, permissions)
            raise OSError("crash after mode application")

        for name, patch_target, replacement, error_message in (
            ("stage-sync", "os.fsync", sync_then_crash, "crash after stage sync"),
            ("mode", "os.fchmod", chmod_then_crash, "crash after mode application"),
        ):
            with (
                self.subTest(name=name),
                patch(f"instruct_eval.artifacts.{patch_target}", replacement),
                pytest.raises(OSError, match=rf"^{error_message}$"),
            ):
                self.store.publish_bytes(f"{name}.bin", b"payload")
            destination = self.store.path_for(f"{name}.bin")
            assert not destination.exists()
            self.store.publish_bytes(f"{name}.bin", b"payload")
            assert stat.S_IMODE(destination.stat().st_mode) == 420

    def test_recovery_after_link_crash_is_exact_and_durable(self) -> None:
        destination = self.store.path_for("linked.bin")
        original_link = os.link

        def link_then_crash(
            source: str | Path, target: str | Path, *args: Any, **kwargs: Any
        ) -> None:
            original_link(source, target, *args, **kwargs)
            raise OSError("crash after link")

        with (
            patch("instruct_eval.artifacts.os.link", link_then_crash),
            pytest.raises(OSError, match=r"^crash after link$"),
        ):
            self.store.publish_bytes("linked.bin", b"payload")
        assert destination.read_bytes() == b"payload"
        self.store.publish_bytes("linked.bin", b"payload")
        assert stat.S_IMODE(destination.stat().st_mode) == 420

    def test_nested_directory_sync_failures_recover_every_created_entry(self) -> None:
        original_sync = artifacts._fsync_directory
        for failure_point in range(1, 8):
            with self.subTest(failure_point=failure_point):
                directory = tempfile.TemporaryDirectory()
                self.addCleanup(directory.cleanup)
                store = ArtifactStore(Path(directory.name) / "artifacts")
                calls = 0

                def sync_then_crash(path: Path, *, failure_point: int = failure_point) -> None:
                    nonlocal calls
                    calls += 1
                    original_sync(path)
                    if calls == failure_point:
                        raise OSError("crash during directory durability")

                with (
                    patch("instruct_eval.artifacts._fsync_directory", sync_then_crash),
                    pytest.raises(
                        OSError,
                        match=r"^crash during directory durability$",
                    ),
                ):
                    store.publish_bytes("one/two/three/result.bin", b"payload")
                store.publish_bytes("one/two/three/result.bin", b"payload")
                destination = store.path_for("one/two/three/result.bin")
                assert destination.read_bytes() == b"payload"
                assert stat.S_IMODE(destination.stat().st_mode) == 420

    def test_equal_retry_rejects_non_regular_conflicts(self) -> None:
        destination = self.store.path_for("conflict.bin")
        destination.mkdir()
        with pytest.raises(ArtifactConflictError):
            self.store.publish_bytes("conflict.bin", b"payload")
        destination.rmdir()
        destination.symlink_to(self.directory.name)
        with pytest.raises(ArtifactConflictError):
            self.store.publish_bytes("conflict.bin", b"payload")


if __name__ == "__main__":
    unittest.main()
