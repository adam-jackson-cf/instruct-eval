from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from instruct_eval.artifacts import (
    ArtifactConflictError,
    ArtifactError,
    ArtifactMode,
    ArtifactStore,
)
from instruct_eval.coordination import (
    CoordinationError,
    CoordinationStore,
    InvocationDisposition,
)


class ArtifactStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = ArtifactStore(Path(self.directory.name) / "artifacts")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_publication_is_canonical_write_once_and_recovers_equal_bytes(self) -> None:
        digest = self.store.publish_json("gate/result.json", {"b": 2, "a": 1})
        assert digest == self.store.publish_json("gate/result.json", {"a": 1, "b": 2})
        assert self.store.read_bytes("gate/result.json") == b'{"a":1,"b":2}'
        with pytest.raises(ArtifactConflictError):
            self.store.publish_bytes("gate/result.json", b"different")

    def test_private_mode_is_separate_and_restrictive(self) -> None:
        self.store.publish_bytes("mapping.bin", b"secret", ArtifactMode.PRIVATE)
        private = self.store.path_for("mapping.bin", ArtifactMode.PRIVATE)
        public = self.store.path_for("mapping.bin")
        assert private.exists()
        assert not public.exists()
        assert stat.S_IMODE(private.stat().st_mode) == 384
        with pytest.raises(ArtifactError):
            self.store.publish_bytes("private/leak.bin", b"public")

    def test_rejects_escape_symlink_and_conflicting_existing_path(self) -> None:
        for unsafe in ("", "/absolute", "../escape", "one/../two", "one\\two"):
            with pytest.raises(ArtifactError):
                self.store.publish_bytes(unsafe, b"x")
        target = self.store.path_for("dir")
        target.symlink_to(Path(self.directory.name))
        with pytest.raises(ArtifactError):
            self.store.publish_bytes("dir/file", b"x")

    def test_link_race_recovers_only_exact_existing_bytes(self) -> None:
        destination = self.store.path_for("race.bin")
        original_link = os.link

        def racing_link(source: Any, target: Any, *_: Any, **__: Any) -> None:
            Path(os.fsdecode(os.fspath(target))).write_bytes(
                Path(os.fsdecode(os.fspath(source))).read_bytes()
            )
            raise FileExistsError

        with patch("instruct_eval.artifacts.os.link", racing_link):
            self.store.publish_bytes("race.bin", b"payload")
        assert destination.read_bytes() == b"payload"
        assert not list(destination.parent.glob(".race.bin.stage-*"))
        assert original_link is not racing_link

    def test_staging_failure_leaves_no_final_or_stage(self) -> None:
        with (
            patch("instruct_eval.artifacts.os.write", side_effect=OSError("disk full")),
            pytest.raises(OSError, match=r"^disk full$"),
        ):
            self.store.publish_bytes("failure.bin", b"payload")
        assert not self.store.path_for("failure.bin").exists()
        assert not list(self.store.path_for("failure.bin").parent.glob(".failure.bin.stage-*"))

    def test_file_sync_failure_cleans_staging_without_publishing(self) -> None:
        with (
            patch("instruct_eval.artifacts.os.fsync", side_effect=OSError("sync failed")),
            pytest.raises(OSError, match=r"^sync failed$"),
        ):
            self.store.publish_bytes("sync-failure.bin", b"payload")
        destination = self.store.path_for("sync-failure.bin")
        assert not destination.exists()
        assert not list(destination.parent.glob(".sync-failure.bin.stage-*"))

    def test_parent_sync_failure_is_recovered_by_exact_republication(self) -> None:
        calls = 0
        original_fsync = os.fsync

        def fail_parent_once(fd: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("parent sync failed")
            original_fsync(fd)

        with (
            patch("instruct_eval.artifacts.os.fsync", fail_parent_once),
            pytest.raises(OSError, match=r"^parent sync failed$"),
        ):
            self.store.publish_bytes("parent-sync.bin", b"payload")
        assert self.store.publish_bytes("parent-sync.bin", b"payload") == self.store.publish_bytes(
            "parent-sync.bin", b"payload"
        )
        assert not list(
            self.store.path_for("parent-sync.bin").parent.glob(".parent-sync.bin.stage-*")
        )


class CoordinationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "private" / "coordination.sqlite"
        self.store = CoordinationStore(self.path)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_invocation_authorizes_once_and_recovers_committed_bytes(self) -> None:
        first = self.store.reserve_invocation("call", b"frozen input")
        assert first.disposition == InvocationDisposition.ACQUIRED
        assert (
            self.store.reserve_invocation("call", b"frozen input").disposition
            == InvocationDisposition.IN_FLIGHT
        )
        committed = self.store.commit_result("call", first.owner_epoch or 0, b"result")
        assert committed.result_bytes == b"result"
        assert (
            self.store.reserve_invocation("call", b"frozen input").disposition
            == InvocationDisposition.RESULT_RECOVERED
        )
        with pytest.raises(CoordinationError):
            self.store.reserve_invocation("call", b"changed input")
        with pytest.raises(CoordinationError):
            self.store.commit_result("call", first.owner_epoch or 0, b"other result")

    def test_database_is_private(self) -> None:
        assert stat.S_IMODE(self.path.stat().st_mode) == 384
