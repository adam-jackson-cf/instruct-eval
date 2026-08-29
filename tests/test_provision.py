"""Contract tests for pinned, fail-closed Temporal CLI provisioning."""

from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO
from unittest.mock import patch

import pytest

from instruct_eval import provision


class Result:
    def __init__(self, output: str, returncode: int = 0) -> None:
        self.stdout, self.returncode = output, returncode


def archive_bytes(binary: bytes = b"binary") -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        info = tarfile.TarInfo("temporal")
        info.size = len(binary)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(binary))
    return result.getvalue()


class ProvisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_exact_platform_vectors_urls_and_checked_in_manifest(self) -> None:
        darwin = provision.select_platform("Darwin", "arm64")
        linux = provision.select_platform("Linux", "amd64")
        assert darwin.filename == "temporal_cli_1.8.2_darwin_arm64.tar.gz"
        assert linux.sha256 == "d8421bda989e6514b4bdb4d63a9012a8a05a806892e881a5aad8510496349a94"
        assert (
            provision.release_url(darwin)
            == "https://github.com/temporalio/cli/releases/download/v1.8.2/temporal_cli_1.8.2_darwin_arm64.tar.gz"
        )
        assert provision.parse_checksums()[darwin.filename] == darwin.sha256
        for system, machine in (("Darwin", "x86_64"), ("Linux", "arm64"), ("Windows", "amd64")):
            with (
                self.subTest(system=system, machine=machine),
                pytest.raises(provision.ProvisionError),
            ):
                provision.select_platform(system, machine)

    def test_manifest_refuses_tamper_duplicates_and_extras(self) -> None:
        valid = (
            "dacdc3587682c04cf27e67c8878ca2d755230b6ad63c0c6ebddd7348ae90ed94  "
            "temporal_cli_1.8.2_darwin_arm64.tar.gz\n"
            "d8421bda989e6514b4bdb4d63a9012a8a05a806892e881a5aad8510496349a94  "
            "temporal_cli_1.8.2_linux_amd64.tar.gz\n"
        )
        for content in (
            valid.replace("dacd", "face", 1),
            valid + valid.splitlines()[0] + "\n",
            valid + "a" * 64 + "  extra.tar.gz\n",
        ):
            path = self.root / "checksums"
            path.write_text(content)
            with self.subTest(content=content), pytest.raises(provision.ProvisionError):
                provision.parse_checksums(path)

    def test_https_downloader_rejects_partial_and_oversize_payloads(self) -> None:
        class Response:
            def __init__(self) -> None:
                self.headers = {"Content-Length": "99"}

            def geturl(self) -> str:
                return "https://example.test/file"

            def read(self, _: int) -> bytes:
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *_: object) -> None:
                pass

        with (
            patch("instruct_eval.provision.urlopen", return_value=Response()),
            pytest.raises(provision.ProvisionError),
        ):
            provision._download_https("https://example.test/file", io.BytesIO(), max_bytes=1)
        with pytest.raises(provision.ProvisionError):
            provision._download_https("http://example.test/file", io.BytesIO(), max_bytes=1)

    def test_tampered_or_partial_archive_never_replaces_existing_binary(self) -> None:
        destination = self.root / "temporal"
        destination.write_bytes(b"old")

        def download(_: str, target: BinaryIO) -> str:
            target.write(b"partial")
            return sha256(b"partial").hexdigest()

        with (
            patch(
                "instruct_eval.provision.parse_checksums",
                return_value={"temporal_cli_1.8.2_darwin_arm64.tar.gz": "0" * 64},
            ),
            pytest.raises(provision.ProvisionError),
        ):
            provision.provision_temporal_cli(
                destination,
                system="Darwin",
                machine="arm64",
                operations=provision.ProvisionOperations(downloader=download),
            )
        assert destination.read_bytes() == b"old"

    def test_atomic_install_has_executable_mode_and_exact_version(self) -> None:
        destination = self.root / "bin" / "temporal"
        payload = archive_bytes()
        digest = sha256(payload).hexdigest()

        def download(_: str, target: BinaryIO) -> str:
            target.write(payload)
            return digest

        with patch(
            "instruct_eval.provision.parse_checksums",
            return_value={"temporal_cli_1.8.2_darwin_arm64.tar.gz": digest},
        ):
            result = provision.provision_temporal_cli(
                destination,
                system="Darwin",
                machine="arm64",
                operations=provision.ProvisionOperations(
                    downloader=download,
                    runner=lambda *_args, **_kwargs: Result(
                        f"{provision.TEMPORAL_CLI_VERSION_OUTPUT}\n"
                    ),
                ),
            )
        assert result == destination
        assert destination.stat().st_mode & 511 == 493
        for output in (
            "temporal version 1.8.3\n",
            "temporal version 1.8.2 (Server 1.31.1, UI 2.50.1)\n",
            "temporal version 1.8.2 (Server 1.31.2, UI 2.50.0)\n",
        ):
            with pytest.raises(provision.ProvisionError):
                provision.assert_temporal_version(
                    destination, runner=lambda *_a, output=output, **_k: Result(output)
                )

    def test_equal_recovery_reuses_exact_existing_binary(self) -> None:
        destination = self.root / "temporal"
        destination.write_bytes(b"existing")
        with patch("instruct_eval.provision.parse_checksums") as checksums:
            result = provision.provision_temporal_cli(
                destination,
                system="Darwin",
                machine="arm64",
                operations=provision.ProvisionOperations(
                    downloader=lambda *_: self.fail("must not download an exact binary"),
                    runner=lambda *_args, **_kwargs: Result(
                        f"{provision.TEMPORAL_CLI_VERSION_OUTPUT}\n"
                    ),
                ),
            )
        assert result == destination
        checksums.assert_called_once_with()

    def test_symlinks_and_invalid_service_configuration_fail_closed(self) -> None:
        target = self.root / "target"
        target.write_text("x")
        link = self.root / "link"
        link.symlink_to(target)
        with pytest.raises(provision.ProvisionError):
            provision.assert_temporal_version(link)
        db = self.root / "state.sqlite"
        run_root = self.root / "runs"
        argv = provision.server_start_dev_argv(
            target, address="127.0.0.1", database_path=db, run_roots=(run_root,)
        )
        assert argv == (
            str(target),
            "server",
            "start-dev",
            "--ip",
            "127.0.0.1",
            "--namespace",
            "instruct-eval",
            "--db-filename",
            str(db),
        )
        for address, namespace, path in (
            ("0.0.0.0", "instruct-eval", db),
            ("127.0.0.1", "wrong", db),
            ("127.0.0.1", "instruct-eval", run_root / "state.sqlite"),
        ):
            with (
                self.subTest(address=address, namespace=namespace, path=path),
                pytest.raises(provision.ServicePrerequisiteError),
            ):
                provision.validate_service_prerequisites(
                    address, namespace, path, run_roots=(run_root,)
                )


if __name__ == "__main__":
    unittest.main()
