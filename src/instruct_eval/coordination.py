"""Crash-safe coordination records for non-idempotent role invocations."""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path


class CoordinationError(RuntimeError):
    """Raised when durable coordination invariants would be violated."""


class InvocationState(StrEnum):
    STARTED = "STARTED"
    RESULT_COMMITTED = "RESULT_COMMITTED"
    INDETERMINATE_TERMINALIZED = "INDETERMINATE_TERMINALIZED"


class InvocationDisposition(StrEnum):
    ACQUIRED = "ACQUIRED"
    RESULT_RECOVERED = "RESULT_RECOVERED"
    INDETERMINATE = "INDETERMINATE"
    IN_FLIGHT = "IN_FLIGHT"


class GateState(StrEnum):
    RESERVED = "RESERVED"
    RELEASE_COMMITTING = "RELEASE_COMMITTING"
    PUBLISHED = "PUBLISHED"


class GateDisposition(StrEnum):
    ACQUIRED = "ACQUIRED"
    RECOVERED = "RECOVERED"
    COMMITTING = "COMMITTING"
    PUBLISHED = "PUBLISHED"


@dataclass(frozen=True, slots=True)
class InvocationReservation:
    disposition: InvocationDisposition
    invocation_key: str
    owner_epoch: int | None
    input_bytes: bytes
    input_sha256: str
    result_bytes: bytes | None = None
    result_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class InvocationCommitRequest:
    invocation_key: str
    owner_epoch: int
    state: str
    epoch: int
    result_bytes: bytes
    result_sha256: str


@dataclass(frozen=True, slots=True)
class GateReservation:
    disposition: GateDisposition
    workflow_id: str
    run_id: str
    ordinal: int
    prior_record_sha256: str
    expected_revision_sha256: str
    branch_kind: str
    record_input_bytes: bytes
    record_input_sha256: str
    owner_epoch: int | None
    publication_path: Path | None = None
    publication_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class DecisionReservation:
    disposition: GateDisposition
    workflow_id: str
    run_id: str
    target_kind: str
    target_id: str
    sequence: int
    prior_record_sha256: str
    expected_revision_sha256: str
    record_input_bytes: bytes
    record_input_sha256: str
    owner_epoch: int | None
    publication_path: Path | None = None
    publication_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class GateRequest:
    workflow_id: str
    run_id: str
    ordinal: int
    prior_record_sha256: str
    expected_revision_sha256: str
    branch_kind: str
    record_input_bytes: bytes


@dataclass(frozen=True, slots=True)
class GateReservationContext:
    disposition: GateDisposition
    request: GateRequest
    row: tuple[object, ...] | None = None
    owner_epoch: int | None = None
    publication_path: Path | None = None
    publication_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class GateCommitRequest:
    workflow_id: str
    run_id: str
    ordinal: int
    expected_revision_sha256: str
    owner_epoch: int


@dataclass(frozen=True, slots=True)
class GatePublicationRequest:
    workflow_id: str
    run_id: str
    ordinal: int
    expected_revision_sha256: str
    owner_epoch: int
    final_artifact_path: str | Path
    expected_bytes: bytes
    expected_sha256: str


@dataclass(frozen=True, slots=True)
class DecisionRequest:
    workflow_id: str
    run_id: str
    target_kind: str
    target_id: str
    sequence: int
    prior_record_sha256: str
    expected_revision_sha256: str
    record_input_bytes: bytes


@dataclass(frozen=True, slots=True)
class DecisionCommitRequest:
    workflow_id: str
    run_id: str
    target_kind: str
    target_id: str
    sequence: int
    expected_revision_sha256: str
    owner_epoch: int


@dataclass(frozen=True, slots=True)
class DecisionPublicationRequest:
    workflow_id: str
    run_id: str
    target_kind: str
    target_id: str
    sequence: int
    expected_revision_sha256: str
    owner_epoch: int
    final_artifact_path: str | Path
    expected_bytes: bytes
    expected_sha256: str


class ChildAuthorizationState(StrEnum):
    ISSUED = "ISSUED"
    CLAIMED = "CLAIMED"


@dataclass(frozen=True, slots=True)
class ChildAuthorization:
    campaign_id: str
    parent_workflow_id: str
    parent_run_id: str
    claim_sha256: str
    fingerprint_sha256: str
    coverage_sha256: str
    experiment_id: str | None
    child_workflow_id: str | None
    child_run_id: str | None
    state: ChildAuthorizationState
    owner_epoch: int


@dataclass(frozen=True, slots=True)
class ChildAuthorizationRequest:
    campaign_id: str
    parent_workflow_id: str
    parent_run_id: str
    claim_sha256: str
    fingerprint_sha256: str
    coverage_sha256: str


@dataclass(frozen=True, slots=True)
class ChildAuthorizationClaimRequest:
    campaign_id: str
    parent_workflow_id: str
    parent_run_id: str
    claim_sha256: str
    fingerprint_sha256: str
    coverage_sha256: str
    experiment_id: str
    child_workflow_id: str
    child_run_id: str


@dataclass(frozen=True, slots=True)
class ClaimedChildAuthorizationRequest:
    campaign_id: str
    experiment_id: str
    child_workflow_id: str
    child_run_id: str


@dataclass(frozen=True, slots=True)
class PublishedDecisionRequest:
    workflow_id: str
    run_id: str
    target_kind: str
    target_id: str
    sequence: int


_INVOCATION_SELECT = (
    "SELECT state,input_bytes,input_sha256,result_bytes,result_sha256,owner_epoch "
    "FROM invocations WHERE invocation_key=?"
)
_GATE_SELECT = (
    "SELECT prior_record_sha256,expected_revision_sha256,branch_kind,"
    "record_input_bytes,record_input_sha256,state,owner_epoch,publication_path,"
    "publication_sha256 FROM gates WHERE workflow_id=? AND run_id=? AND ordinal=?"
)
_CHILD_SELECT = (
    "SELECT campaign_id,parent_workflow_id,parent_run_id,claim_sha256,"
    "fingerprint_sha256,coverage_sha256,experiment_id,child_workflow_id,"
    "child_run_id,state,owner_epoch FROM child_authorizations"
)


def _digest(value: bytes) -> str:
    return sha256(value).hexdigest()


def _hash_text(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CoordinationError(f"{label} must be a lowercase SHA-256 digest")


def _nonempty(value: str, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise CoordinationError(f"{label} must be a nonempty string")


def _bytes(value: bytes, label: str, maximum: int) -> None:
    if not isinstance(value, bytes):
        raise CoordinationError(f"{label} must be bytes")
    if len(value) > maximum:
        raise CoordinationError(f"{label} exceeds configured byte limit")


def _blob_bytes(value: object, error_message: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    raise CoordinationError(error_message)


def _row_int(value: object, error_message: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise CoordinationError(error_message)


class CoordinationStore:
    """A fail-closed SQLite ledger with CAS ownership epochs.

    ``reserve_invocation`` is the sole authorization point for an external
    call: a row in STARTED is never reissued to another owner. A crashed owner
    must be terminalized, rather than retried, unless it committed exact bytes.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        max_invocation_input_bytes: int = 1_048_576,
        max_invocation_result_bytes: int = 1_048_576,
        max_private_subject_result_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self._validate_limits(
            max_invocation_input_bytes,
            max_invocation_result_bytes,
            max_private_subject_result_bytes,
        )
        self.max_invocation_input_bytes = max_invocation_input_bytes
        self.max_invocation_result_bytes = max_invocation_result_bytes
        self.max_private_subject_result_bytes = max_private_subject_result_bytes
        self.path = Path(database)
        self._prepare_database_path()
        self._initialize()

    @staticmethod
    def _validate_limits(
        maximum_input: int,
        maximum_result: int,
        maximum_private_result: int,
    ) -> None:
        if not isinstance(maximum_input, int) or maximum_input < 0:
            raise CoordinationError("maximum invocation input bytes must be nonnegative")
        if not isinstance(maximum_result, int) or maximum_result < 0:
            raise CoordinationError("maximum invocation result bytes must be nonnegative")
        if not isinstance(maximum_private_result, int) or maximum_private_result < maximum_result:
            raise CoordinationError(
                "maximum private subject result bytes must cover invocation results"
            )

    def _prepare_database_path(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise CoordinationError("coordination parent is unsafe")
        os.chmod(self.path.parent, 0o700)
        if self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
            raise CoordinationError("coordination database is unsafe")
        if not self.path.exists():
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            os.close(descriptor)
        else:
            os.chmod(self.path, 0o600)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=30.0)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                os.chmod(candidate, 0o600)
        return connection

    def _initialize(self) -> None:
        connection = self._connection()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS invocations (
                    invocation_key TEXT PRIMARY KEY NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'STARTED','RESULT_COMMITTED','INDETERMINATE_TERMINALIZED'
                    )),
                    input_bytes BLOB NOT NULL,
                    input_sha256 TEXT NOT NULL,
                    result_bytes BLOB,
                    result_sha256 TEXT,
                    owner_epoch INTEGER NOT NULL,
                    CHECK ((result_bytes IS NULL) = (result_sha256 IS NULL))
                );
                CREATE TABLE IF NOT EXISTS gates (
                    workflow_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                    prior_record_sha256 TEXT NOT NULL,
                    expected_revision_sha256 TEXT NOT NULL,
                    branch_kind TEXT NOT NULL,
                    record_input_bytes BLOB NOT NULL,
                    record_input_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'RESERVED','RELEASE_COMMITTING','PUBLISHED'
                    )),
                    owner_epoch INTEGER NOT NULL,
                    publication_path TEXT,
                    publication_sha256 TEXT,
                    PRIMARY KEY(workflow_id, run_id, ordinal),
                    CHECK ((state = 'PUBLISHED') = (
                        publication_path IS NOT NULL AND publication_sha256 IS NOT NULL
                    ))
                );
                CREATE TABLE IF NOT EXISTS child_authorizations (
                    campaign_id TEXT NOT NULL,
                    parent_workflow_id TEXT NOT NULL,
                    parent_run_id TEXT NOT NULL,
                    claim_sha256 TEXT NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    coverage_sha256 TEXT NOT NULL,
                    experiment_id TEXT NOT NULL UNIQUE,
                    child_workflow_id TEXT,
                    child_run_id TEXT,
                    state TEXT NOT NULL CHECK(state IN ('ISSUED','CLAIMED')),
                    owner_epoch INTEGER NOT NULL,
                    PRIMARY KEY(
                        campaign_id,parent_workflow_id,parent_run_id,claim_sha256,
                        fingerprint_sha256,coverage_sha256
                    )
                );
                """
            )
            self._validate_schema(connection)
        finally:
            connection.close()
        os.chmod(self.path, 0o600)

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        gate_columns = {row[1] for row in connection.execute("PRAGMA table_info(gates)")}
        required_gate_columns = {
            "prior_record_sha256",
            "expected_revision_sha256",
            "branch_kind",
            "record_input_bytes",
            "record_input_sha256",
            "publication_path",
        }
        if not required_gate_columns.issubset(gate_columns):
            raise CoordinationError("coordination gate schema is obsolete")
        authorization_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(child_authorizations)")
        }
        required_authorization_columns = {
            "campaign_id",
            "parent_workflow_id",
            "parent_run_id",
            "claim_sha256",
            "fingerprint_sha256",
            "coverage_sha256",
            "experiment_id",
            "child_workflow_id",
            "child_run_id",
            "state",
            "owner_epoch",
        }
        if "opaque_id" in authorization_columns or not required_authorization_columns.issubset(
            authorization_columns
        ):
            raise CoordinationError("child authorization schema is obsolete")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _validate_invocation_row(row: tuple[object, ...]) -> None:
        input_bytes = _blob_bytes(row[1], "invocation record hash is corrupt")
        result_bytes = row[3]
        if _digest(input_bytes) != row[2] or (
            result_bytes is not None
            and _digest(_blob_bytes(result_bytes, "invocation record hash is corrupt")) != row[4]
        ):
            raise CoordinationError("invocation record hash is corrupt")

    @staticmethod
    def _invocation_reservation(
        disposition: InvocationDisposition,
        invocation_key: str,
        row: tuple[object, ...],
        owner_epoch: int | None = None,
    ) -> InvocationReservation:
        return InvocationReservation(
            disposition=disposition,
            invocation_key=invocation_key,
            owner_epoch=owner_epoch,
            input_bytes=_blob_bytes(row[1], "invocation record hash is corrupt"),
            input_sha256=str(row[2]),
            result_bytes=(
                _blob_bytes(row[3], "invocation record hash is corrupt")
                if row[3] is not None
                else None
            ),
            result_sha256=str(row[4]) if row[4] is not None else None,
        )

    def reserve_invocation(self, invocation_key: str, input_bytes: bytes) -> InvocationReservation:
        _nonempty(invocation_key, "invocation key")
        _bytes(input_bytes, "invocation input", self.max_invocation_input_bytes)
        input_hash = _digest(input_bytes)
        with self._transaction() as connection:
            row = connection.execute(_INVOCATION_SELECT, (invocation_key,)).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO invocations VALUES (?,?,?,?,?,?,?)",
                    (
                        invocation_key,
                        InvocationState.STARTED.value,
                        input_bytes,
                        input_hash,
                        None,
                        None,
                        1,
                    ),
                )
                return InvocationReservation(
                    InvocationDisposition.ACQUIRED,
                    invocation_key,
                    1,
                    input_bytes,
                    input_hash,
                )
            self._validate_invocation_row(row)
            if (
                _blob_bytes(row[1], "invocation record hash is corrupt") != input_bytes
                or row[2] != input_hash
            ):
                raise CoordinationError("invocation key was reused with different input bytes")
            return self._reserved_invocation(invocation_key, row)

    @staticmethod
    def _reserved_invocation(invocation_key: str, row: tuple[object, ...]) -> InvocationReservation:
        dispositions = {
            InvocationState.RESULT_COMMITTED.value: InvocationDisposition.RESULT_RECOVERED,
            InvocationState.INDETERMINATE_TERMINALIZED.value: InvocationDisposition.INDETERMINATE,
            InvocationState.STARTED.value: InvocationDisposition.IN_FLIGHT,
        }
        return CoordinationStore._invocation_reservation(
            dispositions[str(row[0])],
            invocation_key,
            row,
        )

    def reserve_gate_invocation(self, record_input_bytes: bytes) -> InvocationReservation:
        """Reserve the durable result journal for one immutable gate record."""
        _bytes(record_input_bytes, "gate invocation input", self.max_invocation_input_bytes)
        return self.reserve_invocation(
            f"gate-invocation:{_digest(record_input_bytes)}",
            record_input_bytes,
        )

    def commit_result(
        self, invocation_key: str, owner_epoch: int, result_bytes: bytes
    ) -> InvocationReservation:
        return self._commit_result(
            invocation_key,
            owner_epoch,
            result_bytes,
            self.max_invocation_result_bytes,
        )

    def commit_private_subject_result(
        self, invocation_key: str, owner_epoch: int, result_bytes: bytes
    ) -> InvocationReservation:
        """Commit bounded private evidence without raising the public role limit."""
        return self._commit_result(
            invocation_key,
            owner_epoch,
            result_bytes,
            self.max_private_subject_result_bytes,
        )

    def _commit_result(
        self,
        invocation_key: str,
        owner_epoch: int,
        result_bytes: bytes,
        maximum_bytes: int,
    ) -> InvocationReservation:
        _nonempty(invocation_key, "invocation key")
        _bytes(result_bytes, "invocation result", maximum_bytes)
        result_hash = _digest(result_bytes)
        with self._transaction() as connection:
            row = connection.execute(_INVOCATION_SELECT, (invocation_key,)).fetchone()
            if row is None:
                raise CoordinationError("unknown invocation")
            self._validate_invocation_row(row)
            if self._is_recovered_result(row, result_bytes, result_hash):
                return self._invocation_reservation(
                    InvocationDisposition.RESULT_RECOVERED,
                    invocation_key,
                    row,
                )
            self._commit_invocation_cas(
                connection,
                InvocationCommitRequest(
                    invocation_key,
                    owner_epoch,
                    str(row[0]),
                    int(row[5]),
                    result_bytes,
                    result_hash,
                ),
            )
            return InvocationReservation(
                InvocationDisposition.RESULT_RECOVERED,
                invocation_key,
                None,
                _blob_bytes(row[1], "invocation record hash is corrupt"),
                str(row[2]),
                result_bytes,
                result_hash,
            )

    @staticmethod
    def _is_recovered_result(
        row: tuple[object, ...], result_bytes: bytes, result_hash: str
    ) -> bool:
        return (
            row[0] == InvocationState.RESULT_COMMITTED.value
            and row[3] is not None
            and _blob_bytes(row[3], "invocation record hash is corrupt") == result_bytes
            and row[4] == result_hash
        )

    @staticmethod
    def _commit_invocation_cas(
        connection: sqlite3.Connection, request: InvocationCommitRequest
    ) -> None:
        if request.state != InvocationState.STARTED.value or request.epoch != request.owner_epoch:
            raise CoordinationError("invocation result CAS failed")
        changed = connection.execute(
            "UPDATE invocations SET state=?,result_bytes=?,result_sha256=? "
            "WHERE invocation_key=? AND state=? AND owner_epoch=?",
            (
                InvocationState.RESULT_COMMITTED.value,
                request.result_bytes,
                request.result_sha256,
                request.invocation_key,
                InvocationState.STARTED.value,
                request.owner_epoch,
            ),
        ).rowcount
        if changed != 1:
            raise CoordinationError("invocation result CAS failed")

    def terminalize_indeterminate(self, invocation_key: str, owner_epoch: int) -> None:
        with self._transaction() as connection:
            changed = connection.execute(
                "UPDATE invocations SET state=? "
                "WHERE invocation_key=? AND state=? AND owner_epoch=?",
                (
                    InvocationState.INDETERMINATE_TERMINALIZED.value,
                    invocation_key,
                    InvocationState.STARTED.value,
                    owner_epoch,
                ),
            ).rowcount
            if changed != 1:
                raise CoordinationError("invocation terminalization CAS failed")

    @staticmethod
    def _validate_gate_request(request: GateRequest) -> str:
        _nonempty(request.workflow_id, "workflow id")
        _nonempty(request.run_id, "run id")
        _nonempty(request.branch_kind, "branch kind")
        _hash_text(request.prior_record_sha256, "prior record hash")
        _hash_text(request.expected_revision_sha256, "expected revision hash")
        if not isinstance(request.ordinal, int) or request.ordinal < 0:
            raise CoordinationError("gate ordinal must be nonnegative")
        if not isinstance(request.record_input_bytes, bytes):
            raise CoordinationError("gate record input must be bytes")
        return _digest(request.record_input_bytes)

    @staticmethod
    def _gate_reservation(context: GateReservationContext) -> GateReservation:
        request = context.request
        if context.row is None:
            return GateReservation(
                context.disposition,
                request.workflow_id,
                request.run_id,
                request.ordinal,
                request.prior_record_sha256,
                request.expected_revision_sha256,
                request.branch_kind,
                request.record_input_bytes,
                _digest(request.record_input_bytes),
                context.owner_epoch,
                context.publication_path,
                context.publication_sha256,
            )
        return GateReservation(
            context.disposition,
            request.workflow_id,
            request.run_id,
            request.ordinal,
            str(context.row[0]),
            str(context.row[1]),
            str(context.row[2]),
            _blob_bytes(context.row[3], "gate record input hash is corrupt"),
            str(context.row[4]),
            context.owner_epoch,
            context.publication_path,
            context.publication_sha256,
        )

    @staticmethod
    def _validate_gate_row(row: tuple[object, ...]) -> None:
        if _digest(_blob_bytes(row[3], "gate record input hash is corrupt")) != row[4]:
            raise CoordinationError("gate record input hash is corrupt")

    @staticmethod
    def _gate_matches_request(request: GateRequest, row: tuple[object, ...]) -> bool:
        return (
            row[0],
            row[1],
            row[2],
            _blob_bytes(row[3], "gate record input hash is corrupt"),
            row[4],
        ) == (
            request.prior_record_sha256,
            request.expected_revision_sha256,
            request.branch_kind,
            request.record_input_bytes,
            _digest(request.record_input_bytes),
        )

    def reserve_gate(self, request: GateRequest) -> GateReservation:
        record_hash = self._validate_gate_request(request)
        with self._transaction() as connection:
            row = connection.execute(
                _GATE_SELECT,
                (request.workflow_id, request.run_id, request.ordinal),
            ).fetchone()
            if row is None:
                self._insert_gate(connection, request, record_hash)
                return self._gate_reservation(
                    GateReservationContext(
                        GateDisposition.ACQUIRED,
                        request,
                        owner_epoch=1,
                    )
                )
            self._validate_gate_row(row)
            if not self._gate_matches_request(request, row):
                raise CoordinationError("gate reservation conflicts with another branch")
            return self._recover_gate(connection, request, row)

    def _insert_gate(
        self, connection: sqlite3.Connection, request: GateRequest, record_hash: str
    ) -> None:
        expected = connection.execute(
            "SELECT COALESCE(MAX(ordinal)+1,0) FROM gates WHERE workflow_id=? AND run_id=?",
            (request.workflow_id, request.run_id),
        ).fetchone()[0]
        if request.ordinal != expected:
            raise CoordinationError("gate ordinal is not next")
        self._validate_gate_predecessor(connection, request)
        connection.execute(
            "INSERT INTO gates VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                request.workflow_id,
                request.run_id,
                request.ordinal,
                request.prior_record_sha256,
                request.expected_revision_sha256,
                request.branch_kind,
                request.record_input_bytes,
                record_hash,
                GateState.RESERVED.value,
                1,
                None,
                None,
            ),
        )

    @staticmethod
    def _validate_gate_predecessor(connection: sqlite3.Connection, request: GateRequest) -> None:
        if request.ordinal == 0:
            if request.prior_record_sha256 != "0" * 64:
                raise CoordinationError("first gate must have zero prior record hash")
            return
        predecessor = connection.execute(
            "SELECT state,publication_sha256 FROM gates "
            "WHERE workflow_id=? AND run_id=? AND ordinal=?",
            (request.workflow_id, request.run_id, request.ordinal - 1),
        ).fetchone()
        if (
            predecessor is None
            or predecessor[0] != GateState.PUBLISHED.value
            or predecessor[1] != request.prior_record_sha256
        ):
            raise CoordinationError("gate prior record is not the published predecessor")

    def _recover_gate(
        self,
        connection: sqlite3.Connection,
        request: GateRequest,
        row: tuple[object, ...],
    ) -> GateReservation:
        state = str(row[5])
        if state == GateState.PUBLISHED.value:
            return self._gate_reservation(
                GateReservationContext(
                    GateDisposition.PUBLISHED,
                    request,
                    row,
                    publication_path=Path(str(row[7])),
                    publication_sha256=str(row[8]),
                )
            )
        disposition = GateDisposition.COMMITTING
        cas_state = GateState.RELEASE_COMMITTING
        if state == GateState.RESERVED.value:
            disposition = GateDisposition.RECOVERED
            cas_state = GateState.RESERVED
        next_epoch = _row_int(row[6], "gate owner epoch is corrupt") + 1
        changed = connection.execute(
            "UPDATE gates SET owner_epoch=? WHERE workflow_id=? AND run_id=? "
            "AND ordinal=? AND state=? AND owner_epoch=?",
            (
                next_epoch,
                request.workflow_id,
                request.run_id,
                request.ordinal,
                cas_state.value,
                row[6],
            ),
        ).rowcount
        if changed != 1:
            message = "release recovery CAS failed"
            if cas_state is GateState.RESERVED:
                message = "gate recovery CAS failed"
            raise CoordinationError(message)
        return self._gate_reservation(GateReservationContext(disposition, request, row, next_epoch))

    @staticmethod
    def _gate_request_from_commit(request: GateCommitRequest) -> GateRequest:
        return GateRequest(
            request.workflow_id,
            request.run_id,
            request.ordinal,
            "",
            request.expected_revision_sha256,
            "",
            b"",
        )

    def begin_release_commit(self, request: GateCommitRequest) -> GateReservation:
        _hash_text(request.expected_revision_sha256, "expected revision hash")
        gate_request = self._gate_request_from_commit(request)
        with self._transaction() as connection:
            row = connection.execute(
                _GATE_SELECT,
                (request.workflow_id, request.run_id, request.ordinal),
            ).fetchone()
            if row is None or row[1] != request.expected_revision_sha256:
                raise CoordinationError("unknown or competing gate branch")
            self._validate_gate_row(row)
            if row[5] == GateState.PUBLISHED.value:
                return self._gate_reservation(
                    GateReservationContext(
                        GateDisposition.PUBLISHED,
                        gate_request,
                        row,
                        publication_path=Path(str(row[7])),
                        publication_sha256=str(row[8]),
                    )
                )
            if row[5] == GateState.RELEASE_COMMITTING.value:
                raise CoordinationError("release commit is irreversible")
            self._begin_release_cas(connection, request, row)
            return self._gate_reservation(
                GateReservationContext(
                    GateDisposition.ACQUIRED,
                    gate_request,
                    row,
                    request.owner_epoch,
                )
            )

    @staticmethod
    def _begin_release_cas(
        connection: sqlite3.Connection,
        request: GateCommitRequest,
        row: tuple[object, ...],
    ) -> None:
        changed = 0
        if row[6] == request.owner_epoch:
            changed = connection.execute(
                "UPDATE gates SET state=? WHERE workflow_id=? AND run_id=? "
                "AND ordinal=? AND state=? AND owner_epoch=?",
                (
                    GateState.RELEASE_COMMITTING.value,
                    request.workflow_id,
                    request.run_id,
                    request.ordinal,
                    GateState.RESERVED.value,
                    request.owner_epoch,
                ),
            ).rowcount
        if changed != 1:
            raise CoordinationError("release commit CAS failed")

    @staticmethod
    def _publication_artifact(request: GatePublicationRequest) -> Path:
        _hash_text(request.expected_revision_sha256, "expected revision hash")
        _hash_text(request.expected_sha256, "publication hash")
        if not isinstance(request.expected_bytes, bytes):
            raise CoordinationError("expected publication bytes must be bytes")
        artifact_path = Path(request.final_artifact_path)
        try:
            if not artifact_path.is_file() or artifact_path.is_symlink():
                raise CoordinationError("final artifact is not a regular file")
            actual_bytes = artifact_path.read_bytes()
        except OSError as error:
            raise CoordinationError("final artifact is unavailable") from error
        if (
            actual_bytes != request.expected_bytes
            or _digest(actual_bytes) != request.expected_sha256
        ):
            raise CoordinationError("final artifact bytes do not match publication")
        return artifact_path

    @staticmethod
    def _gate_request_from_publication(request: GatePublicationRequest) -> GateRequest:
        return GateRequest(
            request.workflow_id,
            request.run_id,
            request.ordinal,
            "",
            request.expected_revision_sha256,
            "",
            b"",
        )

    def publish_gate(self, request: GatePublicationRequest) -> GateReservation:
        artifact_path = self._publication_artifact(request)
        gate_request = self._gate_request_from_publication(request)
        with self._transaction() as connection:
            row = connection.execute(
                _GATE_SELECT,
                (request.workflow_id, request.run_id, request.ordinal),
            ).fetchone()
            if row is None or row[1] != request.expected_revision_sha256:
                raise CoordinationError("unknown or competing gate branch")
            self._validate_gate_row(row)
            if row[5] == GateState.PUBLISHED.value:
                if row[8] != request.expected_sha256 or Path(str(row[7])) != artifact_path:
                    raise CoordinationError("published gate artifact conflicts")
                return self._gate_reservation(
                    GateReservationContext(
                        GateDisposition.PUBLISHED,
                        gate_request,
                        row,
                        publication_path=artifact_path,
                        publication_sha256=str(row[8]),
                    )
                )
            self._publish_gate_cas(connection, request, row, artifact_path)
            return self._gate_reservation(
                GateReservationContext(
                    GateDisposition.PUBLISHED,
                    gate_request,
                    row,
                    publication_path=artifact_path,
                    publication_sha256=request.expected_sha256,
                )
            )

    @staticmethod
    def _publish_gate_cas(
        connection: sqlite3.Connection,
        request: GatePublicationRequest,
        row: tuple[object, ...],
        artifact_path: Path,
    ) -> None:
        if row[5] != GateState.RELEASE_COMMITTING.value or row[6] != request.owner_epoch:
            raise CoordinationError("gate publication CAS failed")
        changed = connection.execute(
            "UPDATE gates SET state=?,publication_path=?,publication_sha256=? "
            "WHERE workflow_id=? AND run_id=? AND ordinal=? AND state=? "
            "AND owner_epoch=?",
            (
                GateState.PUBLISHED.value,
                str(artifact_path),
                request.expected_sha256,
                request.workflow_id,
                request.run_id,
                request.ordinal,
                GateState.RELEASE_COMMITTING.value,
                request.owner_epoch,
            ),
        ).rowcount
        if changed != 1:
            raise CoordinationError("gate publication CAS failed")

    def _decision_ledger(
        self, workflow_id: str, run_id: str, target_kind: str, target_id: str
    ) -> tuple[str, str]:
        _nonempty(workflow_id, "workflow id")
        _nonempty(run_id, "run id")
        _nonempty(target_kind, "target kind")
        _nonempty(target_id, "target id")
        binding = json.dumps(
            {
                "workflow_id": workflow_id,
                "run_id": run_id,
                "target_kind": target_kind,
                "target_id": target_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"decision-ledger:{_digest(binding)}", "decisions"

    @staticmethod
    def _decision_reservation(
        request: DecisionRequest | DecisionCommitRequest | DecisionPublicationRequest,
        reservation: GateReservation,
        prior_record_sha256: str,
        record_input_bytes: bytes,
        record_input_sha256: str,
    ) -> DecisionReservation:
        return DecisionReservation(
            reservation.disposition,
            request.workflow_id,
            request.run_id,
            request.target_kind,
            request.target_id,
            request.sequence,
            prior_record_sha256,
            request.expected_revision_sha256,
            record_input_bytes,
            record_input_sha256,
            reservation.owner_epoch,
            reservation.publication_path,
            reservation.publication_sha256,
        )

    def reserve_decision(self, request: DecisionRequest) -> DecisionReservation:
        if not isinstance(request.sequence, int) or request.sequence <= 0:
            raise CoordinationError("decision sequence must be positive")
        _hash_text(request.prior_record_sha256, "prior record hash")
        ledger_workflow, ledger_run = self._decision_ledger(
            request.workflow_id,
            request.run_id,
            request.target_kind,
            request.target_id,
        )
        envelope = json.dumps(
            {
                "prior_record_sha256": request.prior_record_sha256,
                "record_input": request.record_input_bytes.hex(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        gate_prior = "0" * 64 if request.sequence == 1 else request.prior_record_sha256
        reservation = self.reserve_gate(
            GateRequest(
                ledger_workflow,
                ledger_run,
                request.sequence - 1,
                gate_prior,
                request.expected_revision_sha256,
                "decision",
                envelope,
            )
        )
        return self._decision_reservation(
            request,
            reservation,
            request.prior_record_sha256,
            request.record_input_bytes,
            _digest(request.record_input_bytes),
        )

    def begin_decision_commit(self, request: DecisionCommitRequest) -> DecisionReservation:
        ledger_workflow, ledger_run = self._decision_ledger(
            request.workflow_id,
            request.run_id,
            request.target_kind,
            request.target_id,
        )
        reservation = self.begin_release_commit(
            GateCommitRequest(
                ledger_workflow,
                ledger_run,
                request.sequence - 1,
                request.expected_revision_sha256,
                request.owner_epoch,
            )
        )
        return self._decision_reservation(request, reservation, "", b"", "")

    def publish_decision(self, request: DecisionPublicationRequest) -> DecisionReservation:
        ledger_workflow, ledger_run = self._decision_ledger(
            request.workflow_id,
            request.run_id,
            request.target_kind,
            request.target_id,
        )
        reservation = self.publish_gate(
            GatePublicationRequest(
                ledger_workflow,
                ledger_run,
                request.sequence - 1,
                request.expected_revision_sha256,
                request.owner_epoch,
                request.final_artifact_path,
                request.expected_bytes,
                request.expected_sha256,
            )
        )
        return self._decision_reservation(request, reservation, "", b"", "")

    @staticmethod
    def _child_authorization(row: tuple[object, ...]) -> ChildAuthorization:
        return ChildAuthorization(
            campaign_id=str(row[0]),
            parent_workflow_id=str(row[1]),
            parent_run_id=str(row[2]),
            claim_sha256=str(row[3]),
            fingerprint_sha256=str(row[4]),
            coverage_sha256=str(row[5]),
            experiment_id=row[6] if isinstance(row[6], str) else None,
            child_workflow_id=row[7] if isinstance(row[7], str) else None,
            child_run_id=row[8] if isinstance(row[8], str) else None,
            state=ChildAuthorizationState(str(row[9])),
            owner_epoch=int(str(row[10])),
        )

    @staticmethod
    def _validate_child_authorization_request(request: ChildAuthorizationRequest) -> None:
        for value, label in (
            (request.campaign_id, "campaign id"),
            (request.parent_workflow_id, "parent workflow id"),
            (request.parent_run_id, "parent run id"),
        ):
            _nonempty(value, label)
        for value, label in (
            (request.claim_sha256, "claim hash"),
            (request.fingerprint_sha256, "fingerprint hash"),
            (request.coverage_sha256, "coverage hash"),
        ):
            _hash_text(value, label)

    @staticmethod
    def _child_identity(request: ChildAuthorizationRequest) -> tuple[str, ...]:
        return (
            request.campaign_id,
            request.parent_workflow_id,
            request.parent_run_id,
            request.claim_sha256,
            request.fingerprint_sha256,
            request.coverage_sha256,
        )

    def issue_child_authorization(self, request: ChildAuthorizationRequest) -> ChildAuthorization:
        self._validate_child_authorization_request(request)
        identity = self._child_identity(request)
        with self._transaction() as connection:
            row = connection.execute(
                f"{_CHILD_SELECT} WHERE campaign_id=? AND parent_workflow_id=? "
                "AND parent_run_id=? AND claim_sha256=? AND fingerprint_sha256=? "
                "AND coverage_sha256=?",
                identity,
            ).fetchone()
            if row is not None:
                return self._child_authorization(row)
            experiment_id = f"experiment-{secrets.randbelow(1 << 106):032d}"
            connection.execute(
                "INSERT INTO child_authorizations("
                "campaign_id,parent_workflow_id,parent_run_id,claim_sha256,"
                "fingerprint_sha256,coverage_sha256,experiment_id,state,owner_epoch"
                ") VALUES(?,?,?,?,?,?,?,?,?)",
                (*identity, experiment_id, ChildAuthorizationState.ISSUED.value, 1),
            )
            return ChildAuthorization(
                identity[0],
                identity[1],
                identity[2],
                identity[3],
                identity[4],
                identity[5],
                experiment_id,
                None,
                None,
                ChildAuthorizationState.ISSUED,
                1,
            )

    def claim_child_authorization(
        self, request: ChildAuthorizationClaimRequest
    ) -> ChildAuthorization:
        authorization_request = ChildAuthorizationRequest(
            request.campaign_id,
            request.parent_workflow_id,
            request.parent_run_id,
            request.claim_sha256,
            request.fingerprint_sha256,
            request.coverage_sha256,
        )
        self._validate_child_authorization_request(authorization_request)
        for value, label in (
            (request.experiment_id, "experiment id"),
            (request.child_workflow_id, "child workflow id"),
            (request.child_run_id, "child run id"),
        ):
            _nonempty(value, label)
        identity = self._child_identity(authorization_request)
        with self._transaction() as connection:
            row = connection.execute(
                f"{_CHILD_SELECT} WHERE campaign_id=? AND parent_workflow_id=? "
                "AND parent_run_id=? AND claim_sha256=? AND fingerprint_sha256=? "
                "AND coverage_sha256=? AND experiment_id=?",
                (*identity, request.experiment_id),
            ).fetchone()
            if row is None:
                raise CoordinationError("child authorization was not issued")
            authorization = self._child_authorization(row)
            if authorization.state is ChildAuthorizationState.CLAIMED:
                self._validate_claimed_authorization(authorization, request)
                return authorization
            self._claim_child_authorization_cas(connection, request, authorization)
            return ChildAuthorization(
                identity[0],
                identity[1],
                identity[2],
                identity[3],
                identity[4],
                identity[5],
                request.experiment_id,
                request.child_workflow_id,
                request.child_run_id,
                ChildAuthorizationState.CLAIMED,
                authorization.owner_epoch + 1,
            )

    @staticmethod
    def _validate_claimed_authorization(
        authorization: ChildAuthorization,
        request: ChildAuthorizationClaimRequest,
    ) -> None:
        if (authorization.child_workflow_id, authorization.child_run_id) != (
            request.child_workflow_id,
            request.child_run_id,
        ):
            raise CoordinationError("child authorization is already consumed")

    @staticmethod
    def _claim_child_authorization_cas(
        connection: sqlite3.Connection,
        request: ChildAuthorizationClaimRequest,
        authorization: ChildAuthorization,
    ) -> None:
        changed = connection.execute(
            "UPDATE child_authorizations SET child_workflow_id=?,child_run_id=?,"
            "state=?,owner_epoch=? WHERE campaign_id=? AND parent_workflow_id=? "
            "AND parent_run_id=? AND claim_sha256=? AND fingerprint_sha256=? "
            "AND coverage_sha256=? AND experiment_id=? AND state=? AND owner_epoch=?",
            (
                request.child_workflow_id,
                request.child_run_id,
                ChildAuthorizationState.CLAIMED.value,
                authorization.owner_epoch + 1,
                request.campaign_id,
                request.parent_workflow_id,
                request.parent_run_id,
                request.claim_sha256,
                request.fingerprint_sha256,
                request.coverage_sha256,
                request.experiment_id,
                ChildAuthorizationState.ISSUED.value,
                authorization.owner_epoch,
            ),
        ).rowcount
        if changed != 1:
            raise CoordinationError("child authorization claim CAS failed")

    def claimed_child_authorization(
        self, request: ClaimedChildAuthorizationRequest
    ) -> ChildAuthorization:
        """Return the one claimed authority binding for a trusted child execution."""
        for value, label in (
            (request.campaign_id, "campaign id"),
            (request.experiment_id, "experiment id"),
            (request.child_workflow_id, "child workflow id"),
            (request.child_run_id, "child run id"),
        ):
            _nonempty(value, label)
        connection = self._connection()
        try:
            row = connection.execute(
                f"{_CHILD_SELECT} WHERE campaign_id=? AND experiment_id=? "
                "AND child_workflow_id=? AND child_run_id=?",
                (
                    request.campaign_id,
                    request.experiment_id,
                    request.child_workflow_id,
                    request.child_run_id,
                ),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise CoordinationError("child authorization was not claimed by this execution")
        authorization = self._child_authorization(row)
        if authorization.state is not ChildAuthorizationState.CLAIMED:
            raise CoordinationError("child authorization is not claimed")
        return authorization

    def published_decision(self, request: PublishedDecisionRequest) -> DecisionReservation:
        """Return one immutable published signed decision from its exact ledger binding."""
        if (
            not isinstance(request.sequence, int)
            or isinstance(request.sequence, bool)
            or request.sequence <= 0
        ):
            raise CoordinationError("decision sequence must be positive")
        ledger_workflow, ledger_run = self._decision_ledger(
            request.workflow_id,
            request.run_id,
            request.target_kind,
            request.target_id,
        )
        connection = self._connection()
        try:
            row = connection.execute(
                "SELECT prior_record_sha256,expected_revision_sha256,record_input_bytes,"
                "record_input_sha256,owner_epoch,publication_path,publication_sha256,state "
                "FROM gates WHERE workflow_id=? AND run_id=? AND ordinal=?",
                (ledger_workflow, ledger_run, request.sequence - 1),
            ).fetchone()
        finally:
            connection.close()
        if (
            row is None
            or row[7] != GateState.PUBLISHED.value
            or not isinstance(row[5], str)
            or not isinstance(row[6], str)
        ):
            raise CoordinationError("signed decision is not published")
        return DecisionReservation(
            GateDisposition.PUBLISHED,
            request.workflow_id,
            request.run_id,
            request.target_kind,
            request.target_id,
            request.sequence,
            str(row[0]),
            str(row[1]),
            _blob_bytes(row[2], "signed decision is not published"),
            str(row[3]),
            int(row[4]),
            Path(row[5]),
            str(row[6]),
        )
