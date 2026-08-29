"""Private, durable Step 6 trial primitives."""

from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import sqlite3
import unicodedata
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast

from .models import ExperimentDesign, ProtocolError, canonical_bytes

ASSIGNMENT_IDS = (
    "core-1-A-1",
    "core-1-A-2",
    "core-1-B-1",
    "core-1-B-2",
    "core-2-A-1",
    "core-2-A-2",
    "core-2-B-1",
    "core-2-B-2",
    "negative-control-A-1",
    "negative-control-B-1",
)
SCENARIOS = ("core-1", "core-2", "negative-control")
MAX_CHANNEL_BYTES = 2 * 1024 * 1024
MAX_RAW_QUARANTINE_BYTES = 8 * 1024 * 1024
MAX_NORMALIZED_SCALARS = 2_097_152
MAX_AGGREGATE_SCALARS = 8_388_608
MAX_TREATMENT_SCALARS = 8192
TERMINALS = frozenset(
    {
        "result",
        "terminal",
        "canceled-before-invocation",
        "indeterminate",
        "UNSCHEDULED_DUE_TO_TERMINAL",
        "UNSCHEDULED_DUE_TO_CANCELLATION",
    }
)
WHITE_SPACE_15_1 = frozenset(
    "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680\u2000\u2001\u2002"
    "\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f"
    "\u3000"
)


class TrialProtocolError(ProtocolError):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _token(n: int) -> str:
    return _b64(secrets.token_bytes(n))


def _sha(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _hex(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _idchar(char: str) -> bool:
    return char == "_" or unicodedata.category(char)[0] in {"L", "N"}


def _bound(value: str, start: int, end: int) -> bool:
    return (start == 0 or not _idchar(value[start - 1])) and (
        end == len(value) or not _idchar(value[end])
    )


def normalize(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def pre_map_input_hash(**fields: str) -> str:
    expected = {
        "namespace",
        "workflow_type",
        "task_queue",
        "campaign_id",
        "experiment_id",
        "workflow_id",
        "run_id",
        "claim_hash",
        "g0_record_hash",
        "design_proposal_hash",
        "design_hash",
        "treatment_hash",
        "fixture_manifest_hash",
    }
    if set(fields) != expected or any(
        not isinstance(value, str) or not value for value in fields.values()
    ):
        raise TrialProtocolError("pre-map fields must be nonempty text")
    return _sha({"schema": "instruct-eval-pre-map-v1", **fields})


@dataclass(frozen=True, slots=True)
class WorkflowIdentity:
    namespace: str
    workflow_type: str
    task_queue: str
    workflow_id: str
    run_id: str

    def json(self) -> dict[str, str]:
        return {
            "namespace": self.namespace,
            "workflow_type": self.workflow_type,
            "task_queue": self.task_queue,
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
        }


_METADATA_SEAL = object()


@dataclass(frozen=True, slots=True)
class TrustedActivityMetadata:
    identity: WorkflowIdentity
    activity_type: str
    activity_id: str
    parent_workflow_id: str
    parent_run_id: str
    freeze_chain: str
    _seal: object


@dataclass(frozen=True, slots=True)
class TrustedActivityMetadataParams:
    info: Any
    expected_namespace: str
    expected_activity_type: str
    expected_task_queue: str
    expected_activity_id: str
    verified_parent_workflow_id: str
    verified_parent_run_id: str
    freeze_chain: str


def _activity_values(info: Any) -> dict[str, Any]:
    return {
        "namespace": getattr(info, "workflow_namespace", None),
        "workflow_type": getattr(info, "workflow_type", None),
        "task_queue": getattr(info, "task_queue", None),
        "workflow_id": getattr(info, "workflow_id", None),
        "run_id": getattr(info, "workflow_run_id", None),
        "activity_type": getattr(info, "activity_type", None),
        "activity_id": getattr(info, "activity_id", None),
    }


def _has_nonempty_text(*values: object) -> bool:
    return all(isinstance(value, str) and value for value in values)


def _matches_activity_values(values: Mapping[str, Any], expected: Mapping[str, str]) -> bool:
    return all(
        isinstance(values[key], str) and hmac.compare_digest(cast(str, values[key]), expected_value)
        for key, expected_value in expected.items()
    )


def trusted_activity_metadata(
    params: TrustedActivityMetadataParams,
) -> TrustedActivityMetadata:
    """Construct private metadata from Activity Info and Describe-verified parent identity."""
    values = _activity_values(params.info)
    expected = {
        "namespace": params.expected_namespace,
        "activity_type": params.expected_activity_type,
        "task_queue": params.expected_task_queue,
        "activity_id": params.expected_activity_id,
    }
    if not _has_nonempty_text(
        params.verified_parent_workflow_id,
        params.verified_parent_run_id,
        params.freeze_chain,
    ) or not _matches_activity_values(values, expected):
        raise TrialProtocolError("untrusted Temporal activity metadata")
    if not _has_nonempty_text(
        values["workflow_type"],
        values["workflow_id"],
        values["run_id"],
    ):
        raise TrialProtocolError("unstable Temporal activity metadata")
    return TrustedActivityMetadata(
        WorkflowIdentity(
            values["namespace"],
            values["workflow_type"],
            values["task_queue"],
            values["workflow_id"],
            values["run_id"],
        ),
        values["activity_type"],
        values["activity_id"],
        params.verified_parent_workflow_id,
        params.verified_parent_run_id,
        params.freeze_chain,
        _METADATA_SEAL,
    )


@dataclass(frozen=True, slots=True)
class PrivateAssignment:
    assignment_id: str
    scenario: str
    condition: str
    blind_id: str
    token: str

    def json(self) -> dict[str, str]:
        return {
            "assignment_id": self.assignment_id,
            "scenario": self.scenario,
            "condition": self.condition,
            "blind_id": self.blind_id,
            "token": self.token,
        }


class TrialAuthorityResolver(Protocol):
    """Private authority boundary: resolve one opaque token under trusted metadata."""

    def resolve(
        self, *, map_ref: str, metadata: TrustedActivityMetadata, token: str
    ) -> PrivateAssignment: ...


class SubjectExecutor(Protocol):
    """Private subject boundary with child-scoped disclosure treatment."""

    def __call__(
        self,
        *,
        assignment: PrivateAssignment,
        treatment: str | None,
        disclosure_treatment: str,
        frozen_design: ExperimentDesign,
    ) -> Mapping[str, Any]: ...


SUBJECT_ARTIFACT_KINDS = frozenset(
    {
        "outcome",
        "response",
        "runtime_streams",
        "tool_outputs",
        "diff",
        "verifier",
        "observer",
        "trusted_logs",
    }
)


@dataclass(frozen=True, slots=True)
class FrozenPrivateMap:
    campaign_id: str
    experiment_id: str
    workflow_identity: WorkflowIdentity
    pre_map_input_hash: str
    seed: str
    assignment_order: tuple[str, ...]
    assignments: tuple[PrivateAssignment, ...]
    preferred_directions: Mapping[str, str]
    freeze_chain: str

    @property
    def authorization_rule(self) -> dict[str, Any]:
        return authorization_rule()

    def json(self) -> dict[str, Any]:
        return {
            "schema": "instruct-eval-private-map-v1",
            "campaign_id": self.campaign_id,
            "experiment_id": self.experiment_id,
            "workflow_identity": self.workflow_identity.json(),
            "pre_map_input_hash": self.pre_map_input_hash,
            "seed": self.seed,
            "assignment_order": list(self.assignment_order),
            "assignments": [assignment.json() for assignment in self.assignments],
            "preferred_directions": dict(self.preferred_directions),
            "freeze_chain": self.freeze_chain,
            "authorization_rule": self.authorization_rule,
        }

    @property
    def map_sha256(self) -> str:
        return _sha(self.json())


@dataclass(frozen=True, slots=True)
class PrivateMapParams:
    campaign_id: str
    experiment_id: str
    metadata: TrustedActivityMetadata
    pre_map_input_hash: str
    preferred_directions: Mapping[str, str]
    seed: bytes | None = None


def authorization_rule() -> dict[str, Any]:
    return {
        "schema": "instruct-eval-authorization-rule-v1",
        "core_scenarios": ["core-1", "core-2"],
        "negative_control_scenario": "negative-control",
        "core_comparison": "preferred_count_B_strictly_greater_than_A",
        "negative_control_comparison": "both_subjects_match_preferred_direction",
    }


def _require_trusted_metadata(metadata: object) -> TrustedActivityMetadata:
    if not isinstance(metadata, TrustedActivityMetadata) or metadata._seal is not _METADATA_SEAL:
        raise TrialProtocolError("untrusted Temporal activity metadata")
    return metadata


def _validate_preferred_directions(directions: Mapping[str, str]) -> None:
    if set(directions) != set(SCENARIOS) or any(
        not isinstance(value, str) or not value for value in directions.values()
    ):
        raise TrialProtocolError("three preferred directions required")


def _assignment_order(raw_seed: bytes) -> tuple[str, ...]:
    order = list(ASSIGNMENT_IDS)
    state = int.from_bytes(raw_seed, "big")
    for index in range(len(order) - 1, 0, -1):
        state = int.from_bytes(sha256(state.to_bytes(32, "big")).digest(), "big")
        selected = state % (index + 1)
        order[index], order[selected] = order[selected], order[index]
    return tuple(order)


def _private_assignments() -> tuple[PrivateAssignment, ...]:
    return tuple(
        PrivateAssignment(
            assignment_id,
            assignment_id.rsplit("-", 2)[0],
            assignment_id.rsplit("-", 2)[1],
            _token(24),
            _token(32),
        )
        for assignment_id in ASSIGNMENT_IDS
    )


def prepare_private_map(params: PrivateMapParams) -> FrozenPrivateMap:
    metadata = _require_trusted_metadata(params.metadata)
    _validate_preferred_directions(params.preferred_directions)
    raw_seed = params.seed or secrets.token_bytes(32)
    if not isinstance(raw_seed, bytes) or len(raw_seed) != 32:
        raise TrialProtocolError("seed must be 32 bytes")
    return FrozenPrivateMap(
        params.campaign_id,
        params.experiment_id,
        metadata.identity,
        params.pre_map_input_hash,
        _b64(raw_seed),
        _assignment_order(raw_seed),
        _private_assignments(),
        MappingProxyType(dict(params.preferred_directions)),
        metadata.freeze_chain,
    )


@dataclass(frozen=True, slots=True)
class PreparedMap:
    map_ref: str
    mapping: FrozenPrivateMap
    k_map: bytes
    k_evidence: bytes
    k_artifact: bytes


@dataclass(frozen=True, slots=True)
class ArtifactRecordParams:
    map_ref: str
    metadata: TrustedActivityMetadata
    token: str
    artifact_kind: str
    artifact_sha256: str


@dataclass(frozen=True, slots=True)
class _StoredArtifact:
    token: str | None
    artifact_kind: str
    artifact_sha256: str
    artifact_path: str


def _database_row(value: object) -> tuple[Any, ...] | None:
    if value is None or isinstance(value, tuple):
        return value
    raise TrialProtocolError("private map database row is malformed")


class PrivateMapLifecycle:
    """Private 0600 SQLite CAS journal; rows survive coordinator restarts."""

    def __init__(
        self, db_path: str | Path, private_artifact_root: str | Path | None = None
    ) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_root = (
            Path(private_artifact_root) if private_artifact_root is not None else None
        )
        for directory in (self.path.parent, self.artifact_root):
            if directory is not None:
                directory.mkdir(parents=True, exist_ok=True)
                os.chmod(directory, 0o700)
        self._db = sqlite3.connect(self.path, isolation_level=None)
        try:
            self._initialize_database()
            self._chmod_database_files()
        except BaseException:
            self._db.close()
            raise

    def _initialize_database(self) -> None:
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS private_maps ("
            "campaign TEXT, experiment TEXT, workflow_id TEXT, run_id TEXT, "
            "input_hash TEXT, freeze_chain TEXT, map_ref TEXT UNIQUE, payload BLOB, "
            "k_map BLOB, k_evidence BLOB, k_artifact BLOB, state TEXT NOT NULL, "
            "PRIMARY KEY(campaign,experiment,workflow_id,run_id,input_hash))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS private_artifacts ("
            "map_ref TEXT NOT NULL, token TEXT, artifact_kind TEXT NOT NULL, "
            "artifact_sha256 TEXT NOT NULL, commitment TEXT NOT NULL, "
            "artifact_path TEXT, PRIMARY KEY(map_ref,token,artifact_kind))"
        )
        columns = {column[1] for column in self._db.execute("PRAGMA table_info(private_artifacts)")}
        if "artifact_path" not in columns:
            self._db.execute("ALTER TABLE private_artifacts ADD COLUMN artifact_path TEXT")

    def _chmod_database_files(self) -> None:
        paths = (
            self.path,
            self.path.with_name(f"{self.path.name}-wal"),
            self.path.with_name(f"{self.path.name}-shm"),
        )
        for path in paths:
            if path.exists():
                os.chmod(path, 0o600)

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> PrivateMapLifecycle:
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    def _prepared(self, row: tuple[Any, ...]) -> PreparedMap:
        data = json.loads(row[1])
        identity = WorkflowIdentity(**data["workflow_identity"])
        assignments = tuple(PrivateAssignment(**item) for item in data["assignments"])
        mapping = FrozenPrivateMap(
            data["campaign_id"],
            data["experiment_id"],
            identity,
            data["pre_map_input_hash"],
            data["seed"],
            tuple(data["assignment_order"]),
            assignments,
            MappingProxyType(data["preferred_directions"]),
            data["freeze_chain"],
        )
        return PreparedMap(row[0], mapping, row[2], row[3], row[4])

    def _private_path(self, relative: str) -> Path:
        if self.artifact_root is None:
            raise TrialProtocolError("private artifact root is unavailable")
        root = self.artifact_root.resolve(strict=True)
        path = (root / relative).resolve(strict=False)
        if root not in path.parents or path.is_symlink():
            raise TrialProtocolError("private artifact path is invalid")
        return path

    def _write_private(self, relative: str, value: Any) -> str:
        path = self._private_path(relative)
        data = canonical_bytes(value)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if path.read_bytes() != data:
                raise TrialProtocolError("private artifact is immutable") from None
        else:
            with os.fdopen(fd, "wb") as output:
                output.write(data)
        return str(path)

    def _verify_private(self, path_text: str | None, expected: str) -> None:
        if not isinstance(path_text, str) or not path_text:
            raise TrialProtocolError("private artifact descriptor is unavailable")
        path = Path(path_text)
        if self._invalid_private_descriptor_path(path):
            raise TrialProtocolError("private artifact descriptor is invalid")
        try:
            value = json.loads(path.read_bytes())
        except (OSError, ValueError, UnicodeDecodeError) as error:
            raise TrialProtocolError("private artifact is unavailable") from error
        digest = sha256(canonical_bytes(value)).hexdigest()
        if not hmac.compare_digest(digest, expected):
            raise TrialProtocolError("private artifact digest mismatch")

    def _invalid_private_descriptor_path(self, path: Path) -> bool:
        return (
            self.artifact_root is None
            or not path.is_absolute()
            or self.artifact_root.resolve(strict=True) not in path.resolve(strict=False).parents
            or path.is_symlink()
        )

    def _map_row_for_key(self, key: tuple[str, str, str, str, str]) -> tuple[Any, ...] | None:
        return _database_row(
            self._db.execute(
                "SELECT map_ref,payload,k_map,k_evidence,k_artifact,state,freeze_chain "
                "FROM private_maps WHERE campaign=? AND experiment=? AND workflow_id=? "
                "AND run_id=? AND input_hash=?",
                key,
            ).fetchone()
        )

    def _map_row_for_ref(self, map_ref: str) -> tuple[Any, ...] | None:
        return _database_row(
            self._db.execute(
                "SELECT map_ref,payload,k_map,k_evidence,k_artifact,state,freeze_chain "
                "FROM private_maps WHERE map_ref=?",
                (map_ref,),
            ).fetchone()
        )

    def _map_row_for_metadata(self, metadata: TrustedActivityMetadata) -> tuple[Any, ...] | None:
        return _database_row(
            self._db.execute(
                "SELECT map_ref,payload,k_map,k_evidence,k_artifact,state,freeze_chain "
                "FROM private_maps WHERE workflow_id=? AND run_id=? AND freeze_chain=?",
                (
                    metadata.identity.workflow_id,
                    metadata.identity.run_id,
                    metadata.freeze_chain,
                ),
            ).fetchone()
        )

    def _map_key(
        self, params: PrivateMapParams, metadata: TrustedActivityMetadata
    ) -> tuple[str, str, str, str, str]:
        return (
            params.campaign_id,
            params.experiment_id,
            metadata.identity.workflow_id,
            metadata.identity.run_id,
            params.pre_map_input_hash,
        )

    def _new_prepared(self, params: PrivateMapParams) -> PreparedMap:
        return PreparedMap(
            _token(24),
            prepare_private_map(params),
            secrets.token_bytes(32),
            secrets.token_bytes(32),
            secrets.token_bytes(32),
        )

    def _insert_prepared(
        self,
        key: tuple[str, str, str, str, str],
        metadata: TrustedActivityMetadata,
        prepared: PreparedMap,
    ) -> None:
        self._db.execute(
            "INSERT INTO private_maps VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                *key,
                metadata.freeze_chain,
                prepared.map_ref,
                json.dumps(prepared.mapping.json(), separators=(",", ":")).encode(),
                prepared.k_map,
                prepared.k_evidence,
                prepared.k_artifact,
                "MAP_PREPARED",
            ),
        )

    def prepare(self, params: PrivateMapParams) -> PreparedMap:
        metadata = _require_trusted_metadata(params.metadata)
        key = self._map_key(params, metadata)
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._map_row_for_key(key)
            if row:
                return self._existing_prepared(row, metadata)
            prepared = self._new_prepared(params)
            self._insert_prepared(key, metadata, prepared)
            map_path = self._write_private(
                f"private-maps/{prepared.map_ref}.json", prepared.mapping.json()
            )
            self._record_artifact(
                prepared,
                _StoredArtifact(
                    None,
                    "map",
                    prepared.mapping.map_sha256,
                    map_path,
                ),
            )
            self._db.execute("COMMIT")
            return prepared
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def _existing_prepared(
        self, row: tuple[Any, ...], metadata: TrustedActivityMetadata
    ) -> PreparedMap:
        if row[5] != "MAP_PREPARED" or not hmac.compare_digest(row[6], metadata.freeze_chain):
            raise TrialProtocolError("private map CAS conflict")
        self._db.execute("COMMIT")
        return self._prepared(row)

    def resolve(
        self, *, map_ref: str, metadata: TrustedActivityMetadata, token: str
    ) -> PrivateAssignment:
        metadata = _require_trusted_metadata(metadata)
        row = self._map_row_for_ref(map_ref)
        if (
            not row
            or row[5] != "MAP_PREPARED"
            or not hmac.compare_digest(row[6], metadata.freeze_chain)
        ):
            raise TrialProtocolError("map reference is invalid")
        prepared = self._prepared(row)
        if prepared.mapping.workflow_identity != metadata.identity:
            raise TrialProtocolError("cross-workflow map resolution")
        return self._assignment_for_token(prepared, token)

    def _assignment_for_token(self, prepared: PreparedMap, token: str) -> PrivateAssignment:
        for assignment in prepared.mapping.assignments:
            if hmac.compare_digest(assignment.token, token):
                return assignment
        raise TrialProtocolError("map token is invalid")

    def resolve_index(self, *, metadata: TrustedActivityMetadata, index: int) -> PrivateAssignment:
        metadata = _require_trusted_metadata(metadata)
        self._validate_trial_index(index)
        row = self._map_row_for_metadata(metadata)
        if not row or row[5] != "MAP_PREPARED":
            raise TrialProtocolError("private map is unavailable")
        prepared = self._prepared(row)
        if prepared.mapping.workflow_identity != metadata.identity:
            raise TrialProtocolError("cross-workflow map resolution")
        assignment_id = prepared.mapping.assignment_order[index]
        return next(
            assignment
            for assignment in prepared.mapping.assignments
            if assignment.assignment_id == assignment_id
        )

    def _validate_trial_index(self, index: int) -> None:
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < len(ASSIGNMENT_IDS)
        ):
            raise TrialProtocolError("trial index is invalid")

    def record_outcome_index(
        self, *, metadata: TrustedActivityMetadata, index: int, outcome_sha256: str
    ) -> None:
        if not _hex(outcome_sha256):
            raise TrialProtocolError("outcome digest is invalid")
        assignment = self.resolve_index(metadata=metadata, index=index)
        row = self._map_row_for_metadata(metadata)
        if not row:
            raise TrialProtocolError("private map is unavailable")
        prepared = self._prepared(row)
        path = str(
            self._private_path(
                f"quarantine/{prepared.mapping.campaign_id}/"
                f"{prepared.mapping.experiment_id}/{index}.json"
            )
        )
        self._record_artifact(
            prepared,
            _StoredArtifact(assignment.token, "outcome", outcome_sha256, path),
        )
        self._db.commit()

    def _record_artifact(self, prepared: PreparedMap, artifact: _StoredArtifact) -> None:
        commitment = private_artifact_commitment(
            PrivateArtifactCommitmentParams(
                PrivateArtifactDescriptorParams(
                    prepared.mapping.campaign_id,
                    prepared.mapping.experiment_id,
                    artifact.token,
                    artifact.artifact_kind,
                    artifact.artifact_sha256,
                ),
                prepared.k_artifact,
            )
        )
        self._db.execute(
            "INSERT INTO private_artifacts "
            "(map_ref,token,artifact_kind,artifact_sha256,commitment,artifact_path) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(map_ref,token,artifact_kind) DO UPDATE "
            "SET artifact_sha256=excluded.artifact_sha256,"
            "commitment=excluded.commitment,artifact_path=excluded.artifact_path "
            "WHERE private_artifacts.artifact_sha256=excluded.artifact_sha256 "
            "AND private_artifacts.commitment=excluded.commitment "
            "AND private_artifacts.artifact_path=excluded.artifact_path",
            (
                prepared.map_ref,
                artifact.token,
                artifact.artifact_kind,
                artifact.artifact_sha256,
                commitment,
                artifact.artifact_path,
            ),
        )
        row = self._db.execute(
            "SELECT artifact_sha256,commitment,artifact_path FROM private_artifacts "
            "WHERE map_ref=? AND token IS ? AND artifact_kind=?",
            (prepared.map_ref, artifact.token, artifact.artifact_kind),
        ).fetchone()
        if row != (artifact.artifact_sha256, commitment, artifact.artifact_path):
            raise TrialProtocolError("private artifact is immutable")

    def record_artifact(self, params: ArtifactRecordParams) -> None:
        if params.artifact_kind not in SUBJECT_ARTIFACT_KINDS:
            raise TrialProtocolError("private artifact kind is invalid")
        if not _hex(params.artifact_sha256):
            raise TrialProtocolError("private artifact digest is invalid")
        assignment = self.resolve(
            map_ref=params.map_ref,
            metadata=params.metadata,
            token=params.token,
        )
        row = self._map_row_for_ref(params.map_ref)
        if not row:
            raise TrialProtocolError("map reference is invalid")
        prepared = self._prepared(row)
        path = self._artifact_quarantine_path(prepared, assignment, params.artifact_kind)
        self._verify_private(str(path), params.artifact_sha256)
        self._record_artifact(
            prepared,
            _StoredArtifact(
                assignment.token,
                params.artifact_kind,
                params.artifact_sha256,
                str(path),
            ),
        )
        self._db.commit()

    def _artifact_quarantine_path(
        self,
        prepared: PreparedMap,
        assignment: PrivateAssignment,
        artifact_kind: str,
    ) -> Path:
        relative = (
            f"quarantine/{prepared.mapping.campaign_id}/"
            f"{prepared.mapping.experiment_id}/{assignment.token}/"
            f"{artifact_kind}.json"
        )
        return self._private_path(relative)

    def record_outcome(
        self,
        *,
        map_ref: str,
        metadata: TrustedActivityMetadata,
        token: str,
        outcome_sha256: str,
    ) -> None:
        self.record_artifact(
            ArtifactRecordParams(
                map_ref,
                metadata,
                token,
                "outcome",
                outcome_sha256,
            )
        )

    def release(self, *, metadata: TrustedActivityMetadata) -> dict[str, Any]:
        metadata = _require_trusted_metadata(metadata)
        row = self._map_row_for_metadata(metadata)
        if not row or row[5] != "MAP_PREPARED":
            raise TrialProtocolError("private map is unavailable for release")
        prepared = self._prepared(row)
        inventory, directions = self._release_records(prepared)
        return release_g5(prepared.mapping, inventory, prepared.k_artifact, directions)

    def _release_records(
        self, prepared: PreparedMap
    ) -> tuple[list[dict[str, Any]], dict[str, str]]:
        inventory: list[dict[str, Any]] = []
        directions: dict[str, str] = {}
        assignments = {assignment.token: assignment for assignment in prepared.mapping.assignments}
        rows = self._db.execute(
            "SELECT token,artifact_kind,artifact_sha256,commitment,artifact_path "
            "FROM private_artifacts WHERE map_ref=?",
            (prepared.map_ref,),
        )
        for token, kind, digest, commitment, path in rows:
            self._verify_private(path, digest)
            inventory.append(
                {
                    "campaign_id": prepared.mapping.campaign_id,
                    "experiment_id": prepared.mapping.experiment_id,
                    "token": token,
                    "artifact_kind": kind,
                    "artifact_sha256": digest,
                    "commitment": commitment,
                }
            )
            self._record_release_direction(directions, assignments, token, kind, path)
        return inventory, directions

    def _record_release_direction(
        self,
        directions: dict[str, str],
        assignments: Mapping[str, PrivateAssignment],
        token: str | None,
        kind: str,
        path: str | None,
    ) -> None:
        if kind != "outcome":
            return
        if not isinstance(token, str) or not token or not isinstance(path, str) or not path:
            raise TrialProtocolError("private outcome artifact is malformed")
        outcome = self._read_release_outcome(path)
        assignment = assignments.get(token)
        if not _authoritative_outcome(outcome, assignment):
            raise TrialProtocolError("private outcome artifact is not authoritative")
        directions[token] = outcome["direction_code"]

    def _read_release_outcome(self, path: str) -> Any:
        try:
            return json.loads(Path(path).read_bytes())
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise TrialProtocolError("private outcome artifact is malformed") from error


def _authoritative_outcome(outcome: Any, assignment: PrivateAssignment | None) -> bool:
    fields = {
        "blind_id",
        "fixture",
        "protocol_valid",
        "verifier_passed",
        "observer_state",
        "direction_code",
        "changed_paths",
        "evidence_id",
    }
    return (
        assignment is not None
        and isinstance(outcome, Mapping)
        and set(outcome) == fields
        and outcome["blind_id"] == assignment.blind_id
        and outcome["fixture"] == assignment.scenario
        and outcome["protocol_valid"] is True
        and isinstance(outcome["direction_code"], str)
        and bool(outcome["direction_code"])
    )


def map_descriptor(mapping: FrozenPrivateMap, map_ref: str) -> dict[str, str]:
    return {
        "schema": "instruct-eval-map-commitment-v1",
        "campaign_id": mapping.campaign_id,
        "experiment_id": mapping.experiment_id,
        "workflow_id": mapping.workflow_identity.workflow_id,
        "run_id": mapping.workflow_identity.run_id,
        "pre_map_input_hash": mapping.pre_map_input_hash,
        "map_ref": map_ref,
        "map_sha256": mapping.map_sha256,
    }


def map_commitment(mapping: FrozenPrivateMap, map_ref: str, k_map: bytes) -> str:
    if not isinstance(k_map, bytes) or len(k_map) != 32:
        raise TrialProtocolError("K_map must be 256-bit")
    return _b64(
        hmac.new(
            k_map,
            b"instruct-eval-map-commitment-v1\0"
            + canonical_bytes(map_descriptor(mapping, map_ref)),
            sha256,
        ).digest()
    )


class TrialDispatcher:
    def __init__(self, mapping: FrozenPrivateMap) -> None:
        self._order = tuple(mapping.assignment_order)
        self._state: dict[str, str | None] = dict.fromkeys(self._order)
        self._halt: str | None = None

    def dispatch(self) -> tuple[str, ...]:
        if self._halt:
            return ()
        slots = 4 - sum(value == "started" for value in self._state.values())
        ready = [token for token in self._order if self._state[token] is None][:slots]
        for token in ready:
            self._state[token] = "started"
        return tuple(ready)

    def terminal(self, assignment_id: str, disposition: str) -> tuple[str, ...]:
        valid_dispositions = {
            "result",
            "terminal",
            "indeterminate",
            "canceled-before-invocation",
        }
        if (
            assignment_id not in self._state
            or self._state[assignment_id] != "started"
            or disposition not in valid_dispositions
        ):
            raise TrialProtocolError("invalid terminal transition")
        self._state[assignment_id] = disposition
        if disposition in {"terminal", "indeterminate"}:
            self._halt = disposition
            self._mark_unscheduled("UNSCHEDULED_DUE_TO_TERMINAL")
        return ()

    def cancel(self) -> None:
        self._halt = "cancellation"
        self._mark_unscheduled("UNSCHEDULED_DUE_TO_CANCELLATION")

    def _mark_unscheduled(self, disposition: str) -> None:
        for token, state in self._state.items():
            if state is None:
                self._state[token] = disposition

    def accounting(self) -> Mapping[str, str]:
        if any(value is None or value == "started" for value in self._state.values()):
            raise TrialProtocolError("dispatcher has unaccounted tokens")
        return MappingProxyType(cast(dict[str, str], dict(self._state)))


def schedule_batches(mapping: FrozenPrivateMap) -> tuple[tuple[str, ...], ...]:
    return tuple(
        tuple(mapping.assignment_order[index : index + 4])
        for index in range(0, len(mapping.assignment_order), 4)
    )


def classify_terminal(
    *, started: bool, result: bool, canceled: bool, indeterminate: bool, terminal: bool
) -> str:
    if result and started:
        return "result"
    if indeterminate and started:
        return "indeterminate"
    if terminal and started:
        return "terminal"
    if canceled and not started:
        return "canceled-before-invocation"
    if terminal and not started:
        return "UNSCHEDULED_DUE_TO_TERMINAL"
    if canceled and not started:
        return "UNSCHEDULED_DUE_TO_CANCELLATION"
    raise TrialProtocolError("no terminal disposition")


def validate_allowed_paths(paths: Sequence[str], root: str | Path) -> tuple[str, ...]:
    root_path = Path(root).resolve(strict=True)
    if (
        not paths
        or len(paths) > 256
        or len(set(paths)) != len(paths)
        or list(paths) != sorted(paths)
    ):
        raise TrialProtocolError("paths must be sorted unique bounded")
    for path in paths:
        _validate_allowed_path(path, root_path)
    return tuple(paths)


def _validate_allowed_path(path: str, root_path: Path) -> None:
    if (
        not isinstance(path, str)
        or not path
        or path != unicodedata.normalize("NFC", path)
        or path.startswith("/")
        or "\\" in path
        or any(part in {".", "..", ""} for part in path.split("/"))
    ):
        raise TrialProtocolError("invalid allowed path")
    candidate = root_path
    for component in path.split("/"):
        candidate /= component
        if candidate.is_symlink():
            raise TrialProtocolError("symlinked allowed path")


@dataclass(frozen=True, slots=True)
class ClosedOutcomeParams:
    blind_id: str
    fixture: str
    verifier_passed: bool
    observer_state: Sequence[str]
    direction_code: str
    changed_paths: Sequence[str]
    token: str
    k_evidence: bytes
    fixture_paths: Mapping[str, Sequence[str]]
    root: str | Path


def _validate_closed_outcome_params(params: ClosedOutcomeParams) -> None:
    if (
        not isinstance(params.blind_id, str)
        or not params.blind_id
        or not isinstance(params.verifier_passed, bool)
        or not isinstance(params.direction_code, str)
        or not params.direction_code
        or not isinstance(params.token, str)
        or not params.token
        or not isinstance(params.k_evidence, bytes)
        or len(params.k_evidence) != 32
        or params.fixture not in params.fixture_paths
    ):
        raise TrialProtocolError("invalid closed outcome")


def _validate_outcome_paths(params: ClosedOutcomeParams, allowed: Sequence[str]) -> None:
    if (
        not all(isinstance(value, str) for value in params.observer_state)
        or len(set(params.changed_paths)) != len(params.changed_paths)
        or tuple(sorted(params.changed_paths)) != tuple(params.changed_paths)
        or any(path not in allowed for path in params.changed_paths)
    ):
        raise TrialProtocolError("invalid outcome paths")


def closed_outcome(params: ClosedOutcomeParams) -> dict[str, Any]:
    _validate_closed_outcome_params(params)
    allowed = validate_allowed_paths(params.fixture_paths[params.fixture], params.root)
    _validate_outcome_paths(params, allowed)
    return {
        "blind_id": params.blind_id,
        "fixture": params.fixture,
        "protocol_valid": True,
        "verifier_passed": params.verifier_passed,
        "observer_state": list(params.observer_state),
        "direction_code": params.direction_code,
        "changed_paths": list(params.changed_paths),
        "evidence_id": _b64(
            hmac.new(
                params.k_evidence,
                b"instruct-eval-evidence-id-v1\0" + params.token.encode(),
                sha256,
            ).digest()
        ),
    }


@dataclass(frozen=True, slots=True)
class PrivateArtifactDescriptorParams:
    campaign_id: str
    experiment_id: str
    token: str | None
    artifact_kind: str
    artifact_sha256: str


def private_artifact_descriptor(
    params: PrivateArtifactDescriptorParams,
) -> dict[str, str | None]:
    if (
        params.artifact_kind not in SUBJECT_ARTIFACT_KINDS | {"map"}
        or (params.artifact_kind == "map") != (params.token is None)
        or (params.artifact_kind != "map" and not isinstance(params.token, str))
        or not _hex(params.artifact_sha256)
    ):
        raise TrialProtocolError("invalid private artifact descriptor")
    return {
        "schema": "instruct-eval-private-artifact-v1",
        "campaign_id": params.campaign_id,
        "experiment_id": params.experiment_id,
        "token": params.token,
        "artifact_kind": params.artifact_kind,
        "artifact_sha256": params.artifact_sha256,
    }


@dataclass(frozen=True, slots=True)
class PrivateArtifactCommitmentParams:
    descriptor: PrivateArtifactDescriptorParams
    k_artifact: bytes


def private_artifact_commitment(params: PrivateArtifactCommitmentParams) -> str:
    if not isinstance(params.k_artifact, bytes) or len(params.k_artifact) != 32:
        raise TrialProtocolError("K_artifact must be 256-bit")
    descriptor = private_artifact_descriptor(params.descriptor)
    return _b64(
        hmac.new(
            params.k_artifact,
            b"instruct-eval-private-commitment-v1\0" + canonical_bytes(descriptor),
            sha256,
        ).digest()
    )


def _expected_inventory(mapping: FrozenPrivateMap) -> set[tuple[str | None, str, str | None]]:
    return {(None, "map", mapping.map_sha256)} | {
        (assignment.token, artifact_kind, None)
        for assignment in mapping.assignments
        for artifact_kind in SUBJECT_ARTIFACT_KINDS
    }


def _inventory_item_key(
    item: Mapping[str, Any],
    mapping: FrozenPrivateMap,
    k_artifact: bytes,
) -> tuple[str | None, str, str | None]:
    descriptor_params = PrivateArtifactDescriptorParams(
        cast(str, item.get("campaign_id")),
        cast(str, item.get("experiment_id")),
        cast(str | None, item.get("token")),
        cast(str, item.get("artifact_kind")),
        cast(str, item.get("artifact_sha256")),
    )
    descriptor = private_artifact_descriptor(descriptor_params)
    commitment = private_artifact_commitment(
        PrivateArtifactCommitmentParams(
            PrivateArtifactDescriptorParams(
                mapping.campaign_id,
                mapping.experiment_id,
                descriptor["token"],
                cast(str, descriptor["artifact_kind"]),
                cast(str, descriptor["artifact_sha256"]),
            ),
            k_artifact,
        )
    )
    if (
        descriptor["campaign_id"] != mapping.campaign_id
        or descriptor["experiment_id"] != mapping.experiment_id
        or not hmac.compare_digest(str(item.get("commitment", "")), commitment)
    ):
        raise TrialProtocolError("artifact commitment mismatch")
    token = descriptor["token"]
    digest = descriptor["artifact_sha256"] if token is None else None
    return token, cast(str, descriptor["artifact_kind"]), digest


def _validate_inventory(
    mapping: FrozenPrivateMap,
    inventory: Sequence[Mapping[str, Any]],
    k_artifact: bytes,
) -> None:
    expected = _expected_inventory(mapping)
    seen: set[tuple[str | None, str, str | None]] = set()
    for item in inventory:
        key = _inventory_item_key(item, mapping, k_artifact)
        if key not in expected or key in seen:
            raise TrialProtocolError("artifact inventory mismatch")
        seen.add(key)
    if seen != expected:
        raise TrialProtocolError("incomplete artifact inventory")


def _validate_release_directions(mapping: FrozenPrivateMap, directions: Mapping[str, str]) -> None:
    expected_tokens = {assignment.token for assignment in mapping.assignments}
    if (
        not isinstance(directions, Mapping)
        or set(directions) != expected_tokens
        or any(not isinstance(direction, str) or not direction for direction in directions.values())
    ):
        raise TrialProtocolError("G5 directions must come from exactly ten private outcomes")


def _released_assignments(
    mapping: FrozenPrivateMap, directions: Mapping[str, str]
) -> list[dict[str, str]]:
    assignments = (
        {
            "blind_id": assignment.blind_id,
            "scenario": assignment.scenario,
            "condition": assignment.condition,
            "direction": directions[assignment.token],
        }
        for assignment in mapping.assignments
    )
    return sorted(assignments, key=lambda record: record["blind_id"])


def release_g5(
    mapping: FrozenPrivateMap,
    inventory: Sequence[Mapping[str, Any]],
    k_artifact: bytes,
    directions: Mapping[str, str],
) -> dict[str, Any]:
    _validate_inventory(mapping, inventory, k_artifact)
    _validate_release_directions(mapping, directions)
    released = {
        "assignments": _released_assignments(mapping, directions),
        "preferred_directions": dict(mapping.preferred_directions),
        "authorization_rule": mapping.authorization_rule,
    }
    return {**released, "release_sha256": _sha(released)}


class AhoMatcher:
    def __init__(self, patterns: Sequence[Any]) -> None:
        self.patterns = tuple(dict.fromkeys(pattern for pattern in patterns if pattern))
        self.next: list[dict[Any, int]] = [{}]
        self.fail = [0]
        self.out: list[list[int]] = [[]]
        for index, pattern in enumerate(self.patterns):
            self._add_pattern(index, pattern)
        self._build_failures()

    def _add_pattern(self, index: int, pattern: Any) -> None:
        node = 0
        for char in pattern:
            node = self._next_node(node, char)
        self.out[node].append(index)

    def _next_node(self, node: int, char: Any) -> int:
        child = self.next[node].get(char)
        if child is not None:
            return child
        child = len(self.next)
        self.next[node][char] = child
        self.next.append({})
        self.fail.append(0)
        self.out.append([])
        return child

    def _build_failures(self) -> None:
        queue = deque(self.next[0].values())
        while queue:
            node = queue.popleft()
            for char, child in self.next[node].items():
                queue.append(child)
                fallback = self.fail[node]
                while fallback and char not in self.next[fallback]:
                    fallback = self.fail[fallback]
                self.fail[child] = self.next[fallback].get(char, 0)
                self.out[child].extend(self.out[self.fail[child]])

    def matches(self, text: Any) -> tuple[Any, ...]:
        node = 0
        found = set()
        for char in text:
            while node and char not in self.next[node]:
                node = self.fail[node]
            node = self.next[node].get(char, 0)
            found.update(self.out[node])
        return tuple(self.patterns[index] for index in sorted(found))


def disclosure_patterns(treatment: str) -> tuple[bytes, ...]:
    if len(treatment) > MAX_TREATMENT_SCALARS:
        raise TrialProtocolError("treatment exceeds 8192 scalars")
    return (treatment.encode(), *(assignment.encode() for assignment in ASSIGNMENT_IDS))


def normalized_patterns(treatment: str) -> tuple[str, ...]:
    normalized = normalize(treatment)
    chunks = (
        (normalized,)
        if len(normalized) <= 32
        else tuple(normalized[index : index + 32] for index in range(len(normalized) - 31))
    )
    return tuple(
        dict.fromkeys(chunks + tuple(normalize(assignment) for assignment in ASSIGNMENT_IDS))
    )


def _raw_channels(raw: bytes | Sequence[bytes]) -> tuple[bytes, ...]:
    return (raw,) if isinstance(raw, bytes) else tuple(raw)


def _validate_raw_channels(channels: Sequence[bytes]) -> None:
    if (
        not channels
        or any(
            not isinstance(channel, bytes) or len(channel) > MAX_CHANNEL_BYTES
            for channel in channels
        )
        or sum(map(len, channels)) > MAX_RAW_QUARANTINE_BYTES
    ):
        raise TrialProtocolError("raw quarantine overflow")


def _decode_channels(channels: Sequence[bytes]) -> str:
    try:
        return "".join(channel.decode("utf-8", "strict") for channel in channels)
    except UnicodeDecodeError as error:
        raise TrialProtocolError("invalid UTF-8") from error


def _validate_normalized_stream(normalized: str, channel_count: int) -> None:
    if (
        len(normalized) > MAX_NORMALIZED_SCALARS
        or len(normalized) * channel_count > MAX_AGGREGATE_SCALARS
    ):
        raise TrialProtocolError("normalized stream overflow")


def scan_disclosure(*, raw: bytes | Sequence[bytes], treatment: str) -> bool:
    channels = _raw_channels(raw)
    _validate_raw_channels(channels)
    raw_matcher = AhoMatcher(disclosure_patterns(treatment))
    if any(raw_matcher.matches(channel) for channel in channels):
        return True
    normalized = normalize(_decode_channels(channels))
    _validate_normalized_stream(normalized, len(channels))
    return bool(AhoMatcher(normalized_patterns(treatment)).matches(normalized)) or (
        condition_disclosure(normalized)
    )


def _skip_white_space(value: str, index: int) -> int:
    while index < len(value) and value[index] in WHITE_SPACE_15_1:
        index += 1
    return index


def _condition_value_matches(value: str, index: int) -> bool:
    values = ("a", "b", '"a"', '"b"', "'a'", "'b'")
    return any(
        value.startswith(candidate, index)
        and _bound(value, index, index + len(candidate))
        and not (index + len(candidate) < len(value) and value[index + len(candidate)] in "'\"")
        for candidate in values
    )


def _condition_key_matches(value: str, index: int, key: str) -> bool:
    if not value.startswith(key, index) or not _bound(value, index, index + len(key)):
        return False
    separator = _skip_white_space(value, index + len(key))
    if separator >= len(value) or value[separator] not in "=:":
        return False
    return _condition_value_matches(value, _skip_white_space(value, separator + 1))


def condition_disclosure(text: str) -> bool:
    value = normalize(text)
    keys = ("condition", '"condition"', "'condition'")
    return any(
        _condition_key_matches(value, index, key) for index in range(len(value)) for key in keys
    )


def _g6_input_valid(released: Sequence[Mapping[str, str]], preferred: Mapping[str, str]) -> bool:
    return not (
        not isinstance(released, Sequence)
        or isinstance(released, (str, bytes))
        or not isinstance(preferred, Mapping)
        or set(preferred) != set(SCENARIOS)
        or any(not isinstance(value, str) or not value for value in preferred.values())
        or len(released) != len(ASSIGNMENT_IDS)
    )


def _g6_expected_pairs() -> set[tuple[str, str]]:
    return {
        (assignment.rsplit("-", 2)[0], assignment.rsplit("-", 2)[1])
        for assignment in ASSIGNMENT_IDS
    }


def _g6_rows(released: Sequence[Mapping[str, str]]) -> list[tuple[str, str, str, str]] | None:
    fields = frozenset({"blind_id", "scenario", "condition", "direction"})
    if any(not isinstance(score, Mapping) or set(score) != fields for score in released):
        return None
    return [
        (score["blind_id"], score["scenario"], score["condition"], score["direction"])
        for score in released
    ]


def _g6_rows_valid(
    rows: Sequence[tuple[str, str, str, str]], expected: set[tuple[str, str]]
) -> bool:
    return not (
        any(not all(isinstance(value, str) and value for value in row) for row in rows)
        or len({row[0] for row in rows}) != len(ASSIGNMENT_IDS)
        or {(row[1], row[2]) for row in rows} != expected
    )


def _g6_directions(
    rows: Sequence[tuple[str, str, str, str]], expected: set[tuple[str, str]]
) -> dict[tuple[str, str], list[str]]:
    directions: dict[tuple[str, str], list[str]] = {
        (scenario, condition): [] for scenario, condition in expected
    }
    for _, scenario, condition, direction in rows:
        directions[(scenario, condition)].append(direction)
    return directions


def _g6_counts_valid(
    directions: Mapping[tuple[str, str], Sequence[str]],
    expected: set[tuple[str, str]],
) -> bool:
    return all(
        len(directions[(scenario, condition)]) == (2 if scenario != "negative-control" else 1)
        for scenario, condition in expected
    )


def _g6_core_authorized(
    directions: Mapping[tuple[str, str], Sequence[str]], preferred: Mapping[str, str]
) -> bool:
    return all(
        sum(direction == preferred[scenario] for direction in directions[(scenario, "B")])
        > sum(direction == preferred[scenario] for direction in directions[(scenario, "A")])
        for scenario in ("core-1", "core-2")
    )


def _g6_negative_control_authorized(
    directions: Mapping[tuple[str, str], Sequence[str]], preferred: Mapping[str, str]
) -> bool:
    return all(
        directions[("negative-control", condition)][0] == preferred["negative-control"]
        for condition in ("A", "B")
    )


def g6_authorized(released: Sequence[Mapping[str, str]], preferred: Mapping[str, str]) -> bool:
    if not _g6_input_valid(released, preferred):
        return False
    expected = _g6_expected_pairs()
    rows = _g6_rows(released)
    if rows is None or not _g6_rows_valid(rows, expected):
        return False
    directions = _g6_directions(rows, expected)
    return (
        _g6_counts_valid(directions, expected)
        and _g6_core_authorized(directions, preferred)
        and _g6_negative_control_authorized(directions, preferred)
    )
