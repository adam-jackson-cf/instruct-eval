"""Public client entrypoint for starting or safely adopting a campaign."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from temporalio.client import Client, WorkflowHandle
from temporalio.common import WorkflowIDReusePolicy
from temporalio.exceptions import WorkflowAlreadyStartedError

from .messages import request_fingerprint
from .worker import PUBLIC_TASK_QUEUE, TEMPORAL_NAMESPACE
from .workflows import CampaignInput, CampaignStatus, ExperimentCampaignWorkflow

_CAMPAIGN_ID = re.compile(r"campaign-[0-9]{32}\Z")
_INITIALIZATION_TIMEOUT_SECONDS = 30.0
_BACKOFF_CAP_SECONDS = 1.0


class CampaignStartError(RuntimeError):
    """A campaign could not be started or safely adopted."""


@dataclass(frozen=True, slots=True)
class CampaignStartResult:
    """A started/adopted handle, or an explicit pending initialization result."""

    state: str
    handle: WorkflowHandle[Any, Any] | None

    @property
    def initialization_pending(self) -> bool:
        return self.state == "initialization_pending"


def _validate_input(input_: CampaignInput) -> None:
    if not isinstance(input_, CampaignInput):
        raise TypeError("campaign start requires CampaignInput")
    if not _CAMPAIGN_ID.fullmatch(input_.campaign_id):
        raise CampaignStartError("campaign id must be caller-supplied campaign-[0-9]{32}")


async def _adopt_campaign(
    input_: CampaignInput,
    handle: WorkflowHandle[Any, Any],
    sleep: Callable[[float], Awaitable[None]],
    monotonic: Callable[[], float],
) -> CampaignStartResult:
    expected = request_fingerprint(
        input_.public_input, input_.model_identity, input_.runtime_identity
    )
    deadline = monotonic() + _INITIALIZATION_TIMEOUT_SECONDS
    delay = 0.03125
    while monotonic() < deadline:
        try:
            status = await handle.query("status", result_type=CampaignStatus)
        except Exception as error:
            raise CampaignStartError("existing campaign cannot be queried") from error
        if not isinstance(status, CampaignStatus) or status.campaign_id != input_.campaign_id:
            raise CampaignStartError("existing campaign status is invalid") from None
        if status.fingerprint_sha256 is not None:
            if status.fingerprint_sha256 != expected:
                raise CampaignStartError(
                    "existing campaign fingerprint does not match request"
                ) from None
            return CampaignStartResult("adopted", handle)
        if status.state in {
            "FINGERPRINT_FAILED",
            "COMPLETED",
            "FAILED",
            "CANCELLED",
            "TERMINATED",
        }:
            raise CampaignStartError(
                "existing campaign is closed or failed before fingerprint readiness"
            ) from None
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        await sleep(min(delay, remaining))
        delay = min(delay * 2, _BACKOFF_CAP_SECONDS)
    return CampaignStartResult("initialization_pending", None)


async def start_campaign(
    client: Client,
    input_: CampaignInput,
    *,
    task_queue: str = PUBLIC_TASK_QUEUE,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> CampaignStartResult:
    """Start the sole public workflow path, or adopt an exact duplicate safely."""
    _validate_input(input_)
    if getattr(client, "namespace", None) != TEMPORAL_NAMESPACE:
        raise CampaignStartError("campaign client must use the pinned instruct-eval namespace")
    if not task_queue:
        raise ValueError("campaign task queue is required")
    try:
        handle = await client.start_workflow(
            ExperimentCampaignWorkflow.run,
            input_,
            id=input_.campaign_id,
            task_queue=task_queue,
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
        )
        return CampaignStartResult("started", handle)
    except WorkflowAlreadyStartedError:
        handle = client.get_workflow_handle_for(ExperimentCampaignWorkflow.run, input_.campaign_id)
        return await _adopt_campaign(input_, handle, sleep, monotonic)


async def run_campaign(
    client: Client, input_: CampaignInput, **kwargs: Any
) -> WorkflowHandle[Any, Any]:
    """Compatibility-free command helper: pending initialization is not a handle."""
    result = await start_campaign(client, input_, **kwargs)
    if result.handle is None:
        raise CampaignStartError("initialization_pending")
    return result.handle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="instruct-eval")
    parser.add_argument("--address", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start")
    start.add_argument("--campaign-id", required=True)
    start.add_argument("--model-identity", required=True)
    start.add_argument("--runtime-identity", required=True)
    start.add_argument("--coverage-sha256", required=True)
    start.add_argument("--public-input-json", required=True)
    status = commands.add_parser("status")
    status.add_argument("--workflow-id", required=True)
    update = commands.add_parser("update")
    update.add_argument("--workflow-id", required=True)
    update.add_argument("--wire-json", required=True)
    return parser


async def _main_async(arguments: argparse.Namespace) -> int:
    client = await Client.connect(arguments.address, namespace=TEMPORAL_NAMESPACE)
    if arguments.command == "status":
        status = await client.get_workflow_handle(arguments.workflow_id).query("status")
        print(json.dumps(__import__("dataclasses").asdict(status), sort_keys=True))
        return 0
    if arguments.command == "update":
        try:
            wire = json.loads(arguments.wire_json)
        except json.JSONDecodeError as error:
            raise CampaignStartError("decision wire must be JSON") from error
        revision = await client.get_workflow_handle(arguments.workflow_id).execute_update(
            "decision", wire
        )
        print(
            json.dumps(
                {"workflow_id": arguments.workflow_id, "revision_sha256": revision}, sort_keys=True
            )
        )
        return 0
    try:
        public_input = json.loads(arguments.public_input_json)
    except json.JSONDecodeError as error:
        raise CampaignStartError("public input must be JSON") from error
    if not isinstance(public_input, dict):
        raise CampaignStartError("public input must be a JSON object")
    result = await start_campaign(
        client,
        CampaignInput(
            arguments.campaign_id,
            arguments.model_identity,
            arguments.runtime_identity,
            public_input,
            arguments.coverage_sha256,
        ),
    )
    print(json.dumps({"campaign_id": arguments.campaign_id, "state": result.state}, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_main_async(_parser().parse_args(argv)))
