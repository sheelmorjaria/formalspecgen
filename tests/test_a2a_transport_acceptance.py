# Copyright 2026 Sheel Morjaria
# SPDX-License-Identifier: Apache-2.0
"""Real official-SDK A2A transport acceptance for the worker client."""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest


REQUIRED = os.environ.get("FORMALSPECGEN_REQUIRE_A2A_ACCEPTANCE") == "1"
pytestmark = pytest.mark.skipif(
    not REQUIRED, reason="real A2A acceptance runs only in its provisioned CI job")
try:
    import httpx
    import uvicorn
    import anyio
    from starlette.applications import Starlette
    from a2a.server.agent_execution.agent_executor import AgentExecutor
    from a2a.server.agent_execution.context import RequestContext
    from a2a.server.events.event_queue import EventQueue
    from a2a.server.request_handlers import DefaultRequestHandler
    from a2a.server.routes import (
        create_agent_card_routes,
        create_jsonrpc_routes,
    )
    from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
    from a2a.server.tasks.task_updater import TaskUpdater
    from a2a.types import (
        AgentCapabilities,
        AgentCard,
        AgentInterface,
        AgentSkill,
        Part,
        Task,
        TaskState,
        TaskStatus,
    )
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
except ImportError as exc:  # pragma: no cover - depends on optional environment
    if REQUIRED:
        raise RuntimeError("mandatory A2A acceptance dependencies are missing") from exc
    pytest.skip("A2A SDK is not installed", allow_module_level=True)

from pipeline.a2a_coordination import (
    OfficialA2AWorkerClient,
    WorkItem,
    WorkerProfile,
    agent_card_sha256,
    current_git_revision,
)
import mcp_server


REVISION = "a" * 40


class FixtureWorker(AgentExecutor):
    async def execute(self, context: RequestContext, queue: EventQueue) -> None:
        item = json.loads(context.get_user_input())
        assert context.task_id and context.context_id and context.message
        await queue.enqueue_event(Task(
            id=context.task_id,
            context_id=context.context_id,
            status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
            history=[context.message],
        ))
        updater = TaskUpdater(
            event_queue=queue,
            task_id=context.task_id,
            context_id=context.context_id,
        )
        await updater.start_work()
        result = {
            "schema": "formalspecgen-worker-result-v1",
            "work_item_id": item["work_item_id"],
            "base_revision": item["base_revision"],
            "patch_sha256": "b" * 64,
            "changed_files": ["pipeline/worker.py"],
            "artifacts": [{
                "artifact_id": "patch",
                "uri": f"a2a://{context.task_id}/patch",
                "sha256": "c" * 64,
            }],
        }
        await updater.add_artifact(
            parts=[Part(text=json.dumps(result, sort_keys=True))],
            name="formalspecgen-work-result",
            last_chunk=True,
        )
        await updater.complete()

    async def cancel(self, context: RequestContext, queue: EventQueue) -> None:
        updater = TaskUpdater(
            event_queue=queue,
            task_id=context.task_id or "",
            context_id=context.context_id or "",
        )
        await updater.cancel()


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _card(port: int) -> AgentCard:
    return AgentCard(
        name="FormalSpecGen fixture worker",
        description="Returns a digest-bound candidate patch reference.",
        version="1.0.0",
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[AgentSkill(
            id="formalspecgen-work-item",
            name="FormalSpecGen work item",
            description="Produces unaccepted implementation proposals.",
            tags=["implementation", "proposal"],
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        )],
        supported_interfaces=[AgentInterface(
            protocol_binding="JSONRPC",
            protocol_version="1.0",
            url=f"http://127.0.0.1:{port}/a2a/jsonrpc",
        )],
    )


@contextmanager
def _server():
    port = _free_port()
    card = _card(port)
    handler = DefaultRequestHandler(
        agent_executor=FixtureWorker(),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    app = Starlette(routes=(
        create_agent_card_routes(agent_card=card)
        + create_jsonrpc_routes(
            request_handler=handler, rpc_url="/a2a/jsonrpc")
    ))
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(
                    endpoint + "/.well-known/agent-card.json",
                    timeout=0.2).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.02)
    else:
        server.should_exit = True
        thread.join(timeout=2)
        raise RuntimeError("A2A fixture server did not start")
    try:
        yield endpoint, card
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def _item() -> WorkItem:
    return WorkItem(
        work_item_id="transport-001",
        base_revision=REVISION,
        objective="Produce a candidate adapter patch",
        workflow="verify",
        variant={"language": "rust"},
        allowed_paths=("pipeline/**",),
        protected_paths=("pipeline/mcp_policy.py",),
        acceptance_plan_ref="transport-acceptance",
        authority_ref="fixture-grant",
        deliverables=("patch",),
        requested_effects=("workspace_read", "workspace_write_new"),
        resource_budget={"wall_seconds": 10},
    )


def test_official_a2a_sdk_round_trip_and_agent_card_pinning():
    with _server() as (endpoint, card):
        profile = WorkerProfile(
            worker_id="fixture", endpoint=endpoint,
            agent_card_sha256=agent_card_sha256(card),
            workflows=("verify",),
            effects=("workspace_read", "workspace_write_new"),
            allowed_paths=("pipeline/**",),
            max_budget={"wall_seconds": 20},
        )
        observation = OfficialA2AWorkerClient(
            timeout_seconds=5).submit(profile, _item())
        assert observation.state == "completed"
        assert observation.remote_task_id
        assert observation.result["patch_sha256"] == "b" * 64
        assert observation.result["work_item_id"] == "transport-001"

        changed_identity = WorkerProfile(
            **{**profile.as_dict(), "agent_card_sha256": "f" * 64})
        with pytest.raises(Exception, match="Agent Card digest changed"):
            OfficialA2AWorkerClient(timeout_seconds=5).submit(
                changed_identity, _item())


async def _mcp_round_trip(environment: dict[str, str], revision: str):
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(mcp_server.__file__).resolve())],
        cwd=str(Path.cwd()),
        env=environment,
    )
    with anyio.fail_after(30):
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                discovered = {tool.name for tool in tools.tools}
                submitted = await session.call_tool(
                    "submit_work_item",
                    arguments={
                        "work_item_id": "mcp-a2a-001",
                        "base_revision": revision,
                        "objective": "Produce a candidate adapter patch",
                        "workflow": "verify",
                        "variant": {"language": "rust", "backend": "prusti"},
                        "allowed_paths": ["pipeline/**"],
                        "protected_paths": ["pipeline/mcp_policy.py"],
                        "acceptance_plan_ref": "a2a-transport-v1",
                        "authority_ref": "fixture-grant",
                        "deliverables": ["patch", "changed-file-manifest"],
                        "requested_effects": [
                            "workspace_read", "workspace_write_new"],
                        "resource_budget": {"wall_seconds": 10},
                        "worker_id": "fixture",
                    },
                )
                artifacts = await session.call_tool(
                    "get_work_artifacts",
                    arguments={"work_item_id": "mcp-a2a-001"},
                )
    return discovered, submitted.structuredContent, artifacts.structuredContent


def test_real_mcp_bridge_submits_over_a2a_and_returns_unaccepted_artifacts(
        tmp_path):
    with _server() as (endpoint, card):
        policy = tmp_path / "policy.json"
        state = tmp_path / "state"
        policy.write_text(json.dumps({
            "schema": "formalspecgen-a2a-policy-v1",
            "authorities": [{
                "ref": "fixture-grant",
                "principal_id": "aiderdesk",
                "project_root": str(Path.cwd()),
                "workers": ["fixture"],
                "workflows": ["verify"],
                "effects": ["workspace_read", "workspace_write_new"],
                "allowed_paths": ["pipeline/**"],
                "max_budget": {"wall_seconds": 20},
            }],
            "workers": [{
                "worker_id": "fixture",
                "endpoint": endpoint,
                "agent_card_sha256": agent_card_sha256(card),
                "workflows": ["verify"],
                "effects": ["workspace_read", "workspace_write_new"],
                "allowed_paths": ["pipeline/**"],
                "max_budget": {"wall_seconds": 20},
            }],
        }), encoding="utf-8")
        environment = dict(os.environ)
        environment.update({
            "FORMALSPECGEN_A2A_POLICY": str(policy),
            "FORMALSPECGEN_A2A_STATE_ROOT": str(state),
            "FORMALSPECGEN_A2A_PRINCIPAL": "aiderdesk",
            "FORMALSPECGEN_MCP_STRICT_JAVA_ONLY": "1",
        })
        discovered, submitted, artifacts = anyio.run(
            _mcp_round_trip, environment, current_git_revision(Path.cwd()))

    assert {
        "submit_work_item", "get_work_item", "get_work_artifacts",
        "cancel_work_item",
    }.issubset(discovered)
    assert submitted["status"] == "COMPLETED"
    assert submitted["worker_completed"] is True
    assert submitted["implementation_accepted"] is False
    assert submitted["claim"] == "NO_PROOF"
    assert artifacts["patch_sha256"] == "b" * 64
    assert artifacts["acceptance"] == {"status": "pending", "claim": "NO_PROOF"}
