import asyncio
import json
import socket
import subprocess
import sys
import time

import pytest
websockets = pytest.importorskip("websockets", reason="install requirements-e2e.txt for protocol E2E")

from fixtures import COUNTER


pytestmark = pytest.mark.protocol


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


async def _exchange(uri: str) -> list[dict]:
    deadline = time.monotonic() + 20
    while True:
        try:
            connection = await websockets.connect(uri)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            await asyncio.sleep(0.1)
    async with connection:
        await connection.send(json.dumps({"action": "verify", "code": COUNTER, "mode": "esc"}))
        events = []
        while True:
            event = json.loads(await asyncio.wait_for(connection.recv(), timeout=60))
            events.append(event)
            if event["type"] in {"verified", "complete", "error"}:
                return events


def test_real_websocket_process_runs_real_openjml(openjml_tool):
    port = _port()
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        events = asyncio.run(_exchange(f"ws://127.0.0.1:{port}/ws/verify"))
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    assert events[0]["type"] == "progress"
    assert events[-1]["type"] == "verified", events
    assert events[-1]["status"] == "VERIFIED"
    assert events[-1]["failures"] == 0
