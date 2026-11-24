# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""GHIDRA_MCP_STALL_DUMP_S: a call stuck in Java dumps Python and Java stacks to the log."""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from tests.live.test_ghidra_live import GHIDRA, SAMPLE, pytestmark  # noqa: F401

SLEEP_MS = 6000
STALL_S = "2"


async def _scenario(work: Path, logs: Path) -> str:
    supervisor = Path(sys.executable).with_name("re-mcp-ghidra")
    env = {
        **os.environ,
        "GHIDRA_INSTALL_DIR": GHIDRA,
        "GHIDRA_MCP_STALL_DUMP_S": STALL_S,
        "RE_MCP_LOG_DIR": str(logs),
    }
    path = work / "sample"
    shutil.copy(SAMPLE, path)
    async with Client(StdioTransport(str(supervisor), [], env=env), timeout=300) as client:
        opened = await client.call_tool("open_database", {"file_path": str(path)})
        db = (opened.structured_content or {}).get("result", opened.structured_content)["database"]
        await client.call_tool("wait_for_analysis", {"database": db})
        code = f"from java.lang import Thread\nThread.sleep({SLEEP_MS})\nreturn 1"
        await client.call_tool(
            "execute", {"database": db, "code": code, "read_only": True, "timeout_s": 60}
        )
    return "\n".join(p.read_text(errors="replace") for p in logs.glob("*worker-sample*"))


def test_stuck_call_dumps_python_and_java_stacks(tmp_path: Path):
    logs = tmp_path / "logs"
    log = asyncio.run(_scenario(tmp_path, logs))
    assert "=== stall: one tool call has run" in log
    # Python side: the main thread inside the execute tool.
    assert "programmable.py" in log
    # Java side: the main thread's frames, past the 8 ThreadInfo.toString() keeps.
    assert "java.lang.Thread.sleep" in log
    assert '"main"' in log or '"Thread-' in log
