# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""End-to-end tests against a real Ghidra, through the real supervisor.

Skipped unless GHIDRA_INSTALL_DIR points at a Ghidra installation.  One MCP
session runs every scenario once (Ghidra start-up and auto-analysis cost tens
of seconds), records what came back, and the tests below assert on it.

    GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.3_PUBLIC uv run pytest tests/live -m live
"""

from __future__ import annotations

import ast
import asyncio
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

GHIDRA = os.environ.get("GHIDRA_INSTALL_DIR", "")
SAMPLE = shutil.which("true") or "/bin/true"

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not GHIDRA or not os.path.isdir(GHIDRA), reason="GHIDRA_INSTALL_DIR not set"
    ),
]


class Recorder:
    """Calls tools and keeps each outcome as plain data."""

    def __init__(self, client: Any, database: str = "") -> None:
        self.client = client
        self.database = database

    async def __call__(self, name: str, /, **args: Any) -> dict[str, Any]:
        result = await self.client.call_tool(name, args, raise_on_error=False)
        text = result.content[0].text if result.content else ""
        if result.is_error:
            try:
                body = json.loads(text)
            except ValueError:
                body = {"error": text}
            return {"is_error": True, **body}
        data = result.structured_content or {}
        if isinstance(data, dict) and set(data) - {"database"} == {"result"}:
            data = data["result"]
        return {"is_error": False, **data} if isinstance(data, dict) else {"value": data}

    async def tool(self, name: str, /, **params: Any) -> dict[str, Any]:
        """Call any tool (pinned or hidden) on the open database."""
        return await self("call", tool=name, arguments=params, database=self.database)


async def _scenario(binary: Path) -> dict[str, Any]:
    supervisor = Path(sys.executable).with_name("re-mcp-ghidra")
    env = {**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA}
    out: dict[str, Any] = {}

    async with Client(StdioTransport(str(supervisor), [], env=env), timeout=900) as client:
        rec = Recorder(client)
        out["listed"] = [t.name for t in await client.list_tools()]
        out["search"] = await rec("search_tools", pattern=".*")
        out["api"] = (await client.read_resource("ghidra://api/tools.pyi"))[0].text

        opened = await rec("open_database", file_path=str(binary), run_auto_analysis=True)
        db = opened["database"]
        rec.database = db
        out["ready"] = await rec("wait_for_analysis", database=db)

        funcs = await rec.tool("list_functions", limit=2)
        first, second = funcs["items"][0], funcs["items"][1]
        out["first"], out["second"] = first, second

        out["rollback"] = await rec(
            "batch",
            database=db,
            ops=[
                {
                    "tool": "rename_function",
                    "params": {"address": first["start"], "new_name": "a1"},
                },
                {
                    "tool": "rename_function",
                    "params": {"address": "0xdeadbeefdead", "new_name": "b"},
                },
            ],
        )
        out["after_rollback"] = await rec.tool("get_function", address=first["start"])

        out["refs"] = await rec(
            "batch",
            database=db,
            label="name second",
            ops=[
                {"tool": "get_function", "params": {"address": second["start"]}},
                {
                    "tool": "rename_function",
                    "params": {"address": "$0.start", "new_name": "handler_${0.start}"},
                },
            ],
        )
        rev = out["refs"]["revision"]
        out["stale"] = await rec(
            "batch",
            database=db,
            if_revision=rev - 1,
            ops=[{"tool": "get_function", "params": {"address": "$$x"}}],
        )

        op = {"tool": "set_comment", "params": {"address": first["start"], "comment": "c"}}
        out["once"] = await rec("batch", database=db, ops=[op], operation_id="k1")
        out["twice"] = await rec("batch", database=db, ops=[op], operation_id="k1")

        out["dry"] = await rec(
            "batch",
            database=db,
            dry_run=True,
            ops=[
                {"tool": "rename_function", "params": {"address": first["start"], "new_name": "d"}}
            ],
        )
        out["after_dry"] = await rec.tool("get_function", address=first["start"])

        out["exec_write"] = await rec(
            "execute",
            database=db,
            label="exec write",
            code=(
                "n = program.getFunctionManager().getFunctionCount()\n"
                "print('count', n)\n"
                f"tools.set_comment(address={first['start']!r}, comment='from execute')\n"
                "n"
            ),
        )
        out["exec_ro"] = await rec(
            "execute",
            database=db,
            read_only=True,
            code=f"tools.rename_function(address={first['start']!r}, new_name='ro')\nreturn 1",
        )
        out["after_ro"] = await rec.tool("get_function", address=first["start"])
        out["exec_timeout"] = await rec(
            "execute", database=db, code="while True:\n    pass", timeout_s=2
        )
        out["exec_error"] = await rec(
            "execute",
            database=db,
            code=f"tools.rename_function(address={first['start']!r}, new_name='e')\n1/0",
        )
        out["after_error"] = await rec.tool("get_function", address=first["start"])
        out["undo"] = await rec.tool("undo")
        out["blocked"] = await rec("batch", database=db, ops=[{"tool": "undo", "params": {}}])
        out["call_internal"] = await rec("call", tool="_batch", arguments={}, database=db)

        out["save"] = await rec("save_database", database=db)
        await rec("close_database", database=db)

        gpr = binary.parent / "ghidra_projects" / f"{binary.name}.gpr"
        out["project_files"] = await rec("list_project_files", project=str(gpr))
        reopened = await rec(
            "open_database", file_path=str(gpr), program=out["project_files"]["files"][0]
        )
        rec.database = reopened["database"]
        await rec("wait_for_analysis", database=rec.database)
        out["persisted"] = await rec.tool("get_function", address=second["start"])
    return out


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    work = tmp_path_factory.mktemp("live")
    binary = work / "sample"
    shutil.copy(SAMPLE, binary)
    return asyncio.run(_scenario(binary))


def test_internal_tools_never_listed(run):
    assert not [n for n in run["listed"] if n.startswith("_")]
    assert "_batch" not in json.dumps(run["search"])


def test_listed_catalog_stays_small(run):
    assert len(run["listed"]) <= 25


def test_api_resource_is_a_valid_stub(run):
    ast.parse(run["api"])
    assert "def rename_function(" in run["api"]
    assert "def _batch" not in run["api"]


def test_analysis_runs_in_a_transaction(run):
    # GhidraProject.analyze without a held transaction finds a fraction of the code.
    assert run["ready"]["function_count"] > 50


def test_failed_batch_changes_nothing(run):
    assert run["rollback"]["is_error"]
    assert run["rollback"]["op_index"] == 1
    assert run["after_rollback"]["name"] == run["first"]["name"]


def test_references_and_undo_step(run):
    refs = run["refs"]
    assert refs["applied"] is True
    assert refs["undo_name"] == "MCP: name second"
    assert refs["results"][1]["new_name"] == f"handler_{run['second']['start']}"


def test_stale_revision_refused(run):
    assert run["stale"]["error_type"] == "TargetChanged"
    assert run["stale"]["revision"] == run["refs"]["revision"]


def test_operation_id_replays(run):
    assert run["twice"]["replayed"] is True
    assert run["twice"]["revision"] == run["once"]["revision"]


def test_dry_run_rolls_back(run):
    assert run["dry"]["applied"] is False
    assert run["after_dry"]["name"] == run["first"]["name"]


def test_execute_returns_and_commits(run):
    ex = run["exec_write"]
    assert ex["result"] == run["ready"]["function_count"]
    assert ex["stdout"].startswith("count ")
    assert ex["undo_name"] == "MCP: exec write"


def test_read_only_execute_cannot_write(run):
    assert run["exec_ro"]["applied"] is False
    assert run["after_ro"]["name"] == run["first"]["name"]


def test_execute_timeout_and_error_roll_back(run):
    assert run["exec_timeout"]["error_type"] == "TimeoutError"
    assert run["exec_error"]["error_type"] == "ScriptError"
    assert run["exec_error"]["line"] == 2
    assert run["after_error"]["name"] == run["first"]["name"]


def test_undo_names_the_step(run):
    assert run["undo"]["step"] == "MCP: exec write"


def test_lifecycle_tools_refused_in_batch(run):
    assert run["blocked"]["error_type"] == "InvalidOp"
    assert run["call_internal"]["is_error"]


def test_save_reopen_from_project(run):
    assert run["save"]["is_error"] is False
    assert run["project_files"]["files"] == ["/sample"]
    assert run["persisted"]["name"] == f"handler_{run['second']['start']}"
