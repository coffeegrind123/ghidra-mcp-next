# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""match_functions / propagate_documentation between two real databases."""

from __future__ import annotations

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

from tests.live.test_ghidra_live import GHIDRA, SAMPLE, pytestmark  # noqa: F401

STRUCT = "typedef struct prop_ctx { int fd; char name[16]; } prop_ctx_t;"


async def _scenario(work: Path) -> dict[str, Any]:
    supervisor = Path(sys.executable).with_name("re-mcp-ghidra")
    env = {**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA}
    out: dict[str, Any] = {}
    async with Client(StdioTransport(str(supervisor), [], env=env), timeout=900) as client:

        async def call(name: str, /, **args: Any) -> dict[str, Any]:
            result = await client.call_tool(name, args, raise_on_error=False)
            text = result.content[0].text if result.content else ""
            if result.is_error:
                return {"is_error": True, **json.loads(text)}
            data = result.structured_content or {}
            return data.get("result", data) if isinstance(data, dict) else data

        dbs = []
        for name in ("one", "two"):
            path = work / name / "sample"
            path.parent.mkdir()
            shutil.copy(SAMPLE, path)
            db = (await call("open_database", file_path=str(path), run_auto_analysis=True))[
                "database"
            ]
            await call("wait_for_analysis", database=db)
            dbs.append(db)
        src, dst = dbs

        # Pick a function both copies hash uniquely, with at least two instructions.
        pairs = (
            await call(
                "match_functions",
                source_database=src,
                target_database=dst,
                source_names="all",
                target_names="all",
                limit=5000,
            )
        )["matches"]
        pair = next(p for p in pairs if p["target"]["is_default_name"])
        addr = pair["source"]["address"]
        insns = await call(
            "call",
            tool="decode_instructions",
            arguments={"address": addr, "count": 2},
            database=src,
        )
        second = insns["instructions"][1]["address"]
        out["pair"] = pair

        documented = await call(
            "batch",
            database=src,
            label="document",
            ops=[
                {"tool": "parse_c_source", "params": {"source": STRUCT}},
                {"tool": "rename_function", "params": {"address": addr, "new_name": "prop_open"}},
                {
                    "tool": "set_function_prototype",
                    "params": {"address": addr, "type_string": "int prop_open(prop_ctx_t *ctx)"},
                },
                {
                    "tool": "set_comment",
                    "params": {"address": addr, "comment": "Opens it.", "comment_type": "plate"},
                },
                {
                    "tool": "set_comment",
                    "params": {"address": second, "comment": "second insn", "comment_type": "eol"},
                },
                {"tool": "rename_symbol", "params": {"address": second, "new_name": "prop_step"}},
            ],
        )
        assert documented.get("applied"), documented

        out["dry"] = await call(
            "propagate_documentation", source_database=src, target_database=dst, dry_run=True
        )
        out["after_dry"] = await call(
            "call", tool="get_function", arguments={"address": addr}, database=dst
        )
        out["real"] = await call(
            "propagate_documentation", source_database=src, target_database=dst
        )
        tgt = pair["target"]["address"]
        out["fn"] = await call(
            "call", tool="get_function", arguments={"address": tgt}, database=dst
        )
        out["proto"] = await call(
            "call", tool="get_function_prototype", arguments={"address": tgt}, database=dst
        )
        out["comments_plate"] = await call(
            "call", tool="get_comment", arguments={"address": tgt}, database=dst
        )
        out["comments_second"] = await call(
            "call", tool="get_comment", arguments={"address": second}, database=dst
        )
        out["struct"] = await call(
            "call", tool="get_data_type", arguments={"name": "prop_ctx_t"}, database=dst
        )
        out["undo"] = await call("undo", database=dst)
        out["after_undo"] = await call(
            "call", tool="get_function", arguments={"address": tgt}, database=dst
        )
    return out


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return asyncio.run(_scenario(tmp_path_factory.mktemp("matching")))


def test_dry_run_changes_nothing(run):
    assert run["dry"]["dry_run"] is True
    assert run["dry"]["applied"].get("name") == 1
    assert run["after_dry"]["name"] != "prop_open"


def test_propagates_name_prototype_and_comments(run):
    real = run["real"]
    assert real["matched"] >= 1
    assert real["undo_name"].startswith("MCP: propagate from ")
    assert run["fn"]["name"] == "prop_open"
    assert "prop_ctx_t" in run["proto"]["signature"]
    assert run["comments_plate"]["plate_comment"] == "Opens it."
    assert run["comments_second"]["eol_comment"] == "second insn"
    assert "/prop_ctx_t" in real["types_added"] or any(
        p.endswith("prop_ctx_t") for p in real["types_added"]
    )
    assert run["struct"].get("is_error") is not True


def test_one_undo_step_removes_it_all(run):
    assert run["undo"]["step"].startswith("MCP: propagate from ")
    assert run["after_undo"]["name"] != "prop_open"
