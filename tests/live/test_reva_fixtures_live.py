# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Dataflow on a purpose-built binary from ReVa's test fixtures.

tests/live/fixtures/reva/test_dataflow_x86_64 is built from test_dataflow.c:
transform(seed) { a = seed + 7; b = a * 3; c = b - a; return c; } and main
calls transform(11). Mach-O x86_64, Apache-2.0, from
cyberkaida/reverse-engineering-assistant.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from tests.live.test_ghidra_live import GHIDRA, Recorder, pytestmark  # noqa: F401

FIXTURES = Path(__file__).with_name("fixtures") / "reva"


async def _open(rec: Recorder, path: Path) -> str:
    opened = await rec("open_database", file_path=str(path), run_auto_analysis=True)
    rec.database = opened["database"]
    await rec("wait_for_analysis", database=rec.database)
    return rec.database


async def _dataflow(rec: Recorder) -> dict[str, Any]:
    out: dict[str, Any] = {}
    transform = (await rec.tool("get_function", address="_transform"))["start"]
    main = (await rec.tool("get_function", address="_main"))["start"]
    out["transform"] = transform
    high = await rec.tool("get_function_pcode", address=transform, level="high", limit=200)
    out["pcode"] = high["items"]
    ret = next(i["address"] for i in high["items"] if "RETURN" in i["op"])
    out["back_ret"] = await rec.tool(
        "analyze_dataflow", address=ret, direction="backward", max_steps=100
    )
    params = await rec.tool("list_decompiler_variables", function_address=transform)
    out["vars"] = params["variables"]
    seed = next(v["name"] for v in params["variables"] if v["is_param"])
    out["seed"] = seed
    out["accesses"] = await rec.tool("find_variable_accesses", address=transform, variable=seed)
    out["accesses_missing"] = await rec.tool(
        "find_variable_accesses", address=transform, variable=seed + "x"
    )
    first_read = out["accesses"]["accesses"][0]["address"]
    out["fwd_seed"] = await rec.tool(
        "analyze_dataflow", address=first_read, variable=seed, direction="forward", max_steps=100
    )
    # main: the result of transform(11) flows into printf's second argument.
    mhigh = await rec.tool("get_function_pcode", address=main, level="high", limit=200)
    out["main_pcode"] = mhigh["items"]
    call = next(i for i in mhigh["items"] if "CALL" in i["op"] and transform[2:] in i["op"])
    out["fwd_call"] = await rec.tool(
        "analyze_dataflow", address=call["address"], direction="forward", max_steps=100
    )
    zext = next(i["address"] for i in mhigh["items"] if "INT_ZEXT" in i["op"])
    out["back_zext"] = await rec.tool("analyze_dataflow", address=zext, direction="backward")
    zero = next(i["address"] for i in mhigh["items"] if "COPY (const, 0x0," in i["op"])
    out["back_zero"] = await rec.tool("analyze_dataflow", address=zero, direction="backward")
    return out


async def _scenario(work: Path) -> dict[str, Any]:
    supervisor = Path(sys.executable).with_name("re-mcp-ghidra")
    env = {**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA}
    async with Client(StdioTransport(str(supervisor), [], env=env), timeout=900) as client:
        rec = Recorder(client)
        binary = work / "test_dataflow_x86_64"
        shutil.copy(FIXTURES / binary.name, binary)
        await _open(rec, binary)
        return {"dataflow": await _dataflow(rec)}


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return asyncio.run(_scenario(tmp_path_factory.mktemp("reva")))


def _stops(result: dict[str, Any]) -> list[dict[str, Any]]:
    assert not result["is_error"], result
    return [{k: v for k, v in stop.items() if v is not None} for stop in result["stops"]]


def test_backward_reaches_parameter_not_operands(run):
    # Ghidra folds the body to (seed + 7) * 2: 7 and 2 are operands, not origins.
    assert _stops(run["dataflow"]["back_ret"]) == [
        {"kind": "parameter", "name": run["dataflow"]["seed"], "slot": 0}
    ]


def test_forward_from_parameter_reaches_return(run):
    stops = _stops(run["dataflow"]["fwd_seed"])
    assert [s["kind"] for s in stops] == ["return"]


def test_forward_stops_at_call_argument(run):
    (stop,) = _stops(run["dataflow"]["fwd_call"])
    assert stop["kind"] == "call_arg"
    assert stop["slot"] == 1
    assert stop["target"].lstrip("_") == "printf"


def test_backward_stops_at_call_result_and_constant(run):
    (call,) = _stops(run["dataflow"]["back_zext"])
    assert call["kind"] == "call_result"
    assert call["target"].lstrip("_") == "transform"
    assert _stops(run["dataflow"]["back_zero"]) == [{"kind": "constant", "value": "0x0"}]


def test_find_variable_accesses(run):
    d = run["dataflow"]
    acc = d["accesses"]
    assert not acc["is_error"], acc
    assert acc["is_parameter"] and acc["data_type"] == "int"
    kinds = [a["kind"] for a in acc["accesses"]]
    assert kinds.count("read") >= 1 and "write" not in kinds
    missing = d["accesses_missing"]
    assert missing["is_error"] and missing["error_type"] == "NotFound"
    assert d["seed"] in missing["error"]
