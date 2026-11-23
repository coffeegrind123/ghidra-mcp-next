# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Dataflow and C++ vtables on purpose-built binaries from ReVa's test fixtures.

tests/live/fixtures/reva/test_dataflow_x86_64 is built from test_dataflow.c:
transform(seed) { a = seed + 7; b = a * 3; c = b - a; return c; } and main
calls transform(11). test_cpp_x86_64 (test_cpp_program.cpp): Animal with Dog
and Cat overriding legs/speak, their tables adjacent in __const, and dispatch()
calling legs and speak through an Animal pointer. Mach-O x86_64, Apache-2.0,
from cyberkaida/reverse-engineering-assistant.
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
    # Backward from the transform call's own result, and from main's return 0.
    # Found by opcode, not by the surrounding P-code, which differs across
    # Ghidra versions (12.2 has no INT_ZEXT here).
    out["back_call"] = await rec.tool(
        "analyze_dataflow", address=call["address"], direction="backward"
    )
    ret = [i["address"] for i in mhigh["items"] if "RETURN" in i["op"]][-1]
    out["back_zero"] = await rec.tool("analyze_dataflow", address=ret, direction="backward")
    return out


async def _cpp(rec: Recorder) -> dict[str, Any]:
    out: dict[str, Any] = {}
    legs = (await rec.tool("get_function", address="__ZNK3Dog4legsEv"))["start"]
    out["dog_table"] = await rec.tool("analyze_vtable", address="Dog::vtable")
    out["animal_table"] = await rec.tool("analyze_vtable", address="Animal::vtable")
    out["cat_table"] = await rec.tool("analyze_vtable", address="Cat::vtable")
    out["containing"] = await rec.tool("find_vtables_containing", address=legs)
    out["callers"] = await rec.tool("find_vtable_callers", address=legs)
    out["callers_cat"] = await rec.tool(
        "find_vtable_callers", address="__ZNK3Cat5speakEv", vtable="Cat::vtable"
    )
    out["not_a_table"] = await rec.tool("analyze_vtable", address=legs)
    out["dispatch"] = (await rec.tool("get_function", address="__Z8dispatchPK6Animal"))["start"]
    return out


async def _scenario(work: Path) -> dict[str, Any]:
    supervisor = Path(sys.executable).with_name("re-mcp-ghidra")
    env = {**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA}
    async with Client(StdioTransport(str(supervisor), [], env=env), timeout=900) as client:
        rec = Recorder(client)
        binary = work / "test_dataflow_x86_64"
        shutil.copy(FIXTURES / binary.name, binary)
        await _open(rec, binary)
        out = {"dataflow": await _dataflow(rec)}
        cpp = work / "test_cpp_x86_64"
        shutil.copy(FIXTURES / cpp.name, cpp)
        await _open(rec, cpp)
        out["cpp"] = await _cpp(rec)
        return out


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
    (call,) = _stops(run["dataflow"]["back_call"])
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


def _slots(table: dict[str, Any]) -> dict[int, str | None]:
    assert not table["is_error"], table
    return {e["slot"]: e["function"] for e in table["entries"]}


def test_vtable_layout_itanium(run):
    dog = run["cpp"]["dog_table"]
    slots = _slots(dog)
    # Slots count from the address point; the header is -2 (offset_to_top), -1 (typeinfo).
    assert [e["kind"] for e in dog["entries"] if e["slot"] < 0] == ["offset", "rtti"]
    assert slots[2] == "Dog::legs" and slots[3] == "Dog::speak"
    assert max(slots) == 3 and dog["ended_by"] == "labelled_address"
    assert dog["class_name"] == "Dog"


def test_vtable_pure_virtual_slot_kept(run):
    animal = run["cpp"]["animal_table"]
    slots = _slots(animal)
    assert slots[3] == "Animal::speak"
    assert next(e for e in animal["entries"] if e["slot"] == 2)["kind"] == "import"


def test_adjacent_tables_not_merged(run):
    cat = run["cpp"]["cat_table"]
    slots = _slots(cat)
    assert slots[2] == "Cat::legs" and max(slots) == 3
    dog_point = run["cpp"]["dog_table"]["address"]
    assert cat["address"] != dog_point


def test_find_vtables_containing(run):
    hits = run["cpp"]["containing"]
    assert not hits["is_error"], hits
    assert [(h["class_name"], h["slot"], h["offset"]) for h in hits["items"]] == [("Dog", 2, 16)]
    assert hits["items"][0]["vtable"] == run["cpp"]["dog_table"]["address"]


def test_find_vtable_callers(run):
    calls = run["cpp"]["callers"]
    assert not calls["is_error"], calls
    assert calls["offsets"] == [16]
    in_dispatch = [c for c in calls["items"] if c["function"] == "dispatch"]
    assert len(in_dispatch) == 1
    assert in_dispatch[0]["confidence"] == "typed"
    speak = run["cpp"]["callers_cat"]
    assert speak["offsets"] == [24]
    assert [c["function"] for c in speak["items"]] == ["dispatch"]


def test_analyze_vtable_refuses_code(run):
    bad = run["cpp"]["not_a_table"]
    assert bad["is_error"] and bad["error_type"] == "NotFound"
