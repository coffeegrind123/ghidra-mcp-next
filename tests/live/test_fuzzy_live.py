# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Fuzzy matching between two real databases where one function was changed."""

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

# Finds, among exactly-matched target functions, one with an instruction whose
# last byte is its own 1-byte immediate, so flipping that byte changes a
# constant (and the exact hash) without changing any instruction's length.
FIND_PATCH_SITE = """
wanted = set(int(a, 16) for a in ADDRESSES)
for f in program.getFunctionManager().getFunctions(True):
    if f.getEntryPoint().getOffset() not in wanted:
        continue
    insns = list(program.getListing().getInstructions(f.getBody(), True))
    if len(insns) < 12:
        continue
    for i in insns:
        b = [x & 0xFF for x in i.getBytes()]
        for op in range(i.getNumOperands()):
            s = i.getScalar(op)
            if s is not None and len(b) >= 3 and 2 < s.getValue() < 0x70 and b[-1] == s.getValue():
                return {"function": hex(f.getEntryPoint().getOffset()),
                        "insn": hex(i.getAddress().getOffset()), "length": len(b),
                        "value": int(s.getValue())}
"""


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
        for name in ("old", "new"):
            path = work / name / "sample"
            path.parent.mkdir()
            shutil.copy(SAMPLE, path)
            db = (await call("open_database", file_path=str(path), run_auto_analysis=True))[
                "database"
            ]
            await call("wait_for_analysis", database=db)
            dbs.append(db)
        src, dst = dbs

        pairs = (
            await call(
                "match_functions",
                source_database=src,
                target_database=dst,
                source_names="all",
                limit=5000,
            )
        )["matches"]
        by_target = {int(p["target"]["address"], 16): p for p in pairs}
        code = FIND_PATCH_SITE.replace("ADDRESSES", repr([p["target"]["address"] for p in pairs]))
        # call() unwraps execute's {"result": ...} to the script's return value
        site = await call("execute", database=dst, read_only=True, code=code)
        assert site and not site.get("is_error"), site
        pair = by_target[int(site["function"], 16)]
        out["pair"] = pair
        insn = int(site["insn"], 16)
        last = insn + site["length"] - 1
        out["patch"] = await call(
            "batch",
            database=dst,
            label="change one constant",
            ops=[
                {
                    "tool": "patch_bytes",
                    "params": {"address": hex(last), "hex_bytes": f"{site['value'] ^ 1:02x}"},
                },
                {"tool": "disassemble_at", "params": {"address": hex(insn)}},
            ],
        )
        await call(
            "call",
            tool="rename_function",
            arguments={"address": pair["source"]["address"], "new_name": "fuzzy_target"},
            database=src,
        )

        out["exact"] = await call(
            "match_functions", source_database=src, target_database=dst, limit=5000
        )
        out["fuzzy"] = await call(
            "match_functions",
            source_database=src,
            target_database=dst,
            algorithm="fuzzy",
            limit=5000,
        )
        out["programs"] = await call(
            "diff_programs", source_database=src, target_database=dst, limit=5000
        )
        out["programs_bytes"] = await call(
            "diff_programs",
            source_database=src,
            target_database=dst,
            include_body_bytes=True,
            limit=5000,
        )
        out["propagated"] = await call(
            "propagate_documentation",
            source_database=src,
            target_database=dst,
            algorithm="fuzzy",
            fields=["name"],
        )
        out["renamed"] = await call(
            "call",
            tool="get_function",
            arguments={"address": pair["target"]["address"]},
            database=dst,
        )
        out["diff"] = await call(
            "diff_functions_across",
            database_a=src,
            address_a=pair["source"]["address"],
            database_b=dst,
            address_b=pair["target"]["address"],
        )
        out["cdiff"] = await call(
            "diff_functions_across",
            database_a=src,
            address_a=pair["source"]["address"],
            database_b=dst,
            address_b=pair["target"]["address"],
            level="decompiled",
        )
    return out


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return asyncio.run(_scenario(tmp_path_factory.mktemp("fuzzy")))


def _targets(result: dict) -> dict[int, dict]:
    return {int(m["target"]["address"], 16): m for m in result["matches"]}


def test_changed_function_no_longer_matches_exactly(run):
    assert run["patch"]["applied"] is True, run["patch"]
    target = int(run["pair"]["target"]["address"], 16)
    assert target not in _targets(run["exact"])


def test_fuzzy_finds_it(run):
    target = int(run["pair"]["target"]["address"], 16)
    match = _targets(run["fuzzy"]).get(target)
    assert match is not None, run["fuzzy"]["fuzzy"]
    assert match["method"] == "fuzzy"
    assert match["source"]["name"] == "fuzzy_target"
    assert match["score"] >= 0.75


def test_fuzzy_propagation_and_cross_database_diff(run):
    assert run["propagated"]["fuzzy"] >= 1
    assert run["renamed"]["name"] == "fuzzy_target"
    assert 0.8 < run["diff"]["similarity"] < 1.0
    assert any(op["kind"] == "replace" for op in run["diff"]["ops"])
    # The patched immediate (SHR RSI,0x3f -> 0x3e in one /bin/true) feeds dead
    # code the decompiler drops, so the C may legitimately be unchanged: this
    # checks the cross-database decompiled path, not a change.
    c = run["cdiff"]
    assert not c.get("is_error"), c
    assert c["level"] == "decompiled" and c["a_instructions"] > 0
    assert 0.0 < c["similarity"] <= 1.0


def test_diff_programs_finds_the_patched_function(run):
    target = int(run["pair"]["target"]["address"], 16)
    for key, kinds in (("programs", {"code"}), ("programs_bytes", {"code", "bytes"})):
        result = run[key]
        assert not result.get("is_error"), result
        assert result["analysis_warning"] is None
        assert result["matched"]["identical"] > 0
        by_target = {int(c["target"]["address"], 16): c for c in result["changes"]}
        assert target in by_target, result["changes"]
        assert kinds <= set(by_target[target]["change_types"])
        # Both databases come from the same file: only the patched function differs.
        assert result["matched"]["changed"] == 1, result["changes"]
