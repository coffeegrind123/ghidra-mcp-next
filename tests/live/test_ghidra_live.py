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
SCRIPTS = Path(__file__).with_name("scripts")

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
    env = {**os.environ, "GHIDRA_INSTALL_DIR": GHIDRA, "GHIDRA_MCP_SCRIPT_DIRS": str(SCRIPTS)}
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

        out["scripts"] = await rec.tool("list_ghidra_scripts", filter_pattern="Test")
        out["java"] = await rec.tool(
            "run_ghidra_script", script="RenameFirst.java", args=[first["start"], "via_java"]
        )
        out["java_fail"] = await rec.tool(
            "run_ghidra_script", script="RenameFirst.java", args=[first["start"], "x", "fail"]
        )
        out["after_java"] = await rec.tool("get_function", address=first["start"])
        out["python_script"] = await rec.tool("run_ghidra_script", script="count_funcs.py")
        out["python_fail"] = await rec.tool(
            "run_ghidra_script",
            script="rename_then_fail.py",
            args=[first["start"], "should_not_stick"],
        )
        out["after_python_fail"] = await rec.tool("get_function", address=first["start"])

        out["scores"] = await rec.tool("score_documentation", include_locals=True, limit=5)
        out["rerun"] = await rec.tool("run_auto_analysis")
        out["c_source"] = await rec.tool("parse_c_source", source=MULTI_DECL_HEADER)
        out["c_source_types"] = {
            name: await rec.tool("get_data_type", name=name)
            for name in ("hdr_a_t", "hdr_b_t", "hdr_id_t")
        }
        imports = await rec.tool("list_imports", limit=50)
        out["import"] = imports["items"][0]
        out["import_refs_by_address"] = await rec.tool(
            "get_xrefs_to", address=out["import"]["address"]
        )
        out["import_refs_by_name"] = await rec.tool("get_xrefs_to", address=out["import"]["name"])
        out["analysis"] = await _analysis_cases(rec, first, second)
        out["extras"] = await _extras_cases(rec, first, second)
        out["markup"] = await _markup_cases(rec, db, second)
        out["types"] = await _type_cases(rec, db, exclude={first["start"], second["start"]})
        out["low"] = await _low_level_cases(rec, db, exclude={first["start"], second["start"]})
        out["regvalue"] = await _register_value_cases(
            rec, db, exclude={first["start"], second["start"]}
        )

        out["save"] = await rec("save_database", database=db, comment="live test")
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


# Three declarations in one header: every one must land in the program.
MULTI_DECL_HEADER = """
typedef struct hdr_a { int x; int y; } hdr_a_t;
typedef struct hdr_b { hdr_a_t a; char tag[8]; } hdr_b_t;
typedef unsigned int hdr_id_t;
"""


# find_register_value cases, as x86-64 machine code patched over function entries:
# (bytes, offset of the queried instruction, register, expected value or None)
REGISTER_CASES = {
    # mov eax, 7 ; nop: asking for the 64-bit register
    "constant": ("b80700000090", 5, "RAX", "0x7"),
    # same code, asking for the 32-bit register the instruction names
    "subregister": ("b80700000090", 5, "EAX", "0x7"),
    # mov eax, 5 ; mov eax, ebx ; nop: 5 was overwritten
    "overwritten": ("b80500000089d890", 7, "RAX", None),
    # mov eax, 5 ; mov eax, [rbx+0x10] ; nop: 0x10 is a displacement, not a value
    "displacement": ("b8050000008b431090", 8, "RAX", None),
}


async def _register_value_cases(rec: Recorder, db: str, exclude: set[str]) -> dict[str, Any]:
    picked = await rec(
        "execute",
        database=db,
        read_only=True,
        code=(
            "out = []\n"
            "for f in program.getFunctionManager().getFunctions(True):\n"
            "    if f.isThunk() or f.isExternal() or f.getBody().getNumAddresses() < 32:\n"
            "        continue\n"
            "    out.append('0x' + str(f.getEntryPoint()).lstrip('0'))\n"
            "return out[2:]"
        ),
    )
    targets = [a for a in picked["result"] if a.lower() not in {e.lower() for e in exclude}]
    results: dict[str, Any] = {}
    for (name, (hexbytes, query_offset, register, _)), entry in zip(
        REGISTER_CASES.items(), targets, strict=False
    ):
        base = int(entry, 16)
        ops: list[dict[str, Any]] = [
            {"tool": "patch_bytes", "params": {"address": entry, "hex_bytes": hexbytes}}
        ]
        offset = 0
        for size in _instruction_sizes(hexbytes):
            ops.append({"tool": "disassemble_at", "params": {"address": hex(base + offset)}})
            offset += size
        patched = await rec("batch", database=db, label=f"regcase {name}", ops=ops)
        assert not patched["is_error"], patched
        results[name] = await rec.tool(
            "find_register_value", address=hex(base + query_offset), register_name=register
        )
    return results


async def _analysis_cases(rec: Recorder, first: dict, second: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    out["metrics"] = await rec.tool("get_function_metrics", sort_by="cyclomatic", limit=20)
    out["metrics_one"] = await rec.tool("get_function_metrics", address=first["start"])
    out["summary"] = await rec.tool("analyze_call_graph", mode="summary")
    out["roots"] = await rec.tool("analyze_call_graph", mode="roots", limit=50)
    out["scc"] = await rec.tool("analyze_call_graph", mode="scc")
    out["edges"] = await rec.tool("analyze_call_graph", mode="edges", limit=5)
    caller, callee = out["edges"]["edge_list"][0]
    out["edge_pair"] = (caller, callee)
    out["path"] = await rec.tool(
        "analyze_call_graph", mode="path", from_address=caller, to_address=callee
    )
    out["gaps"] = await rec.tool("find_code_gaps", min_size=1)
    big = out["metrics"]["items"][0]["address"]
    out["big"] = big
    out["pcode_low"] = await rec.tool("get_function_pcode", address=big, level="low", limit=10)
    out["pcode_high"] = await rec.tool("get_function_pcode", address=big, level="high", limit=10)
    out["dataflow"] = await rec.tool(
        "analyze_dataflow",
        address=out["pcode_high"]["items"][-1]["address"],
        direction="backward",
    )
    out["dsearch"] = await rec.tool("search_decompiled", pattern=r"return", max_hits=5)
    out["dsearch_next"] = await rec.tool(
        "search_decompiled", pattern=r"return", max_hits=5, cursor=out["dsearch"]["next_cursor"]
    )
    out["diff_same"] = await rec.tool("diff_functions", address_a=big, address_b=big)
    out["diff_other"] = await rec.tool("diff_functions", address_a=big, address_b=second["start"])
    return out


async def _extras_cases(rec: Recorder, first: dict, second: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    out["lines"] = await rec.tool(
        "decompile_function", address=second["start"], line_numbers=True, limit=3
    )
    out["whole"] = await rec.tool("decompile_function", address=second["start"])
    out["context"] = await rec.tool("get_context_registers", address=second["start"])
    reg = out["context"]["registers"][0]["register"]
    out["context_conflict"] = await rec.tool(
        "set_context_register", start=second["start"], register=reg, value=1
    )
    insn = await rec.tool("decode_instruction", address=second["start"])
    out["context_batch"] = await rec(
        "batch",
        database=rec.database,
        dry_run=True,
        ops=[
            {
                "tool": "clear_code_units",
                "params": {"address": second["start"], "size": insn["size"]},
            },
            {
                "tool": "set_context_register",
                "params": {"start": second["start"], "register": reg, "value": 1},
            },
        ],
    )
    out["context_bad"] = await rec.tool(
        "set_context_register", start=second["start"], register="NoSuchReg", value=1
    )
    out["relocs"] = await rec.tool("list_relocations", limit=500)
    out["const"] = await rec.tool("find_constant_uses", value="0x1", limit=5)
    await rec.tool(
        "set_comment", address=second["start"], comment="NOTE-xyzzy here", comment_type="pre"
    )
    out["comments"] = await rec.tool("search_comments", pattern="xyzzy")
    out["candidates"] = await rec.tool("find_function_candidates")
    out["thunk"] = await rec.tool(
        "set_function_thunk", address=second["start"], target=first["start"]
    )
    out["thunk_self"] = await rec.tool(
        "set_function_thunk", address=second["start"], target=second["start"]
    )
    out["unthunk"] = await rec.tool("set_function_thunk", address=second["start"])
    return out


async def _markup_cases(rec: Recorder, db: str, second: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    found = await rec(
        "execute",
        database=db,
        read_only=True,
        code=(
            "for i in program.getListing().getInstructions(True):\n"
            "    for op in range(i.getNumOperands()):\n"
            "        s = i.getScalar(op)\n"
            "        if s is not None and 2 < s.getValue() < 0x10000 and not i.getOperandReferences(op):\n"
            "            return {'address': '0x' + str(i.getAddress()).lstrip('0'), 'op': op,"
            " 'value': int(s.getValue())}"
        ),
    )
    site = found["result"]
    out["site"] = site
    out["equate"] = await rec.tool(
        "set_equate", address=site["address"], operand=site["op"], name="MY_CONST"
    )
    out["equates"] = await rec.tool("list_equates", filter_pattern="MY_CONST")
    out["unequate"] = await rec.tool("remove_equate", address=site["address"], operand=site["op"])
    out["equates_after"] = await rec.tool("list_equates", filter_pattern="MY_CONST")

    target = second["start"]
    await rec.tool("tag_function", address=target, add=["CRYPTO", "TODO"])
    out["tags"] = await rec.tool("tag_function", address=target, remove=["TODO"])
    out["tag_list"] = await rec.tool("list_function_tags")
    out["method"] = await rec.tool("set_function_class", address=target, class_name="net::Conn")
    out["members"] = await rec.tool("list_class_members", class_name="net::Conn")
    out["ns_label"] = await rec.tool(
        "create_label", address=target, name="in_class", namespace="net::Conn"
    )

    raw = await rec.tool("read_bytes", address=target, size=4)
    hexed = raw["hex_data"].replace(" ", "")
    out["pattern_target"] = target
    out["wild"] = await rec.tool("search_bytes", pattern=hexed[:6] + "??", start_address=target)
    out["nibble"] = await rec.tool(
        "search_bytes", pattern=hexed[:6] + hexed[6] + "?", start_address=target
    )
    return out


async def _type_cases(rec: Recorder, db: str, exclude: set[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    out["category"] = await rec.tool("create_data_type_category", path="/net/hdr")
    out["moved"] = await rec.tool("move_data_type", type_path="/hdr_a", category="/net/hdr")
    out["renamed"] = await rec.tool(
        "rename_data_type", type_path="/net/hdr/hdr_a", new_name="hdr_alpha"
    )
    out["cloned"] = await rec.tool(
        "clone_data_type", type_path="/net/hdr/hdr_alpha", new_name="hdr_alpha_copy"
    )
    out["clone_again"] = await rec.tool(
        "clone_data_type", type_path="/net/hdr/hdr_alpha", new_name="hdr_alpha_copy"
    )
    out["merged"] = await rec.tool(
        "consolidate_data_types", keep="/net/hdr/hdr_alpha", replace=["/net/hdr/hdr_alpha_copy"]
    )
    out["copy_gone"] = await rec.tool("get_data_type", name="hdr_alpha_copy")
    out["categories"] = await rec.tool("list_data_type_categories")
    found = await rec(
        "execute",
        database=db,
        read_only=True,
        code=(
            f"exclude = set({sorted(e.lower() for e in exclude)!r})\n"
            "for f in program.getFunctionManager().getFunctions(True):\n"
            "    entry = '0x' + str(f.getEntryPoint()).lstrip('0')\n"
            "    if f.getName().startswith('FUN_') and entry.lower() not in exclude:\n"
            "        return entry"
        ),
    )
    target = found["result"]
    await rec.tool(
        "set_function_prototype",
        address=target,
        type_string="int f(hdr_alpha *p)",
    )
    out["uses"] = await rec.tool("find_data_type_uses", type_path="/net/hdr/hdr_alpha")
    out["uses_target"] = target
    return out


async def _low_level_cases(rec: Recorder, db: str, exclude: set[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    out["analyzers"] = await rec.tool("list_analyzers")
    pick = next(
        a
        for a in out["analyzers"]["items"]
        if a["one_time_supported"] and any(o["type"] == "BOOLEAN_TYPE" for o in a["options"])
    )
    option = next(o for o in pick["options"] if o["type"] == "BOOLEAN_TYPE")
    out["analyzer_pick"] = pick
    out["option_pick"] = option
    out["configured"] = await rec.tool(
        "configure_analyzer",
        name=pick["name"],
        enabled="off" if pick["enabled"] else "on",
        options={option["name"]: not option["value"]},
    )
    out["one_time"] = await rec.tool("run_auto_analysis", analyzers=[pick["name"]])

    found = await rec(
        "execute",
        database=db,
        read_only=True,
        code=(
            f"exclude = set({sorted(e.lower() for e in exclude)!r})\n"
            "call = target = None\n"
            "for f in program.getFunctionManager().getFunctions(True):\n"
            "    entry = '0x' + str(f.getEntryPoint()).lstrip('0')\n"
            "    if f.isThunk() or f.isExternal() or entry.lower() in exclude:\n"
            "        continue\n"
            "    for i in program.getListing().getInstructions(f.getBody(), True):\n"
            "        if call is None and i.getFlowType().isCall():\n"
            "            call = '0x' + str(i.getAddress()).lstrip('0')\n"
            "    if target is None and f.getName().startswith('FUN_'):\n"
            "        target = entry\n"
            "    if call and target:\n"
            "        break\n"
            "return {'call': call, 'target': target}"
        ),
    )
    call, target = found["result"]["call"], found["result"]["target"]
    out["flow_set"] = await rec.tool("set_flow_override", address=call, override="CALL_RETURN")
    out["flow_cleared"] = await rec.tool("set_flow_override", address=call, override="NONE")
    out["repair"] = await rec(
        "batch",
        database=db,
        ops=[{"tool": "clear_flow_and_repair", "params": {"address": call}}],
    )
    out["storage"] = await rec(
        "batch",
        database=db,
        ops=[
            {
                "tool": "set_function_prototype",
                "params": {"address": target, "type_string": "int f(int a, int b)"},
            },
            {
                "tool": "set_variable_storage",
                "params": {"function_address": target, "variable_name": "a", "storage": "ECX"},
            },
        ],
    )
    out["label"] = await rec.tool("create_label", address=call, name="extra_name")
    out["label_again"] = await rec.tool("create_label", address=call, name="extra_name")
    out["unlabel"] = await rec.tool("delete_label", address=call, name="extra_name")
    out["unlabel_again"] = await rec.tool("delete_label", address=call, name="extra_name")
    out["undo_direct"] = await rec.tool("undo")
    return out


def _instruction_sizes(hexbytes: str) -> list[int]:
    sizes = {"b8": 5, "89": 2, "8b": 3, "90": 1}
    out, i = [], 0
    while i < len(hexbytes):
        size = sizes[hexbytes[i : i + 2]]
        out.append(size)
        i += size * 2
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


def test_scripts_listed_from_extra_dirs(run):
    names = [i["name"] for i in run["scripts"]["items"]]
    assert {"RenameFirst.java", "count_funcs.py"} <= set(names)


def test_java_script_runs_as_one_step(run):
    assert run["java"]["applied"] is True
    assert run["java"]["undo_name"] == "MCP: script RenameFirst.java"
    assert run["java"]["stdout"].startswith("renamed ")


def test_failing_script_rolls_back(run):
    assert run["java_fail"]["error_type"] == "ScriptError"
    assert run["after_java"]["name"] == "via_java"


def test_failing_python_script_rolls_back(run):
    assert run["python_fail"].get("error_type") == "ScriptError", run["python_fail"]
    assert run["after_python_fail"]["name"] != "should_not_stick"


def test_python_script_runs(run):
    assert run["python_script"]["stdout"].startswith("functions: ")


def test_documentation_scores_worst_first(run):
    items = run["scores"]["items"]
    assert items, run["scores"]
    assert [i["score"] for i in items] == sorted(i["score"] for i in items)
    assert all(0 <= i["score"] <= 100 for i in items)
    assert "name" in items[0]["missing"]


def test_auto_analysis_reruns(run):
    assert run["rerun"]["functions_after"] >= run["rerun"]["functions_before"] > 0


@pytest.mark.parametrize("name", ["hdr_a_t", "hdr_b_t", "hdr_id_t"])
def test_parse_c_source_keeps_every_declaration(run, name):
    assert run["c_source"]["is_error"] is False, run["c_source"]
    assert name in run["c_source"]["types"], run["c_source"]
    got = run["c_source_types"][name]
    assert got["is_error"] is False, got


@pytest.mark.parametrize("case", sorted(REGISTER_CASES))
def test_find_register_value(run, case):
    expected = REGISTER_CASES[case][3]
    got = run["regvalue"][case]
    if expected is None:
        assert got["found"] is False, got
    else:
        assert got["found"] is True, got
        assert got["value"].lower() == expected
        assert got["source_address"], got


def test_import_addresses_keep_their_space(run):
    # list_imports hands out addresses get_xrefs_to must accept; imports live in
    # Ghidra's EXTERNAL space, not the default one.
    for key in ("import_refs_by_address", "import_refs_by_name"):
        refs = run[key]
        assert refs["is_error"] is False, (key, refs)
        assert refs["total"] >= 1, (key, run["import"], refs)


def test_analysis_tools(run):
    a = run["analysis"]
    for key, value in a.items():
        if isinstance(value, dict):
            assert value.get("is_error") is not True, (key, value)
    scores = [m["cyclomatic"] for m in a["metrics"]["items"]]
    assert scores == sorted(scores, reverse=True)
    # The sample is whatever /bin/true the machine has: from ~15 to a few hundred functions.
    assert a["metrics"]["total"] >= 10
    assert a["metrics_one"]["items"][0]["instructions"] > 0
    assert a["summary"]["functions"] >= 10 and a["summary"]["edges"] > 0
    assert a["roots"]["nodes"]
    caller, callee = a["edge_pair"]
    assert [n["address"].lower() for n in a["path"]["nodes"]] == [caller.lower(), callee.lower()]
    assert a["pcode_low"]["total"] > 0 and a["pcode_high"]["total"] > 0
    assert a["dataflow"]["steps"] or a["dataflow"]["stops"]
    assert a["diff_same"]["similarity"] == 1.0
    first_page, second_page = a["dsearch"], a["dsearch_next"]
    assert len(first_page["items"]) >= 5 and first_page["next_cursor"]
    assert second_page["items"]
    seen = {(h["address"], h["line"]) for h in first_page["items"]}
    assert not seen & {(h["address"], h["line"]) for h in second_page["items"]}
    assert a["diff_other"]["similarity"] < 1.0


def test_decompile_lines_and_listing_extras(run):
    x = run["extras"]
    for key, value in x.items():
        if isinstance(value, dict) and key not in ("context_bad", "thunk_self", "context_conflict"):
            assert value.get("is_error") is not True, (key, value)
    lines = x["lines"]
    assert [ln["line"] for ln in lines["lines"]] == [1, 2, 3]
    assert lines["total_lines"] == x["whole"]["total_lines"] > 3
    assert any(ln["address"] for ln in lines["lines"]) or lines["total_lines"] > 3
    assert x["context"]["registers"]
    assert x["context_conflict"]["error_type"] in ("ContextConflict", None)
    assert x["context_batch"]["results"][1]["verified"] is True
    assert x["context_bad"]["error_type"] == "InvalidArgument"
    assert x["relocs"]["total"] > 0
    assert x["const"]["total"] > 0 and x["const"]["items"][0]["value"] == 1
    assert [c["text"] for c in x["comments"]["items"]] == ["NOTE-xyzzy here"]
    assert "items" in x["candidates"]
    assert x["thunk"]["target"] and x["thunk_self"]["error_type"] == "InvalidArgument"
    assert x["unthunk"]["target"] == ""


def test_equates_tags_classes_and_wildcards(run):
    m = run["markup"]
    for key, value in m.items():
        if isinstance(value, dict):
            assert value.get("is_error") is not True, (key, value)
    assert m["equate"]["value"] == m["site"]["value"]
    assert [e["name"] for e in m["equates"]["items"]] == ["MY_CONST"]
    assert m["equates_after"]["items"] == []
    assert m["tags"]["tags"] == ["CRYPTO"]
    assert {"name": "CRYPTO", "comment": "", "functions": 1} in m["tag_list"]["items"]
    assert m["pattern_target"].lower() in [x["address"].lower() for x in m["members"]["members"]]
    assert m["ns_label"]["namespace"] == "net::Conn"
    target = int(m["pattern_target"], 16)
    assert int(m["wild"]["result"][0]["address"], 16) == target
    assert int(m["nibble"]["result"][0]["address"], 16) == target


def test_type_categories_rename_clone_merge(run):
    t = run["types"]
    for key in ("category", "moved", "renamed", "cloned", "merged", "categories", "uses"):
        assert t[key]["is_error"] is False, (key, t[key])
    assert t["moved"]["path"] == "/net/hdr/hdr_a"
    assert t["renamed"]["path"] == "/net/hdr/hdr_alpha"
    assert t["cloned"]["path"] == "/net/hdr/hdr_alpha_copy"
    assert t["clone_again"]["error_type"] == "AlreadyExists"
    assert [r["path"] for r in t["merged"]["replaced"]] == ["/net/hdr/hdr_alpha_copy"]
    assert t["copy_gone"]["is_error"] is True
    assert "/net/hdr" in [c["path"] for c in t["categories"]["items"]]


def test_find_data_type_uses(run):
    uses = run["types"]["uses"]
    assert uses["timed_out"] is False
    assert run["types"]["uses_target"].lower() in [
        u["function_address"].lower() for u in uses["items"]
    ], uses


def test_list_and_configure_analyzers(run):
    low = run["low"]
    assert low["analyzers"]["total"] > 10
    pick, option = low["analyzer_pick"], low["option_pick"]
    configured = low["configured"]
    assert configured["is_error"] is False, configured
    assert configured["enabled"] is (not pick["enabled"])
    changed = next(o for o in configured["options"] if o["name"] == option["name"])
    assert changed["value"] is (not option["value"])


def test_run_selected_analyzer(run):
    one = run["low"]["one_time"]
    assert one["is_error"] is False, one
    assert one["analyzers"] == [run["low"]["analyzer_pick"]["name"]]


def test_flow_override_set_and_cleared(run):
    low = run["low"]
    assert low["flow_cleared"]["is_error"] is False, low["flow_cleared"]
    assert low["flow_set"]["current"] == "CALL_RETURN"
    assert low["flow_cleared"]["previous"] == "CALL_RETURN"
    assert low["flow_cleared"]["current"] == "NONE"
    assert low["repair"]["applied"] is True, low["repair"]


def test_set_variable_storage(run):
    batch = run["low"]["storage"]
    assert batch["applied"] is True, batch
    result = batch["results"][1]
    assert "ECX" in result["storage"]
    assert result["custom_storage_enabled"] is True


def test_labels_add_and_delete(run):
    low = run["low"]
    assert low["label_again"]["is_error"] is False, low["label_again"]
    assert low["unlabel"]["is_error"] is False, low["unlabel"]
    assert low["label"]["name"] == "extra_name"
    assert low["label_again"]["name"] == "extra_name"
    assert low["unlabel"]["name"] == "extra_name"
    assert low["unlabel_again"]["error_type"] == "NotFound"


def test_direct_write_is_its_own_undo_step(run):
    # A write tool called outside batch/execute gets its own transaction.
    assert run["low"]["undo_direct"]["step"] == "MCP: delete_label"


def test_save_reopen_from_project(run):
    assert run["save"]["is_error"] is False
    assert run["project_files"]["files"] == ["/sample"]
    assert run["persisted"]["name"] == f"handler_{run['second']['start']}"
