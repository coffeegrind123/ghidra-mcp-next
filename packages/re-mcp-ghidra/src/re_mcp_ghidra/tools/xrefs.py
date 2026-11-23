# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Cross-reference analysis tools."""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    format_location,
    paginate_iter,
    resolve_address,
)
from re_mcp_ghidra.session import session


class XrefTo(BaseModel):
    from_address: str = Field(description="Source address (hex).")
    from_function: str = Field(description="Containing function name, if any.")
    ref_type: str = Field(description="Reference type.")
    is_call: bool = Field(description="True if this is a call reference.")
    via_thunk: str = Field(
        default="", description="The thunk this reference reaches the target through, if any."
    )


class XrefFrom(BaseModel):
    to_address: str = Field(description="Target address (hex).")
    to_function: str = Field(description="Target function name, if any.")
    ref_type: str = Field(description="Reference type.")
    is_call: bool = Field(description="True if this is a call reference.")


class CallGraphEntry(BaseModel):
    name: str
    address: str
    callers: list[dict] = Field(default_factory=list)
    callees: list[dict] = Field(default_factory=list)
    node_count: int = Field(default=0, description="Functions in the tree (root only).")
    truncated: bool = Field(default=False, description="max_nodes stopped the expansion.")


def _key(func) -> str:
    """Identity of a function across address spaces (EXTERNAL vs RAM)."""
    return str(func.getEntryPoint())


def _order(func) -> tuple[bool, int]:
    entry = func.getEntryPoint()
    return (entry.isExternalAddress(), entry.getOffset())


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def get_xrefs_to(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List incoming references: every place that calls, jumps to or accesses an address.

        Answers "who uses this?"; use get_xrefs_from for what the code at an address
        refers to. For a function reached through thunks (an import called via its
        PLT/IAT stub), references to every thunk are included, with via_thunk set to
        the thunk's address. Returns a page dict (items, total, offset, limit,
        has_more); each item has from_address, from_function, ref_type, is_call and
        via_thunk.
        """
        program = session.program
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()
        target = resolve_address(address)

        # Imports are reached through thunks; Ghidra stores the calls on the thunk.
        targets = [(target, "")]
        func_at = func_mgr.getFunctionAt(target)
        if func_at is not None:
            thunks = func_at.getFunctionThunkAddresses(True) or []
            targets += [(t, format_location(t)) for t in thunks]

        def _gen():
            for where, via in targets:
                for ref in ref_mgr.getReferencesTo(where):
                    from_addr = ref.getFromAddress()
                    func = func_mgr.getFunctionContaining(from_addr)
                    ref_type = ref.getReferenceType()
                    yield XrefTo(
                        from_address=format_location(from_addr),
                        from_function=func.getName() if func else "",
                        ref_type=str(ref_type),
                        is_call=ref_type.isCall(),
                        via_thunk=via,
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def get_xrefs_from(
        address: Address,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List outgoing references: what the instruction or data at an address refers to.

        Answers "what does this use?"; use get_xrefs_to for incoming references. Returns
        a page dict (items, total, offset, limit, has_more); each item has to_address,
        to_function, ref_type and is_call.
        """
        program = session.program
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()
        source = resolve_address(address)

        def _gen():
            refs = ref_mgr.getReferencesFrom(source)
            for ref in refs:
                to_addr = ref.getToAddress()
                func = func_mgr.getFunctionContaining(to_addr)
                ref_type = ref.getReferenceType()
                yield XrefFrom(
                    to_address=format_address(to_addr.getOffset()),
                    to_function=func.getName() if func else "",
                    ref_type=str(ref_type),
                    is_call=ref_type.isCall(),
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def get_call_graph(
        address: Address,
        depth: Annotated[
            int,
            Field(ge=1, le=10, description="Levels to expand in each direction (1-10). Example: 2"),
        ] = 1,
        direction: Annotated[
            Literal["both", "callers", "callees"],
            Field(description='Which way to expand. Example: "callers"'),
        ] = "both",
        max_nodes: Annotated[
            int,
            Field(ge=1, le=5000, description="Most functions per direction. Example: 250"),
        ] = 250,
    ) -> CallGraphEntry:
        """Build the caller/callee tree around the function containing an address.

        Function-level view; use get_xrefs_to / get_xrefs_from for individual
        references, analyze_call_graph for whole-program questions. Calls through
        thunks (import stubs) count as calls to the real function. A function
        met again in the same direction appears once more with cyclic true and is
        not expanded; truncated marks where max_nodes stopped expansion. Returns
        {name, address, callers, callees, node_count, truncated}; nodes nest
        callers/callees to depth.
        """
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        from re_mcp_ghidra.helpers import resolve_function  # noqa: PLC0415
        from re_mcp_ghidra.tools.program_analysis import _resolve_thunk  # noqa: PLC0415

        root = _resolve_thunk(resolve_function(address))
        thunks_of: dict[str, list] = {}
        for f in session.program.getFunctionManager().getFunctions(True):
            if f.isThunk():
                target = f.getThunkedFunction(True)
                if target is not None:
                    thunks_of.setdefault(_key(target), []).append(f)

        def callers_of(func):
            seen = {}
            for f in [func, *thunks_of.get(_key(func), [])]:
                for raw in f.getCallingFunctions(TaskMonitor.DUMMY):
                    c = _resolve_thunk(raw)
                    seen.setdefault(_key(c), c)
            return sorted(seen.values(), key=_order)

        def callees_of(func):
            seen = {}
            for raw in func.getCalledFunctions(TaskMonitor.DUMMY):
                c = _resolve_thunk(raw)
                seen.setdefault(_key(c), c)
            return sorted(seen.values(), key=_order)

        def expand(func, level: int, step, visited: set, state: dict) -> list[dict]:
            out = []
            for nxt in step(func):
                key = _key(nxt)
                node = {"name": str(nxt.getName()), "address": format_location(nxt.getEntryPoint())}
                if key in visited:
                    node["cyclic"] = True
                    out.append(node)
                    continue
                if state["nodes"] >= max_nodes:
                    state["truncated"] = True
                    break
                state["nodes"] += 1
                visited.add(key)
                if level < depth:
                    child = expand(nxt, level + 1, step, visited, state)
                    node["callers" if step is callers_of else "callees"] = child
                out.append(node)
            return out

        up = {"nodes": 0, "truncated": False}
        down = {"nodes": 0, "truncated": False}
        callers = expand(root, 1, callers_of, {_key(root)}, up) if direction != "callees" else []
        callees = expand(root, 1, callees_of, {_key(root)}, down) if direction != "callers" else []
        return CallGraphEntry(
            name=str(root.getName()),
            address=format_location(root.getEntryPoint()),
            callers=callers,
            callees=callees,
            node_count=1 + up["nodes"] + down["nodes"],
            truncated=up["truncated"] or down["truncated"],
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def find_common_callers(
        addresses: Annotated[
            list[str],
            Field(
                min_length=2,
                description='Functions (addresses or names). Example: ["send_packet", "log_error"]',
            ),
        ],
        depth: Annotated[
            int,
            Field(
                ge=1,
                le=10,
                description="1: direct callers; more: callers at most this many calls up. Example: 2",
            ),
        ] = 1,
    ) -> dict:
        """Find functions that call all of the given functions (directly or within depth).

        Use to find the dispatcher or routine tying several functions together.
        Calls through thunks count. Returns {items: [{address, name}], total}.
        """
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        from re_mcp_ghidra.helpers import resolve_function  # noqa: PLC0415
        from re_mcp_ghidra.tools.program_analysis import _resolve_thunk  # noqa: PLC0415

        # Reverse edges keyed by full address string, so calls to external
        # functions (through their import thunks) count and EXTERNAL offsets
        # never collide with RAM offsets in base-0 objects.
        funcs: dict[str, object] = {}
        reverse: dict[str, set[str]] = {}
        for func in session.program.getFunctionManager().getFunctions(True):
            if func.isThunk():
                continue
            key = _key(func)
            funcs[key] = func
            for called in func.getCalledFunctions(TaskMonitor.DUMMY):
                reverse.setdefault(_key(_resolve_thunk(called)), set()).add(key)

        def up(key: str) -> set[str]:
            found, frontier = set(), {key}
            for _ in range(depth):
                frontier = {c for k in frontier for c in reverse.get(k, ())} - found
                found |= frontier
            return found

        sets = [up(_key(_resolve_thunk(resolve_function(a)))) for a in addresses]
        common = sorted((funcs[k] for k in set.intersection(*sets)), key=_order)
        items = [
            {"address": format_location(f.getEntryPoint()), "name": str(f.getName())}
            for f in common
        ]
        return {"items": items, "total": len(items)}
