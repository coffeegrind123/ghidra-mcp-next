# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Whole-program and per-function analysis: metrics, call graph, code gaps, P-code,
dataflow, and instruction diffs."""

from __future__ import annotations

import difflib
from collections import deque
from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.cdiff import code_lines, diff_c
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    compile_filter,
    format_address,
    format_location,
    resolve_address,
    resolve_function,
)
from re_mcp_ghidra.session import session

DECOMPILE_TIMEOUT_S = 60
MAX_DIFF_OPS = 500


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FunctionMetrics(BaseModel):
    address: str = Field(description="Function entry point.")
    name: str = Field(description="Function name.")
    instructions: int = Field(description="Instruction count.")
    bytes: int = Field(description="Body size in bytes.")
    blocks: int = Field(description="Basic blocks.")
    edges: int = Field(description="Control-flow edges between its blocks.")
    cyclomatic: int = Field(description="Cyclomatic complexity, edges - blocks + 2.")
    loops: int = Field(description="Loops (back edges to a dominating block).")
    calls: int = Field(description="Distinct functions it calls.")
    callers: int = Field(description="Distinct functions that call it.")
    strings: int = Field(description="Defined strings it references.")


class MetricsList(BaseModel):
    items: list[FunctionMetrics] = Field(description="One page, sorted by sort_by.")
    total: int = Field(description="Functions matching the filter.")
    offset: int = Field(description="Offset used.")
    limit: int = Field(description="Limit used.")
    has_more: bool = Field(description="More results past this page.")


class GraphNode(BaseModel):
    address: str = Field(description="Function entry point.")
    name: str = Field(description="Function name.")


class CallGraphResult(BaseModel):
    mode: str = Field(description="Mode run.")
    functions: int = Field(description="Functions in the graph.")
    edges: int = Field(description="Call edges in the graph.")
    nodes: list[GraphNode] = Field(
        description="roots/leaves: the functions; path: the shortest call path, in order."
    )
    groups: list[list[GraphNode]] = Field(
        description="scc: groups of mutually recursive functions (size > 1, or self-calling)."
    )
    edge_list: list[list[str]] = Field(description="edges: [caller, callee] address pairs.")
    max_in: GraphNode | None = Field(description="Most-called function (summary).")
    max_out: GraphNode | None = Field(description="Function calling the most others (summary).")
    has_more: bool = Field(description="The list was cut at limit.")


class CodeGap(BaseModel):
    start: str = Field(description="First address not in any function.")
    end: str = Field(description="Last address of the gap.")
    size: int = Field(description="Bytes.")
    instructions: int = Field(description="Instructions defined in it (orphaned code).")
    data_bytes: int = Field(description="Bytes covered by defined data (tables, strings).")
    undefined_bytes: int = Field(description="Bytes with nothing defined.")
    block: str = Field(description="Memory block.")
    before: str = Field(description="Function just before, if any.")
    after: str = Field(description="Function just after, if any.")


class CodeGapList(BaseModel):
    items: list[CodeGap] = Field(description="One page, address order.")
    total: int = Field(description="Gaps at least min_size bytes.")
    offset: int = Field(description="Offset used.")
    limit: int = Field(description="Limit used.")
    has_more: bool = Field(description="More results past this page.")


class PcodeOp(BaseModel):
    address: str = Field(description="Instruction address.")
    op: str = Field(description="P-code operation as text, e.g. '(register, 0x0, 8) INT_ADD ...'.")


class PcodeList(BaseModel):
    function: str = Field(description="Function entry point.")
    level: str = Field(description="low (raw, per instruction) or high (decompiler).")
    items: list[PcodeOp] = Field(description="One page of operations.")
    total: int = Field(description="Operations in the function.")
    offset: int = Field(description="Offset used.")
    limit: int = Field(description="Limit used.")
    has_more: bool = Field(description="More results past this page.")


class FlowStep(BaseModel):
    address: str = Field(description="Where the operation is.")
    op: str = Field(description="Decompiler P-code operation.")
    depth: int = Field(description="Steps from the starting value.")


class VariableAccess(BaseModel):
    address: str = Field(description="Instruction address.")
    kind: str = Field(description="read or write.")
    op: str = Field(description="Decompiler P-code operation.")


class VariableAccesses(BaseModel):
    function: str = Field(description="Function entry point.")
    variable: str = Field(description="Variable name as the decompiler shows it.")
    storage: str = Field(description="Where the variable lives (register, stack, address).")
    data_type: str = Field(description="Decompiler data type.")
    is_parameter: bool = Field(description="True for a parameter.")
    accesses: list[VariableAccess] = Field(description="Reads and writes, by address.")
    total: int = Field(description="Number of accesses.")


class FlowStop(BaseModel):
    kind: str = Field(
        description=(
            "backward: constant, parameter, input (register or stack value at entry that "
            "is not a parameter), global, load (value read through a pointer; the pointer "
            "is followed on), call_result, no_definition. forward: store, call_arg, "
            "call_target, return, global (written to a global)."
        )
    )
    address: str | None = Field(default=None, description="Operation where the branch ends.")
    name: str | None = Field(default=None, description="Parameter, global or register name.")
    slot: int | None = Field(default=None, description="Parameter or argument index (0-based).")
    target: str | None = Field(
        default=None, description='Called function name, its address, or "indirect".'
    )
    value: str | None = Field(default=None, description="Constant value (hex).")


class DataflowResult(BaseModel):
    function: str = Field(description="Function entry point.")
    start: str = Field(description="The value followed (varnode text).")
    direction: str = Field(description="backward (definitions) or forward (uses).")
    steps: list[FlowStep] = Field(description="Operations reached, breadth first.")
    stops: list[FlowStop] = Field(description="Where and why each branch ended.")
    truncated: bool = Field(description="Stopped at max_steps.")


class DiffOp(BaseModel):
    kind: str = Field(description="equal, replace, insert (only in b) or delete (only in a).")
    a: list[str] = Field(description="Instructions from function a.")
    b: list[str] = Field(description="Instructions from function b.")


class CHunk(BaseModel):
    kind: str = Field(description="code (a real change), var-renumber, string-label or artifact.")
    a_start: int = Field(description="First line in a (1-based).")
    b_start: int = Field(description="First line in b (1-based).")
    a: list[str] = Field(description="Lines from a.")
    b: list[str] = Field(description="Lines from b.")


class DiffResult(BaseModel):
    a: GraphNode = Field(description="Function a.")
    b: GraphNode = Field(description="Function b.")
    level: str = Field(default="instructions", description="instructions or decompiled.")
    similarity: float = Field(description="0-1, share of matching normalised lines.")
    a_instructions: int = Field(description="Instructions in a (C lines at level decompiled).")
    b_instructions: int = Field(description="Instructions in b (C lines at level decompiled).")
    ops: list[DiffOp] = Field(
        default_factory=list, description="Instruction diff; runs of equal lines are collapsed."
    )
    hunks: list[CHunk] = Field(default_factory=list, description="Decompiled-C diff hunks.")
    suppressed: dict[str, int] = Field(
        default_factory=dict, description="Artifact hunks left out, by kind."
    )
    truncated: bool = Field(description="ops or hunks was cut at 500 entries.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


DiffLevel = Annotated[
    Literal["instructions", "decompiled"],
    Field(
        description=(
            "instructions: normalised instruction lines; decompiled: C lines, "
            'decompiler artifacts separated. Example: "decompiled"'
        )
    ),
]
IncludeArtifacts = Annotated[
    bool,
    Field(
        description=(
            "decompiled only: also show hunks that differ only by renumbered "
            "variables or string labels. Example: false"
        )
    ),
]


def _c_lines(func) -> list[str]:
    from re_mcp_ghidra.tools.decompiled_search import _decompiled  # noqa: PLC0415

    text = _decompiled(func)
    if text is None:
        raise GhidraError(
            f"{func.getName()} did not decompile; level instructions still works.",
            error_type="DecompilationFailed",
        )
    return code_lines(text)


def _node(func) -> GraphNode:
    return GraphNode(
        address=format_address(func.getEntryPoint().getOffset()), name=str(func.getName())
    )


def _resolve_thunk(func):
    if func is not None and func.isThunk():
        target = func.getThunkedFunction(True)
        return target or func
    return func


def _blocks(func):
    from ghidra.program.model.block import BasicBlockModel  # noqa: PLC0415
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    model = BasicBlockModel(session.program)
    blocks = list(model.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY))
    index = {b.getFirstStartAddress().getOffset(): i for i, b in enumerate(blocks)}
    succ: list[list[int]] = [[] for _ in blocks]
    for i, block in enumerate(blocks):
        it = block.getDestinations(TaskMonitor.DUMMY)
        while it.hasNext():
            ref = it.next()
            target = ref.getDestinationAddress()
            if target is not None and func.getBody().contains(target):
                j = index.get(target.getOffset())
                if j is not None:
                    succ[i].append(j)
    entry = index.get(func.getEntryPoint().getOffset(), 0)
    return blocks, succ, entry


def _count_loops(succ: list[list[int]], entry: int) -> int:
    """Back edges u -> v where v dominates u (Cooper-Harvey-Kennedy dominators)."""
    n = len(succ)
    if n == 0:
        return 0
    order, seen, stack = [], {entry}, [(entry, iter(succ[entry]))]
    while stack:
        node, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            order.append(node)
            stack.pop()
        elif nxt not in seen:
            seen.add(nxt)
            stack.append((nxt, iter(succ[nxt])))
    rpo = list(reversed(order))
    pos = {v: i for i, v in enumerate(rpo)}
    preds: dict[int, list[int]] = {v: [] for v in rpo}
    for u in rpo:
        for v in succ[u]:
            if v in preds:
                preds[v].append(u)
    idom = {entry: entry}
    changed = True
    while changed:
        changed = False
        for v in rpo[1:]:
            done = [p for p in preds[v] if p in idom]
            if not done:
                continue
            new = done[0]
            for p in done[1:]:
                a, b = p, new
                while a != b:
                    while pos[a] > pos[b]:
                        a = idom[a]
                    while pos[b] > pos[a]:
                        b = idom[b]
                new = a
            if idom.get(v) != new:
                idom[v] = new
                changed = True

    def dominates(v: int, u: int) -> bool:
        while True:
            if u == v:
                return True
            if u == entry:
                return False
            u = idom[u]

    return sum(1 for u in rpo for v in succ[u] if v in idom and dominates(v, u))


def metrics(func) -> FunctionMetrics:
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    program = session.program
    listing = program.getListing()
    blocks, succ, entry = _blocks(func)
    edges = sum(len(s) for s in succ)
    strings = set()
    refs = program.getReferenceManager()
    for insn in listing.getInstructions(func.getBody(), True):
        for ref in refs.getReferencesFrom(insn.getAddress()):
            data = listing.getDefinedDataAt(ref.getToAddress())
            if data is not None and data.hasStringValue():
                strings.add(ref.getToAddress().getOffset())
    instructions = sum(1 for _ in listing.getInstructions(func.getBody(), True))
    return FunctionMetrics(
        address=format_address(func.getEntryPoint().getOffset()),
        name=str(func.getName()),
        instructions=instructions,
        bytes=int(func.getBody().getNumAddresses()),
        blocks=len(blocks),
        edges=edges,
        cyclomatic=max(1, edges - len(blocks) + 2),
        loops=_count_loops(succ, entry),
        calls=len(
            {f.getEntryPoint().getOffset() for f in func.getCalledFunctions(TaskMonitor.DUMMY)}
        ),
        callers=len(
            {f.getEntryPoint().getOffset() for f in func.getCallingFunctions(TaskMonitor.DUMMY)}
        ),
        strings=len(strings),
    )


def _call_graph():
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    funcs = {}
    adj: dict[int, set[int]] = {}
    for func in session.program.getFunctionManager().getFunctions(True):
        if func.isThunk():
            continue
        key = func.getEntryPoint().getOffset()
        funcs[key] = func
        adj[key] = set()
    for key, func in funcs.items():
        for called in func.getCalledFunctions(TaskMonitor.DUMMY):
            ck = _resolve_thunk(called).getEntryPoint().getOffset()
            if ck in funcs:
                adj[key].add(ck)
    return funcs, adj


def _tarjan(adj: dict[int, set[int]]) -> list[list[int]]:
    """Strongly connected components, iterative (no recursion limit)."""
    index: dict[int, int] = {}
    low: dict[int, int] = {}
    on_stack: set[int] = set()
    stack: list[int] = []
    out: list[list[int]] = []
    counter = 0
    for root, targets in adj.items():
        if root in index:
            continue
        work = [(root, iter(sorted(targets)))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            nxt = next(it, None)
            if nxt is not None:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(sorted(adj[nxt]))))
                elif nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                out.append(comp)
    return out


def _normalised(func) -> list[str]:
    """Instruction lines with intra-function targets as instruction indexes and
    calls as callee names, so the same code at another address compares equal."""
    program = session.program
    listing = program.getListing()
    insns = list(listing.getInstructions(func.getBody(), True))
    index = {i.getAddress().getOffset(): n for n, i in enumerate(insns)}
    fm = program.getFunctionManager()
    lines = []
    for insn in insns:
        ops = []
        for op in range(insn.getNumOperands()):
            refs = insn.getOperandReferences(op)
            target = refs[0].getToAddress() if refs else None
            if target is not None and target.getOffset() in index:
                ops.append(f"L{index[target.getOffset()]}")
            elif target is not None and fm.getFunctionAt(target) is not None:
                ops.append(str(_resolve_thunk(fm.getFunctionAt(target)).getName()))
            elif target is not None:
                ops.append("<ref>")
            else:
                ops.append(str(insn.getDefaultOperandRepresentation(op)))
        lines.append(f"{insn.getMnemonicString()} {','.join(ops)}".strip())
    return lines


def _high_function(func):
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    iface = session.decompiler()
    iface.openProgram(session.program)
    try:
        res = iface.decompileFunction(func, DECOMPILE_TIMEOUT_S, TaskMonitor.DUMMY)
        high = res.getHighFunction() if res is not None else None
        if high is None:
            raise GhidraError(
                f"Decompilation failed: {res.getErrorMessage() if res else 'no result'}",
                error_type="DecompilationFailed",
            )
        return high
    finally:
        iface.dispose()


def _page(items: list, offset: int, limit: int) -> tuple[list, bool]:
    return items[offset : offset + limit], offset + limit < len(items)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def get_function_metrics(
        address: Annotated[
            str,
            Field(
                description='One function; empty measures every function, paged. Example: "main"'
            ),
        ] = "",
        filter_pattern: FilterPattern = "",
        sort_by: Annotated[
            Literal[
                "address", "instructions", "cyclomatic", "loops", "calls", "callers", "strings"
            ],
            Field(description='Sort, largest first except address. Example: "cyclomatic"'),
        ] = "address",
        offset: Annotated[int, Field(ge=0, description="Pagination offset. Example: 0")] = 0,
        limit: Annotated[int, Field(ge=1, le=1000, description="Page size. Example: 50")] = 50,
    ) -> MetricsList:
        """Measure functions: size, blocks, complexity, loops, calls, callers, strings.

        Use to triage a binary (sort_by="cyclomatic" or "callers" to find the core
        logic) or to size one function before reading it. Loops are back edges to
        a dominating block, so rotated loops count and backward non-loop jumps do
        not. Thunks and externals are skipped. Returns {items: [{address, name,
        instructions, bytes, blocks, edges, cyclomatic, loops, calls, callers,
        strings}], total, offset, limit, has_more}.
        """
        if address:
            items = [metrics(resolve_function(address))]
            return MetricsList(items=items, total=1, offset=0, limit=limit, has_more=False)
        filt = compile_filter(filter_pattern)
        funcs = [
            f
            for f in session.program.getFunctionManager().getFunctions(True)
            if not f.isThunk() and not f.isExternal() and (not filt or filt.search(f.getName()))
        ]
        if sort_by == "address":
            page, more = _page(funcs, offset, limit)
            items = [metrics(f) for f in page]
        else:
            every = sorted((metrics(f) for f in funcs), key=lambda m: -getattr(m, sort_by))
            items, more = _page(every, offset, limit)
        return MetricsList(items=items, total=len(funcs), offset=offset, limit=limit, has_more=more)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def analyze_call_graph(
        mode: Annotated[
            Literal["summary", "path", "scc", "roots", "leaves", "edges"],
            Field(
                description=(
                    "summary: counts and the most-called function; path: shortest call "
                    "path from_address -> to_address; scc: mutually recursive groups; "
                    "roots: never called; leaves: call nothing; edges: every call edge. "
                    'Example: "path"'
                )
            ),
        ] = "summary",
        from_address: Annotated[
            str, Field(description='path: the calling end. Example: "main"')
        ] = "",
        to_address: Annotated[
            str, Field(description='path: the called end. Example: "0x401a20"')
        ] = "",
        limit: Annotated[
            int, Field(ge=1, le=20000, description="Most nodes, groups or edges. Example: 500")
        ] = 500,
    ) -> CallGraphResult:
        """Analyse the whole program's call graph.

        Use to find how execution reaches a function (path), recursion (scc),
        entry candidates (roots) or utility functions (leaves); get_call_graph
        gives the neighbourhood of one function instead. Calls through thunks
        count as calls to the real function. Returns {mode, functions, edges,
        nodes, groups, edge_list, max_in, max_out, has_more}.
        """
        funcs, adj = _call_graph()
        n_edges = sum(len(v) for v in adj.values())
        result = {
            "mode": mode,
            "functions": len(funcs),
            "edges": n_edges,
            "nodes": [],
            "groups": [],
            "edge_list": [],
            "max_in": None,
            "max_out": None,
            "has_more": False,
        }
        indeg: dict[int, int] = dict.fromkeys(adj, 0)
        for targets in adj.values():
            for t in targets:
                indeg[t] += 1
        if mode == "summary":
            if adj:
                result["max_in"] = _node(funcs[max(indeg, key=indeg.get)])
                result["max_out"] = _node(funcs[max(adj, key=lambda k: len(adj[k]))])
        elif mode in ("roots", "leaves"):
            keys = [k for k in adj if (indeg[k] == 0 if mode == "roots" else not adj[k])]
            page, result["has_more"] = _page(sorted(keys), 0, limit)
            result["nodes"] = [_node(funcs[k]) for k in page]
        elif mode == "path":
            if not from_address or not to_address:
                raise GhidraError(
                    "path needs from_address and to_address.", error_type="InvalidArgument"
                )
            src = _resolve_thunk(resolve_function(from_address)).getEntryPoint().getOffset()
            dst = _resolve_thunk(resolve_function(to_address)).getEntryPoint().getOffset()
            prev = {src: None}
            queue = deque([src])
            while queue and dst not in prev:
                cur = queue.popleft()
                for nxt in adj.get(cur, ()):
                    if nxt not in prev:
                        prev[nxt] = cur
                        queue.append(nxt)
            if dst in prev:
                path, cur = [], dst
                while cur is not None:
                    path.append(cur)
                    cur = prev[cur]
                result["nodes"] = [_node(funcs[k]) for k in reversed(path)]
        elif mode == "scc":
            groups = [c for c in _tarjan(adj) if len(c) > 1 or (len(c) == 1 and c[0] in adj[c[0]])]
            page, result["has_more"] = _page(sorted(groups, key=len, reverse=True), 0, limit)
            result["groups"] = [[_node(funcs[k]) for k in sorted(c)] for c in page]
        else:
            pairs = sorted((a, b) for a, targets in adj.items() for b in targets)
            page, result["has_more"] = _page(pairs, 0, limit)
            result["edge_list"] = [[format_address(a), format_address(b)] for a, b in page]
        return CallGraphResult(**result)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def find_code_gaps(
        min_size: Annotated[
            int, Field(ge=1, description="Ignore gaps smaller than this many bytes. Example: 16")
        ] = 16,
        only_with_instructions: Annotated[
            bool,
            Field(description="Only gaps that contain orphaned instructions. Example: true"),
        ] = False,
        offset: Annotated[int, Field(ge=0, description="Pagination offset. Example: 0")] = 0,
        limit: Annotated[int, Field(ge=1, le=2000, description="Page size. Example: 100")] = 100,
    ) -> CodeGapList:
        """Find executable bytes that belong to no function (missed code).

        Use to discover code analysis did not turn into functions: a gap with
        instructions is orphaned code (create_function on it); undefined bytes
        may be code never disassembled (disassemble_at); data bytes are usually
        jump tables or strings. Returns {items: [{start, end, size, instructions,
        data_bytes, undefined_bytes, block, before, after}], total, offset,
        limit, has_more}.
        """
        from ghidra.program.model.address import AddressSet  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        fm = program.getFunctionManager()
        exec_set = AddressSet()
        for block in program.getMemory().getBlocks():
            if block.isExecute() and block.isInitialized() and not block.isExternalBlock():
                exec_set.add(block.getStart(), block.getEnd())
        for func in fm.getFunctions(True):
            exec_set.delete(func.getBody())

        gaps = []
        for rng in exec_set.getAddressRanges():
            size = int(rng.getLength())
            if size < min_size:
                continue
            rset = AddressSet(rng)
            insns = sum(1 for _ in listing.getInstructions(rset, True))
            if only_with_instructions and insns == 0:
                continue
            data = sum(int(d.getLength()) for d in listing.getDefinedData(rset, True))
            code_bytes = sum(int(i.getLength()) for i in listing.getInstructions(rset, True))
            before = next(iter(fm.getFunctions(rng.getMinAddress(), False)), None)
            after = next(iter(fm.getFunctions(rng.getMaxAddress(), True)), None)
            gaps.append(
                CodeGap(
                    start=format_address(rng.getMinAddress().getOffset()),
                    end=format_address(rng.getMaxAddress().getOffset()),
                    size=size,
                    instructions=insns,
                    data_bytes=data,
                    undefined_bytes=max(0, size - data - code_bytes),
                    block=str(program.getMemory().getBlock(rng.getMinAddress()).getName()),
                    before=str(before.getName()) if before else "",
                    after=str(after.getName()) if after else "",
                )
            )
        page, more = _page(gaps, offset, limit)
        return CodeGapList(items=page, total=len(gaps), offset=offset, limit=limit, has_more=more)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"decompiler"})
    @session.require_open
    def get_function_pcode(
        address: Address,
        level: Annotated[
            Literal["low", "high"],
            Field(
                description=(
                    "low: raw P-code per instruction (exact semantics); high: the "
                    'decompiler\'s simplified P-code with SSA variables. Example: "high"'
                )
            ),
        ] = "high",
        offset: Annotated[int, Field(ge=0, description="Pagination offset. Example: 0")] = 0,
        limit: Annotated[int, Field(ge=1, le=5000, description="Page size. Example: 300")] = 300,
    ) -> PcodeList:
        """Get a function's P-code, Ghidra's intermediate representation.

        Use when the decompiled C hides what an instruction does, or to script
        precise dataflow questions. high needs a successful decompile. Returns
        {function, level, items: [{address, op}], total, offset, limit,
        has_more}.
        """
        func = resolve_function(address)
        ops: list[PcodeOp] = []
        if level == "low":
            for insn in session.program.getListing().getInstructions(func.getBody(), True):
                where = format_address(insn.getAddress().getOffset())
                ops.extend(PcodeOp(address=where, op=str(op)) for op in insn.getPcode())
        else:
            it = _high_function(func).getPcodeOps()
            while it.hasNext():
                op = it.next()
                ops.append(
                    PcodeOp(
                        address=format_address(op.getSeqnum().getTarget().getOffset()), op=str(op)
                    )
                )
        page, more = _page(ops, offset, limit)
        return PcodeList(
            function=format_address(func.getEntryPoint().getOffset()),
            level=level,
            items=page,
            total=len(ops),
            offset=offset,
            limit=limit,
            has_more=more,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"decompiler"})
    @session.require_open
    def analyze_dataflow(
        address: Address,
        variable: Annotated[
            str,
            Field(
                description=(
                    "Register or decompiler variable used or set at address; empty takes "
                    "the value the instruction writes, else its first non-constant input. "
                    'Example: "RAX"'
                )
            ),
        ] = "",
        direction: Annotated[
            Literal["backward", "forward"],
            Field(
                description=(
                    "backward: where the value comes from; forward: where it goes. "
                    'Example: "backward"'
                )
            ),
        ] = "backward",
        max_steps: Annotated[
            int, Field(ge=1, le=500, description="Most operations to visit. Example: 50")
        ] = 50,
    ) -> DataflowResult:
        """Follow a value through the decompiler's dataflow from one instruction.

        Use to answer "where does this argument come from" or "what is this
        result used for" across the function. Backward ends at constants that
        are the value itself (not operands like the 8 in p + 8), parameters
        (name and slot), globals, call results (with the callee) and loads (the
        pointer is followed on). Forward lists every use and ends at stores,
        call arguments (callee and slot), returns and globals; a call's result
        is not followed. Returns {function, start, direction, steps: [{address,
        op, depth}], stops: [{kind, address, name, slot, target, value}],
        truncated}.
        """
        func = resolve_function(address)
        addr = resolve_address(address)
        high = _high_function(func)
        start_vn = None
        # An op whose inputs are all constants (RETURN 0 on Ghidra 12.2) still
        # has a value to report: the last constant, since RETURN's input 0 is
        # the return-address offset, not the value.
        fallback = None
        it = high.getPcodeOps(addr)
        while it.hasNext() and start_vn is None:
            op = it.next()
            candidates = ([op.getOutput()] if op.getOutput() is not None else []) + list(
                op.getInputs()
            )
            for vn in candidates:
                if vn is None:
                    continue
                if not variable:
                    if vn.isConstant():
                        fallback = vn
                        continue
                    start_vn = vn
                    break
                hv = vn.getHigh()
                names = {str(hv.getName())} if hv is not None and hv.getName() else set()
                if vn.isRegister():
                    reg = session.program.getRegister(vn.getAddress(), vn.getSize())
                    if reg is not None:
                        names.add(str(reg.getName()))
                if variable in names or variable.upper() in names:
                    start_vn = vn
                    break
        if start_vn is None and not variable:
            start_vn = fallback
        if start_vn is None:
            raise GhidraError(
                f"No value {variable or '(any)'} in the decompiler's operations at "
                f"{format_address(addr.getOffset())}.",
                error_type="NotFound",
            )

        steps, stops, truncated = _walk(start_vn, direction, max_steps)
        return DataflowResult(
            function=format_address(func.getEntryPoint().getOffset()),
            start=str(start_vn),
            direction=direction,
            steps=steps,
            stops=stops,
            truncated=truncated,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"decompiler"})
    @session.require_open
    def find_variable_accesses(
        address: Address,
        variable: Annotated[
            str,
            Field(
                description=(
                    "Decompiler variable (local, parameter or global used by the "
                    'function) exactly as list_decompiler_variables shows it. Example: "param_1"'
                )
            ),
        ],
    ) -> VariableAccesses:
        """List every place a function reads or writes one decompiler variable.

        Use to see how a parameter or local is used without reading the whole
        decompiled function; analyze_dataflow follows a value from one place
        instead. SSA merge points (MULTIEQUAL, INDIRECT) are left out, so each
        access is an operation in the source. An unused parameter has no
        accesses. Returns {function, variable, storage, data_type, is_parameter,
        accesses: [{address, kind: read|write, op}], total}.
        """
        func = resolve_function(address)
        high = _high_function(func)
        symbols = []
        for table in (high.getLocalSymbolMap(), high.getGlobalSymbolMap()):
            it = table.getSymbols()
            while it.hasNext():
                symbols.append(it.next())
        sym = next((x for x in symbols if str(x.getName()) == variable), None)
        if sym is None:
            names = sorted({str(x.getName()) for x in symbols})
            close = difflib.get_close_matches(variable, names, n=5, cutoff=0.5)
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            raise GhidraError(
                f"No variable {variable!r} in {func.getName()}.{hint} "
                f"Variables: {', '.join(names[:40])}.",
                error_type="NotFound",
            )

        hv = sym.getHighVariable()
        found: dict[tuple, VariableAccess] = {}

        def add(op, kind: str) -> None:
            if op is None or op.getMnemonic() in ("MULTIEQUAL", "INDIRECT"):
                return
            where = _where(op)
            if where is None:
                return
            item = VariableAccess(address=where, kind=kind, op=str(op))
            found.setdefault((where, kind, item.op), item)

        for vn in list(hv.getInstances()) if hv is not None else []:
            add(vn.getDef(), "write")
            for op in vn.getDescendants():
                add(op, "read")
        accesses = sorted(found.values(), key=lambda a: (int(a.address, 16), a.kind))
        storage = sym.getStorage()
        return VariableAccesses(
            function=format_address(func.getEntryPoint().getOffset()),
            variable=str(sym.getName()),
            storage=str(storage) if storage is not None else "",
            data_type=str(sym.getDataType()),
            is_parameter=bool(sym.isParameter()),
            accesses=accesses,
            total=len(accesses),
        )

    @mcp.tool(name="_normalized_instructions", annotations=ANNO_READ_ONLY, tags={"internal"})
    @session.require_open
    def normalized_instructions(address: str) -> dict:
        """Internal: a function's normalised instruction lines (for cross-database diffs)."""
        func = resolve_function(address)
        return {
            "address": format_address(func.getEntryPoint().getOffset()),
            "name": str(func.getName()),
            "lines": _normalised(func),
        }

    @mcp.tool(name="_decompiled_lines", annotations=ANNO_READ_ONLY, tags={"internal"})
    @session.require_open
    def decompiled_lines(address: str) -> dict:
        """Internal: a function's decompiled C as lines (for cross-database diffs)."""
        func = resolve_function(address)
        return {
            "address": format_address(func.getEntryPoint().getOffset()),
            "name": str(func.getName()),
            "lines": _c_lines(func),
        }

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def diff_functions(
        address_a: Address,
        address_b: Address,
        level: DiffLevel = "instructions",
        include_artifacts: IncludeArtifacts = False,
    ) -> DiffResult:
        """Diff two functions, by instruction or by decompiled C.

        Use to compare variants (a patched copy, an inlined duplicate, the same
        routine in two places). instructions: branch targets inside each
        function become instruction indexes and calls become callee names, so
        moved code compares equal. decompiled: C lines with load addresses in
        default names masked; hunks that differ only by renumbered auto
        variables or string labels are counted in suppressed, not shown.
        Returns {a, b, level, similarity, a_instructions, b_instructions, ops:
        [{kind, a, b}] (instructions), hunks: [{kind, a_start, b_start, a, b}]
        and suppressed (decompiled), truncated}.
        """
        fa, fb = resolve_function(address_a), resolve_function(address_b)
        if level == "decompiled":
            ca, cb = _c_lines(fa), _c_lines(fb)
            d = diff_c(ca, cb, include_artifacts)
            return DiffResult(
                a=_node(fa),
                b=_node(fb),
                level=level,
                similarity=d["similarity"],
                a_instructions=d["a_lines"],
                b_instructions=d["b_lines"],
                hunks=[CHunk(**h) for h in d["hunks"]],
                suppressed=d["suppressed"],
                truncated=d["truncated"],
            )
        la, lb = _normalised(fa), _normalised(fb)
        matcher = difflib.SequenceMatcher(a=la, b=lb, autojunk=False)
        ops = [
            DiffOp(
                kind=tag,
                a=la[i1:i2] if tag != "equal" else [f"... {i2 - i1} equal"],
                b=lb[j1:j2] if tag != "equal" else [],
            )
            for tag, i1, i2, j1, j2 in matcher.get_opcodes()
        ]
        return DiffResult(
            a=_node(fa),
            b=_node(fb),
            similarity=round(matcher.ratio(), 4),
            a_instructions=len(la),
            b_instructions=len(lb),
            ops=ops[:MAX_DIFF_OPS],
            truncated=len(ops) > MAX_DIFF_OPS,
        )


# Ops whose output is one of their inputs unchanged (or widened/narrowed), so a
# constant input is the value's origin rather than an operand of a computation.
_COPYING_OPS = {"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "MULTIEQUAL", "INDIRECT", "SUBPIECE"}


def _where(op) -> str | None:
    seq = op.getSeqnum() if op is not None else None
    target = seq.getTarget() if seq is not None else None
    return format_address(target.getOffset()) if target is not None else None


def _call_target(op) -> str:
    if op.getMnemonic() == "CALLIND":
        return "indirect"
    dest = op.getInput(0).getAddress()
    func = session.program.getFunctionManager().getFunctionAt(dest)
    func = _resolve_thunk(func)
    return str(func.getName()) if func is not None else format_location(dest)


def _value_inputs(op) -> list:
    """Inputs of a def op that carry the value further back.

    LOAD's input 0 is an address-space id, SUBPIECE's and INDIRECT's input 1 a
    byte offset / op reference: none of them are values.
    """
    mnem = op.getMnemonic()
    inputs = list(op.getInputs())
    if mnem == "LOAD":
        return inputs[1:2]
    if mnem in ("SUBPIECE", "INDIRECT"):
        return inputs[:1]
    if mnem in _COPYING_OPS:
        return inputs
    return [vn for vn in inputs if not vn.isConstant()]


def _walk(start_vn, direction: str, max_steps: int):
    from ghidra.program.model.pcode import HighGlobal, HighParam  # noqa: PLC0415

    steps: list[FlowStep] = []
    stops: dict[tuple, FlowStop] = {}

    def stop(**fields) -> None:
        item = FlowStop(**fields)
        stops.setdefault(tuple(item.model_dump().values()), item)

    def var_name(vn) -> str:
        hv = vn.getHigh()
        if hv is not None and hv.getName():
            return str(hv.getName())
        if vn.isRegister():
            reg = session.program.getRegister(vn.getAddress(), vn.getSize())
            if reg is not None:
                return str(reg.getName())
        return str(vn)

    seen = set()
    queue = deque([(start_vn, 0)])
    while queue and len(steps) < max_steps:
        vn, depth = queue.popleft()
        hv = vn.getHigh()
        if direction == "backward":
            if vn.isConstant():
                stop(kind="constant", value=hex(vn.getOffset()))
                continue
            if isinstance(hv, HighGlobal):
                rep = hv.getRepresentative()
                where = format_location(rep.getAddress()) if rep is not None else None
                stop(kind="global", name=var_name(vn), address=where)
                continue
            if vn.isInput():
                if isinstance(hv, HighParam):
                    stop(kind="parameter", name=var_name(vn), slot=int(hv.getSlot()))
                else:
                    stop(kind="input", name=var_name(vn))
                continue
            op = vn.getDef()
            if op is None:
                stop(kind="no_definition", name=var_name(vn))
                continue
            if op.getSeqnum() in seen:
                continue
            seen.add(op.getSeqnum())
            steps.append(_step(op, depth))
            mnem = op.getMnemonic()
            if mnem in ("CALL", "CALLIND"):
                stop(kind="call_result", address=_where(op), target=_call_target(op))
                continue
            if mnem == "LOAD":
                stop(kind="load", address=_where(op))
            for inp in _value_inputs(op):
                queue.append((inp, depth + 1))
            continue

        for op in vn.getDescendants():
            if op.getSeqnum() in seen:
                continue
            seen.add(op.getSeqnum())
            steps.append(_step(op, depth))
            mnem = op.getMnemonic()
            slots = [i for i in range(op.getNumInputs()) if op.getInput(i).equals(vn)]
            if mnem == "STORE":
                stop(kind="store", address=_where(op))
                continue
            if mnem in ("CALL", "CALLIND"):
                for i in slots:
                    if i == 0:
                        stop(kind="call_target", address=_where(op))
                    else:
                        stop(
                            kind="call_arg",
                            address=_where(op),
                            target=_call_target(op),
                            slot=i - 1,
                        )
                continue
            if mnem == "RETURN":
                stop(kind="return", address=_where(op))
                continue
            out = op.getOutput()
            if out is None:
                continue
            if isinstance(out.getHigh(), HighGlobal):
                stop(kind="global", name=var_name(out), address=_where(op))
            queue.append((out, depth + 1))
    return steps, list(stops.values()), bool(queue) and len(steps) >= max_steps


def _step(op, depth: int) -> FlowStep:
    return FlowStep(
        address=format_address(op.getSeqnum().getTarget().getOffset()), op=str(op), depth=depth
    )
