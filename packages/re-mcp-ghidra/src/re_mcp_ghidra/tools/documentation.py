# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Re-running analysis, and finding the functions that still need documenting."""

from __future__ import annotations

import re
import time
from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    format_address,
)
from re_mcp_ghidra.session import analyze, session

# Names Ghidra invents.  A function or variable still carrying one has not
# been looked at by anyone.
DEFAULT_FUNCTION_NAME = re.compile(r"^(thunk_)?(FUN|SUB|LAB)_[0-9a-fA-F]+$")
DEFAULT_PARAM_NAME = re.compile(r"^param_\d+$")
DEFAULT_LOCAL_NAME = re.compile(
    r"^(local_[0-9a-fA-F]+|[a-z]{1,2}Var\d+|in_\w+|unaff_\w+|extraout_\w+|auStack_\w+)$"
)
UNDEFINED_TYPE = re.compile(r"^undefined\d*\b")

# Points per aspect; a fully documented function scores 100.
WEIGHTS = {"name": 25, "prototype": 15, "plate_comment": 15, "parameters": 25, "locals": 20}
DECOMPILE_TIMEOUT_S = 30


class AnalysisRun(BaseModel):
    functions_before: int = Field(description="Function count before analysis.")
    functions_after: int = Field(description="Function count after analysis.")
    seconds: float = Field(description="How long analysis took.")
    analyzers: list[str] = Field(description="Analyzers run alone; empty for full analysis.")


def _run_selected(program, names: list[str]) -> None:
    """Run the named analyzers once each over the whole program, in a transaction."""
    from ghidra.app.script import GhidraScriptUtil  # noqa: PLC0415
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    from re_mcp_ghidra.exceptions import GhidraError  # noqa: PLC0415
    from re_mcp_ghidra.tools.analyzers import manager  # noqa: PLC0415

    mgr = manager()
    chosen = []
    for name in names:
        analyzer = mgr.getAnalyzer(name)
        if analyzer is None:
            raise GhidraError(
                f"No analyzer {name!r}. list_analyzers shows them.", error_type="NotFound"
            )
        if not analyzer.supportsOneTimeAnalysis():
            raise GhidraError(
                f"{name} cannot run on its own; enable it and run full analysis instead.",
                error_type="InvalidArgument",
            )
        chosen.append(analyzer)

    tx = program.startTransaction("Run analyzers")
    ok = False
    GhidraScriptUtil.acquireBundleHostReference()
    try:
        everything = program.getMemory().getLoadedAndInitializedAddressSet()
        for analyzer in chosen:
            mgr.scheduleOneTimeAnalysis(analyzer, everything)
        mgr.startAnalysis(TaskMonitor.DUMMY, False)
        ok = True
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
        program.endTransaction(tx, ok)


class FunctionScore(BaseModel):
    address: str = Field(description="Function entry point.")
    name: str = Field(description="Current name.")
    score: int = Field(description="0-100; 100 means nothing left to document.")
    missing: list[str] = Field(
        description=(
            "What is still undone: name, prototype, plate_comment, parameters "
            "(default-named or undefined-typed), locals (decompiler-invented names)."
        )
    )


class ScoreList(BaseModel):
    items: list[FunctionScore] = Field(description="Lowest score first.")
    total: int = Field(description="Functions matching the filter and max_score.")
    offset: int = Field(description="Offset used.")
    limit: int = Field(description="Limit used.")
    has_more: bool = Field(description="More results past this page.")


def _static_gaps(func) -> list[str]:
    from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415
    from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

    gaps = []
    if DEFAULT_FUNCTION_NAME.match(func.getName()) or func.getSymbol().getSource() == (
        SourceType.DEFAULT
    ):
        gaps.append("name")
    if func.getSignatureSource() == SourceType.DEFAULT:
        gaps.append("prototype")
    listing = session.program.getListing()
    if not listing.getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint()):
        gaps.append("plate_comment")
    for param in func.getParameters():
        if DEFAULT_PARAM_NAME.match(param.getName()) or UNDEFINED_TYPE.match(
            str(param.getDataType().getName())
        ):
            gaps.append("parameters")
            break
    return gaps


def _has_default_locals(decomp, func) -> bool:
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_S, TaskMonitor.DUMMY)
    high = result.getHighFunction() if result is not None else None
    if high is None:
        return False
    for sym in high.getLocalSymbolMap().getSymbols():
        if not sym.isParameter() and DEFAULT_LOCAL_NAME.match(sym.getName()):
            return True
    return False


def _score(gaps: list[str]) -> int:
    return 100 - sum(WEIGHTS[g] for g in gaps)


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"analysis"})
    @session.require_open
    def run_auto_analysis(
        analyzers: Annotated[
            list[str],
            Field(
                description=(
                    "Run only these analyzers (names from list_analyzers) over the whole "
                    'program; empty runs full auto-analysis. Example: ["Decompiler Switch '
                    'Analysis"]'
                )
            ),
        ] = [],  # noqa: B006 -- pydantic copies the default; never mutated
    ) -> AnalysisRun:
        """Run Ghidra's auto-analysis again on the open program, and wait.

        Use after creating functions, applying types or patching, so analysis
        picks up the change across the program (reanalyze_range is the cheaper
        choice for one range). With analyzers, only those run; each must support
        one-time runs (list_analyzers: one_time_supported). It blocks this
        database until done, which takes minutes on large binaries. Returns
        {functions_before, functions_after, seconds, analyzers}.
        """
        program = session.program
        before = program.getFunctionManager().getFunctionCount()
        start = time.monotonic()
        if analyzers:
            _run_selected(program, analyzers)
        else:
            analyze(program)
        return AnalysisRun(
            functions_before=before,
            functions_after=program.getFunctionManager().getFunctionCount(),
            seconds=round(time.monotonic() - start, 2),
            analyzers=list(analyzers),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def score_documentation(
        filter_pattern: FilterPattern = "",
        max_score: Annotated[
            int,
            Field(
                ge=0,
                le=100,
                description=(
                    "Only list functions scoring at or below this; 99 hides finished "
                    "ones. Example: 60"
                ),
            ),
        ] = 99,
        include_locals: Annotated[
            bool,
            Field(
                description=(
                    "Also decompile each listed function to check for decompiler-"
                    "invented local names (local_10, uVar1). Slower: one decompile per "
                    "listed function. Example: true"
                )
            ),
        ] = False,
        offset: Offset = 0,
        limit: Limit = 50,
    ) -> ScoreList:
        """Rank functions by how much documentation they still need, worst first.

        Use to pick what to document next. Scores 0-100 from: a real name (25),
        a set prototype (15), a plate comment (15), named and typed parameters
        (25), and, with include_locals, named locals (20; without it locals are
        not checked and not counted against the score; ranking across pages
        uses the other aspects, and each page is re-sorted once its locals are
        known). External functions and thunks are skipped. Returns {items: [{address, name, score, missing}],
        total, offset, limit, has_more}.
        """

        filt = compile_filter(filter_pattern)
        scored = []
        for func in session.program.getFunctionManager().getFunctions(True):
            if func.isExternal() or func.isThunk():
                continue
            name = func.getName()
            if filt and not filt.search(name):
                continue
            gaps = _static_gaps(func)
            if _score(gaps) <= max_score:
                scored.append((func, gaps))
        scored.sort(key=lambda fg: (_score(fg[1]), fg[0].getEntryPoint().getOffset()))

        page = scored[offset : offset + limit]
        decomp = None
        if include_locals and page:
            decomp = session.decompiler()
            decomp.openProgram(session.program)
        try:
            items = []
            for func, static_gaps in page:
                gaps = list(static_gaps)
                if decomp is not None and _has_default_locals(decomp, func):
                    gaps.append("locals")
                items.append(
                    FunctionScore(
                        address=format_address(func.getEntryPoint().getOffset()),
                        name=func.getName(),
                        score=_score(gaps),
                        missing=gaps,
                    )
                )
        finally:
            if decomp is not None:
                decomp.dispose()
        # Locals are only known for this page, so re-sort it with them counted.
        items.sort(key=lambda item: item.score)

        return ScoreList(
            items=items,
            total=len(scored),
            offset=offset,
            limit=limit,
            has_more=offset + limit < len(scored),
        )
