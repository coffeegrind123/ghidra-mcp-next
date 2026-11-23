# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Regex search over decompiled C, resumable across calls."""

from __future__ import annotations

import re
import time
from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_READ_ONLY, FilterPattern, compile_filter, format_address
from re_mcp_ghidra.session import session

DECOMPILE_TIMEOUT_S = 30
MAX_SEARCH_SECONDS = 300

# Decompiled text per function entry, valid for one program revision. Any change
# to the program (a rename, a retype, an undo) bumps the revision and empties it.
_cache: dict[int, str] = {}
_cache_revision: list[int] = [-1]


class DecompiledHit(BaseModel):
    function: str = Field(description="Function name.")
    address: str = Field(description="Function entry point.")
    line: int = Field(description="Line number in the decompiled C, from 1.")
    text: str = Field(description="The matching line.")


class DecompiledSearch(BaseModel):
    items: list[DecompiledHit] = Field(description="Matches, in function address order.")
    functions_searched: int = Field(description="Functions decompiled or read from cache.")
    failed: int = Field(description="Functions that did not decompile (skipped).")
    next_cursor: str = Field(
        description="Pass as cursor to continue; empty when the search finished."
    )
    seconds: float = Field(description="Time taken.")


def _decompiled(func) -> str | None:
    rev = int(session.program.getModificationNumber())
    if _cache_revision[0] != rev:
        _cache.clear()
        _cache_revision[0] = rev
    key = func.getEntryPoint().getOffset()
    if key not in _cache:
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        res = session.decompiler().decompileFunction(func, DECOMPILE_TIMEOUT_S, TaskMonitor.DUMMY)
        if res is None or not res.decompileCompleted():
            return None
        _cache[key] = str(res.getDecompiledFunction().getC())
    return _cache[key]


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"search"})
    @session.require_open
    def search_decompiled(
        pattern: Annotated[
            str,
            Field(
                description=(
                    "Case-insensitive regex matched against each line of decompiled C. "
                    r'Example: "param_1->\w+ \+ 0x10"'
                )
            ),
        ],
        function_filter: FilterPattern = "",
        cursor: Annotated[
            str,
            Field(description='next_cursor from the previous call; empty to start. Example: ""'),
        ] = "",
        max_hits: Annotated[
            int,
            Field(
                ge=1,
                le=2000,
                description="Stop once this many matches are found (the last function's are all kept). Example: 100",
            ),
        ] = 100,
        max_seconds: Annotated[
            int,
            Field(
                ge=1,
                le=MAX_SEARCH_SECONDS,
                description="Stop after about this long; continue with next_cursor. Example: 60",
            ),
        ] = 60,
    ) -> DecompiledSearch:
        """Search the decompiled C of every function (or a filtered set) for a regex.

        Use to find code by what it does when no string or symbol leads there
        (a magic constant in an expression, a field offset, an API pattern).
        Decompiling is slow on large programs, so the search stops at max_hits or
        max_seconds and returns next_cursor to resume; decompiled text is cached
        until the program changes. Functions that fail to decompile are counted
        in failed and skipped. Returns {items: [{function, address, line,
        text}], functions_searched, failed, next_cursor, seconds}.
        """
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise GhidraError(f"Invalid regex: {exc}", error_type="InvalidArgument") from exc
        filt = compile_filter(function_filter)
        resume = int(cursor, 16) if cursor else -1

        start = time.monotonic()
        hits: list[DecompiledHit] = []
        searched = failed = 0
        next_cursor = ""
        funcs = session.program.getFunctionManager().getFunctions(True)
        for func in funcs:
            entry = func.getEntryPoint().getOffset()
            if entry <= resume or func.isExternal() or func.isThunk():
                continue
            if filt and not filt.search(func.getName()):
                continue
            if len(hits) >= max_hits or time.monotonic() - start > max_seconds:
                # Resume just before this function, so the next call starts with it.
                next_cursor = format(entry - 1, "x")
                break
            text = _decompiled(func)
            searched += 1
            resume = entry
            if text is None:
                failed += 1
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if regex.search(line):
                    hits.append(
                        DecompiledHit(
                            function=str(func.getName()),
                            address=format_address(entry),
                            line=number,
                            text=line.strip()[:300],
                        )
                    )
        return DecompiledSearch(
            items=hits,
            functions_searched=searched,
            failed=failed,
            next_cursor=next_cursor,
            seconds=round(time.monotonic() - start, 2),
        )
