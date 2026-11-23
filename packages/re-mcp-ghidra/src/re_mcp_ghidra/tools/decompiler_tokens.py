# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Decompiler AST (PCode/token tree) exploration tools.

Uses the decompiler's ClangTokenGroup to build a simplified AST
representation.
"""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_function,
)
from re_mcp_ghidra.session import session


class DecompilerTokensResult(BaseModel):
    """Decompiler AST for a function."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    tokens: dict | None = Field(description="AST as a nested dict, or null.")


class DecompiledCallInfo(BaseModel):
    """A function call found in the decompiled output."""

    callee: str = Field(description="Callee name.")
    call_address: str | None = Field(default=None, description="Call site address (hex).")


class FindDecompiledCallsResult(BaseModel):
    """Function calls found in the decompiled output."""

    function: str = Field(description="Function address (hex).")
    name: str = Field(description="Function name.")
    call_count: int = Field(description="Number of calls found.")
    calls: list[DecompiledCallInfo] = Field(description="Call list.")


def _decompile(func):
    """Decompile a function and return (DecompileResults, HighFunction)."""
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    program = session.program
    decomp = session.decompiler()
    decomp.openProgram(program)

    try:
        results = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
        if not results.decompileCompleted():
            error_msg = results.getErrorMessage() or "Decompilation failed"
            raise GhidraError(error_msg, error_type="DecompilationFailed")
        return results
    except GhidraError:
        raise
    finally:
        decomp.dispose()


def _token_to_dict(token, depth: int) -> dict | None:
    """Convert a ClangToken/ClangTokenGroup to a simplified dict."""
    from ghidra.app.decompiler import ClangFuncNameToken, ClangTokenGroup  # noqa: PLC0415

    if token is None or depth <= 0:
        return None

    result: dict = {}

    # Get the token text
    text = str(token).strip()
    if text:
        result["text"] = text

    # Get min/max address if available
    try:
        min_addr = token.getMinAddress()
        if min_addr is not None:
            result["address"] = format_address(min_addr.getOffset())
    except Exception:
        pass

    # Check if this is a function name token
    if isinstance(token, ClangFuncNameToken):
        result["type"] = "func_name"

    # If this is a group, recurse into children
    if isinstance(token, ClangTokenGroup) and depth > 1:
        children = []
        for i in range(token.numChildren()):
            child = token.Child(i)
            child_dict = _token_to_dict(child, depth - 1)
            if child_dict:
                children.append(child_dict)
        if children:
            result["children"] = children

    return result or None


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"decompiler"})
    @session.require_open
    def get_decompiler_tokens(
        function_address: Address,
        depth: Annotated[int, Field(description="Maximum tree depth (1-10).", ge=1, le=10)] = 3,
    ) -> DecompilerTokensResult:
        """Return the decompiler token tree for a function as a structured dict.

        Returns a structured representation of the decompiled code's
        token tree, useful for pattern matching and analysis. Output
        can be large for complex functions -- keep depth low (2-3)
        for initial exploration.

        Args:
            function_address: Address or name of the function.
            depth: Maximum tree depth to return (1-10, default 3).
        """
        func = resolve_function(function_address)
        results = _decompile(func)

        depth = max(1, min(depth, 10))

        markup = results.getCCodeMarkup()
        tokens = None
        if markup is not None:
            tokens = _token_to_dict(markup, depth)

        entry = func.getEntryPoint()
        return DecompilerTokensResult(
            function=format_address(entry.getOffset()),
            name=func.getName(),
            tokens=tokens,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"decompiler", "analysis"})
    @session.require_open
    def find_decompiled_calls(
        function_address: Address,
        callee_name: str = "",
    ) -> FindDecompiledCallsResult:
        """Find function call sites in the decompiled output.

        Scans the decompiler's token tree for function call tokens.
        Optionally filter by callee name (substring match).

        Args:
            function_address: Address or name of the function to analyze.
            callee_name: Optional name to filter calls (empty = all calls).
        """
        from ghidra.app.decompiler import ClangFuncNameToken, ClangTokenGroup  # noqa: PLC0415

        func = resolve_function(function_address)
        results = _decompile(func)

        markup = results.getCCodeMarkup()
        calls: list[DecompiledCallInfo] = []

        def _scan_tokens(token):
            if isinstance(token, ClangFuncNameToken):
                name = str(token).strip()
                if not callee_name or callee_name in name:
                    call_addr = None
                    try:
                        min_addr = token.getMinAddress()
                        if min_addr is not None:
                            call_addr = format_address(min_addr.getOffset())
                    except Exception:
                        pass
                    calls.append(
                        DecompiledCallInfo(
                            callee=name,
                            call_address=call_addr,
                        )
                    )

            if isinstance(token, ClangTokenGroup):
                for i in range(token.numChildren()):
                    _scan_tokens(token.Child(i))

        if markup is not None:
            _scan_tokens(markup)

        entry = func.getEntryPoint()
        return FindDecompiledCallsResult(
            function=format_address(entry.getOffset()),
            name=func.getName(),
            call_count=len(calls),
            calls=calls,
        )
