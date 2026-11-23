# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Comment management tools."""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session


class GetCommentResult(BaseModel):
    address: str
    eol_comment: str = Field(default="", description="End-of-line comment.")
    pre_comment: str = Field(default="", description="Pre-instruction comment.")
    post_comment: str = Field(default="", description="Post-instruction comment.")
    plate_comment: str = Field(default="", description="Plate (block) comment.")
    repeatable_comment: str = Field(default="", description="Repeatable comment.")


class SetCommentResult(BaseModel):
    address: str
    comment_type: str
    comment: str
    status: str
    placed_at_line: int = Field(
        default=0, description="Decompiled line the comment went on (when line was given)."
    )


class GetFunctionCommentResult(BaseModel):
    address: str
    function_name: str
    comment: str
    repeatable_comment: str


class SetFunctionCommentResult(BaseModel):
    address: str
    function_name: str
    comment: str
    status: str


def _address_for_line(function: str, line: int):
    """(address, line used) for a decompiled line, or the nearest line with an address."""
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    from re_mcp_ghidra.helpers import resolve_function  # noqa: PLC0415
    from re_mcp_ghidra.tools.functions import decompiled_lines  # noqa: PLC0415

    func = resolve_function(function)
    results = session.decompiler().decompileFunction(func, 60, TaskMonitor.DUMMY)
    if not results.decompileCompleted():
        raise GhidraError(
            f"Decompilation failed: {results.getErrorMessage()}", error_type="DecompilationFailed"
        )
    lines = decompiled_lines(results)
    if not 1 <= line <= len(lines):
        raise GhidraError(f"Line {line} is outside 1..{len(lines)}.", error_type="InvalidArgument")
    for distance in range(len(lines)):
        for candidate in (line - distance, line + distance):
            if 1 <= candidate <= len(lines) and lines[candidate - 1].address:
                return resolve_address(lines[candidate - 1].address), candidate
    raise GhidraError(f"No line of {func.getName()} has an address.", error_type="NotFound")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"comments"})
    @session.require_open
    def get_comment(address: Address) -> GetCommentResult:
        """Read every listing comment on the code unit at an address.

        Read-only; use set_comment to write one, get_function_comment for a function's
        header comment. Returns address plus eol_comment, pre_comment, post_comment,
        plate_comment and repeatable_comment (empty string when unset or when no code
        unit exists there).
        """
        from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)
        cu = listing.getCodeUnitAt(addr)

        if cu is None:
            return GetCommentResult(address=format_address(addr.getOffset()))

        return GetCommentResult(
            address=format_address(addr.getOffset()),
            eol_comment=cu.getComment(CodeUnit.EOL_COMMENT) or "",
            pre_comment=cu.getComment(CodeUnit.PRE_COMMENT) or "",
            post_comment=cu.getComment(CodeUnit.POST_COMMENT) or "",
            plate_comment=cu.getComment(CodeUnit.PLATE_COMMENT) or "",
            repeatable_comment=cu.getComment(CodeUnit.REPEATABLE_COMMENT) or "",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"comments"})
    @session.require_open
    def set_comment(
        address: Address,
        comment: Annotated[
            str,
            Field(
                description="Comment text; an empty string clears that slot. "
                "Example: 'decrypts config blob'"
            ),
        ],
        comment_type: Annotated[
            Literal["eol", "pre", "post", "plate", "repeatable"],
            Field(
                description="Comment slot: eol (end of line), pre (above the line, also "
                "shown in decompiler output), post (below), plate (boxed header) or "
                "repeatable (echoed at referencing sites). Example: 'pre'"
            ),
        ] = "eol",
    ) -> SetCommentResult:
        """Write or clear one listing comment slot at an address, replacing its text.

        Use get_comment to read comments, set_function_comment for a function's header
        comment. Fails with NotFound when no code unit exists at the address. Returns
        address, comment_type, comment and status "ok".
        """
        from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

        type_map = {
            "eol": CodeUnit.EOL_COMMENT,
            "pre": CodeUnit.PRE_COMMENT,
            "post": CodeUnit.POST_COMMENT,
            "plate": CodeUnit.PLATE_COMMENT,
            "repeatable": CodeUnit.REPEATABLE_COMMENT,
        }
        ct = type_map.get(comment_type.lower())
        if ct is None:
            raise GhidraError(
                f"Invalid comment_type: {comment_type!r}. Must be one of: {', '.join(type_map)}",
                error_type="InvalidArgument",
            )

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)
        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            raise GhidraError(
                f"No code unit at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Set comment")
        try:
            cu.setComment(ct, comment or None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set comment: {e}", error_type="CommentFailed") from e

        return SetCommentResult(
            address=format_address(addr.getOffset()),
            comment_type=comment_type,
            comment=comment,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"comments", "decompiler"})
    @session.require_open
    def set_decompiler_comment(
        address: Address,
        comment: Annotated[
            str,
            Field(
                description="Comment text; an empty string clears the pre comment. "
                "Example: 'walk the import table'"
            ),
        ],
        line: Annotated[
            int,
            Field(
                ge=0,
                description=(
                    "Line number from decompile_function(line_numbers=true); address then "
                    "names the function. A line with no address of its own uses the "
                    "nearest line that has one. 0: comment at address. Example: 42"
                ),
            ),
        ] = 0,
    ) -> SetCommentResult:
        """Write the PRE comment shown above a line of pseudocode.

        Give an address, or a function plus a decompiled line number. Shorthand for
        set_comment with comment_type="pre". Fails with NotFound when no code unit
        exists there. Returns address, comment_type ("pre"), comment, status "ok",
        and placed_at_line when line was given.
        """
        from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        placed = 0
        if line:
            addr, placed = _address_for_line(address, line)
        else:
            addr = resolve_address(address)
        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            raise GhidraError(
                f"No code unit at {format_address(addr.getOffset())}",
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Set decompiler comment")
        try:
            cu.setComment(CodeUnit.PRE_COMMENT, comment or None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set comment: {e}", error_type="CommentFailed") from e

        return SetCommentResult(
            address=format_address(addr.getOffset()),
            comment_type="pre",
            comment=comment,
            status="ok",
            placed_at_line=placed,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"comments", "functions"})
    @session.require_open
    def get_function_comment(address: Address) -> GetFunctionCommentResult:
        """Read the header comments of the function containing an address.

        Read-only; use set_function_comment to write, get_comment for per-instruction
        comments. Returns the function's entry address, function_name, comment and
        repeatable_comment (empty string when unset).
        """
        from re_mcp_ghidra.helpers import resolve_function  # noqa: PLC0415

        func = resolve_function(address)
        return GetFunctionCommentResult(
            address=format_address(func.getEntryPoint().getOffset()),
            function_name=func.getName(),
            comment=func.getComment() or "",
            repeatable_comment=func.getRepeatableComment() or "",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"comments", "functions"})
    @session.require_open
    def set_function_comment(
        address: Address,
        comment: Annotated[
            str,
            Field(
                description="Comment text; an empty string clears it. "
                "Example: 'Parses the PE header and returns the entry RVA.'"
            ),
        ],
        repeatable: Annotated[
            bool,
            Field(
                description="True writes the repeatable comment (also shown at call "
                "sites); False writes the plain function comment. Example: false"
            ),
        ] = True,
    ) -> SetFunctionCommentResult:
        """Write or clear the header comment of the function containing an address.

        Use get_function_comment to read it back, set_comment for comments on single
        instructions. Returns the function's entry address, function_name, comment
        and status "ok".
        """
        from re_mcp_ghidra.helpers import resolve_function  # noqa: PLC0415

        func = resolve_function(address)

        tx_id = session.program.startTransaction("Set function comment")
        try:
            if repeatable:
                func.setRepeatableComment(comment or None)
            else:
                func.setComment(comment or None)
            session.program.endTransaction(tx_id, True)
        except Exception as e:
            session.program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to set function comment: {e}", error_type="CommentFailed"
            ) from e

        return SetFunctionCommentResult(
            address=format_address(func.getEntryPoint().getOffset()),
            function_name=func.getName(),
            comment=comment,
            status="ok",
        )
