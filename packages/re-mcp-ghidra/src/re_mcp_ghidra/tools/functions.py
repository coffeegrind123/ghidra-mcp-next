# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Function analysis tools — list, decompile, disassemble, rename."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    format_address,
    format_location,
    paginate_iter,
    resolve_function,
)
from re_mcp_ghidra.models import FunctionSummary, RenameResult
from re_mcp_ghidra.session import session


class FunctionDetail(BaseModel):
    name: str
    start: str
    end: str
    size: int
    calling_convention: str = ""
    signature: str = ""
    is_thunk: bool = False
    is_external: bool = False
    comment: str = ""
    entry_point: str = ""
    thunk_target: str | None = Field(
        default=None,
        description="For a thunk: the function it finally reaches (name), following chains.",
    )
    thunk_target_address: str | None = Field(
        default=None, description="That function's address (EXTERNAL:... for an import)."
    )


class DecompiledLine(BaseModel):
    line: int = Field(description="Line number, from 1.")
    address: str = Field(description="Address the line's code comes from, empty if none.")
    text: str = Field(description="The line, with its indentation.")


class DecompilationResult(BaseModel):
    function_name: str
    address: str
    decompiled_code: str = Field(description="The C text (only the requested lines when paged).")
    total_lines: int = Field(default=0, description="Lines in the whole function.")
    lines: list[DecompiledLine] = Field(
        default_factory=list, description="With line_numbers: the requested lines."
    )


class Instruction(BaseModel):
    address: str
    bytes: str
    mnemonic: str
    operands: str


class DisassemblyResult(BaseModel):
    function_name: str
    start: str
    end: str
    instruction_count: int
    instructions: list[Instruction]


class DeleteFunctionResult(BaseModel):
    address: str
    name: str
    status: str


def decompiled_lines(results) -> list[DecompiledLine]:
    """Numbered lines built from the decompiler's own line markup.

    Built from the markup rather than by splitting getC(), so a line's number
    and its address always describe the same tokens.
    """
    from ghidra.app.decompiler.component import DecompilerUtils  # noqa: PLC0415

    out = []
    for number, line in enumerate(DecompilerUtils.toLines(results.getCCodeMarkup()), 1):
        tokens = list(line.getAllTokens())
        text = " " * int(line.getIndent()) + "".join(str(t) for t in tokens)
        addr = next((t.getMinAddress() for t in tokens if t.getMinAddress() is not None), None)
        out.append(
            DecompiledLine(
                line=number,
                address=format_address(addr.getOffset()) if addr is not None else "",
                text=text.rstrip(),
            )
        )
    return out


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def list_functions(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
        tag: Annotated[
            str, Field(description='Only functions with this tag. Example: "crypto"')
        ] = "",
        untagged: Annotated[
            bool, Field(description="Only functions with no tag. Example: true")
        ] = False,
        exclude_default_names: Annotated[
            bool,
            Field(
                description=(
                    "Leave out functions still named by Ghidra (FUN_..., thunk_FUN_...): "
                    "what is left is what someone named. Example: true"
                )
            ),
        ] = False,
    ) -> dict:
        """List the functions in the database, paginated.

        Filter by a regex on the name, a tag (set_function_tag), untagged, or
        exclude_default_names to see only named functions (or keep them and
        page through the unnamed ones to triage). Returns {items: [{name, start,
        end, size}], total, offset, limit, has_more}.
        """
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        program = session.program
        func_mgr = program.getFunctionManager()
        filt = compile_filter(filter_pattern)

        def _gen():
            func_iter = func_mgr.getFunctions(True)
            while func_iter.hasNext():
                func = func_iter.next()
                name = func.getName()
                if filt and not filt.search(name):
                    continue
                if exclude_default_names and func.getSymbol().getSource() == SourceType.DEFAULT:
                    continue
                if tag or untagged:
                    tags = {str(t.getName()) for t in func.getTags()}
                    if (tag and tag not in tags) or (untagged and tags):
                        continue
                body = func.getBody()
                start = func.getEntryPoint().getOffset()
                end = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else start
                yield FunctionSummary(
                    name=name,
                    start=format_address(start),
                    end=format_address(end),
                    size=int(body.getNumAddresses()),
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def get_function(address: Address) -> FunctionDetail:
        """Describe the function containing an address: bounds, signature and flags.

        Use list_functions to enumerate functions, decompile_function or
        disassemble_function for its body. Returns name, start, end (exclusive), size
        (bytes in body), calling_convention, signature, is_thunk, is_external, comment
        and entry_point; for a thunk, thunk_target and thunk_target_address
        (the function the chain of thunks ends at, often an import).
        """
        func = resolve_function(address)
        target = func.getThunkedFunction(True) if func.isThunk() else None
        body = func.getBody()
        entry = func.getEntryPoint()
        start = entry.getOffset()
        end = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else start

        return FunctionDetail(
            name=func.getName(),
            start=format_address(start),
            end=format_address(end),
            size=int(body.getNumAddresses()),
            calling_convention=func.getCallingConventionName() or "",
            signature=func.getPrototypeString(False, False) or "",
            is_thunk=func.isThunk(),
            is_external=func.isExternal(),
            comment=func.getComment() or "",
            entry_point=format_address(start),
            thunk_target=str(target.getName(True)) if target is not None else None,
            thunk_target_address=(
                format_location(target.getEntryPoint()) if target is not None else None
            ),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions", "decompiler"})
    @session.require_open
    def decompile_function(
        address: Address,
        line_numbers: Annotated[
            bool,
            Field(
                description=(
                    "Also return the code as numbered lines with each line's address "
                    "(for set_decompiler_comment, or reading a long function in pages). "
                    "Example: true"
                )
            ),
        ] = False,
        offset: Annotated[
            int,
            Field(ge=0, description="With line_numbers: first line to return, from 0. Example: 0"),
        ] = 0,
        limit: Annotated[
            int,
            Field(ge=0, description="With line_numbers: most lines; 0 for all. Example: 200"),
        ] = 0,
        timeout_s: Annotated[
            int,
            Field(ge=1, le=600, description="Decompiler time limit in seconds. Example: 120"),
        ] = 60,
    ) -> DecompilationResult:
        """Decompile the function containing an address to C pseudocode.

        Use disassemble_function for the machine instructions instead. Fails with
        DecompilationFailed when Ghidra's decompiler gives up (raise timeout_s for
        very large functions). Returns function_name, address (entry),
        decompiled_code (the C text) and total_lines; with line_numbers, also lines
        [{line, address, text}] for the requested page.
        """
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        func = resolve_function(address)
        results = session.decompiler().decompileFunction(func, timeout_s, TaskMonitor.DUMMY)
        if not results.decompileCompleted():
            error_msg = results.getErrorMessage() or "Decompilation failed"
            raise GhidraError(error_msg, error_type="DecompilationFailed")
        decomp_func = results.getDecompiledFunction()
        if decomp_func is None:
            raise GhidraError("Decompilation returned no result", error_type="DecompilationFailed")

        code = str(decomp_func.getC())
        entry = format_address(func.getEntryPoint().getOffset())
        if not line_numbers:
            return DecompilationResult(
                function_name=func.getName(),
                address=entry,
                decompiled_code=code,
                total_lines=len(code.splitlines()),
            )
        lines = decompiled_lines(results)
        page = lines[offset : offset + limit] if limit else lines[offset:]
        return DecompilationResult(
            function_name=func.getName(),
            address=entry,
            decompiled_code="\n".join(ln.text for ln in page),
            total_lines=len(lines),
            lines=page,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def disassemble_function(address: Address) -> DisassemblyResult:
        """List every instruction in the body of the function containing an address.

        Use decompile_function for C pseudocode, disassemble_at to turn undefined bytes
        into code. Returns function_name, start, end, instruction_count and
        instructions, each with address, bytes (hex), mnemonic and operands.
        """
        func = resolve_function(address)
        program = session.program
        listing = program.getListing()
        body = func.getBody()

        instructions = []
        insn_iter = listing.getInstructions(body, True)
        while insn_iter.hasNext():
            insn = insn_iter.next()
            addr = insn.getAddress()
            raw_bytes = []
            for i in range(insn.getLength()):
                b = insn.getByte(i)
                raw_bytes.append(f"{b & 0xFF:02X}")

            operands = []
            for i in range(insn.getNumOperands()):
                op_str = insn.getDefaultOperandRepresentation(i)
                if op_str:
                    operands.append(op_str)

            instructions.append(
                Instruction(
                    address=format_address(addr.getOffset()),
                    bytes=" ".join(raw_bytes),
                    mnemonic=insn.getMnemonicString(),
                    operands=", ".join(operands),
                )
            )

        entry = func.getEntryPoint().getOffset()
        end_addr = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else entry

        return DisassemblyResult(
            function_name=func.getName(),
            start=format_address(entry),
            end=format_address(end_addr),
            instruction_count=len(instructions),
            instructions=instructions,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def rename_function(
        address: Address,
        new_name: Annotated[
            str,
            Field(description="New function name (user-defined). Example: 'parse_config'"),
        ],
    ) -> RenameResult:
        """Rename the function containing an address.

        Address may point anywhere inside the function. For labels, data or other
        symbols use rename_symbol. Returns address (function entry), old_name and
        new_name.
        """
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        func = resolve_function(address)
        old_name = func.getName()

        tx_id = session.program.startTransaction("Rename function")
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            session.program.endTransaction(tx_id, True)
        except Exception as e:
            session.program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rename function: {e}", error_type="RenameFailed") from e

        return RenameResult(
            address=format_address(func.getEntryPoint().getOffset()),
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def delete_function(address: Address) -> DeleteFunctionResult:
        """Remove the function definition containing an address; instructions stay.

        Undoes create_function: the code and bytes remain but are no longer grouped as
        a function. Returns address (former entry), name and status "deleted".
        """
        func = resolve_function(address)
        name = func.getName()
        entry = func.getEntryPoint()

        tx_id = session.program.startTransaction("Delete function")
        try:
            success = session.program.getFunctionManager().removeFunction(entry)
            session.program.endTransaction(tx_id, success)
            if not success:
                raise GhidraError("Failed to delete function", error_type="DeleteFailed")
        except GhidraError:
            raise
        except Exception as e:
            session.program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete function: {e}", error_type="DeleteFailed") from e

        return DeleteFunctionResult(
            address=format_address(entry.getOffset()),
            name=name,
            status="deleted",
        )
