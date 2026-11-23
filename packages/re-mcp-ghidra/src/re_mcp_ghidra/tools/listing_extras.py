# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Processor context registers, relocations, constant operands, comment search,
function-candidate discovery and thunk assignment."""

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
    paginate,
    resolve_address,
    resolve_function,
)
from re_mcp_ghidra.session import session

COMMENT_KINDS = ("eol", "pre", "post", "plate", "repeatable")


class ContextValue(BaseModel):
    register: str = Field(description="Context register name.")
    value: int | None = Field(description="Value at the address, or null if unset.")


class ContextValues(BaseModel):
    address: str = Field(description="Address read.")
    registers: list[ContextValue] = Field(description="Context registers and their values.")


class ContextSet(BaseModel):
    register: str = Field(description="Register set.")
    start: str = Field(description="First address.")
    end: str = Field(description="Last address (inclusive).")
    value: int = Field(description="Value set.")
    verified: bool = Field(description="Reading it back at start returned the value.")


class ThunkResult(BaseModel):
    address: str = Field(description="The thunk function.")
    target: str = Field(description="The function it forwards to, empty when cleared.")
    target_name: str = Field(description="Target name.")


def _context_register(name: str):
    ctx = session.program.getProgramContext()
    regs = list(ctx.getContextRegisters())
    for reg in regs:
        if str(reg.getName()).lower() == name.lower():
            return reg
    names = ", ".join(sorted(str(r.getName()) for r in regs))
    raise GhidraError(f"No context register {name!r} (has: {names}).", error_type="InvalidArgument")


def _context_value(reg, addr) -> int | None:
    ctx = session.program.getProgramContext()
    value = ctx.getValue(reg, addr, False)
    if value is None:
        # Analysis-set defaults (e.g. ARM TMode) live in the default context,
        # which getValue does not read.
        rv = ctx.getDisassemblyContext(addr).getRegisterValue(reg)
        value = rv.getUnsignedValue() if rv is not None and rv.hasValue() else None
    return int(str(value)) if value is not None else None


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"processor"})
    @session.require_open
    def get_context_registers(
        address: Address,
        register: Annotated[
            str, Field(description='One register; empty lists all. Example: "TMode"')
        ] = "",
    ) -> ContextValues:
        """Read processor context registers at an address (e.g. ARM TMode, x86 longMode).

        Context registers steer disassembly: TMode=1 means Thumb on ARM. Use
        before set_context_register, or to see why bytes disassembled the way they
        did. Returns {address, registers: [{register, value}]}.
        """
        addr = resolve_address(address)
        regs = (
            [_context_register(register)]
            if register
            else list(session.program.getProgramContext().getContextRegisters())
        )
        return ContextValues(
            address=format_address(addr.getOffset()),
            registers=[
                ContextValue(register=str(r.getName()), value=_context_value(r, addr)) for r in regs
            ],
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"processor"})
    @session.require_open
    def set_context_register(
        start: Address,
        register: Annotated[str, Field(description='Context register. Example: "TMode"')],
        value: Annotated[int, Field(ge=0, description="Value to set. Example: 1")],
        end: Annotated[
            str,
            Field(description='Last address (inclusive); empty for just start. Example: "0x8100"'),
        ] = "",
    ) -> ContextSet:
        """Set a processor context register over an address range.

        Use to fix code disassembled in the wrong mode, e.g. ARM bytes that are
        really Thumb: clear_code_units on the range, set_context_register(TMode=1),
        then disassemble_at (or reanalyze_range). Returns {register, start, end,
        value, verified}.
        """
        from java.math import BigInteger  # noqa: PLC0415

        reg = _context_register(register)
        first = resolve_address(start)
        last = resolve_address(end) if end else first
        ctx = session.program.getProgramContext()
        try:
            ctx.setValue(reg, first, last, BigInteger.valueOf(value))
        except Exception as exc:
            if "ContextChangeException" not in type(exc).__name__ + str(exc):
                raise
            raise GhidraError(
                "Instructions in the range were disassembled with the old value; "
                "clear_code_units on the range first, then set it and disassemble_at.",
                error_type="ContextConflict",
            ) from exc
        return ContextSet(
            register=str(reg.getName()),
            start=format_address(first.getOffset()),
            end=format_address(last.getOffset()),
            value=value,
            verified=_context_value(reg, first) == value,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def list_relocations(
        address: Annotated[
            str, Field(description='Only relocations at this address; empty for all. Example: ""')
        ] = "",
        filter_pattern: FilterPattern = "",
        offset: Offset = 0,
        limit: Limit = 200,
    ) -> dict:
        """List the loader's relocation entries (where the binary is patched at load time).

        Use to see which slots get an import's address (GOT/IAT entries name
        their symbol) or why bytes differ from the file. filter_pattern matches
        the symbol name. Returns a page {items: [{address, type, symbol, bytes,
        values, status}], total, offset, limit, has_more}.
        """
        table = session.program.getRelocationTable()
        rels = table.getRelocations(resolve_address(address)) if address else table.getRelocations()
        filt = compile_filter(filter_pattern)
        items = []
        for rel in rels:
            symbol = str(rel.getSymbolName() or "")
            if filt and not filt.search(symbol):
                continue
            raw = rel.getBytes()
            items.append(
                {
                    "address": format_address(rel.getAddress().getOffset()),
                    "type": int(rel.getType()),
                    "symbol": symbol,
                    "bytes": bytes(b & 0xFF for b in raw).hex() if raw is not None else "",
                    "values": [int(v) for v in (rel.getValues() or [])],
                    "status": str(rel.getStatus()),
                }
            )
        return paginate(items, offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"search"})
    @session.require_open
    def find_constant_uses(
        value: Annotated[
            str,
            Field(
                description=(
                    "Constant to find, decimal or 0x hex, negative allowed; empty to use "
                    'min_value/max_value. Example: "0xedb88320"'
                )
            ),
        ] = "",
        min_value: Annotated[str, Field(description='Range start. Example: "0x1000"')] = "",
        max_value: Annotated[str, Field(description='Range end. Example: "0x1fff"')] = "",
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Find instructions whose operands contain a constant (or one in a range).

        Use for magic numbers (crypto constants, protocol IDs, error codes, struct
        sizes), including displacements like [ebx+0x7f3a]. A negative value also
        matches its two's-complement form at the operand's width. Operands that
        are addresses (have a reference) are flagged is_address. Returns a page
        {items: [{address, function, operand, value, is_address, instruction}],
        total, offset, limit, has_more}.
        """
        from ghidra.program.model.scalar import Scalar  # noqa: PLC0415

        if bool(value) == bool(min_value or max_value):
            raise GhidraError(
                "Give value, or min_value and max_value.", error_type="InvalidArgument"
            )
        try:
            lo = hi = int(value, 0) if value else None
            if not value:
                lo, hi = int(min_value or "0", 0), int(max_value or "0", 0)
        except ValueError as exc:
            raise GhidraError(f"Not a number: {exc}", error_type="InvalidArgument") from exc

        def matches(scalar) -> int | None:
            for candidate in (int(scalar.getUnsignedValue()), int(scalar.getSignedValue())):
                if lo <= candidate <= hi:
                    return candidate
            if value and lo < 0:
                wrapped = lo & ((1 << scalar.bitLength()) - 1)
                if int(scalar.getUnsignedValue()) == wrapped:
                    return lo
            return None

        program = session.program
        fm = program.getFunctionManager()
        items = []
        for insn in program.getListing().getInstructions(True):
            for op in range(insn.getNumOperands()):
                hit = None
                for obj in insn.getOpObjects(op):
                    if isinstance(obj, Scalar):
                        hit = matches(obj)
                        if hit is not None:
                            break
                if hit is None:
                    continue
                func = fm.getFunctionContaining(insn.getAddress())
                items.append(
                    {
                        "address": format_address(insn.getAddress().getOffset()),
                        "function": str(func.getName()) if func else "",
                        "operand": op,
                        "value": hit,
                        "is_address": bool(insn.getOperandReferences(op)),
                        "instruction": str(insn),
                    }
                )
                break
        return paginate(items, offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"comments"})
    @session.require_open
    def search_comments(
        pattern: Annotated[
            str,
            Field(description='Case-insensitive regex over comment text. Example: "TODO|FIXME"'),
        ],
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Search every comment in the program (all five kinds) for a regex.

        Use to find your own notes or imported annotations. Returns a page
        {items: [{address, kind, function, text}], total, offset, limit,
        has_more}.
        """
        from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

        filt = compile_filter(pattern)
        if filt is None:
            raise GhidraError("pattern is required.", error_type="InvalidArgument")
        kinds = {
            "eol": CodeUnit.EOL_COMMENT,
            "pre": CodeUnit.PRE_COMMENT,
            "post": CodeUnit.POST_COMMENT,
            "plate": CodeUnit.PLATE_COMMENT,
            "repeatable": CodeUnit.REPEATABLE_COMMENT,
        }
        program = session.program
        listing = program.getListing()
        fm = program.getFunctionManager()
        everything = program.getMemory()
        items = []
        for kind in COMMENT_KINDS:
            it = listing.getCommentAddressIterator(kinds[kind], everything, True)
            while it.hasNext():
                addr = it.next()
                text = str(listing.getComment(kinds[kind], addr) or "")
                if filt.search(text):
                    func = fm.getFunctionContaining(addr)
                    items.append(
                        {
                            "address": format_address(addr.getOffset()),
                            "kind": kind,
                            "function": str(func.getName()) if func else "",
                            "text": text,
                        }
                    )
        items.sort(key=lambda i: (int(i["address"], 16), i["kind"]))
        return paginate(items, offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def find_function_candidates(
        min_refs: Annotated[
            int, Field(ge=1, description="Least references a candidate needs. Example: 2")
        ] = 1,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Find referenced code that is not inside any function (likely missed functions).

        Complements find_code_gaps: this one starts from references, so it finds
        call targets and function pointers in data. A target counts if it holds an
        instruction, is in an executable block, is inside no function, or is
        called. create_function on a candidate makes it a function. Returns a page
        {items: [{address, refs, calls, sample_from}], total, offset, limit,
        has_more}, most-referenced first.
        """
        program = session.program
        listing = program.getListing()
        fm = program.getFunctionManager()
        mem = program.getMemory()
        found: dict[int, dict] = {}
        it = program.getReferenceManager().getReferenceIterator(program.getMinAddress())
        while it.hasNext():
            ref = it.next()
            to = ref.getToAddress()
            if not to.isMemoryAddress() or listing.getInstructionAt(to) is None:
                continue
            if fm.getFunctionAt(to) is not None:
                continue
            block = mem.getBlock(to)
            if block is None or not block.isExecute() or block.isExternalBlock():
                continue
            is_call = ref.getReferenceType().isCall()
            if fm.getFunctionContaining(to) is not None and not is_call:
                continue  # a branch or table target inside a function
            entry = found.setdefault(
                to.getOffset(),
                {
                    "address": format_address(to.getOffset()),
                    "refs": 0,
                    "calls": 0,
                    "sample_from": format_address(ref.getFromAddress().getOffset()),
                },
            )
            entry["refs"] += 1
            entry["calls"] += int(is_call)
        items = sorted(
            (e for e in found.values() if e["refs"] >= min_refs), key=lambda e: -e["refs"]
        )
        return paginate(items, offset, limit)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def set_function_thunk(
        address: Address,
        target: Annotated[
            str,
            Field(
                description=(
                    "Function it forwards to (address or name); empty makes it a normal "
                    'function again. Example: "malloc"'
                )
            ),
        ] = "",
    ) -> ThunkResult:
        """Mark a function as a thunk (a stub that only jumps to another), or undo it.

        A thunk takes the target's name and signature, and calls through it count
        as calls to the target. Refuses a function thunking to itself. Returns
        {address, target, target_name}.
        """
        func = resolve_function(address)
        if not target:
            func.setThunkedFunction(None)
            return ThunkResult(
                address=format_address(func.getEntryPoint().getOffset()), target="", target_name=""
            )
        dest = resolve_function(target)
        if dest.getEntryPoint().equals(func.getEntryPoint()):
            raise GhidraError("A function cannot thunk to itself.", error_type="InvalidArgument")
        func.setThunkedFunction(dest)
        return ThunkResult(
            address=format_address(func.getEntryPoint().getOffset()),
            target=format_address(dest.getEntryPoint().getOffset()),
            target_name=str(dest.getName()),
        )
