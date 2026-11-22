# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Instruction assembly tools."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_READ_ONLY,
    Address,
    format_address,
    read_memory,
    resolve_address,
    write_memory,
)
from re_mcp_ghidra.session import session


class AssembleResult(BaseModel):
    """Result of assembling an instruction."""

    address: str = Field(description="Target address (hex).")
    instruction: str = Field(description="Assembly instruction.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    assembled_bytes: str = Field(description="Assembled bytes (hex).")
    length: int = Field(description="Instruction length in bytes.")


class PatchAsmResult(BaseModel):
    """Result of patching with assembly."""

    address: str = Field(description="Target address (hex).")
    instruction: str = Field(description="Assembly instruction.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    new_bytes: str = Field(description="New bytes (hex).")
    length: int = Field(description="Instruction length in bytes.")
    patched: bool = Field(description="Whether bytes were patched.")


def _read_bytes_hex(program, addr, length: int) -> str:
    """Read bytes from the program memory and return as hex string."""
    mem = program.getMemory()
    try:
        return read_memory(mem, addr, length).hex()
    except Exception:
        return ""


def _assemble_at(program, addr, instruction: str) -> bytes:
    """Assemble an instruction at the given address.

    Returns the assembled bytes. Raises :class:`GhidraError` on failure.
    """
    from ghidra.app.plugin.assembler import Assemblers  # noqa: PLC0415

    try:
        assembler = Assemblers.getAssembler(program)
        # assembleLine returns byte[] directly
        result = assembler.assembleLine(addr, instruction)
        if result is None or len(result) == 0:
            raise GhidraError(
                f"Assembly produced no bytes: {instruction!r}",
                error_type="AssemblyFailed",
            )
        # Java byte[] elements are signed; mask to unsigned
        return bytes(b & 0xFF for b in result)
    except GhidraError:
        raise
    except Exception as e:
        raise GhidraError(
            f"Failed to assemble: {instruction!r}: {e}", error_type="AssemblyFailed"
        ) from e


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"disassembly", "assembler"})
    @session.require_open
    def assemble_instruction(
        address: Address,
        instruction: Annotated[
            str,
            Field(
                description="One instruction in the program's assembler syntax. "
                "Example: 'MOV EAX,0x1'"
            ),
        ],
    ) -> AssembleResult:
        """Assemble one instruction for an address without writing it (dry run).

        Use it to check encoding and length before patching; patch_instruction writes
        the result, patch_bytes writes raw hex. Returns address, instruction,
        old_bytes (current bytes over the same length), assembled_bytes and length.
        """
        program = session.program
        addr = resolve_address(address)
        assembled = _assemble_at(program, addr, instruction)
        old_bytes = _read_bytes_hex(program, addr, len(assembled))

        return AssembleResult(
            address=format_address(addr.getOffset()),
            instruction=instruction,
            old_bytes=old_bytes,
            assembled_bytes=assembled.hex(),
            length=len(assembled),
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"disassembly", "assembler"})
    @session.require_open
    def patch_instruction(
        address: Address,
        instruction: Annotated[
            str,
            Field(
                description="One instruction in the program's assembler syntax. "
                "Example: 'MOV EAX,0x1'"
            ),
        ],
    ) -> PatchAsmResult:
        """Assemble one instruction and overwrite the bytes at an address with it.

        Destructive; existing code units over the range are cleared and not
        re-disassembled. Use assemble_instruction for a dry run, patch_bytes for raw
        hex. Returns address, instruction, old_bytes, new_bytes, length and patched.
        """
        program = session.program
        addr = resolve_address(address)
        assembled = _assemble_at(program, addr, instruction)
        old_bytes = _read_bytes_hex(program, addr, len(assembled))

        write_memory(program, addr, assembled, label="Patch assembly")

        return PatchAsmResult(
            address=format_address(addr.getOffset()),
            instruction=instruction,
            old_bytes=old_bytes,
            new_bytes=assembled.hex(),
            length=len(assembled),
            patched=True,
        )
