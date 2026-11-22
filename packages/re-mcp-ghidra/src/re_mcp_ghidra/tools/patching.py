# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Binary modification tools — patching, code/function creation, undefine."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    Address,
    HexBytes,
    format_address,
    read_memory,
    resolve_address,
    write_memory,
)
from re_mcp_ghidra.session import session


class PatchBytesResult(BaseModel):
    """Result of patching bytes."""

    address: str = Field(description="Patch address (hex).")
    size: int = Field(description="Number of bytes patched.")
    old_bytes: str = Field(description="Previous bytes (hex).")
    new_bytes: str = Field(description="New bytes (hex).")


class CreateFunctionResult(BaseModel):
    """Result of creating a function."""

    address: str = Field(description="Function start address (hex).")
    name: str = Field(description="Function name.")
    end: str = Field(description="Function end address (hex, exclusive).")
    size: int = Field(description="Function size in bytes.")


class MakeCodeResult(BaseModel):
    """Result of converting to code."""

    address: str = Field(description="Target address (hex).")
    size: int = Field(description="Number of bytes disassembled.")
    status: str = Field(description="Status message.")


class UndefineResult(BaseModel):
    """Result of undefining an item."""

    address: str = Field(description="Target address (hex).")
    size: int = Field(description="Number of bytes undefined.")
    status: str = Field(description="Status message.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"modification", "patching"})
    @session.require_open
    def patch_bytes(
        address: Address,
        hex_bytes: HexBytes,
    ) -> PatchBytesResult:
        """Overwrite raw bytes at an address with literal hex bytes (destructive).

        Existing code units over the range are cleared first. Use patch_instruction to
        assemble and write an instruction from text instead of raw bytes. Accepts up to
        1 MB. Returns address, size, old_bytes and new_bytes (hex; old_bytes is empty
        when the previous bytes were unreadable).
        """
        program = session.program
        memory = program.getMemory()
        addr = resolve_address(address)

        # Parse hex bytes
        _MAX_PATCH_HEX_LEN = 2 * 1024 * 1024  # 1 MB of data = 2M hex chars
        cleaned = hex_bytes.replace(" ", "")
        if not cleaned:
            raise GhidraError("Empty hex string", error_type="InvalidArgument")
        if len(cleaned) > _MAX_PATCH_HEX_LEN:
            raise GhidraError(
                f"Patch data too large ({len(cleaned)} hex chars, max {_MAX_PATCH_HEX_LEN})",
                error_type="InvalidArgument",
            )
        try:
            new_bytes = bytes.fromhex(cleaned)
        except ValueError:
            raise GhidraError(
                f"Invalid hex string: {hex_bytes!r}", error_type="InvalidArgument"
            ) from None

        # Read old bytes for the response
        try:
            old_bytes = read_memory(memory, addr, len(new_bytes)).hex()
        except Exception:
            old_bytes = ""

        # Write new bytes (clear code units first to avoid conflicts)
        write_memory(program, addr, new_bytes, label="Patch bytes")

        return PatchBytesResult(
            address=format_address(addr.getOffset()),
            size=len(new_bytes),
            old_bytes=old_bytes,
            new_bytes=new_bytes.hex(),
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification"})
    @session.require_open
    def create_function(
        address: Address,
    ) -> CreateFunctionResult:
        """Define a function whose entry is the given address; Ghidra derives its body.

        Use disassemble_at to mark bytes as code without creating a function. Fails with
        CreateFailed when Ghidra cannot create one there. Returns the entry address,
        name, end (exclusive) and size in bytes.
        """
        from ghidra.app.cmd.function import CreateFunctionCmd  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)

        tx_id = program.startTransaction("Create function")
        try:
            cmd = CreateFunctionCmd(addr)
            success = cmd.applyTo(program)
            program.endTransaction(tx_id, success)
            if not success:
                raise GhidraError(
                    f"Failed to create function at {format_address(addr.getOffset())}",
                    error_type="CreateFailed",
                )
        except GhidraError:
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to create function: {e}", error_type="CreateFailed") from e

        func = program.getFunctionManager().getFunctionAt(addr)
        if func is None:
            raise GhidraError(
                f"Function created but not found at {format_address(addr.getOffset())}",
                error_type="CreateFailed",
            )

        body = func.getBody()
        entry = func.getEntryPoint().getOffset()
        end = body.getMaxAddress().getOffset() + 1 if body.getNumAddresses() > 0 else entry

        return CreateFunctionResult(
            address=format_address(entry),
            name=func.getName(),
            end=format_address(end),
            size=int(body.getNumAddresses()),
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification"})
    @session.require_open
    def disassemble_at(
        address: Address,
    ) -> MakeCodeResult:
        """Disassemble the single instruction at an address, without creating a function.

        Use it to turn misidentified data into code or to reach unanalysed code; use
        create_function when you also want a function boundary. Returns address, size
        (length of the instruction now at the address, 0 if none) and status "ok".
        """
        from ghidra.app.cmd.disassemble import DisassembleCommand  # noqa: PLC0415
        from ghidra.program.model.address import AddressSet  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)

        addr_set = AddressSet(addr, addr)

        tx_id = program.startTransaction("Disassemble at address")
        try:
            cmd = DisassembleCommand(addr_set, addr_set)
            success = cmd.applyTo(program, TaskMonitor.DUMMY)
            program.endTransaction(tx_id, success)
            if not success:
                raise GhidraError(
                    f"Failed to disassemble at {format_address(addr.getOffset())}",
                    error_type="CreateFailed",
                )
        except GhidraError:
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to disassemble: {e}", error_type="CreateFailed") from e

        # Get the resulting instruction size
        listing = program.getListing()
        insn = listing.getInstructionAt(addr)
        size = insn.getLength() if insn else 0

        return MakeCodeResult(
            address=format_address(addr.getOffset()),
            size=size,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"modification"})
    @session.require_open
    def clear_code_units(
        address: Address,
        size: Annotated[
            int,
            Field(description="Number of bytes from address to undefine. Example: 16"),
        ] = 1,
    ) -> UndefineResult:
        """Undefine code and data over a byte range, leaving the byte values unchanged.

        Use before re-typing or re-disassembling a region; patch_bytes changes the
        bytes themselves. Returns address, size and status "ok".
        """
        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)
        end_addr = addr.add(size - 1)

        tx_id = program.startTransaction("Undefine bytes")
        try:
            listing.clearCodeUnits(addr, end_addr, False)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to undefine {size} bytes at {format_address(addr.getOffset())}",
                error_type="UndefineFailed",
            ) from e

        return UndefineResult(
            address=format_address(addr.getOffset()),
            size=size,
            status="ok",
        )
