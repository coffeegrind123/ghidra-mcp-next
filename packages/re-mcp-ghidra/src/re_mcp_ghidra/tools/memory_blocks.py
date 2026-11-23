# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Memory block (memory_block) management tools."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    Address,
    format_address,
    format_permissions,
    resolve_address,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CreateMemoryBlockResult(BaseModel):
    """Result of creating a memory block."""

    name: str = Field(description="Block name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    permissions: str = Field(description="Permission string.")
    status: str = Field(description="Status.")


class DeleteMemoryBlockResult(BaseModel):
    """Result of deleting a memory block."""

    name: str = Field(description="Block name.")
    start: str = Field(description="Start address (hex).")
    end: str = Field(description="End address (hex, exclusive).")
    old_permissions: str = Field(description="Previous permissions.")
    status: str = Field(description="Status.")


class RenameMemoryBlockResult(BaseModel):
    """Result of renaming a memory block."""

    old_name: str = Field(description="Previous block name.")
    new_name: str = Field(description="New block name.")
    status: str = Field(description="Status.")


class SetMemoryBlockPermissionsResult(BaseModel):
    """Result of changing memory block permissions."""

    name: str = Field(description="Block name.")
    old_permissions: str = Field(description="Previous permissions.")
    permissions: str = Field(description="New permissions.")
    status: str = Field(description="Status.")


def _parse_permissions(perms: str) -> tuple[bool, bool, bool]:
    """Parse a permission string like 'RWX' or 'R-X' into (read, write, execute)."""
    perms = perms.upper().ljust(3, "-")
    read = perms[0] == "R"
    write = perms[1] == "W"
    execute = perms[2] == "X"
    return read, write, execute


def _resolve_block(addr):
    """Resolve an address to its containing memory block.

    Returns the MemoryBlock. Raises :class:`GhidraError` if not found.
    """
    program = session.program
    memory = program.getMemory()
    block = memory.getBlock(addr)
    if block is None:
        raise GhidraError(
            f"No memory block at {format_address(addr.getOffset())}",
            error_type="NotFound",
        )
    return block


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"memory_blocks"})
    @session.require_open
    def create_memory_block(
        name: Annotated[str, Field(description="Name for the new block. Example: '.mydata'")],
        start_address: Address,
        end_address: Address,
        permissions: Annotated[
            str,
            Field(
                description="Three-character R/W/X string, '-' for an absent permission "
                "(case-insensitive, short strings are padded with '-'). Example: 'R-X'"
            ),
        ] = "RW-",
    ) -> CreateMemoryBlockResult:
        """Create a new zero-filled, initialized memory block from start_address to end_address.

        end_address is exclusive and must be greater than start_address. Use
        set_memory_block_permissions or rename_memory_block to change an existing block.
        Returns name, start, end (exclusive), permissions and status "created".
        """
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        program = session.program
        start = resolve_address(start_address)
        end = resolve_address(end_address)

        start_offset = start.getOffset()
        end_offset = end.getOffset()
        if end_offset <= start_offset:
            raise GhidraError(
                "End address must be greater than start address",
                error_type="InvalidArgument",
            )
        size = end_offset - start_offset

        read, write, execute = _parse_permissions(permissions)

        memory = program.getMemory()
        tx_id = program.startTransaction("Create memory block")
        try:
            block = memory.createInitializedBlock(name, start, size, 0, TaskMonitor.DUMMY, False)
            block.setRead(read)
            block.setWrite(write)
            block.setExecute(execute)
            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to create memory block: {e}", error_type="CreateFailed"
            ) from e

        return CreateMemoryBlockResult(
            name=name,
            start=format_address(start_offset),
            end=format_address(end_offset),
            permissions=permissions,
            status="created",
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"memory_blocks"})
    @session.require_open
    def delete_memory_block(
        address: Address,
    ) -> DeleteMemoryBlockResult:
        """Delete the whole memory block containing an address, along with its bytes.

        Any address inside the block selects it; fails with NotFound when none does.
        Returns the removed block's name, start, end (exclusive), old_permissions and
        status "deleted".
        """
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)
        block = _resolve_block(addr)

        name = block.getName()
        start = format_address(block.getStart().getOffset())
        end = format_address(block.getEnd().getOffset() + 1)
        old_permissions = format_permissions(block.isRead(), block.isWrite(), block.isExecute())

        memory = program.getMemory()
        tx_id = program.startTransaction("Delete memory block")
        try:
            memory.removeBlock(block, TaskMonitor.DUMMY)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to delete memory block: {e}", error_type="DeleteFailed"
            ) from e

        return DeleteMemoryBlockResult(
            name=name,
            start=start,
            end=end,
            old_permissions=old_permissions,
            status="deleted",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"memory_blocks"})
    @session.require_open
    def rename_memory_block(
        address: Address,
        new_name: Annotated[
            str, Field(description="New name for the block. Example: '.rdata_decrypted'")
        ],
    ) -> RenameMemoryBlockResult:
        """Rename the memory block (memory_block) containing an address.

        Any address inside the block selects it. Only the name changes; use
        set_memory_block_permissions for R/W/X. Returns old_name, new_name and status
        "renamed".
        """
        program = session.program
        addr = resolve_address(address)
        block = _resolve_block(addr)

        old_name = block.getName()

        tx_id = program.startTransaction("Rename memory block")
        try:
            block.setName(new_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to rename memory block: {e}", error_type="RenameFailed"
            ) from e

        return RenameMemoryBlockResult(old_name=old_name, new_name=new_name, status="renamed")

    @mcp.tool(annotations=ANNO_MUTATE, tags={"memory_blocks"})
    @session.require_open
    def set_memory_block_permissions(
        address: Address,
        permissions: Annotated[
            str,
            Field(
                description="Three-character R/W/X string, '-' for an absent permission "
                "(case-insensitive, short strings are padded with '-'). Example: 'R-X'"
            ),
        ],
    ) -> SetMemoryBlockPermissionsResult:
        """Replace the read/write/execute flags of the memory block containing an address.

        Any address inside the block selects it. Returns the block name,
        old_permissions, the requested permissions and status "updated".
        """
        program = session.program
        addr = resolve_address(address)
        block = _resolve_block(addr)

        old_permissions = format_permissions(block.isRead(), block.isWrite(), block.isExecute())
        read, write, execute = _parse_permissions(permissions)

        tx_id = program.startTransaction("Set memory block permissions")
        try:
            block.setRead(read)
            block.setWrite(write)
            block.setExecute(execute)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set permissions: {e}", error_type="UpdateFailed") from e

        return SetMemoryBlockPermissionsResult(
            name=block.getName(),
            old_permissions=old_permissions,
            permissions=permissions,
            status="updated",
        )
