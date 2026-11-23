# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Data and memory tools — read bytes, memory_blocks, etc."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    format_permissions,
    paginate,
    read_memory,
    resolve_address,
)
from re_mcp_ghidra.session import session


class ReadBytesResult(BaseModel):
    address: str
    size: int
    hex_data: str
    ascii: str = ""


class MemoryBlockInfo(BaseModel):
    name: str
    start: str
    end: str
    size: int
    permissions: str
    type: str = ""
    initialized: bool = True


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"data"})
    @session.require_open
    def read_bytes(
        address: Address,
        size: Annotated[
            int,
            Field(
                description="Number of bytes to read, at least 1; values above 4096 are "
                "capped at 4096. Example: 64"
            ),
        ] = 256,
    ) -> ReadBytesResult:
        """Read raw bytes from program memory starting at an address.

        Stops early at the first unreadable byte, so size in the result can be smaller
        than requested. Returns address, size (bytes actually read), hex_data
        (space-separated uppercase hex) and ascii (non-printables shown as '.').
        """
        if size > 4096:
            size = 4096
        if size < 1:
            raise GhidraError("size must be >= 1", error_type="InvalidArgument")

        program = session.program
        mem = program.getMemory()
        addr = resolve_address(address)

        try:
            data = read_memory(mem, addr, size)
        except Exception:
            buf = bytearray()
            for i in range(size):
                try:
                    buf.append(mem.getByte(addr.add(i)) & 0xFF)
                except Exception:
                    break
            data = bytes(buf)

        hex_str = " ".join(f"{b:02X}" for b in data)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)

        return ReadBytesResult(
            address=format_address(addr.getOffset()),
            size=len(data),
            hex_data=hex_str,
            ascii=ascii_str,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"data"})
    @session.require_open
    def list_memory_blocks(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all memory memory_blocks/blocks."""
        program = session.program
        mem = program.getMemory()
        blocks = list(mem.getBlocks())

        items = []
        for block in blocks:
            start = block.getStart()
            end = block.getEnd()
            items.append(
                MemoryBlockInfo(
                    name=block.getName(),
                    start=format_address(start.getOffset()),
                    end=format_address(end.getOffset()),
                    size=int(block.getSize()),
                    permissions=format_permissions(
                        block.isRead(),
                        block.isWrite(),
                        block.isExecute(),
                    ),
                    type=str(block.getType()) if block.getType() else "",
                    initialized=block.isInitialized(),
                ).model_dump()
            )

        return paginate(items, offset, limit)
