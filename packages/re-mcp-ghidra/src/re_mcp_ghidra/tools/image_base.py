# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Program rebasing tools."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    format_address,
    parse_address,
)
from re_mcp_ghidra.session import session


class SetImageBaseResult(BaseModel):
    """Result of rebasing the program."""

    old_base: str = Field(description="Previous image base address (hex).")
    new_base: str = Field(description="New image base address (hex).")
    delta: str = Field(description="Image base shift (hex).")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"memory_blocks"})
    @session.require_open
    def set_image_base(
        delta: Annotated[
            str,
            Field(
                description="Signed amount added to the current image base, as hex or "
                "decimal; a leading '-' shifts down. Example: '-0x1000'"
            ),
        ],
    ) -> SetImageBaseResult:
        """Move the whole program by shifting its image base by a signed delta.

        Destructive and global: every address in the program moves. Use it to match a
        runtime load address. Returns old_base, new_base and delta (all hex).
        """
        try:
            delta_val = -parse_address(delta[1:]) if delta.startswith("-") else parse_address(delta)
        except ValueError as e:
            raise GhidraError(str(e), error_type="InvalidAddress") from e

        program = session.program
        old_base = program.getImageBase()
        old_offset = old_base.getOffset()

        new_offset = old_offset + delta_val
        addr_factory = program.getAddressFactory()
        new_base = addr_factory.getDefaultAddressSpace().getAddress(new_offset)

        tx_id = program.startTransaction("Set image base")
        try:
            program.setImageBase(new_base, True)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to set image base: {e}", error_type="SetImageBaseFailed"
            ) from e

        delta_str = (
            format_address(delta_val) if delta_val >= 0 else f"-{format_address(-delta_val)}"
        )

        return SetImageBaseResult(
            old_base=format_address(old_offset),
            new_base=format_address(new_offset),
            delta=delta_str,
        )
