# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Instruction and operand analysis tools — decode instructions and their operands."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session


class OperandDetail(BaseModel):
    """Decoded operand information."""

    index: int = Field(description="Operand index.")
    representation: str = Field(description="Operand text representation.")
    type: str = Field(description="Operand type description.")
    value: str | None = Field(default=None, description="Scalar/address value (hex), if any.")


class DecodeInstructionResult(BaseModel):
    """Decoded instruction with operand details."""

    address: str = Field(description="Instruction address (hex).")
    mnemonic: str = Field(description="Instruction mnemonic.")
    disasm: str = Field(description="Full disassembly text.")
    size: int = Field(description="Instruction size in bytes.")
    operand_count: int = Field(description="Number of operands.")
    operands: list[OperandDetail] = Field(description="Operand details.")


class DecodedInstructionBrief(BaseModel):
    """Brief decoded instruction info."""

    address: str = Field(description="Instruction address (hex).")
    mnemonic: str = Field(description="Instruction mnemonic.")
    disasm: str = Field(description="Full disassembly text.")
    size: int = Field(description="Instruction size in bytes.")


class DecodeInstructionsResult(BaseModel):
    """Multiple decoded instructions."""

    start: str = Field(description="Start address (hex).")
    instruction_count: int = Field(description="Number of instructions decoded.")
    instructions: list[DecodedInstructionBrief] = Field(description="Decoded instructions.")


class GetOperandValueResult(BaseModel):
    """Operand value at an address."""

    address: str = Field(description="Instruction address (hex).")
    operand_index: int = Field(description="Operand index.")
    representation: str = Field(description="Operand text representation.")
    value: str | None = Field(description="Resolved operand value (hex) or null.")


def _get_instruction_at(program, addr):
    """Get the instruction at an address, raising GhidraError if none."""
    listing = program.getListing()
    insn = listing.getInstructionAt(addr)
    if insn is None:
        raise GhidraError(
            f"No instruction at {format_address(addr.getOffset())}",
            error_type="NotFound",
        )
    return insn


def _format_disasm(insn) -> str:
    """Format a full disassembly line from an instruction."""
    mnemonic = insn.getMnemonicString()
    operands = []
    for i in range(insn.getNumOperands()):
        op_str = insn.getDefaultOperandRepresentation(i)
        if op_str:
            operands.append(op_str)
    if operands:
        return f"{mnemonic} {', '.join(operands)}"
    return mnemonic


def _build_operand_detail(insn, index: int) -> OperandDetail:
    """Build an OperandDetail for a single operand."""
    representation = insn.getDefaultOperandRepresentation(index) or ""
    op_objects = insn.getOpObjects(index)

    op_type = "unknown"
    value = None

    if op_objects:
        obj = op_objects[0]
        obj_class = type(obj).__name__

        if "Register" in obj_class:
            op_type = "register"
        elif "Scalar" in obj_class:
            op_type = "scalar"
            value = format_address(obj.getUnsignedValue())
        elif "Address" in obj_class:
            op_type = "address"
            value = format_address(obj.getOffset())
        else:
            op_type = obj_class.lower()
    else:
        # Try to get scalar value directly
        scalar = insn.getScalar(index)
        if scalar is not None:
            op_type = "scalar"
            value = format_address(scalar.getUnsignedValue())

    return OperandDetail(
        index=index,
        representation=representation,
        type=op_type,
        value=value,
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"disassembly"})
    @session.require_open
    def decode_instruction(
        address: Address,
    ) -> DecodeInstructionResult:
        """Decode the single instruction at an address, with per-operand detail.

        Use decode_instructions for a run of instructions. Fails with NotFound when no
        instruction starts there. Returns address, mnemonic, disasm, size,
        operand_count and operands (index, representation, type, value); pass an
        operand index to get_operand_value or set_operand_format.
        """
        program = session.program
        addr = resolve_address(address)
        insn = _get_instruction_at(program, addr)

        num_ops = insn.getNumOperands()
        operands = [_build_operand_detail(insn, i) for i in range(num_ops)]

        return DecodeInstructionResult(
            address=format_address(addr.getOffset()),
            mnemonic=insn.getMnemonicString(),
            disasm=_format_disasm(insn),
            size=insn.getLength(),
            operand_count=num_ops,
            operands=operands,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"disassembly"})
    @session.require_open
    def decode_instructions(
        address: Address,
        count: Annotated[
            int,
            Field(
                description="Maximum number of instructions to decode (1-200). Example: 50",
                ge=1,
                le=200,
            ),
        ] = 20,
    ) -> DecodeInstructionsResult:
        """Decode up to count consecutive instructions from an address, ignoring function bounds.

        For ranges that cross function boundaries or are not in any function; use
        disassemble_function for one whole function, decode_instruction for operand
        detail. Stops early at the first address with no instruction (run
        disassemble_at first on raw bytes). Returns start, instruction_count and
        instructions (address, mnemonic, disasm, size).
        """
        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        instructions = []
        current = addr
        for _ in range(count):
            insn = listing.getInstructionAt(current)
            if insn is None:
                break
            instructions.append(
                DecodedInstructionBrief(
                    address=format_address(current.getOffset()),
                    mnemonic=insn.getMnemonicString(),
                    disasm=_format_disasm(insn),
                    size=insn.getLength(),
                )
            )
            current = current.add(insn.getLength())

        return DecodeInstructionsResult(
            start=format_address(addr.getOffset()),
            instruction_count=len(instructions),
            instructions=instructions,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"disassembly"})
    @session.require_open
    def get_operand_value(
        address: Address,
        operand_index: Annotated[
            int,
            Field(description="0-based operand index of the instruction. Example: 1"),
        ] = 0,
    ) -> GetOperandValueResult:
        """Get the numeric value of one instruction operand (immediate or referenced address).

        Use decode_instruction to see all operands at once. Fails with InvalidArgument
        when the index is out of range. Returns address, operand_index, representation
        and value (hex string, or null for operands with no scalar or address, such as
        a bare register).
        """
        program = session.program
        addr = resolve_address(address)
        insn = _get_instruction_at(program, addr)

        num_ops = insn.getNumOperands()
        if operand_index < 0 or operand_index >= num_ops:
            raise GhidraError(
                f"Operand index {operand_index} out of range (instruction has {num_ops} operands)",
                error_type="InvalidArgument",
            )

        representation = insn.getDefaultOperandRepresentation(operand_index) or ""

        # Try to resolve a scalar or address value
        value = None
        scalar = insn.getScalar(operand_index)
        if scalar is not None:
            value = format_address(scalar.getUnsignedValue())
        else:
            # Try opObjects for address references
            op_objects = insn.getOpObjects(operand_index)
            if op_objects:
                obj = op_objects[0]
                obj_class = type(obj).__name__
                if "Scalar" in obj_class:
                    value = format_address(obj.getUnsignedValue())
                elif "Address" in obj_class:
                    value = format_address(obj.getOffset())

        return GetOperandValueResult(
            address=format_address(addr.getOffset()),
            operand_index=operand_index,
            representation=representation,
            value=value,
        )
