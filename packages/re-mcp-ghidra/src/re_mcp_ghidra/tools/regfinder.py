# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Register value at an instruction, by Ghidra's constant propagation.

Runs ``SymbolicPropogator`` over the containing function (the same engine
Ghidra's constant-propagation analyzer uses), which follows control flow,
knows that writing EAX replaces RAX, and treats a memory load as unknown
rather than mistaking its displacement for a value.
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
    resolve_address,
)
from re_mcp_ghidra.session import session


class FindRegisterValueResult(BaseModel):
    """Result of finding a register value."""

    address: str = Field(description="Address (hex).")
    register_name: str = Field(description="Register name.")
    found: bool = Field(description="Whether the value was determined.")
    reason: str | None = Field(default=None, description="Reason value could not be determined.")
    value: str | None = Field(default=None, description="Register value (hex).")
    source_address: str | None = Field(
        default=None, description="Address of the instruction that set the value (hex)."
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"analysis"})
    @session.require_open
    def find_register_value(
        address: Address,
        register_name: Annotated[
            str,
            Field(
                description="Register name as the processor defines it; tried as given, "
                "then upper- and lower-case. Example: 'ECX'"
            ),
        ],
    ) -> FindRegisterValueResult:
        """Compute a register's constant value just before an instruction executes.

        Runs Ghidra's constant propagation over the containing function, following
        control flow, so a value overwritten by a non-constant (a register copy, a
        memory load, a call result) is reported as unknown. Sub-registers work: EAX
        after "mov eax, 7" is 0x7, and so is RAX on x86-64. A value relative to a
        register (e.g. the stack pointer) is reported as unknown with the base named in
        reason. Returns address, register_name, found, and value plus source_address
        (the last instruction in the same basic block that wrote the register, when
        there is one) when found, or reason when not.
        """
        from ghidra.app.plugin.core.analysis import (  # noqa: PLC0415
            ConstantPropagationContextEvaluator,
        )
        from ghidra.program.model.block import BasicBlockModel  # noqa: PLC0415
        from ghidra.program.util import SymbolicPropogator  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)
        lang = program.getLanguage()
        reg = (
            lang.getRegister(register_name)
            or lang.getRegister(register_name.upper())
            or lang.getRegister(register_name.lower())
        )
        if reg is None:
            raise GhidraError(f"Unknown register: {register_name!r}", error_type="InvalidArgument")
        if program.getListing().getInstructionAt(addr) is None:
            raise GhidraError(
                f"No instruction at {format_address(addr.getOffset())}", error_type="NotFound"
            )
        func = program.getFunctionManager().getFunctionContaining(addr)
        if func is None:
            raise GhidraError(
                f"{format_address(addr.getOffset())} is not inside a function; create_function "
                "first.",
                error_type="NotFound",
            )

        def unknown(reason: str) -> FindRegisterValueResult:
            return FindRegisterValueResult(
                address=format_address(addr.getOffset()),
                register_name=register_name,
                found=False,
                reason=reason,
            )

        propagator = SymbolicPropogator(program)
        evaluator = ConstantPropagationContextEvaluator(TaskMonitor.DUMMY, True)
        propagator.flowConstants(
            func.getEntryPoint(), func.getBody(), evaluator, False, TaskMonitor.DUMMY
        )
        value = propagator.getRegisterValue(addr, reg)
        if value is None:
            return unknown("Not a constant here: no constant reaches this instruction.")
        if value.isRegisterRelativeValue():
            base = value.getRelativeRegister()
            return unknown(f"Relative to {base.getName() if base else 'a register'}, not constant.")

        return FindRegisterValueResult(
            address=format_address(addr.getOffset()),
            register_name=register_name,
            found=True,
            value=format_address(value.getValue() & ((1 << reg.getBitLength()) - 1)),
            source_address=_last_write_in_block(program, BasicBlockModel, addr, reg),
        )


def _last_write_in_block(program, block_model_cls, addr, reg) -> str | None:
    """The last instruction before *addr*, in its basic block, that writes *reg* (or a
    register overlapping it)."""
    block = block_model_cls(program).getFirstCodeBlockContaining(addr, None)
    if block is None:
        return None
    insn = program.getListing().getInstructionAt(addr).getPrevious()
    while insn is not None and block.contains(insn.getAddress()):
        for obj in insn.getResultObjects():
            if (
                hasattr(obj, "contains")
                and hasattr(obj, "getBaseRegister")
                and (obj.contains(reg) or reg.contains(obj))
            ):
                return format_address(insn.getAddress().getOffset())
        insn = insn.getPrevious()
    return None
