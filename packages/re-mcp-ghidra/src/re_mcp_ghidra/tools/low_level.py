# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Low-level repairs: variable storage, flow overrides, secondary labels."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    Address,
    format_address,
    resolve_address,
    resolve_function,
)
from re_mcp_ghidra.session import session

FlowOverrideName = Literal["NONE", "BRANCH", "CALL", "CALL_RETURN", "RETURN"]
# "Stack[0x10]", "Stack[-8]:4", "EAX", "RDX:4"
_STACK = re.compile(r"^stack\[(-?(?:0x[0-9a-f]+|\d+))\]$", re.IGNORECASE)


class StorageResult(BaseModel):
    function: str = Field(description="Function entry point.")
    variable: str = Field(description="Variable name.")
    kind: str = Field(description="parameter or local.")
    previous_storage: str = Field(description="Storage before the change.")
    storage: str = Field(description="Storage now, as Ghidra reports it.")
    data_type: str = Field(description="The variable's data type now.")
    custom_storage_enabled: bool = Field(
        description="True if this enabled custom storage for the whole function's parameters."
    )


class FlowOverrideResult(BaseModel):
    address: str = Field(description="Instruction address.")
    previous: str = Field(description="Override before the change.")
    current: str = Field(description="Override now.")
    flow_type: str = Field(description="The instruction's effective flow type now.")


class RepairResult(BaseModel):
    address: str = Field(description="Seed address the flow was cleared from.")
    instructions_before: int = Field(description="Instructions in the containing function before.")
    instructions_after: int = Field(description="Instructions there after the repair.")


class LabelResult(BaseModel):
    address: str = Field(description="Label address.")
    name: str = Field(description="Label name.")
    namespace: str = Field(description="Namespace it lives in (Global for none).")
    primary: bool = Field(description="Whether it is the address's primary symbol.")


def _parse_storage(spec: str, default_size: int):
    """'EAX', 'ECX,EDX', 'Stack[0x10]:4' -> VariableStorage."""
    from ghidra.program.model.listing import VariableStorage  # noqa: PLC0415
    from ghidra.program.model.pcode import Varnode  # noqa: PLC0415

    program = session.program
    varnodes = []
    for raw in [p.strip() for p in spec.split(",") if p.strip()]:
        loc, _, size_text = raw.partition(":")
        size = int(size_text, 0) if size_text else None
        stack = _STACK.match(loc.strip())
        if stack:
            offset = int(stack.group(1), 0)
            space = program.getAddressFactory().getStackSpace()
            varnodes.append(Varnode(space.getAddress(offset), size or default_size))
            continue
        reg = program.getRegister(loc.strip()) or program.getRegister(loc.strip().upper())
        if reg is None:
            raise GhidraError(
                f"Unknown register {loc!r} in storage {spec!r}.", error_type="InvalidArgument"
            )
        reg_size = int(reg.getMinimumByteSize())
        size = size or min(default_size, reg_size) or reg_size
        if size > reg_size:
            raise GhidraError(
                f"{size} bytes do not fit in {reg.getName()} ({reg_size} bytes).",
                error_type="InvalidArgument",
            )
        varnodes.append(Varnode(reg.getAddress(), size))
    if not varnodes:
        raise GhidraError(f"Empty storage {spec!r}.", error_type="InvalidArgument")
    try:
        return VariableStorage(program, varnodes)
    except Exception as exc:
        raise GhidraError(f"Invalid storage {spec!r}: {exc}", error_type="InvalidArgument") from exc


def _instruction_count(func) -> int:
    if func is None:
        return 0
    return sum(1 for _ in session.program.getListing().getInstructions(func.getBody(), True))


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def set_variable_storage(
        function_address: Address,
        variable_name: Annotated[
            str, Field(description='Parameter or local, as listed. Example: "param_2"')
        ],
        storage: Annotated[
            str,
            Field(
                description=(
                    "Register(s) or stack slot, comma-separated pieces, each LOCATION[:size]: "
                    '"ECX", "EDX,EAX" (a value split over two), "Stack[0x8]:4". Example: "ECX"'
                )
            ),
        ],
        data_type: Annotated[
            str,
            Field(
                description=(
                    "Also change the type, to match the new storage; empty keeps it. "
                    'Example: "uint"'
                )
            ),
        ] = "",
    ) -> StorageResult:
        """Move a parameter or local to different storage (register or stack slot).

        Use when the decompiler reads a value from the wrong place, e.g. a
        __thiscall-like parameter Ghidra put on the stack that really arrives in
        ECX. Changing a parameter turns on custom storage for the whole function
        (its parameters then keep exactly the storage they have). Fails with
        InvalidArgument for an unknown register or a size that does not fit.
        Returns {function, variable, kind, previous_storage, storage, data_type,
        custom_storage_enabled}.
        """
        from ghidra.program.model.listing import Parameter  # noqa: PLC0415
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        func = resolve_function(function_address)

        def find():
            for var in func.getAllVariables():
                if var.getName() == variable_name:
                    return var
            names = ", ".join(str(v.getName()) for v in func.getAllVariables())
            raise GhidraError(
                f"No variable {variable_name!r} in {func.getName()} (has: {names}).",
                error_type="NotFound",
            )

        var = find()
        dt = var.getDataType()
        if data_type:
            from re_mcp_ghidra.tools.structs import _parse_data_type  # noqa: PLC0415

            dt = _parse_data_type(data_type)
        new_storage = _parse_storage(storage, int(dt.getLength()))
        previous = str(var.getVariableStorage())

        enabled = False
        if isinstance(var, Parameter) and not func.hasCustomVariableStorage():
            func.setCustomVariableStorage(True)
            enabled = True
            var = find()  # parameters are rebuilt when custom storage changes
        var.setDataType(dt, new_storage, True, SourceType.USER_DEFINED)
        var = find()
        if var.getVariableStorage().compareTo(new_storage) != 0:
            raise GhidraError(
                f"Ghidra stored {variable_name} at {var.getVariableStorage()}, not {new_storage}.",
                error_type="StorageRejected",
            )
        return StorageResult(
            function=format_address(func.getEntryPoint().getOffset()),
            variable=variable_name,
            kind="parameter" if isinstance(var, Parameter) else "local",
            previous_storage=previous,
            storage=str(var.getVariableStorage()),
            data_type=str(var.getDataType().getName()),
            custom_storage_enabled=enabled,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def set_flow_override(
        address: Address,
        override: Annotated[
            FlowOverrideName,
            Field(
                description=(
                    "NONE clears an override; BRANCH, CALL, CALL_RETURN (call that never "
                    'returns here) or RETURN replace the instruction\'s flow. Example: "NONE"'
                )
            ),
        ],
    ) -> FlowOverrideResult:
        """Set or clear an instruction's flow override.

        Use to undo a bad override (a jump Ghidra treats as a tail call, a call
        marked as not returning) or to force one, e.g. RETURN on an indirect jump
        that acts as a return. Follow with clear_flow_and_repair or
        run_auto_analysis to rebuild the code it affects. Returns {address,
        previous, current, flow_type}.
        """
        from ghidra.program.model.listing import FlowOverride  # noqa: PLC0415

        addr = resolve_address(address)
        insn = session.program.getListing().getInstructionAt(addr)
        if insn is None:
            raise GhidraError(
                f"No instruction at {format_address(addr.getOffset())}.", error_type="NotFound"
            )
        previous = str(insn.getFlowOverride())
        insn.setFlowOverride(FlowOverride.valueOf(override))
        insn = session.program.getListing().getInstructionAt(addr)
        return FlowOverrideResult(
            address=format_address(addr.getOffset()),
            previous=previous,
            current=str(insn.getFlowOverride()),
            flow_type=str(insn.getFlowType()),
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"functions"})
    @session.require_open
    def clear_flow_and_repair(address: Address) -> RepairResult:
        """Clear the code reached from an address, then let Ghidra re-disassemble it.

        Use after fixing what made analysis go wrong there (a wrong no-return
        callee, a bad flow override): code that analysis wrongly cut off or ran
        into is cleared and rebuilt from the remaining references. Labels and
        data are kept. One undo step reverses it. Returns {address,
        instructions_before, instructions_after} for the containing function.
        """
        from ghidra.app.plugin.core.clear import ClearFlowAndRepairCmd  # noqa: PLC0415
        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)
        fm = program.getFunctionManager()
        before = _instruction_count(fm.getFunctionContaining(addr))
        cmd = ClearFlowAndRepairCmd(addr, False, False, True)
        if not cmd.applyTo(program, TaskMonitor.DUMMY):
            raise GhidraError(
                f"Clear and repair failed: {cmd.getStatusMsg()}", error_type="RepairFailed"
            )
        return RepairResult(
            address=format_address(addr.getOffset()),
            instructions_before=before,
            instructions_after=_instruction_count(fm.getFunctionContaining(addr)),
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"names"})
    @session.require_open
    def create_label(
        address: Address,
        name: Annotated[str, Field(description='Label name. Example: "loop_head"')],
        namespace: Annotated[
            str,
            Field(
                description=(
                    "Existing namespace (e.g. a function or class name) to put it in; empty "
                    'for global. Example: "parse_packet"'
                )
            ),
        ] = "",
        primary: Annotated[
            bool,
            Field(description="Make it the address's primary (displayed) name. Example: false"),
        ] = False,
    ) -> LabelResult:
        """Add a label at an address, alongside any it already has.

        Use for extra names at one address (rename_symbol replaces the primary
        one instead). An identical label already there is left as is. At the
        entry of a function that still has its default FUN_ name, Ghidra makes
        the label the function's name. Returns {address, name, namespace,
        primary}.
        """
        from ghidra.app.cmd.label import SetLabelPrimaryCmd  # noqa: PLC0415
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)
        table = program.getSymbolTable()
        ns = program.getGlobalNamespace()
        if namespace:
            from ghidra.app.util import NamespaceUtils  # noqa: PLC0415

            found = NamespaceUtils.getNamespaceByPath(program, None, namespace)  # a java List
            if found is None or found.isEmpty():
                raise GhidraError(f"No namespace {namespace!r}.", error_type="NotFound")
            ns = found.get(0)
        sym = table.getSymbol(name, addr, ns) or table.createLabel(
            addr, name, ns, SourceType.USER_DEFINED
        )
        if primary and not sym.isPrimary():
            SetLabelPrimaryCmd(addr, name, ns).applyTo(program)
            sym = table.getSymbol(name, addr, ns)
        return LabelResult(
            address=format_address(addr.getOffset()),
            name=str(sym.getName()),
            namespace=str(sym.getParentNamespace().getName(True)),
            primary=bool(sym.isPrimary()),
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"names"})
    @session.require_open
    def delete_label(
        address: Address,
        name: Annotated[str, Field(description='Label to remove. Example: "loop_head"')],
    ) -> LabelResult:
        """Remove one label from an address (function names are refused).

        Use to drop a wrong or duplicate label; rename_symbol renames instead.
        Fails with NotFound if the address has no such label. Returns the removed
        label {address, name, namespace, primary}.
        """
        from ghidra.program.model.symbol import SymbolType  # noqa: PLC0415

        addr = resolve_address(address)
        for sym in session.program.getSymbolTable().getSymbols(addr):
            if sym.getName() != name:
                continue
            if sym.getSymbolType() != SymbolType.LABEL:
                raise GhidraError(
                    f"{name!r} is a {sym.getSymbolType()}, not a label; only labels are deleted.",
                    error_type="InvalidArgument",
                )
            removed = LabelResult(
                address=format_address(addr.getOffset()),
                name=name,
                namespace=str(sym.getParentNamespace().getName(True)),
                primary=bool(sym.isPrimary()),
            )
            sym.delete()
            return removed
        raise GhidraError(
            f"No label {name!r} at {format_address(addr.getOffset())}.", error_type="NotFound"
        )
