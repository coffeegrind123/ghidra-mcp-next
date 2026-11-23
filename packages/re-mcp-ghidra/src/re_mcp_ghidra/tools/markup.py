# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Equates, function tags and C++ class membership."""

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
    compile_filter,
    format_address,
    resolve_address,
    resolve_function,
)
from re_mcp_ghidra.session import session

OperandIndex = Annotated[
    int, Field(ge=0, description="Operand position in the instruction, from 0. Example: 1")
]


class EquateInfo(BaseModel):
    name: str = Field(description="Equate name.")
    value: int = Field(description="The constant it stands for.")
    references: int = Field(description="Operands displaying it.")


class EquateList(BaseModel):
    items: list[EquateInfo] = Field(description="Equates by name.")
    total: int = Field(description="Number listed.")


class TagInfo(BaseModel):
    name: str = Field(description="Tag name.")
    comment: str = Field(description="Tag description.")
    functions: int = Field(description="Functions carrying it.")


class TagList(BaseModel):
    items: list[TagInfo] = Field(description="Tags by name.")
    total: int = Field(description="Number listed.")


class FunctionTags(BaseModel):
    address: str = Field(description="Function entry point.")
    name: str = Field(description="Function name.")
    tags: list[str] = Field(description="Its tags now.")


class ClassMember(BaseModel):
    address: str = Field(description="Function entry point.")
    name: str = Field(description="Function name (without the class).")
    signature: str = Field(description="Prototype, with the this parameter when Ghidra adds one.")


class ClassInfo(BaseModel):
    name: str = Field(description="Class (namespace) path.")
    members: list[ClassMember] = Field(description="Functions in the class.")


def _scalar(insn, operand: int):
    scalar = insn.getScalar(operand)
    if scalar is None:
        raise GhidraError(
            f"Operand {operand} of {insn} has no constant.", error_type="InvalidArgument"
        )
    return scalar


def _class_namespace(name: str, create: bool):
    from ghidra.app.util import NamespaceUtils  # noqa: PLC0415
    from ghidra.program.model.symbol import SourceType, SymbolType  # noqa: PLC0415

    program = session.program
    found = NamespaceUtils.getNamespaceByPath(program, None, name)  # a java List
    ns = found.get(0) if found is not None and not found.isEmpty() else None
    if ns is None:
        if not create:
            raise GhidraError(f"No class {name!r}.", error_type="NotFound")
        parent, _, leaf = name.rpartition("::")
        parent_ns = (
            NamespaceUtils.createNamespaceHierarchy(parent, None, program, SourceType.USER_DEFINED)
            if parent
            else program.getGlobalNamespace()
        )
        return program.getSymbolTable().createClass(parent_ns, leaf, SourceType.USER_DEFINED)
    if ns.getSymbol().getSymbolType() != SymbolType.CLASS:
        if not create:
            raise GhidraError(f"{name!r} is a namespace, not a class.", error_type="NotFound")
        ns = NamespaceUtils.convertNamespaceToClass(ns)
    return ns


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"names"})
    @session.require_open
    def set_equate(
        address: Address,
        operand: OperandIndex,
        name: Annotated[
            str, Field(description='Name to show for the constant. Example: "SOCK_STREAM"')
        ],
    ) -> EquateInfo:
        """Show a named constant in place of a number in one instruction operand.

        Use to make magic numbers readable (flags, error codes, IDs). Reuses an
        existing equate of that name if its value matches, and fails with
        InvalidArgument if the name already stands for another value. Returns
        the equate {name, value, references}.
        """
        program = session.program
        addr = resolve_address(address)
        insn = program.getListing().getInstructionAt(addr)
        if insn is None:
            raise GhidraError(
                f"No instruction at {format_address(addr.getOffset())}.", error_type="NotFound"
            )
        value = int(_scalar(insn, operand).getValue())
        table = program.getEquateTable()
        eq = table.getEquate(name)
        if eq is None:
            eq = table.createEquate(name, value)
        elif int(eq.getValue()) != value:
            raise GhidraError(
                f"{name} already means {eq.getValue()}, not {value}.", error_type="InvalidArgument"
            )
        old = table.getEquate(addr, operand, value)
        if old is not None and old.getName() != name:
            old.removeReference(addr, operand)
        eq.addReference(addr, operand)
        return EquateInfo(
            name=str(eq.getName()), value=int(eq.getValue()), references=int(eq.getReferenceCount())
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"names"})
    @session.require_open
    def remove_equate(address: Address, operand: OperandIndex) -> EquateInfo:
        """Show an operand's number again instead of its equate name.

        Fails with NotFound if the operand has no equate. An equate left with no
        references is deleted. Returns the equate as it was {name, value,
        references}.
        """
        program = session.program
        addr = resolve_address(address)
        table = program.getEquateTable()
        for eq in table.getEquates(addr, operand):
            info = EquateInfo(
                name=str(eq.getName()),
                value=int(eq.getValue()),
                references=int(eq.getReferenceCount()),
            )
            eq.removeReference(addr, operand)
            if eq.getReferenceCount() == 0:
                table.removeEquate(eq.getName())
            return info
        raise GhidraError(
            f"No equate on operand {operand} at {format_address(addr.getOffset())}.",
            error_type="NotFound",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"names"})
    @session.require_open
    def list_equates(filter_pattern: FilterPattern = "") -> EquateList:
        """List the program's equates (named constants).

        Returns {items: [{name, value, references}], total}.
        """
        filt = compile_filter(filter_pattern)
        items = [
            EquateInfo(
                name=str(eq.getName()),
                value=int(eq.getValue()),
                references=int(eq.getReferenceCount()),
            )
            for eq in session.program.getEquateTable().getEquates()
            if not filt or filt.search(str(eq.getName()))
        ]
        items.sort(key=lambda e: e.name)
        return EquateList(items=items, total=len(items))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def tag_function(
        address: Address,
        add: Annotated[
            list[str], Field(description='Tags to add (created if new). Example: ["CRYPTO"]')
        ] = [],  # noqa: B006 -- pydantic copies the default; never mutated
        remove: Annotated[list[str], Field(description='Tags to take off. Example: ["TODO"]')] = [],  # noqa: B006 -- pydantic copies the default; never mutated
    ) -> FunctionTags:
        """Add or remove tags on a function (free-form labels for grouping).

        Use to mark what a function is for (CRYPTO, NETWORK, PARSER) or its
        review state; list_function_tags shows them all. Returns {address, name,
        tags}.
        """
        func = resolve_function(address)
        for tag in add:
            func.addTag(tag)
        for tag in remove:
            func.removeTag(tag)
        return FunctionTags(
            address=format_address(func.getEntryPoint().getOffset()),
            name=str(func.getName()),
            tags=sorted(str(t.getName()) for t in func.getTags()),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def list_function_tags() -> TagList:
        """List function tags with how many functions carry each.

        Use list_functions to see which functions; tag_function adds or removes
        tags. Returns {items: [{name, comment, functions}], total}.
        """
        program = session.program
        counts: dict[str, int] = {}
        for func in program.getFunctionManager().getFunctions(True):
            for tag in func.getTags():
                counts[str(tag.getName())] = counts.get(str(tag.getName()), 0) + 1
        items = [
            TagInfo(
                name=str(t.getName()),
                comment=str(t.getComment() or ""),
                functions=counts.get(str(t.getName()), 0),
            )
            for t in program.getFunctionManager().getFunctionTagManager().getAllFunctionTags()
        ]
        items.sort(key=lambda t: t.name)
        return TagList(items=items, total=len(items))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"functions"})
    @session.require_open
    def set_function_class(
        address: Address,
        class_name: Annotated[
            str,
            Field(
                description=(
                    "Class to put the method in, :: for nesting; created if missing. "
                    'Example: "net::Connection"'
                )
            ),
        ],
        thiscall: Annotated[
            bool,
            Field(
                description=(
                    "Also switch to the __thiscall convention (when this compiler has it), "
                    "so Ghidra adds a typed this parameter. Example: true"
                )
            ),
        ] = True,
    ) -> ClassMember:
        """Make a function a method of a C++ class.

        Ghidra types the method's this parameter as a pointer to the structure
        named like the class (create it first, e.g. with parse_type_declaration,
        to get field names in the decompiler). Returns the method {address,
        name, signature}.
        """
        func = resolve_function(address)
        ns = _class_namespace(class_name, create=True)
        func.setParentNamespace(ns)
        if thiscall:
            names = [str(n) for n in func.getProgram().getCompilerSpec().getCallingConventions()]
            conv = "__thiscall" if any(n.endswith("__thiscall") for n in names) else None
            if conv is not None:
                func.setCallingConvention(conv)
        return ClassMember(
            address=format_address(func.getEntryPoint().getOffset()),
            name=str(func.getName()),
            signature=str(func.getPrototypeString(True, True)),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"functions"})
    @session.require_open
    def list_class_members(
        class_name: Annotated[
            str, Field(description='Class name or path. Example: "net::Connection"')
        ],
    ) -> ClassInfo:
        """List the methods of a C++ class.

        Returns {name, members: [{address, name, signature}]}.
        """
        ns = _class_namespace(class_name, create=False)
        members = []
        for sym in session.program.getSymbolTable().getChildren(ns.getSymbol()):
            func = session.program.getFunctionManager().getFunctionAt(sym.getAddress())
            if func is not None and func.getParentNamespace().equals(ns):
                members.append(
                    ClassMember(
                        address=format_address(func.getEntryPoint().getOffset()),
                        name=str(func.getName()),
                        signature=str(func.getPrototypeString(True, True)),
                    )
                )
        return ClassInfo(
            name=str(ns.getName(True)), members=sorted(members, key=lambda m: m.address)
        )
