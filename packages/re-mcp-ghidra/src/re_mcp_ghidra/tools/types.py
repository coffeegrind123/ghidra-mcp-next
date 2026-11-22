# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Type information tools — query and apply types."""

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
    paginate_iter,
    resolve_address,
)
from re_mcp_ghidra.session import session


class TypeInfoResult(BaseModel):
    address: str
    type_name: str = ""
    type_size: int | None = None
    function_signature: str = ""


class SetTypeResult(BaseModel):
    address: str
    type_name: str
    status: str


class LocalTypeItem(BaseModel):
    name: str
    category: str = ""
    size: int
    kind: str = Field(description="Type kind: struct, union, enum, typedef, etc.")


class ParseTypeResult(BaseModel):
    type_name: str
    size: int
    kind: str
    status: str


class ApplyTypeResult(BaseModel):
    address: str
    type_name: str
    status: str


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types"})
    @session.require_open
    def get_type_info(address: Address) -> TypeInfoResult:
        """Report what type is applied at an address: a function's prototype or a data item's type.

        Read-only; use get_structure for a struct's member layout. Returns address plus,
        for a function entry, type_name (return type) and function_signature; for
        defined data, type_name and type_size; otherwise only address.
        """
        program = session.program
        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        addr = resolve_address(address)

        # Check if there's a function at this address
        func = func_mgr.getFunctionAt(addr)
        if func:
            return TypeInfoResult(
                address=format_address(addr.getOffset()),
                type_name=str(func.getReturnType()),
                function_signature=func.getPrototypeString(False, False),
            )

        # Check for data type
        data = listing.getDataAt(addr)
        if data is not None:
            dt = data.getDataType()
            return TypeInfoResult(
                address=format_address(addr.getOffset()),
                type_name=dt.getName(),
                type_size=dt.getLength(),
            )

        return TypeInfoResult(
            address=format_address(addr.getOffset()),
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def set_type(
        address: Address,
        type_string: Annotated[
            str,
            Field(
                description="Type spelled as a built-in C name (int, unsigned short, "
                "char, ...) or the name of an existing type, matched case-insensitively, "
                "with optional trailing '*' for pointers. Example: 'char *'"
            ),
        ],
    ) -> SetTypeResult:
        """Define data of a C-style type at an address, clearing code units it overlaps.

        Accepts built-in names and pointer suffixes; use apply_type_at_address to apply an
        existing type by its exact (case-sensitive) name. Returns address, type_name and
        status "ok".
        """
        from re_mcp_ghidra.tools.structs import _parse_data_type  # noqa: PLC0415

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        dt = _parse_data_type(type_string)

        tx_id = program.startTransaction("Set type")
        try:
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set type: {e}", error_type="SetTypeFailed") from e

        return SetTypeResult(
            address=format_address(addr.getOffset()),
            type_name=type_string,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types"})
    @session.require_open
    def list_data_types(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> dict:
        """List locally defined data types."""
        from ghidra.program.model.data import (  # noqa: PLC0415
            Enum,
            FunctionDefinition,
            Structure,
            TypeDef,
            Union,
        )

        program = session.program
        dtm = program.getDataTypeManager()
        filt = compile_filter(filter_pattern)

        def _gen():
            for dt in dtm.getAllDataTypes():
                name = dt.getName()
                if filt and not filt.search(name):
                    continue

                kind = "other"
                if isinstance(dt, Structure):
                    kind = "struct"
                elif isinstance(dt, Union):
                    kind = "union"
                elif isinstance(dt, Enum):
                    kind = "enum"
                elif isinstance(dt, TypeDef):
                    kind = "typedef"
                elif isinstance(dt, FunctionDefinition):
                    kind = "function"

                cat = dt.getCategoryPath()
                yield LocalTypeItem(
                    name=name,
                    category=str(cat) if cat else "",
                    size=dt.getLength(),
                    kind=kind,
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def parse_type_declaration(
        declaration: Annotated[
            str,
            Field(
                description="One C type declaration (struct, union, enum or typedef). "
                "Example: 'struct point { int x; int y; };'"
            ),
        ],
    ) -> ParseTypeResult:
        """Parse one C type declaration and add the resulting type to the program.

        Defines a complete struct, enum or typedef in one call; use create_structure or
        create_enum to start an empty type. parse_c_source runs the same parser and also
        reports typedef as a kind. Returns type_name, size, kind (struct, union, enum or
        other) and status "parsed".
        """
        from ghidra.app.util.cparser.C import CParser  # noqa: PLC0415

        program = session.program
        dtm = program.getDataTypeManager()

        tx_id = program.startTransaction("Parse type declaration")
        try:
            parser = CParser(dtm)
            dt = parser.parse(declaration)
            if dt is None:
                program.endTransaction(tx_id, False)
                raise GhidraError(
                    f"Failed to parse declaration: {declaration!r}",
                    error_type="ParseError",
                )
            dtm.addDataType(dt, None)
            program.endTransaction(tx_id, True)

            kind = "other"
            from ghidra.program.model.data import Enum, Structure, Union  # noqa: PLC0415

            if isinstance(dt, Structure):
                kind = "struct"
            elif isinstance(dt, Union):
                kind = "union"
            elif isinstance(dt, Enum):
                kind = "enum"

            return ParseTypeResult(
                type_name=dt.getName(),
                size=dt.getLength(),
                kind=kind,
                status="parsed",
            )
        except GhidraError:
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to parse declaration: {e}", error_type="ParseError") from e

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def apply_type_at_address(
        address: Address,
        type_name: Annotated[
            str,
            Field(
                description="Exact, case-sensitive name of a type already in the program's "
                "data type manager. Example: 'IMAGE_NT_HEADERS32'"
            ),
        ],
    ) -> ApplyTypeResult:
        """Define data of an existing named type at an address, clearing code units it overlaps.

        The type must already exist (e.g. from parse_type_declaration); use set_type for
        C spellings such as 'char *'. Fails with NotFound for an unknown name. Returns
        address, type_name and status "applied".
        """
        program = session.program
        listing = program.getListing()
        dtm = program.getDataTypeManager()
        addr = resolve_address(address)

        # Find the named type
        dt = None
        for existing in dtm.getAllDataTypes():
            if existing.getName() == type_name:
                dt = existing
                break

        if dt is None:
            raise GhidraError(
                f"Type {type_name!r} not found. Use parse_type_declaration first.",
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Apply type at address")
        try:
            listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
            listing.createData(addr, dt)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to apply type: {e}", error_type="ApplyTypeFailed") from e

        return ApplyTypeResult(
            address=format_address(addr.getOffset()),
            type_name=type_name,
            status="applied",
        )
