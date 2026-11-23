# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Source language parsing tools -- import C declarations via Ghidra's CParser."""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE
from re_mcp_ghidra.session import session


class ParseSourceResult(BaseModel):
    """Result of parsing source declarations."""

    status: str = Field(description="Status message.")
    type_name: str = Field(description="Name of the last type the source declares.")
    kind: str = Field(description="That type's kind (struct, union, enum, typedef, other).")
    types: list[str] = Field(description="Every type the source added, in declaration order.")


def kind_of(dt) -> str:
    from ghidra.program.model.data import Enum, Structure, TypeDef, Union  # noqa: PLC0415

    for cls, name in (
        (Structure, "struct"),
        (Union, "union"),
        (Enum, "enum"),
        (TypeDef, "typedef"),
    ):
        if isinstance(dt, cls):
            return name
    return "other"


def parse_c_declarations(source: str):
    """Parse C declarations and store EVERY type they declare in the program.

    ``CParser(dtm)`` with a single argument returns only the last type parsed,
    and callers used to add just that one, so a header declaring several types
    silently kept only its last. ``CParser(dtm, True, None)`` stores each type
    in the data type manager as it is parsed.

    Returns ``(last_type, names)`` with the stored types' names in declaration
    order.  Raises ``GhidraError(ParseError)`` and stores nothing on failure.
    """
    from ghidra.app.util.cparser.C import CParser  # noqa: PLC0415

    program = session.program
    dtm = program.getDataTypeManager()
    tx_id = program.startTransaction("Parse C declarations")
    ok = False
    try:
        parser = CParser(dtm, True, None)
        try:
            last = parser.parse(source)
        except Exception as exc:
            raise GhidraError(f"Failed to parse source: {exc}", error_type="ParseError") from exc
        if last is None:
            raise GhidraError(f"Failed to parse source: {source!r}", error_type="ParseError")

        names: list[str] = []
        for declared in (parser.getComposites(), parser.getEnums(), parser.getTypes()):
            for dt in declared.values():
                stored = dtm.getDataType(dt.getDataTypePath())
                if stored is not None and str(stored.getName()) not in names:
                    names.append(str(stored.getName()))
        stored_last = dtm.getDataType(last.getDataTypePath()) or dtm.resolve(last, None)
        ok = True
        return stored_last, names
    finally:
        program.endTransaction(tx_id, ok)


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def parse_c_source(
        source: Annotated[
            str,
            Field(
                description="C type declaration text. "
                "Example: 'typedef struct { int x; int y; } point_t;'"
            ),
        ],
        language: Annotated[
            Literal["c"],
            Field(description="Source language; Ghidra's CParser supports only C. Example: 'c'"),
        ] = "c",
    ) -> ParseSourceResult:
        """Parse C declarations (a whole header) and add every type they declare.

        Use for several related types at once; parse_type_declaration takes one.
        Nothing is added if parsing fails. Apply a new type with
        apply_type_at_address. Returns status "parsed", types (every type added, in
        order), and type_name / kind of the last one.
        """
        if language.lower() != "c":
            raise GhidraError(
                f"Only C declarations are supported, got language={language!r}",
                error_type="InvalidArgument",
            )
        dt, names = parse_c_declarations(source)
        return ParseSourceResult(
            status="parsed", type_name=str(dt.getName()), kind=kind_of(dt), types=names
        )
