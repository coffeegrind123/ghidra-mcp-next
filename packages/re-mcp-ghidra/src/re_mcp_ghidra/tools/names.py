# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Naming and labeling tools."""

from __future__ import annotations

from typing import Annotated, Literal

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
    format_location,
    paginate_iter,
    resolve_address,
)
from re_mcp_ghidra.models import RenameResult
from re_mcp_ghidra.session import session


class NameItem(BaseModel):
    address: str = Field(description="Address (hex; space:offset outside the default space).")
    name: str = Field(description="Symbol name.")
    type: str = Field(description="Symbol type.")
    namespace: str = Field(default="", description="Namespace.")
    source: str = Field(default="", description="user, imported, analysis or default.")


_SOURCES = {"USER_DEFINED": "user", "IMPORTED": "imported", "ANALYSIS": "analysis"}


def _source(sym) -> str:
    return _SOURCES.get(str(sym.getSource()), "default")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"names"})
    @session.require_open
    def list_names(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
        source: Annotated[
            Literal["any", "user", "imported", "analysis", "default"],
            Field(
                description=(
                    "Who named it: user, imported (symbols/debug info), analysis, or "
                    'default (FUN_/DAT_-style). Example: "user"'
                )
            ),
        ] = "any",
        symbol_type: Annotated[
            str,
            Field(
                description=(
                    "Only this symbol type (function, label, class, namespace, "
                    'library, global_var, ...); empty for all. Example: "label"'
                )
            ),
        ] = "",
        include_external: Annotated[
            bool, Field(description="Include imported (EXTERNAL) symbols. Example: false")
        ] = True,
        exclude_default_names: Annotated[
            bool,
            Field(
                description=(
                    "Leave out names Ghidra made up (FUN_, LAB_, thunk_FUN_, switchD_, "
                    "s_..._addr), by their source, not their spelling. Example: true"
                )
            ),
        ] = False,
    ) -> dict:
        """List named locations: functions, labels, classes, imports and more.

        Use to find what has been named, by whom (source) or of what kind
        (symbol_type); list_functions lists functions with their bounds.
        Paginated, with an optional regex on the name. Returns {items:
        [{address, name, type, namespace, source}], total, offset, limit,
        has_more}.
        """
        program = session.program
        sym_table = program.getSymbolTable()
        filt = compile_filter(filter_pattern)
        wanted_type = symbol_type.strip().lower().replace(" ", "_")

        def _gen():
            sym_iter = sym_table.getAllSymbols(True)
            for sym in sym_iter:
                if sym.isDynamic():
                    continue
                if not include_external and sym.isExternal():
                    continue
                src = _source(sym)
                if exclude_default_names and src == "default":
                    continue
                if source != "any" and src != source:
                    continue
                kind = str(sym.getSymbolType())
                if wanted_type and kind.lower().replace(" ", "_") != wanted_type:
                    continue
                name = sym.getName()
                if filt and not filt.search(name):
                    continue
                ns = sym.getParentNamespace()
                yield NameItem(
                    address=format_location(sym.getAddress()),
                    name=name,
                    type=kind,
                    namespace=ns.getName() if ns and not ns.isGlobal() else "",
                    source=src,
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"names"})
    @session.require_open
    def rename_symbol(
        address: Address,
        new_name: Annotated[
            str,
            Field(description="New name for the symbol. Example: 'g_config_key'"),
        ],
    ) -> RenameResult:
        """Rename the primary symbol at an address, or create a label if it has none.

        Works for any address (data, code labels, function entries); rename_function
        is the function-specific variant. Returns address, old_name (the address
        itself when there was no symbol) and new_name.
        """
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        program = session.program
        addr = resolve_address(address)
        sym_table = program.getSymbolTable()

        sym = sym_table.getPrimarySymbol(addr)
        old_name = sym.getName() if sym else format_address(addr.getOffset())

        tx_id = program.startTransaction("Rename address")
        try:
            if sym:
                sym.setName(new_name, SourceType.USER_DEFINED)
            else:
                sym_table.createLabel(addr, new_name, SourceType.USER_DEFINED)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rename: {e}", error_type="RenameFailed") from e

        return RenameResult(
            address=format_address(addr.getOffset()),
            old_name=old_name,
            new_name=new_name,
        )
