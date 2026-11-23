# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Import, export, and entry point enumeration tools."""

from __future__ import annotations

import difflib
from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Limit,
    Offset,
    format_address,
    format_location,
    paginate_iter,
)
from re_mcp_ghidra.session import session


class ImportItem(BaseModel):
    """An imported symbol."""

    module: str = Field(description="External library/module name.")
    address: str = Field(description="Import address (EXTERNAL:...).")
    name: str = Field(description="Import name.")
    original_name: str | None = Field(
        default=None, description="Name in the binary's import table, if renamed since."
    )
    ordinal: int | None = Field(
        default=None, description="Ordinal, for imports by ordinal (PE Ordinal_N)."
    )


ORDINAL_PREFIX = "Ordinal_"  # Ghidra's name for a PE import by ordinal (SymbolUtilities)


def _ordinal(*names: str | None) -> int | None:
    for name in names:
        if name and name.startswith(ORDINAL_PREFIX) and name[len(ORDINAL_PREFIX) :].isdigit():
            return int(name[len(ORDINAL_PREFIX) :])
    return None


class ImportReference(BaseModel):
    from_address: str = Field(description="Where the reference is.")
    function: str | None = Field(description="Function containing it.")
    ref_type: str = Field(description="Ghidra reference type.")
    is_call: bool = Field(description="A call (direct, or through the pointer).")
    via: str = Field(
        description=(
            "direct (to the import), thunk (to a stub that jumps to it) or pointer "
            "(reads its IAT/GOT slot, e.g. call [__imp_X])."
        )
    )


class ExportItem(BaseModel):
    """An exported symbol."""

    address: str = Field(description="Export address (hex).")
    name: str = Field(description="Export name.")


class EntryPointItem(BaseModel):
    """An entry point."""

    address: str = Field(description="Entry point address (hex).")
    name: str = Field(description="Entry point name.")


def _calls_through(insn) -> bool:
    """The instruction is a call (e.g. call [slot] reads the slot as data)."""
    return insn is not None and bool(insn.getFlowType().isCall())


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def list_imports(
        module_filter: str = "",
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all imported functions/symbols.

        Use module_filter to narrow results to a specific library (e.g.
        "kernel32", "libc"). After finding an import address, use
        get_xrefs_to to find all code that calls it, or find_import_references
        by name (also follows stubs and IAT/GOT slots). Returns {items: [{module,
        address, name, original_name, ordinal}], total, offset, limit, has_more}.

        Args:
            module_filter: Optional substring to filter module/library names (case-insensitive).
            offset: Pagination offset.
            limit: Maximum number of import entries.
        """
        program = session.program
        filter_lower = module_filter.lower()

        def _gen():
            ext_mgr = program.getExternalManager()
            for lib_name in ext_mgr.getExternalLibraryNames():
                if filter_lower and filter_lower not in lib_name.lower():
                    continue
                for ext_loc in ext_mgr.getExternalLocations(lib_name):
                    sym = ext_loc.getSymbol()
                    if sym is None:
                        continue
                    addr = ext_loc.getExternalSpaceAddress()
                    name = str(sym.getName())
                    original = ext_loc.getOriginalImportedName()
                    original = str(original) if original else None
                    yield ImportItem(
                        module=lib_name,
                        address=format_location(addr) if addr else "0x0",
                        name=name,
                        original_name=original if original != name else None,
                        ordinal=_ordinal(original, name),
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"xrefs"})
    @session.require_open
    def find_import_references(
        name: Annotated[
            str,
            Field(
                description=(
                    'Imported function, exact name (any case) or "Ordinal_N". '
                    'Example: "CreateFileW"'
                )
            ),
        ],
        library: Annotated[
            str, Field(description='Only from this library (any case). Example: "kernel32.dll"')
        ] = "",
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """Find every place that uses an imported function, however it is reached.

        Use to answer "who calls CreateFileW" in one step. Follows the three
        ways code reaches an import: a direct reference, a stub (thunk) that
        jumps to it, and a read of its IAT/GOT pointer slot (call [__imp_X];
        mov rax,[GOT]; call rax). Returns {items: [{from_address, function,
        ref_type, is_call, via}], total, offset, limit, has_more, imports:
        [matched import addresses]}.
        """
        program = session.program
        fm = program.getFunctionManager()
        refs = program.getReferenceManager()
        listing = program.getListing()
        mem = program.getMemory()
        wanted = name.lower()

        externals = []
        for func in fm.getExternalFunctions():
            loc = func.getExternalLocation()
            names = {str(func.getName()).lower()}
            original = loc.getOriginalImportedName() if loc is not None else None
            if original:
                names.add(str(original).lower())
            if wanted not in names:
                continue
            if library and (loc is None or str(loc.getLibraryName()).lower() != library.lower()):
                continue
            externals.append(func)
        if not externals:
            known = sorted({str(f.getName()) for f in fm.getExternalFunctions()})
            close = difflib.get_close_matches(name, known, n=5, cutoff=0.5)
            hint = f" Close matches: {', '.join(close)}." if close else ""
            raise GhidraError(
                f"No imported function {name!r}"
                + (f" from {library!r}" if library else "")
                + f". list_imports lists them.{hint}",
                error_type="NotFound",
            )

        ext_keys = {str(f.getEntryPoint()) for f in externals}
        thunks = []
        for func in fm.getFunctions(True):
            if func.isThunk():
                target = func.getThunkedFunction(True)
                if target is not None and str(target.getEntryPoint()) in ext_keys:
                    thunks.append(func)
        stub_keys = {str(t.getEntryPoint()) for t in thunks}

        found: dict[str, ImportReference] = {}

        def record(ref, via: str) -> None:
            src = ref.getFromAddress()
            caller = fm.getFunctionContaining(src)
            if caller is not None and str(caller.getEntryPoint()) in stub_keys:
                return  # the stub's own jump, not a use
            key = str(src)
            if key in found:
                return
            found[key] = ImportReference(
                from_address=format_location(src),
                function=str(caller.getName()) if caller is not None else None,
                ref_type=str(ref.getReferenceType()),
                is_call=bool(ref.getReferenceType().isCall())
                or _calls_through(listing.getInstructionAt(src)),
                via=via,
            )

        targets = [(f.getEntryPoint(), "direct") for f in externals]
        targets += [(t.getEntryPoint(), "thunk") for t in thunks]
        for target, via in targets:
            for ref in refs.getReferencesTo(target):
                src = ref.getFromAddress()
                if listing.getInstructionContaining(src) is not None:
                    record(ref, via)
                    continue
                block = mem.getBlock(src)
                data = listing.getDataContaining(src)
                if data is None or block is None or block.isExecute():
                    continue
                # An IAT/GOT slot holding the import's address: its readers use it.
                for slot_ref in refs.getReferencesTo(data.getAddress()):
                    if listing.getInstructionContaining(slot_ref.getFromAddress()) is not None:
                        record(slot_ref, "pointer")

        items = sorted(found.values(), key=lambda r: (r.function or "", r.from_address))
        page = paginate_iter((i.model_dump() for i in items), offset, limit)
        page["imports"] = sorted(format_location(f.getEntryPoint()) for f in externals)
        return page

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def list_exports(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all exported symbols.

        Good starting point for analyzing shared libraries or DLLs --
        exports are the public API. Use get_xrefs_to on an export address
        to find internal callers.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        sym_table = program.getSymbolTable()

        def _gen():
            sym_iter = sym_table.getAllSymbols(True)
            for sym in sym_iter:
                if sym.isExternalEntryPoint():
                    addr = sym.getAddress()
                    if addr.isExternalAddress():
                        continue
                    yield ExportItem(
                        address=format_address(addr.getOffset()),
                        name=sym.getName(),
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def list_entry_points(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List binary entry points (main/start/exports).

        Entry points are addresses where execution may begin. For shared
        libraries, list_exports is more complete (includes all exported symbols).

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        program = session.program
        sym_table = program.getSymbolTable()

        def _gen():
            sym_iter = sym_table.getAllSymbols(True)
            for sym in sym_iter:
                if sym.isExternalEntryPoint():
                    addr = sym.getAddress()
                    if addr.isExternalAddress():
                        continue
                    yield EntryPointItem(
                        address=format_address(addr.getOffset()),
                        name=sym.getName(),
                    ).model_dump()

        return paginate_iter(_gen(), offset, limit)
