# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Function hashes, and exporting / applying a function's documentation.

The worker side of cross-binary documentation transfer.  Each worker holds
one program, so the supervisor's match_functions / propagate_documentation
(re_mcp_ghidra.backend) read hashes and documentation from the source
worker, match in Python, move the referenced data types through a temporary
.gdt archive, and apply everything to the target worker in one call (one
transaction, one undo step).

Hashes are Ghidra's own: Function ID's full and specific hashes (what FID
databases use) and the exact hashers Version Tracking's correlators use.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

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
    read_memory,
    resolve_function,
)
from re_mcp_ghidra.session import session

HashAlgorithm = Literal[
    "fid_specific", "fid_full", "exact_instructions", "exact_bytes", "exact_mnemonics"
]
DocField = Literal[
    "name", "prototype", "plate", "comments", "labels", "locals", "tags", "no_return"
]
ALL_FIELDS: tuple[str, ...] = (
    "name",
    "prototype",
    "plate",
    "comments",
    "labels",
    "locals",
    "tags",
    "no_return",
)
# Fields keyed by byte offset from the entry point: only valid when both bodies
# have the same layout (same size and code-unit count).
OFFSET_FIELDS = frozenset({"comments", "labels"})
COMMENT_KINDS = ("plate", "pre", "post", "eol", "repeatable")
MAX_HASH_PAGE = 5000
DEFAULT_NAME = re.compile(r"^(thunk_)?(FUN|SUB|LAB)_[0-9a-fA-F]+$")


class FunctionHash(BaseModel):
    address: str = Field(description="Function entry point.")
    name: str = Field(description="Current name.")
    is_default_name: bool = Field(description="Name was invented by analysis (FUN_...).")
    size: int = Field(description="Body size in bytes.")
    code_units: int = Field(description="Instructions hashed (FID skips padding/NOPs).")
    hash: str | None = Field(description="Hex hash, or null when too_small.")
    too_small: bool = Field(description="Too few instructions for this algorithm to hash.")


class FunctionHashList(BaseModel):
    algorithm: str = Field(description="Algorithm used.")
    items: list[FunctionHash] = Field(description="One entry per function, address order.")
    total: int = Field(description="Functions matching the filters.")
    offset: int = Field(description="Offset used.")
    limit: int = Field(description="Limit used.")
    has_more: bool = Field(description="More results past this page.")


class ApplyReport(BaseModel):
    functions: int = Field(description="Functions processed.")
    applied: dict[str, int] = Field(description="Per field, how many functions it changed.")
    skipped: list[dict[str, str]] = Field(
        description="What was not applied and why: [{address, field, reason}]."
    )


MAX_DATA_REPR = 200


def _is_default(func) -> bool:
    from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

    return bool(
        func.getSymbol().getSource() == SourceType.DEFAULT or DEFAULT_NAME.match(func.getName())
    )


def _hash(func, algorithm: str) -> tuple[str | None, int]:
    """(hex hash or None if too small, code units hashed)."""
    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    if algorithm.startswith("fid_"):
        quad = _fid_service().hashFunction(func)
        if quad is None:
            return None, 0
        value = quad.getFullHash() if algorithm == "fid_full" else quad.getSpecificHash()
        return f"{int(value) & 0xFFFFFFFFFFFFFFFF:016x}", int(quad.getCodeUnitSize())

    from ghidra.app.plugin.match import (  # noqa: PLC0415
        ExactBytesFunctionHasher,
        ExactInstructionsFunctionHasher,
        ExactMnemonicsFunctionHasher,
    )

    hasher = {
        "exact_instructions": ExactInstructionsFunctionHasher,
        "exact_bytes": ExactBytesFunctionHasher,
        "exact_mnemonics": ExactMnemonicsFunctionHasher,
    }[algorithm].INSTANCE
    units = sum(1 for _ in session.program.getListing().getInstructions(func.getBody(), True))
    if units == 0:
        return None, 0
    return f"{int(hasher.hash(func, TaskMonitor.DUMMY)) & 0xFFFFFFFFFFFFFFFF:016x}", units


_FID = None


def _fid_service():
    global _FID  # noqa: PLW0603
    if _FID is None:
        from ghidra.feature.fid.service import FidService  # noqa: PLC0415

        _FID = FidService()
    return _FID


def _comment_type(kind: str):
    from ghidra.program.model.listing import CodeUnit  # noqa: PLC0415

    return {
        "plate": CodeUnit.PLATE_COMMENT,
        "pre": CodeUnit.PRE_COMMENT,
        "post": CodeUnit.POST_COMMENT,
        "eol": CodeUnit.EOL_COMMENT,
        "repeatable": CodeUnit.REPEATABLE_COMMENT,
    }[kind]


def _type_ref(dt) -> dict[str, str]:
    return {"name": str(dt.getName()), "path": str(dt.getPathName())}


def export_documentation(func) -> dict[str, Any]:
    """Everything a function carries that documents it, as plain data."""
    from ghidra.program.model.symbol import SourceType, SymbolType  # noqa: PLC0415

    program = session.program
    listing = program.getListing()
    entry = func.getEntryPoint()
    body = func.getBody()

    comments = []
    for kind in COMMENT_KINDS:
        it = listing.getCommentAddressIterator(_comment_type(kind), body, True)
        while it.hasNext():
            addr = it.next()
            if kind == "plate" and addr.equals(entry):
                continue
            comments.append(
                {
                    "offset": int(addr.subtract(entry)),
                    "kind": kind,
                    "text": str(listing.getComment(_comment_type(kind), addr)),
                }
            )

    labels = []
    for sym in program.getSymbolTable().getSymbols(body, SymbolType.LABEL, True):
        if sym.getSource() == SourceType.DEFAULT:
            continue
        labels.append({"offset": int(sym.getAddress().subtract(entry)), "name": str(sym.getName())})

    types_used: list[str] = []

    def use(dt) -> dict[str, str]:
        ref = _type_ref(dt)
        if ref["path"] not in types_used:
            types_used.append(ref["path"])
        return ref

    use(func.getReturnType())
    params = [
        {
            "ordinal": int(p.getOrdinal()),
            "name": str(p.getName()),
            "type": use(p.getDataType()),
            "storage": str(p.getVariableStorage()),
        }
        for p in func.getParameters()
    ]
    locals_ = [
        {
            "name": str(v.getName()),
            "type": use(v.getDataType()),
            "storage": str(v.getVariableStorage()),
            "user_defined": v.getSource() != SourceType.DEFAULT,
        }
        for v in func.getLocalVariables()
    ]

    units = sum(1 for _ in listing.getInstructions(body, True))
    return {
        "address": format_address(entry.getOffset()),
        "name": str(func.getName()),
        "is_default_name": _is_default(func),
        "prototype": str(func.getPrototypeString(True, True)),
        "prototype_is_default": func.getSignatureSource() == SourceType.DEFAULT,
        "calling_convention": str(func.getCallingConventionName()),
        "parameters": params,
        "locals": locals_,
        "plate": str(listing.getComment(_comment_type("plate"), entry) or ""),
        "comments": comments,
        "labels": labels,
        "tags": sorted(str(t.getName()) for t in func.getTags()),
        "no_return": bool(func.hasNoReturn()),
        "size": int(body.getNumAddresses()),
        "code_units": units,
        "types_used": types_used,
    }


def _apply_one(func, doc: dict[str, Any], fields: set[str], overwrite: str, report) -> None:
    from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

    from re_mcp_ghidra.programmable import registry  # noqa: PLC0415

    program = session.program
    listing = program.getListing()
    entry = func.getEntryPoint()
    where = format_address(entry.getOffset())

    def skip(field: str, reason: str) -> None:
        report["skipped"].append({"address": where, "field": field, "reason": reason})

    def done(field: str) -> None:
        report["applied"][field] = report["applied"].get(field, 0) + 1

    same_layout = int(doc.get("size", -1)) == int(func.getBody().getNumAddresses()) and int(
        doc.get("code_units", -1)
    ) == sum(1 for _ in listing.getInstructions(func.getBody(), True))

    if "name" in fields and not doc.get("is_default_name"):
        if overwrite == "always" or _is_default(func):
            if func.getName() != doc["name"]:
                func.setName(doc["name"], SourceType.USER_DEFINED)
                done("name")
        else:
            skip("name", f"target already named {func.getName()!r}")

    if "prototype" in fields and not doc.get("prototype_is_default"):
        if overwrite == "always" or func.getSignatureSource() == SourceType.DEFAULT:
            proto = doc["prototype"]
            # Our name may have just changed; the prototype must carry the target's name.
            proto = re.sub(
                r"\b" + re.escape(doc["name"]) + r"\s*\(", func.getName() + "(", proto, count=1
            )
            registry.call("set_function_prototype", {"address": where, "type_string": proto})
            done("prototype")
        else:
            skip("prototype", "target prototype already set")

    if "plate" in fields and doc.get("plate"):
        current = listing.getComment(_comment_type("plate"), entry)
        if overwrite == "always" or not current:
            listing.setComment(entry, _comment_type("plate"), doc["plate"])
            done("plate")
        else:
            skip("plate", "target already has a plate comment")

    for field in sorted(OFFSET_FIELDS & fields):
        if not doc.get(field):
            continue
        if not same_layout:
            skip(field, "bodies differ in size or instruction count; offsets would not line up")
            continue
        for item in doc[field]:
            addr = entry.add(int(item["offset"]))
            if field == "comments":
                ctype = _comment_type(item["kind"])
                if overwrite == "always" or not listing.getComment(ctype, addr):
                    listing.setComment(addr, ctype, item["text"])
            else:
                program.getSymbolTable().createLabel(addr, item["name"], SourceType.USER_DEFINED)
        done(field)

    if "locals" in fields and doc.get("locals"):
        by_storage = {str(v.getVariableStorage()): v for v in func.getLocalVariables()}
        dtm = program.getDataTypeManager()
        changed = False
        for item in doc["locals"]:
            if not item.get("user_defined"):
                continue
            var = by_storage.get(item["storage"])
            if var is None:
                skip("locals", f"no local at {item['storage']} for {item['name']!r}")
                continue
            if overwrite != "always" and var.getSource() != SourceType.DEFAULT:
                continue
            dt = dtm.getDataType(item["type"]["path"])
            if dt is not None:
                var.setDataType(dt, SourceType.USER_DEFINED)
            var.setName(item["name"], SourceType.USER_DEFINED)
            changed = True
        if changed:
            done("locals")

    if "tags" in fields and doc.get("tags"):
        for tag in doc["tags"]:
            func.addTag(tag)
        done("tags")

    if "no_return" in fields and doc.get("no_return") and not func.hasNoReturn():
        func.setNoReturn(True)
        done("no_return")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"matching"})
    @session.require_open
    def get_function_hashes(
        address: Annotated[
            str,
            Field(
                description=(
                    "One function (address or name); empty hashes every function, paged. "
                    'Example: "0x401000"'
                )
            ),
        ] = "",
        algorithm: Annotated[
            HashAlgorithm,
            Field(
                description=(
                    "fid_specific (default): Function ID hash with operand constants kept; "
                    "fid_full: Function ID hash with constants masked (survives relinking); "
                    "exact_instructions / exact_bytes / exact_mnemonics: Version Tracking's "
                    'exact hashers. Example: "fid_full"'
                )
            ),
        ] = "fid_specific",
        filter_pattern: FilterPattern = "",
        names: Annotated[
            Literal["all", "named", "unnamed"],
            Field(
                description=(
                    "named: only functions someone named; unnamed: only FUN_-style ones. "
                    'Example: "named"'
                )
            ),
        ] = "all",
        offset: Annotated[int, Field(ge=0, description="Pagination offset. Example: 0")] = 0,
        limit: Annotated[
            int,
            Field(ge=1, le=MAX_HASH_PAGE, description="Page size (max 5000). Example: 1000"),
        ] = 1000,
    ) -> FunctionHashList:
        """Hash functions to recognise the same code in another build or binary.

        Use with another database's hashes to find matching functions; the
        supervisor tools match_functions and propagate_documentation do this for
        you. Functions too small for the algorithm come back with hash null and
        too_small true. Thunks and externals are skipped. Returns {algorithm,
        items: [{address, name, is_default_name, size, code_units, hash,
        too_small}], total, offset, limit, has_more}.
        """
        if address:
            funcs = [resolve_function(address)]
        else:
            filt = compile_filter(filter_pattern)
            funcs = []
            for func in session.program.getFunctionManager().getFunctions(True):
                if func.isExternal() or func.isThunk():
                    continue
                if filt and not filt.search(func.getName()):
                    continue
                default = _is_default(func)
                if (names == "named" and default) or (names == "unnamed" and not default):
                    continue
                funcs.append(func)

        page = funcs[offset : offset + limit] if not address else funcs
        items = []
        for func in page:
            value, units = _hash(func, algorithm)
            items.append(
                FunctionHash(
                    address=format_address(func.getEntryPoint().getOffset()),
                    name=str(func.getName()),
                    is_default_name=_is_default(func),
                    size=int(func.getBody().getNumAddresses()),
                    code_units=units,
                    hash=value,
                    too_small=value is None,
                )
            )
        return FunctionHashList(
            algorithm=algorithm,
            items=items,
            total=len(funcs),
            offset=offset,
            limit=limit,
            has_more=not address and offset + limit < len(funcs),
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"matching"})
    @session.require_open
    def get_function_documentation(address: Address) -> dict:
        """Export everything that documents one function, as data.

        Use to copy documentation to a matching function elsewhere with
        apply_function_documentation (propagate_documentation does both ends).
        Returns {address, name, is_default_name, prototype, prototype_is_default,
        calling_convention, parameters, locals, plate, comments: [{offset, kind,
        text}], labels: [{offset, name}], tags, no_return, size, code_units,
        types_used: [data type paths]}. Offsets are bytes from the entry point.
        """
        return export_documentation(resolve_function(address))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"matching"})
    @session.require_open
    def apply_function_documentation(
        entries: Annotated[
            list[dict[str, Any]],
            Field(
                min_length=1,
                description=(
                    "[{address, documentation}] where documentation is a "
                    "get_function_documentation result from another database. Example: "
                    '[{"address": "0x401000", "documentation": {...}}]'
                ),
            ),
        ],
        fields: Annotated[
            list[DocField],
            Field(
                description=(
                    "What to copy. comments and labels are copied only when both bodies "
                    'have the same size and instruction count. Example: ["name", "prototype"]'
                )
            ),
        ] = list(ALL_FIELDS),  # noqa: B006 -- pydantic copies the default; never mutated
        overwrite: Annotated[
            Literal["default_only", "always"],
            Field(
                description=(
                    "default_only (default): only replace analysis defaults (FUN_ names, "
                    "default prototypes, empty comments); always: replace anything. "
                    'Example: "default_only"'
                )
            ),
        ] = "default_only",
    ) -> ApplyReport:
        """Apply exported function documentation to functions in this database.

        Use after matching functions across databases, or call
        propagate_documentation, which matches and applies in one step. Data types
        the prototypes and locals use must already exist here (propagate copies
        them first). All entries apply in one transaction: an error rolls back
        every entry. Returns {functions, applied: {field: count}, skipped:
        [{address, field, reason}]}.
        """
        wanted = set(fields)
        report: dict[str, Any] = {"applied": {}, "skipped": []}
        for entry in entries:
            if "address" not in entry or "documentation" not in entry:
                raise GhidraError(
                    "Each entry needs address and documentation.", error_type="InvalidArguments"
                )
            _apply_one(
                resolve_function(entry["address"]),
                entry["documentation"],
                wanted,
                overwrite,
                report,
            )
        return ApplyReport(functions=len(entries), **report)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"matching"})
    @session.require_open
    def export_function_signatures(
        names: Annotated[
            Literal["all", "named", "unnamed"],
            Field(description='Which functions to export. Example: "unnamed"'),
        ] = "all",
        min_instructions: Annotated[
            int,
            Field(ge=1, description="Skip functions shorter than this. Example: 8"),
        ] = 8,
        offset: Annotated[int, Field(ge=0, description="Pagination offset. Example: 0")] = 0,
        limit: Annotated[
            int, Field(ge=1, le=2000, description="Page size (max 2000). Example: 500")
        ] = 500,
    ) -> dict:
        """Export per-function features for fuzzy matching against another database.

        Use when exact hashes fail because the code changed a little;
        match_functions(algorithm="fuzzy") calls this on both databases and
        scores the pairs. Features: instruction, block, edge and call counts,
        callee identities (names for named callees, a Function ID hash for
        unnamed ones), referenced strings, small constants, and block hashes
        that ignore addresses. Thunks and externals are skipped; offset and
        limit count functions, so a page can hold fewer items. Returns {items:
        [{address, name, is_default_name, instructions, blocks, edges, calls,
        callees, strings, constants, block_hashes}], total, offset, limit,
        has_more}.
        """
        funcs = []
        for func in session.program.getFunctionManager().getFunctions(True):
            if func.isExternal() or func.isThunk():
                continue
            default = _is_default(func)
            if (names == "named" and default) or (names == "unnamed" and not default):
                continue
            funcs.append(func)
        # Pages are fixed slices of the function list, so a page may hold fewer
        # than limit items (short functions skipped) but never shifts the next.
        items = []
        for func in funcs[offset : offset + limit]:
            sig = function_signature(func)
            if sig["instructions"] >= min_instructions:
                items.append(sig)
        return {
            "items": items,
            "total": len(funcs),
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < len(funcs),
        }

    @mcp.tool(name="_function_facts", annotations=ANNO_READ_ONLY, tags={"internal"})
    @session.require_open
    def function_facts(addresses: list[str], body_bytes: bool = False) -> dict:
        """Internal: per-function size, callee identities and body digest (diff_programs)."""
        import hashlib  # noqa: PLC0415

        from ghidra.util.task import TaskMonitor  # noqa: PLC0415

        mem = session.program.getMemory()
        items = []
        for address in addresses:
            func = resolve_function(address)
            body = func.getBody()
            fact = {
                "address": format_address(func.getEntryPoint().getOffset()),
                "size": int(body.getNumAddresses()),
                "callees": sorted(
                    {_callee_identity(c) for c in func.getCalledFunctions(TaskMonitor.DUMMY)}
                ),
            }
            if body_bytes:
                digest = hashlib.sha256()
                try:
                    for rng in body:
                        digest.update(read_memory(mem, rng.getMinAddress(), int(rng.getLength())))
                    fact["body"] = digest.hexdigest()
                except Exception:  # unreadable or uninitialised: compares as changed
                    fact["body"] = None
            items.append(fact)
        return {"items": items}

    @mcp.tool(name="_defined_values", annotations=ANNO_READ_ONLY, tags={"internal"})
    @session.require_open
    def defined_values(what: str = "strings") -> dict:
        """Internal: every defined string, or every other defined datum, as text (diff_strings).

        Data reads "type=value"; a pointer's value is its target's name when
        someone named it, else "ptr", so relinking does not change it.
        """
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        program = session.program
        table = program.getSymbolTable()
        values = []
        for data in program.getListing().getDefinedData(True):
            if data.hasStringValue() != (what == "strings"):
                continue
            if what == "strings":
                values.append(str(data.getValue()))
                continue
            if data.isPointer():
                target = data.getValue()
                sym = table.getPrimarySymbol(target) if target is not None else None
                named = sym is not None and sym.getSource() != SourceType.DEFAULT
                shown = str(sym.getName(True)) if named else "ptr"
            else:
                shown = str(data.getDefaultValueRepresentation())[:MAX_DATA_REPR]
            values.append(f"{data.getDataType().getName()}={shown}")
        return {"values": values}

    @mcp.tool(name="_export_types", annotations=ANNO_READ_ONLY, tags={"internal"})
    @session.require_open
    def export_types(paths: list[str], archive: str) -> dict:
        """Internal: write the named data types (and what they use) to a .gdt archive."""
        from ghidra.program.model.data import FileDataTypeManager  # noqa: PLC0415
        from java.io import File  # noqa: PLC0415

        dtm = session.program.getDataTypeManager()
        out = FileDataTypeManager.createFileArchive(File(archive))
        tx = out.startTransaction("export")
        written = []
        try:
            for path in paths:
                dt = dtm.getDataType(path)
                if dt is None or _is_builtin(dt):
                    continue
                out.resolve(dt, None)
                written.append(path)
        finally:
            out.endTransaction(tx, True)
            out.save()
            out.close()
        return {"archive": archive, "types": written}

    @mcp.tool(name="_import_types", annotations=ANNO_MUTATE, tags={"internal"})
    @session.require_open
    def import_types(archive: str) -> dict:
        """Internal: add the archive's data types, keeping existing same-path types."""
        from ghidra.program.model.data import (  # noqa: PLC0415
            DataTypeConflictHandler,
            FileDataTypeManager,
        )
        from java.io import File  # noqa: PLC0415

        dtm = session.program.getDataTypeManager()
        src = FileDataTypeManager.openFileArchive(File(archive), False)
        added, kept = [], []
        try:
            it = src.getAllDataTypes()
            while it.hasNext():
                dt = it.next()
                path = str(dt.getPathName())
                if dtm.getDataType(path) is not None:
                    kept.append(path)
                    continue
                dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER)
                added.append(path)
        finally:
            src.close()
        return {"added": added, "kept_existing": kept}


def _callee_identity(callee) -> str:
    from re_mcp_ghidra.tools.program_analysis import _resolve_thunk  # noqa: PLC0415

    callee = _resolve_thunk(callee)
    if callee.isExternal() or not _is_default(callee):
        return "name:" + str(callee.getName())
    value, _ = _hash(callee, "fid_full")
    return "fid:" + value if value else "anon"


def function_signature(func) -> dict[str, Any]:
    """The feature vector match_functions(algorithm="fuzzy") scores."""
    import hashlib  # noqa: PLC0415

    from ghidra.util.task import TaskMonitor  # noqa: PLC0415

    from re_mcp_ghidra.tools.program_analysis import _blocks, _normalised  # noqa: PLC0415

    program = session.program
    listing = program.getListing()
    refs = program.getReferenceManager()
    lines = _normalised(func)
    insns = list(listing.getInstructions(func.getBody(), True))
    position = {i.getAddress().getOffset(): n for n, i in enumerate(insns)}
    blocks, succ, _ = _blocks(func)
    block_hashes = []
    for block in blocks:
        start = position.get(block.getFirstStartAddress().getOffset())
        if start is None:
            continue
        end = start
        while end < len(insns) and block.contains(insns[end].getAddress()):
            end += 1
        text = "\n".join(lines[start:end]).encode()
        block_hashes.append(hashlib.sha1(text, usedforsecurity=False).hexdigest()[:16])

    strings, constants = set(), set()
    for insn in insns:
        for ref in refs.getReferencesFrom(insn.getAddress()):
            data = listing.getDefinedDataAt(ref.getToAddress())
            if data is not None and data.hasStringValue():
                strings.add(str(data.getValue())[:200])
        for op in range(insn.getNumOperands()):
            scalar = insn.getScalar(op)
            if scalar is None or insn.getOperandReferences(op):
                continue
            value = int(scalar.getValue())
            if (
                1 < abs(value) < 0x10000
                and "SP" not in str(insn.getDefaultOperandRepresentation(op)).upper()
            ):
                constants.add(value)

    callees = sorted(_callee_identity(c) for c in func.getCalledFunctions(TaskMonitor.DUMMY))
    return {
        "address": format_address(func.getEntryPoint().getOffset()),
        "name": str(func.getName()),
        "is_default_name": _is_default(func),
        "instructions": len(insns),
        "blocks": len(blocks),
        "edges": sum(len(x) for x in succ),
        "calls": len(callees),
        "callees": callees,
        "strings": sorted(strings),
        "constants": sorted(constants),
        "block_hashes": sorted(block_hashes),
    }


def _is_builtin(dt) -> bool:
    from ghidra.program.model.data import BuiltInDataType, Pointer  # noqa: PLC0415

    while isinstance(dt, Pointer):
        dt = dt.getDataType()
        if dt is None:
            return True
    return isinstance(dt, BuiltInDataType)
