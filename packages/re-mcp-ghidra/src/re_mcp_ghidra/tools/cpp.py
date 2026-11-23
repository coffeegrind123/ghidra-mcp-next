# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""C++ virtual tables: layout, which tables hold a function, and who calls a slot.

Heuristic, for both layouts Ghidra meets:

    Itanium (GCC, Clang)            MSVC
    _ZTV / Class::vtable            [complete object locator]
    [offset_to_top]  slot -2        Class::vftable  -> slot 0
    [typeinfo ptr]   slot -1        [virtual fn]       slot 1 ...
    address point -> slot 0         [next table's COL]
    [virtual fn]     slot 1 ...

Slots count from the address point: the first function pointer, which is what
constructors store into the object and what `call [vptr + 8*slot]` indexes.
A table ends at a labelled address (Ghidra's RTTI analysis labels typeinfo,
vtables and vftables), at an address constructors reference (another table's
address point), or at two non-function entries in a row. One unlabelled
non-function entry between functions is kept: a pure-virtual slot bound to an
import is one. Ideas from cyberkaida/reverse-engineering-assistant (ReVa),
with its merge of adjacent MSVC tables fixed.
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
    format_location,
    resolve_address,
    resolve_function,
)
from re_mcp_ghidra.session import session

MAX_TABLE_ENTRIES = 1024
MAX_BLOCK_LOOKBACK = 32
VTABLE_MARKERS = ("vtable", "vftable", "_ZTV", "??_7")
RTTI_MARKERS = ("typeinfo", "_ZTI", "RTTI", "Complete_Object_Locator", "??_R4")
SLOT_KINDS = ("function", "code_no_function", "import")

_call_index: dict[int | None, list] = {}
_call_index_revision = [-1]


class VtableEntry(BaseModel):
    slot: int = Field(description="Index from the address point; negative for the header.")
    offset: int = Field(description="Byte offset from the address point.")
    address: str = Field(description="Where the entry is stored.")
    target: str | None = Field(description="Address the entry points to (none for integers).")
    function: str | None = Field(description="Function name at the target, if any.")
    signature: str | None = Field(default=None, description="Function prototype, if any.")
    kind: str = Field(
        description=(
            "function, code_no_function (instructions but no function), import "
            "(external, e.g. __cxa_pure_virtual), rtti (typeinfo / object locator), "
            "offset (integer header field), other."
        )
    )


class VtableLayout(BaseModel):
    address: str = Field(description="The address point (slot 0).")
    symbol: str | None = Field(description="Table label, when Ghidra has one.")
    class_name: str | None = Field(description="Class the table belongs to, when known.")
    pointer_size: int = Field(description="Bytes per entry.")
    structure: str | None = Field(description="Data type defined there, when it is a struct.")
    entries: list[VtableEntry] = Field(description="Header entries, then slots in order.")
    ended_by: str = Field(
        description="labelled_address, referenced_address, non_function, max_entries, memory_end."
    )


class VtableHit(BaseModel):
    vtable: str = Field(description="Address point of the table.")
    class_name: str | None = Field(description="Class the table belongs to, when known.")
    symbol: str | None = Field(description="Table label, when Ghidra has one.")
    slot: int = Field(description="Index from the address point.")
    offset: int = Field(description="Byte offset from the address point.")
    entry: str = Field(description="Where the pointer is stored.")


class VtableHits(BaseModel):
    function: str = Field(description="The function looked up.")
    items: list[VtableHit] = Field(description="Tables holding a pointer to it.")
    total: int = Field(description="Number of tables.")


class VirtualCall(BaseModel):
    address: str = Field(description="The indirect call instruction.")
    function: str | None = Field(description="Function containing the call.")
    offset: int = Field(description="Byte offset into the table the call reads.")
    confidence: str = Field(
        description=(
            "typed: the object's decompiled type is a pointer to a C++ class; "
            "offset_only: only the offset matches (verify)."
        )
    )
    object_type: str | None = Field(description="Decompiled type of the object pointer.")


class VirtualCalls(BaseModel):
    function: str = Field(description="The virtual function looked up.")
    offsets: list[int] = Field(description="Table offsets the function occupies.")
    items: list[VirtualCall] = Field(description="Indirect calls through those offsets.")
    total: int = Field(description="Matching calls before limit.")
    has_more: bool = Field(description="More matches than limit.")
    indirect_calls_scanned: int = Field(description="Indirect calls in the program.")


# ---------------------------------------------------------------------------
# Reading table entries
# ---------------------------------------------------------------------------


def _psize() -> int:
    return int(session.program.getDefaultPointerSize())


def _read_pointer(addr):
    """Pointer value stored at addr, or None (unreadable, or not an address)."""
    program = session.program
    data = program.getListing().getDataAt(addr)
    if data is not None and data.isPointer():
        value = data.getValue()
        if value is not None:
            return value
    try:
        size = _psize()
        mem = program.getMemory()
        raw = mem.getLong(addr) if size == 8 else mem.getInt(addr) & 0xFFFFFFFF
        raw &= (1 << (8 * size)) - 1
        return addr.getAddressSpace().getAddress(raw)
    except Exception:  # unreadable memory or an out-of-space value
        return None


def _raw_value(addr) -> int | None:
    try:
        size = _psize()
        mem = session.program.getMemory()
        raw = mem.getLong(addr) if size == 8 else mem.getInt(addr)
        return raw & ((1 << (8 * size)) - 1)
    except Exception:
        return None


def _names_at(addr) -> list[str]:
    return [str(s.getName(True)) for s in session.program.getSymbolTable().getSymbols(addr)]


def _labelled(addr) -> bool:
    """A symbol someone chose (not Ghidra's PTR_/DAT_ placeholders) starts here."""
    from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

    return any(
        s.getSource() != SourceType.DEFAULT
        for s in session.program.getSymbolTable().getSymbols(addr)
    )


def _code_referenced(addr) -> bool:
    """Code takes this address (a constructor storing an address point)."""
    listing = session.program.getListing()
    for ref in session.program.getReferenceManager().getReferencesTo(addr):
        if listing.getInstructionContaining(ref.getFromAddress()) is not None:
            return True
    return False


def _classify(entry_addr) -> tuple[str, object, object]:
    """(kind, target address or None, function or None) for one table entry."""
    program = session.program
    for ref in program.getReferenceManager().getReferencesFrom(entry_addr):
        if ref.isExternalReference():
            ext = ref.getExternalLocation()
            func = ext.getFunction() if ext is not None else None
            return "import", ref.getToAddress(), func
    target = _read_pointer(entry_addr)
    if target is None:
        return "offset", None, None
    func = program.getFunctionManager().getFunctionAt(target)
    if func is not None:
        return ("import" if func.isExternal() else "function"), target, func
    block = program.getMemory().getBlock(target)
    if block is None:
        return "offset", None, None
    if block.isExternalBlock():
        return "import", target, None
    if block.isExecute() and program.getListing().getInstructionAt(target) is not None:
        return "code_no_function", target, None
    names = _names_at(target)
    if any(m in n for n in names for m in RTTI_MARKERS):
        return "rtti", target, None
    return "other", target, None


def _class_of(names: list[str]) -> str | None:
    for name in names:
        if "::" in name and any(m in name for m in VTABLE_MARKERS + RTTI_MARKERS):
            return name.rsplit("::", 1)[0]
    return None


def _table_label(point) -> tuple[str | None, str | None]:
    """(symbol, class) for the table whose address point is `point`."""
    ps = _psize()
    for back in (0, 1, 2):
        try:
            names = _names_at(point.subtract(back * ps))
        except Exception:  # before the start of the address space
            break
        table = [n for n in names if any(m in n for m in VTABLE_MARKERS)]
        if table:
            return table[0], _class_of(table)
    # Itanium: the entry before the address point points at typeinfo.
    try:
        kind, target, _ = _classify(point.subtract(ps))
    except Exception:
        return None, None
    if kind == "rtti" and target is not None:
        return None, _class_of(_names_at(target))
    return None, None


def _entry(slot: int, addr, point) -> VtableEntry:
    kind, target, func = _classify(addr)
    if kind == "other" and slot < 0:
        value = _raw_value(addr)
        if value is not None and value < 0x10000:
            kind, target = "offset", None
    return VtableEntry(
        slot=slot,
        offset=int(addr.subtract(point)),
        address=format_location(addr),
        target=format_location(target) if target is not None else None,
        function=str(func.getName(True)) if func is not None else None,
        signature=str(func.getSignature().getPrototypeString()) if func is not None else None,
        kind=kind,
    )


def _address_point(addr):
    """Skip an Itanium header (offset_to_top, typeinfo) to the first slot."""
    ps = _psize()
    cur = addr
    for _ in range(3):
        kind, _, _ = _classify(cur)
        if kind in SLOT_KINDS:
            return cur
        cur = cur.add(ps)
    return addr


def _walk_slots(point, max_entries: int) -> tuple[list, str]:
    """Entry addresses from the address point to the end of the table."""
    ps = _psize()
    mem = session.program.getMemory()
    out = []
    cur = point
    while True:
        if len(out) >= max_entries:
            return out, "max_entries"
        if not mem.contains(cur):
            return out, "memory_end"
        if out and _labelled(cur):
            return out, "labelled_address"
        if out and _code_referenced(cur):
            return out, "referenced_address"
        kind, _, _ = _classify(cur)
        if kind not in SLOT_KINDS:
            nxt = cur.add(ps)
            gap_ok = (
                out
                and mem.contains(nxt)
                and not _labelled(nxt)
                and not _code_referenced(nxt)
                and _classify(nxt)[0] in SLOT_KINDS
            )
            if not gap_ok:
                return out, "non_function"
        out.append(cur)
        cur = cur.add(ps)


def _table_start(entry_addr):
    """Walk back from one entry to its table's address point."""
    ps = _psize()
    cur = entry_addr
    for _ in range(MAX_TABLE_ENTRIES):
        if _labelled(cur) or _code_referenced(cur):
            return cur
        try:
            prev = cur.subtract(ps)
        except Exception:
            return cur
        if _classify(prev)[0] in SLOT_KINDS:
            cur = prev
            continue
        # One unlabelled non-function entry (a pure-virtual import) may sit
        # between slots; a labelled one, or two in a row, is the table's edge.
        if _labelled(prev) or _code_referenced(prev):
            return cur
        try:
            before = prev.subtract(ps)
        except Exception:
            return cur
        if _classify(before)[0] not in SLOT_KINDS:
            return cur
        cur = before
    return cur


# ---------------------------------------------------------------------------
# Indirect calls and the table offset they read
# ---------------------------------------------------------------------------


def _offset_from_address_vn(vn, defs) -> int | None:
    """[reg + const] -> const, [reg] -> 0, anything else -> None."""
    if vn.isRegister():
        return 0
    op = defs.get(_vkey(vn))
    if op is None:
        return None
    mnem = op.getMnemonic()
    if mnem == "COPY" and op.getInput(0).isRegister():
        return 0
    if mnem in ("INT_ADD", "PTRADD", "PTRSUB"):
        a, b = op.getInput(0), op.getInput(1)
        if b.isConstant() and (a.isRegister() or _vkey(a) in defs):
            value = b.getOffset()
            size = b.getSize()
            if value >= 1 << (8 * size - 1):
                value -= 1 << (8 * size)
            return value
    return None


def _vkey(vn) -> tuple:
    return (str(vn.getAddress()), int(vn.getSize()))


def _call_offset(insn) -> int | None:
    """Table offset an indirect call reads, from the raw P-code.

    x86 `call [rax+0x10]`: the CALLIND target is a LOAD in the same
    instruction. ARM64 `ldr x8, [x9, #0x10]; blr x8`: the target register is
    loaded by an earlier instruction of the same basic block.
    """
    ops = list(insn.getPcode())
    callind = next((op for op in ops if op.getMnemonic() == "CALLIND"), None)
    if callind is None:
        return None
    target = callind.getInput(0)
    defs = {}
    for op in ops:
        if op.getOutput() is not None and op is not callind:
            defs[_vkey(op.getOutput())] = op
    while True:
        op = defs.get(_vkey(target))
        if op is not None and op.getMnemonic() == "LOAD":
            return _offset_from_address_vn(op.getInput(1), defs)
        if op is not None and op.getMnemonic() == "COPY":
            target = op.getInput(0)
            continue
        break
    if not target.isRegister():
        return None
    listing = session.program.getListing()
    prev = insn
    for _ in range(MAX_BLOCK_LOOKBACK):
        prev = listing.getInstructionBefore(prev.getAddress())
        if prev is None:
            return None
        flow = prev.getFlowType()
        if flow.isCall() or flow.isJump() or flow.isTerminal():
            return None
        pops = list(prev.getPcode())
        pdefs = {_vkey(o.getOutput()): o for o in pops if o.getOutput() is not None}
        op = pdefs.get(_vkey(target))
        if op is None:
            continue
        if op.getMnemonic() == "LOAD":
            return _offset_from_address_vn(op.getInput(1), pdefs)
        if op.getMnemonic() == "COPY" and op.getInput(0).isRegister():
            target = op.getInput(0)
            continue
        return None
    return None


def _indirect_calls() -> dict[int | None, list]:
    """Table offset (None: not recognised) -> indirect call addresses; cached per revision."""
    rev = int(session.program.getModificationNumber())
    if _call_index_revision[0] == rev:
        return _call_index
    _call_index.clear()
    _call_index_revision[0] = rev
    for insn in session.program.getListing().getInstructions(True):
        flow = insn.getFlowType()
        if not (flow.isCall() and flow.isComputed()):
            continue
        _call_index.setdefault(_call_offset(insn), []).append(insn.getAddress())
    return _call_index


def _object_type(call_addr) -> str | None:
    """Decompiled type of the object whose table the call reads, if found."""
    from re_mcp_ghidra.tools.program_analysis import _high_function  # noqa: PLC0415

    func = session.program.getFunctionManager().getFunctionContaining(call_addr)
    if func is None:
        return None
    try:
        high = _high_function(func)
    except GhidraError:
        return None
    it = high.getPcodeOps(call_addr)
    while it.hasNext():
        op = it.next()
        if op.getMnemonic() != "CALLIND":
            continue
        vn = op.getInput(0)
        for _ in range(8):
            d = vn.getDef()
            if d is None:
                return None
            if d.getMnemonic() == "LOAD":
                vn = d.getInput(1)
                break
            vn = d.getInput(0)
        # vn: address of the slot; walk to the table pointer, then the object.
        for _ in range(8):
            d = vn.getDef()
            if d is None:
                break
            if d.getMnemonic() == "LOAD":
                obj = d.getInput(1)
                # The decompiler casts the object to long* to read its first word.
                while obj.getDef() is not None and obj.getDef().getMnemonic() in ("CAST", "COPY"):
                    obj = obj.getDef().getInput(0)
                hv = obj.getHigh()
                return str(hv.getDataType()) if hv is not None else None
            vn = d.getInput(0)
    return None


def _is_class_pointer(type_name: str | None) -> bool:
    if not type_name or not type_name.rstrip().endswith("*"):
        return False
    from ghidra.program.model.symbol import SymbolType  # noqa: PLC0415

    base = type_name.rstrip(" *").removeprefix("const ").strip()
    for sym in session.program.getSymbolTable().getSymbols(base.rsplit("::", 1)[-1]):
        if sym.getSymbolType() == SymbolType.CLASS:
            return True
    return False


def _tables_holding(entry) -> list[VtableHit]:
    """Tables with a pointer to the function at entry, with its slot in each."""
    listing = session.program.getListing()
    ps = _psize()
    hits: dict[str, VtableHit] = {}
    for ref in session.program.getReferenceManager().getReferencesTo(entry):
        src = ref.getFromAddress()
        if not src.isMemoryAddress() or listing.getInstructionContaining(src) is not None:
            continue
        target = _read_pointer(src)
        if target is None or not target.equals(entry):
            continue
        point = _table_start(src)
        slots, _ = _walk_slots(point, MAX_TABLE_ENTRIES)
        first = [_classify(a)[0] for a in slots[:5]]
        symbol, cls = _table_label(point)
        if symbol is None and sum(k in SLOT_KINDS for k in first) < 2:
            continue
        offset = int(src.subtract(point))
        hits[format_location(src)] = VtableHit(
            vtable=format_location(point),
            class_name=cls,
            symbol=symbol,
            slot=offset // ps,
            offset=offset,
            entry=format_location(src),
        )
    return sorted(hits.values(), key=lambda h: h.entry)


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"cpp"})
    @session.require_open
    def analyze_vtable(
        address: Address,
        max_entries: Annotated[
            int, Field(ge=1, le=MAX_TABLE_ENTRIES, description="Most slots to read. Example: 200")
        ] = 200,
    ) -> VtableLayout:
        """Read a C++ virtual table: each slot's target function and signature.

        Use on a vtable/vftable label or a constructor's stored pointer to see a
        class's virtual methods. Heuristic; handles Itanium (GCC/Clang: give the
        _ZTV label or the address point) and MSVC (vftable). Slots count from
        the address point, the first function pointer; an Itanium header shows
        as slots -2 (offset_to_top) and -1 (typeinfo). A struct defined at the
        address is read field by field. Returns {address, symbol, class_name,
        pointer_size, structure, entries: [{slot, offset, address, target,
        function, signature, kind}], ended_by}.
        """
        from ghidra.program.model.data import Structure  # noqa: PLC0415

        start = resolve_address(address)
        ps = _psize()
        data = session.program.getListing().getDataAt(start)
        if data is not None and isinstance(data.getDataType(), Structure):
            struct = data.getDataType()
            entries = [
                _entry(i, start.add(comp.getOffset()), start)
                for i, comp in enumerate(struct.getComponents())
                if i < max_entries
            ]
            symbol, cls = _table_label(start)
            return VtableLayout(
                address=format_location(start),
                symbol=symbol,
                class_name=cls,
                pointer_size=ps,
                structure=str(struct.getName()),
                entries=entries,
                ended_by="structure_end"
                if len(entries) == struct.getNumComponents()
                else "max_entries",
            )

        point = _address_point(start)
        slots, ended_by = _walk_slots(point, max_entries)
        if not slots:
            raise GhidraError(
                f"No function pointers at {format_location(start)}: not a virtual table. "
                "find_vtables_containing finds tables from a method.",
                error_type="NotFound",
            )
        header = []
        cur = point
        for slot in (-1, -2):
            try:
                cur = cur.subtract(ps)
            except Exception:
                break
            if cur.compareTo(start) < 0:
                break
            header.insert(0, _entry(slot, cur, point))
        symbol, cls = _table_label(point)
        return VtableLayout(
            address=format_location(point),
            symbol=symbol,
            class_name=cls,
            pointer_size=ps,
            structure=None,
            entries=header + [_entry(i, a, point) for i, a in enumerate(slots)],
            ended_by=ended_by,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"cpp"})
    @session.require_open
    def find_vtables_containing(address: Address) -> VtableHits:
        """Find the virtual tables that hold a pointer to a function, and its slot.

        Use on a method to see which classes have it as a virtual method and at
        which slot (index from the address point, so the slot times the pointer
        size is the offset in `call [vptr + offset]`). Heuristic; Itanium and
        MSVC layouts. Returns {function, items: [{vtable, class_name, symbol,
        slot, offset, entry}], total}.
        """
        func = resolve_function(address)
        entry = func.getEntryPoint()
        items = _tables_holding(entry)
        return VtableHits(function=format_address(entry.getOffset()), items=items, total=len(items))

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"cpp"})
    @session.require_open
    def find_vtable_callers(
        address: Address,
        vtable: Annotated[
            str,
            Field(
                description=(
                    "Only this table's slot (its address or label); empty uses every "
                    'table holding the function. Example: "Dog::vtable"'
                )
            ),
        ] = "",
        limit: Annotated[int, Field(ge=1, le=5000, description="Most calls. Example: 100")] = 100,
        check_types: Annotated[
            bool,
            Field(
                description=(
                    "Decompile each calling function to check the object's type "
                    "(slower; sets confidence). Example: true"
                )
            ),
        ] = True,
    ) -> VirtualCalls:
        """Find indirect calls that may reach a virtual method through its table slot.

        Use to find who calls a C++ virtual method when no direct reference
        exists. Finds the method's slot offsets (find_vtables_containing), then
        every indirect call reading that offset from a table pointer (x86
        `call [reg+off]`, ARM64 `ldr x8, [x9, #off]; blr x8`). Any class with a
        method at the same offset matches too, so check_types marks calls whose
        object is a C++ class pointer `typed` and the rest `offset_only`.
        Returns {function, offsets, items: [{address, function, offset,
        confidence, object_type}], total, has_more, indirect_calls_scanned}.
        """
        func = resolve_function(address)
        entry = func.getEntryPoint()
        if vtable:
            point = _address_point(resolve_address(vtable))
            slots, _ = _walk_slots(point, MAX_TABLE_ENTRIES)
            offsets = sorted(
                {
                    int(a.subtract(point))
                    for a in slots
                    if (t := _read_pointer(a)) is not None and t.equals(entry)
                }
            )
            if not offsets:
                raise GhidraError(
                    f"{func.getName()} is not in the table at {format_location(point)}.",
                    error_type="NotFound",
                )
        else:
            offsets = sorted({h.offset for h in _tables_holding(entry)})
        index = _indirect_calls()
        fm = session.program.getFunctionManager()
        matches = sorted(
            ((off, addr) for off in offsets for addr in index.get(off, [])),
            key=lambda m: (m[1].getAddressSpace().getSpaceID(), m[1].getOffset()),
        )
        items = []
        for off, call in matches[:limit]:
            caller = fm.getFunctionContaining(call)
            obj = _object_type(call) if check_types else None
            items.append(
                VirtualCall(
                    address=format_location(call),
                    function=str(caller.getName(True)) if caller is not None else None,
                    offset=off,
                    confidence="typed" if _is_class_pointer(obj) else "offset_only",
                    object_type=obj,
                )
            )
        return VirtualCalls(
            function=format_address(entry.getOffset()),
            offsets=offsets,
            items=items,
            total=len(matches),
            has_more=len(matches) > limit,
            indirect_calls_scanned=sum(len(v) for v in index.values()),
        )
