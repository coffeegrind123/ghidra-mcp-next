# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Cross-reference manipulation tools -- add and delete xrefs."""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session


class XrefManipResult(BaseModel):
    """Result of adding a cross-reference."""

    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from", description="Source address (hex).")
    to: str = Field(description="Target address (hex).")
    type: str | None = Field(default=None, description="Cross-reference type.")


class DeleteXrefResult(BaseModel):
    """Result of deleting a cross-reference."""

    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from", description="Source address (hex).")
    to: str = Field(description="Target address (hex).")


_CODE_XREF_TYPES = {
    "UNCONDITIONAL_CALL": "UNCONDITIONAL_CALL",
    "CONDITIONAL_CALL": "CONDITIONAL_CALL",
    "UNCONDITIONAL_JUMP": "UNCONDITIONAL_JUMP",
    "CONDITIONAL_JUMP": "CONDITIONAL_JUMP",
    "FALL_THROUGH": "FALL_THROUGH",
}

_DATA_XREF_TYPES = {
    "READ": "READ",
    "WRITE": "WRITE",
    "READ_WRITE": "READ_WRITE",
    "DATA": "DATA",
    "INDIRECTION": "INDIRECTION",
}


def _get_ref_type(type_name: str, valid_types: dict):
    """Resolve a reference type name to a Ghidra RefType constant."""
    from ghidra.program.model.symbol import RefType  # noqa: PLC0415

    if type_name not in valid_types:
        raise GhidraError(
            f"Invalid xref type: {type_name!r}",
            error_type="InvalidArgument",
        )

    ref_type_map = {
        "UNCONDITIONAL_CALL": RefType.UNCONDITIONAL_CALL,
        "CONDITIONAL_CALL": RefType.CONDITIONAL_CALL,
        "UNCONDITIONAL_JUMP": RefType.UNCONDITIONAL_JUMP,
        "CONDITIONAL_JUMP": RefType.CONDITIONAL_JUMP,
        "FALL_THROUGH": RefType.FALL_THROUGH,
        "READ": RefType.READ,
        "WRITE": RefType.WRITE,
        "READ_WRITE": RefType.READ_WRITE,
        "DATA": RefType.DATA,
        "INDIRECTION": RefType.INDIRECTION,
    }

    rt = ref_type_map.get(type_name)
    if rt is None:
        raise GhidraError(
            f"Unsupported xref type: {type_name!r}",
            error_type="InvalidArgument",
        )
    return rt


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"xrefs"})
    @session.require_open
    def add_code_xref(
        from_address: Address,
        to_address: Address,
        xref_type: Annotated[
            Literal[
                "UNCONDITIONAL_CALL",
                "CONDITIONAL_CALL",
                "UNCONDITIONAL_JUMP",
                "CONDITIONAL_JUMP",
                "FALL_THROUGH",
            ],
            Field(description="Control-flow reference kind. Example: 'UNCONDITIONAL_JUMP'"),
        ] = "UNCONDITIONAL_CALL",
    ) -> XrefManipResult:
        """Add a user-defined call, jump or fall-through reference between two addresses.

        Use for flow the analyzer missed, such as an indirect call target; use
        add_data_xref for reads, writes or pointers to data. Returns the from and to
        addresses and type.
        """
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        program = session.program
        ref_mgr = program.getReferenceManager()
        frm = resolve_address(from_address)
        to = resolve_address(to_address)
        rt = _get_ref_type(xref_type, _CODE_XREF_TYPES)

        tx_id = program.startTransaction("Add code xref")
        try:
            ref_mgr.addMemoryReference(frm, to, rt, SourceType.USER_DEFINED, 0)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to add code xref: {e}", error_type="AddXrefFailed") from e

        return XrefManipResult(
            **{
                "from": format_address(frm.getOffset()),
                "to": format_address(to.getOffset()),
                "type": xref_type,
            }
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"xrefs"})
    @session.require_open
    def add_data_xref(
        from_address: Address,
        to_address: Address,
        xref_type: Annotated[
            Literal["READ", "WRITE", "READ_WRITE", "DATA", "INDIRECTION"],
            Field(description="Data-access reference kind. Example: 'WRITE'"),
        ] = "READ",
    ) -> XrefManipResult:
        """Add a user-defined data reference (read, write, pointer) between two addresses.

        Use when code or data accesses a location the analyzer did not link; use
        add_code_xref for calls, jumps and fall-through. Returns the from and to
        addresses and type.
        """
        from ghidra.program.model.symbol import SourceType  # noqa: PLC0415

        program = session.program
        ref_mgr = program.getReferenceManager()
        frm = resolve_address(from_address)
        to = resolve_address(to_address)
        rt = _get_ref_type(xref_type, _DATA_XREF_TYPES)

        tx_id = program.startTransaction("Add data xref")
        try:
            ref_mgr.addMemoryReference(frm, to, rt, SourceType.USER_DEFINED, 0)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to add data xref: {e}", error_type="AddXrefFailed") from e

        return XrefManipResult(
            **{
                "from": format_address(frm.getOffset()),
                "to": format_address(to.getOffset()),
                "type": xref_type,
            }
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"xrefs"})
    @session.require_open
    def delete_code_xref(
        from_address: Address,
        to_address: Address,
    ) -> DeleteXrefResult:
        """Remove the control-flow (call/jump) reference from one address to another.

        Matches only flow references; use delete_data_xref for data references. Fails
        with NotFound when no such reference exists. Returns the from and to addresses.
        """
        program = session.program
        ref_mgr = program.getReferenceManager()
        frm = resolve_address(from_address)
        to = resolve_address(to_address)

        # Find the specific reference to remove
        refs = ref_mgr.getReferencesFrom(frm)
        found = None
        for ref in refs:
            if ref.getToAddress().equals(to) and ref.getReferenceType().isFlow():
                found = ref
                break

        if found is None:
            raise GhidraError(
                f"No code xref from {format_address(frm.getOffset())} "
                f"to {format_address(to.getOffset())}",
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Delete code xref")
        try:
            ref_mgr.delete(found)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to delete code xref: {e}", error_type="DeleteXrefFailed"
            ) from e

        return DeleteXrefResult(
            **{"from": format_address(frm.getOffset()), "to": format_address(to.getOffset())}
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"xrefs"})
    @session.require_open
    def delete_data_xref(
        from_address: Address,
        to_address: Address,
    ) -> DeleteXrefResult:
        """Remove the data (read/write/pointer) reference from one address to another.

        Matches only data references; use delete_code_xref for calls and jumps. Fails
        with NotFound when no such reference exists. Returns the from and to addresses.
        """
        program = session.program
        ref_mgr = program.getReferenceManager()
        frm = resolve_address(from_address)
        to = resolve_address(to_address)

        # Find the specific reference to remove
        refs = ref_mgr.getReferencesFrom(frm)
        found = None
        for ref in refs:
            if ref.getToAddress().equals(to) and ref.getReferenceType().isData():
                found = ref
                break

        if found is None:
            raise GhidraError(
                f"No data xref from {format_address(frm.getOffset())} "
                f"to {format_address(to.getOffset())}",
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Delete data xref")
        try:
            ref_mgr.delete(found)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to delete data xref: {e}", error_type="DeleteXrefFailed"
            ) from e

        return DeleteXrefResult(
            **{"from": format_address(frm.getOffset()), "to": format_address(to.getOffset())}
        )
