# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Enum creation and management tools."""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_MUTATE_NON_IDEMPOTENT,
    ANNO_READ_ONLY,
    Limit,
    Offset,
    paginate,
    paginate_iter,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class EnumSummary(BaseModel):
    """Brief enum info."""

    name: str = Field(description="Enum name.")
    member_count: int = Field(description="Number of members.")
    category: str = Field(default="", description="Category path.")


class EnumMemberItem(BaseModel):
    """Enum member info."""

    name: str = Field(description="Member name.")
    value: int = Field(description="Member value.")


class CreateEnumResult(BaseModel):
    """Result of creating an enum."""

    name: str = Field(description="Enum name.")
    bitfield: bool = Field(description="Whether this is a bitfield.")
    status: str = Field(description="Status.")


class DeleteEnumResult(BaseModel):
    """Result of deleting an enum."""

    name: str = Field(description="Enum name.")
    old_member_count: int = Field(description="Previous member count.")
    status: str = Field(description="Status.")


class AddEnumMemberResult(BaseModel):
    """Result of adding an enum member."""

    enum: str = Field(description="Enum name.")
    member: str = Field(description="Member name.")
    value: int = Field(description="Member value.")
    status: str = Field(description="Status.")


class RenameEnumResult(BaseModel):
    """Result of renaming an enum."""

    old_name: str = Field(description="Previous enum name.")
    new_name: str = Field(description="New enum name.")
    status: str = Field(description="Status.")


class DeleteEnumMemberResult(BaseModel):
    """Result of deleting an enum member."""

    enum: str = Field(description="Enum name.")
    member: str = Field(description="Deleted member name.")
    value: int = Field(description="Member value.")
    status: str = Field(description="Status.")


class RenameEnumMemberResult(BaseModel):
    """Result of renaming an enum member."""

    enum: str = Field(description="Enum name.")
    old_name: str = Field(description="Previous member name.")
    new_name: str = Field(description="New member name.")
    value: int = Field(description="Member value.")
    status: str = Field(description="Status.")


def _resolve_enum(name: str):
    """Resolve an enum by name from the data type manager.

    Returns an ``EnumDataType`` instance. Raises :class:`GhidraError` if not found.
    """
    from ghidra.program.model.data import Enum  # noqa: PLC0415

    program = session.program
    dtm = program.getDataTypeManager()
    for dt in dtm.getAllDataTypes():
        if dt.getName() == name and isinstance(dt, Enum):
            return dt

    raise GhidraError(f"Enum not found: {name}", error_type="NotFound")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types", "enums"})
    @session.require_open
    def list_enums(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all enums in the database, paginated.

        Args:
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        from ghidra.program.model.data import Enum  # noqa: PLC0415

        program = session.program
        dtm = program.getDataTypeManager()

        def _gen():
            for dt in dtm.getAllDataTypes():
                if not isinstance(dt, Enum):
                    continue
                cat = dt.getCategoryPath()
                yield EnumSummary(
                    name=dt.getName(),
                    member_count=dt.getCount(),
                    category=str(cat) if cat else "",
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"types", "enums"})
    @session.require_open
    def create_enum(
        name: Annotated[
            str,
            Field(
                description="Name for the new enum, created in the root category. "
                "Example: 'FILE_ACCESS'"
            ),
        ],
        bitfield: Annotated[
            bool,
            Field(
                description="Recorded and echoed back only; Ghidra enums have no bitfield "
                "flag, so it has no effect. Example: false"
            ),
        ] = False,
    ) -> CreateEnumResult:
        """Create an empty 4-byte enum in the root category; add values with add_enum_member.

        To define an enum with its values from C source in one step use
        parse_type_declaration. Returns name, bitfield and status "created".
        """
        from ghidra.program.model.data import CategoryPath, EnumDataType  # noqa: PLC0415

        program = session.program
        dtm = program.getDataTypeManager()

        tx_id = program.startTransaction("Create enum")
        try:
            enum_dt = EnumDataType(CategoryPath.ROOT, name, 4)
            dtm.addDataType(enum_dt, None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to create enum: {e}", error_type="CreateFailed") from e

        return CreateEnumResult(name=name, bitfield=bitfield, status="created")

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"types", "enums"})
    @session.require_open
    def delete_enum(
        name: Annotated[
            str, Field(description="Exact name of the enum to delete. Example: 'FILE_ACCESS'")
        ],
    ) -> DeleteEnumResult:
        """Delete a whole enum type from the data type manager.

        Use delete_enum_member to remove a single value instead. Returns name,
        old_member_count and status "deleted".
        """
        enum_dt = _resolve_enum(name)
        old_member_count = enum_dt.getCount()

        program = session.program
        dtm = program.getDataTypeManager()

        tx_id = program.startTransaction("Delete enum")
        try:
            dtm.remove(enum_dt, None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete enum: {e}", error_type="DeleteFailed") from e

        return DeleteEnumResult(name=name, old_member_count=old_member_count, status="deleted")

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types", "enums"})
    @session.require_open
    def add_enum_member(
        enum_name: Annotated[
            str, Field(description="Exact name of an existing enum. Example: 'FILE_ACCESS'")
        ],
        member_name: Annotated[
            str, Field(description="Name for the new member. Example: 'ACCESS_READ'")
        ],
        value: Annotated[int, Field(description="Integer value of the member. Example: 1")],
    ) -> AddEnumMemberResult:
        """Add one named value to an existing enum.

        Use rename_enum_member to rename an existing value. Returns enum, member, value
        and status "added".
        """
        enum_dt = _resolve_enum(enum_name)

        program = session.program
        tx_id = program.startTransaction("Add enum member")
        try:
            enum_dt.add(member_name, value)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to add enum member: {e}", error_type="AddMemberFailed"
            ) from e

        return AddEnumMemberResult(enum=enum_name, member=member_name, value=value, status="added")

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types", "enums"})
    @session.require_open
    def get_enum_members(
        enum_name: str,
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all members of an enum, paginated.

        Args:
            enum_name: Name of the enum.
            offset: Pagination offset.
            limit: Maximum number of results.
        """
        enum_dt = _resolve_enum(enum_name)

        members = []
        for value in enum_dt.getValues():
            name = enum_dt.getName(value)
            members.append(EnumMemberItem(name=name or "", value=int(value)).model_dump())

        return paginate(members, offset, limit)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types", "enums"})
    @session.require_open
    def rename_enum(
        old_name: Annotated[str, Field(description="Current name of the enum. Example: 'enum_1'")],
        new_name: Annotated[str, Field(description="New enum name. Example: 'FILE_ACCESS'")],
    ) -> RenameEnumResult:
        """Rename an enum type itself; its members are unchanged.

        Use rename_enum_member to rename a value inside it. Returns old_name, new_name
        and status "renamed".
        """
        enum_dt = _resolve_enum(old_name)

        program = session.program
        tx_id = program.startTransaction("Rename enum")
        try:
            enum_dt.setName(new_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to rename enum {old_name!r} to {new_name!r}",
                error_type="RenameFailed",
            ) from e

        return RenameEnumResult(old_name=old_name, new_name=new_name, status="renamed")

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"types", "enums"})
    @session.require_open
    def delete_enum_member(
        enum_name: Annotated[
            str, Field(description="Exact name of an existing enum. Example: 'FILE_ACCESS'")
        ],
        value: Annotated[
            int,
            Field(description="Integer value that identifies the member. Example: 2"),
        ],
    ) -> DeleteEnumMemberResult:
        """Remove the member with a given value from an enum; the enum itself stays.

        Use delete_enum to remove the whole type. Fails with NotFound when no member has
        that value. Returns enum, member (the removed name), value and status "deleted".
        """
        enum_dt = _resolve_enum(enum_name)

        member_name = enum_dt.getName(value)
        if member_name is None:
            raise GhidraError(f"No member with value {value} in {enum_name}", error_type="NotFound")

        program = session.program
        tx_id = program.startTransaction("Delete enum member")
        try:
            enum_dt.remove(member_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to delete enum member: {e}", error_type="DeleteFailed"
            ) from e

        return DeleteEnumMemberResult(
            enum=enum_name, member=member_name, value=value, status="deleted"
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types", "enums"})
    @session.require_open
    def rename_enum_member(
        enum_name: Annotated[
            str, Field(description="Exact name of an existing enum. Example: 'FILE_ACCESS'")
        ],
        value: Annotated[
            int,
            Field(description="Integer value that identifies the member. Example: 2"),
        ],
        new_name: Annotated[
            str, Field(description="New name for that member. Example: 'ACCESS_WRITE'")
        ],
    ) -> RenameEnumMemberResult:
        """Rename the enum member that has a given value, keeping the value.

        Use rename_enum to rename the enum type. Fails with NotFound when no member has
        that value. Returns enum, old_name, new_name, value and status "renamed".
        """
        enum_dt = _resolve_enum(enum_name)

        old_name = enum_dt.getName(value)
        if old_name is None:
            raise GhidraError(f"No member with value {value} in {enum_name}", error_type="NotFound")

        program = session.program
        tx_id = program.startTransaction("Rename enum member")
        try:
            # Ghidra EnumDataType: remove old by name, add with new name
            enum_dt.remove(old_name)
            enum_dt.add(new_name, value)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to rename enum member: {e}", error_type="RenameFailed"
            ) from e

        return RenameEnumMemberResult(
            enum=enum_name, old_name=old_name, new_name=new_name, value=value, status="renamed"
        )
