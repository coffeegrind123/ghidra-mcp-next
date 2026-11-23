# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Structure (struct/union) management tools."""

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
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    paginate_iter,
)
from re_mcp_ghidra.session import session


class StructSummary(BaseModel):
    name: str
    size: int
    member_count: int
    is_union: bool = False
    category: str = ""


class StructMember(BaseModel):
    offset: int
    name: str
    type: str
    size: int
    comment: str = ""


class StructDetailResult(BaseModel):
    name: str
    size: int
    is_union: bool
    category: str
    members: list[StructMember]


class CreateStructResult(BaseModel):
    name: str
    is_union: bool
    status: str


class AddStructMemberResult(BaseModel):
    struct_name: str
    member_name: str
    offset: int
    type: str
    status: str


class RetypeStructMemberResult(BaseModel):
    struct_name: str
    member_name: str
    old_type: str
    new_type: str
    status: str


class RenameStructMemberResult(BaseModel):
    struct_name: str
    old_name: str
    new_name: str


class DeleteStructMemberResult(BaseModel):
    struct_name: str
    member_name: str
    old_size: int


class DeleteStructureResult(BaseModel):
    name: str
    old_size: int
    old_member_count: int


def _resolve_struct(name: str):
    """Resolve a structure by name from the data type manager."""

    program = session.program
    dtm = program.getDataTypeManager()

    # Search all categories
    for dt in dtm.getAllDataTypes():
        if dt.getName() == name:
            from ghidra.program.model.data import Structure, Union  # noqa: PLC0415

            if isinstance(dt, (Structure, Union)):
                return dt

    raise GhidraError(f"Structure not found: {name}", error_type="NotFound")


def _find_member(dt, member_name: str) -> tuple[int, object]:
    """Find a struct/union component by name.

    Returns ``(index, component)``.
    Raises :class:`GhidraError` if not found.
    """
    for i in range(dt.getNumComponents()):
        comp = dt.getComponent(i)
        if (comp.getFieldName() or f"field_{i}") == member_name:
            return i, comp

    raise GhidraError(
        f"Member {member_name!r} not found in {dt.getName()}",
        error_type="NotFound",
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"structs"})
    @session.require_open
    def list_structures(
        offset: Offset = 0,
        limit: Limit = 100,
        filter_pattern: FilterPattern = "",
    ) -> dict:
        """List all structures and unions in the database."""
        from ghidra.program.model.data import Structure, Union  # noqa: PLC0415

        program = session.program
        dtm = program.getDataTypeManager()
        filt = compile_filter(filter_pattern)

        def _gen():
            for dt in dtm.getAllDataTypes():
                if not isinstance(dt, (Structure, Union)):
                    continue
                name = dt.getName()
                if filt and not filt.search(name):
                    continue
                cat = dt.getCategoryPath()
                yield StructSummary(
                    name=name,
                    size=dt.getLength(),
                    member_count=dt.getNumComponents(),
                    is_union=isinstance(dt, Union),
                    category=str(cat) if cat else "",
                ).model_dump()

        return paginate_iter(_gen(), offset, limit)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"structs"})
    @session.require_open
    def get_structure(
        name: Annotated[
            str,
            Field(description="Exact name of a structure or union. Example: 'IMAGE_DOS_HEADER'"),
        ],
    ) -> StructDetailResult:
        """Show the full member layout of one structure or union.

        Use list_structures to find names; get_type_info instead reports which type is
        applied at an address.
        Fails with NotFound if no struct/union has that name. Returns name, size,
        is_union, category and members (each with offset, name, type, size, comment).
        """
        dt = _resolve_struct(name)
        from ghidra.program.model.data import Union  # noqa: PLC0415

        members = []
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            members.append(
                StructMember(
                    offset=comp.getOffset(),
                    name=comp.getFieldName() or f"field_{i}",
                    type=str(comp.getDataType().getName()),
                    size=comp.getLength(),
                    comment=comp.getComment() or "",
                )
            )

        cat = dt.getCategoryPath()
        return StructDetailResult(
            name=dt.getName(),
            size=dt.getLength(),
            is_union=isinstance(dt, Union),
            category=str(cat) if cat else "",
            members=members,
        )

    @mcp.tool(annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"structs"})
    @session.require_open
    def create_structure(
        name: Annotated[
            str,
            Field(
                description="Name for the new type, created in the root category. "
                "Example: 'config_t'"
            ),
        ],
        is_union: Annotated[
            bool,
            Field(description="True creates a union instead of a structure. Example: false"),
        ] = False,
        size: Annotated[
            int,
            Field(
                description="Initial structure size in bytes, filled with undefined bytes; 0 "
                "starts empty. Ignored for unions. Example: 64"
            ),
        ] = 0,
    ) -> CreateStructResult:
        """Create an empty structure or union in the root category of the type manager.

        Add members afterwards with add_struct_member; to define a full type from C
        source use parse_type_declaration. Returns name, is_union and status "created".
        """
        from ghidra.program.model.data import (  # noqa: PLC0415
            CategoryPath,
            StructureDataType,
            UnionDataType,
        )

        program = session.program
        dtm = program.getDataTypeManager()

        tx_id = program.startTransaction("Create structure")
        try:
            if is_union:
                dt = UnionDataType(CategoryPath.ROOT, name)
            else:
                dt = StructureDataType(CategoryPath.ROOT, name, size)
            dtm.addDataType(dt, None)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to create structure: {e}", error_type="CreateFailed") from e

        return CreateStructResult(
            name=name,
            is_union=is_union,
            status="created",
        )

    @mcp.tool(annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"structs"})
    @session.require_open
    def add_struct_member(
        struct_name: Annotated[
            str,
            Field(
                description="Exact name of an existing structure or union. "
                "Example: 'IMAGE_DOS_HEADER'"
            ),
        ],
        member_name: Annotated[
            str, Field(description="Field name for the new member. Example: 'e_lfanew'")
        ],
        member_type: Annotated[
            str,
            Field(
                description="Member type: a built-in C name (int, unsigned short, char, ...), "
                "an existing type name, with optional trailing '*' for pointers. "
                "Example: 'char *'"
            ),
        ] = "byte",
        offset: Annotated[
            int,
            Field(
                description="Byte offset to place the member at, replacing what is there; "
                "-1 appends at the end. Example: 60"
            ),
        ] = -1,
        size: Annotated[
            int,
            Field(description="Member size in bytes; 0 uses the type's own size. Example: 4"),
        ] = 0,
    ) -> AddStructMemberResult:
        """Append a member to a struct/union, or place it at a byte offset over existing bytes.

        Use retype_struct_member or rename_struct_member to change an existing member.
        Returns struct_name, member_name, the actual offset, type and status "added".
        """

        dt = _resolve_struct(struct_name)
        program = session.program

        member_dt = _parse_data_type(member_type)

        tx_id = program.startTransaction("Add struct member")
        try:
            if offset < 0:
                dt.add(member_dt, size or member_dt.getLength(), member_name, None)
                actual_offset = dt.getLength() - (size or member_dt.getLength())
            else:
                dt.replaceAtOffset(
                    offset, member_dt, size or member_dt.getLength(), member_name, None
                )
                actual_offset = offset
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to add member: {e}", error_type="AddMemberFailed") from e

        return AddStructMemberResult(
            struct_name=struct_name,
            member_name=member_name,
            offset=actual_offset,
            type=member_type,
            status="added",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"structs"})
    @session.require_open
    def retype_struct_member(
        struct_name: Annotated[
            str,
            Field(
                description="Exact name of an existing structure or union. "
                "Example: 'IMAGE_DOS_HEADER'"
            ),
        ],
        member_name: Annotated[
            str,
            Field(
                description="Current member name; unnamed members are 'field_<index>'. "
                "Example: 'field_3'"
            ),
        ],
        new_type: Annotated[
            str,
            Field(
                description="New type: built-in C name or existing type name, optional "
                "trailing '*'. Example: 'unsigned int'"
            ),
        ],
    ) -> RetypeStructMemberResult:
        """Change the data type of one existing struct/union member, keeping its name.

        Use add_struct_member to add a member, rename_struct_member to rename one.
        Returns struct_name, member_name, old_type, new_type and status "retyped".
        """
        dt = _resolve_struct(struct_name)
        program = session.program

        _, member = _find_member(dt, member_name)
        old_type = str(member.getDataType().getName())
        new_dt = _parse_data_type(new_type)

        tx_id = program.startTransaction("Retype struct member")
        try:
            member.setDataType(new_dt)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to retype member: {e}", error_type="RetypeFailed") from e

        return RetypeStructMemberResult(
            struct_name=struct_name,
            member_name=member_name,
            old_type=old_type,
            new_type=new_type,
            status="retyped",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"structs"})
    @session.require_open
    def rename_struct_member(
        struct_name: Annotated[
            str,
            Field(
                description="Exact name of an existing structure or union. "
                "Example: 'IMAGE_DOS_HEADER'"
            ),
        ],
        old_name: Annotated[
            str,
            Field(
                description="Current member name; unnamed members are 'field_<index>'. "
                "Example: 'field_2'"
            ),
        ],
        new_name: Annotated[str, Field(description="New member name. Example: 'buffer_len'")],
    ) -> RenameStructMemberResult:
        """Rename one member of a structure or union, keeping its type and offset.

        Use retype_struct_member to change its type instead. Returns struct_name,
        old_name and new_name.
        """
        dt = _resolve_struct(struct_name)
        program = session.program

        _, member = _find_member(dt, old_name)

        tx_id = program.startTransaction("Rename struct member")
        try:
            member.setFieldName(new_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rename member: {e}", error_type="RenameFailed") from e

        return RenameStructMemberResult(
            struct_name=struct_name,
            old_name=old_name,
            new_name=new_name,
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"structs"})
    @session.require_open
    def delete_struct_member(
        struct_name: Annotated[
            str,
            Field(
                description="Exact name of an existing structure or union. "
                "Example: 'IMAGE_DOS_HEADER'"
            ),
        ],
        member_name: Annotated[
            str,
            Field(
                description="Member to remove; unnamed members are 'field_<index>'. "
                "Example: 'reserved'"
            ),
        ],
    ) -> DeleteStructMemberResult:
        """Remove one member from a struct or union; the type itself stays.

        In a structure the member's bytes become undefined (size and later offsets are
        kept); in a union the member is deleted. Use delete_structure to remove the whole
        type. Returns struct_name, member_name and old_size (the member's byte size).
        """
        from ghidra.program.model.data import Union  # noqa: PLC0415

        dt = _resolve_struct(struct_name)
        program = session.program

        member_idx, comp = _find_member(dt, member_name)
        member_size = comp.getLength()

        tx_id = program.startTransaction("Delete struct member")
        try:
            if isinstance(dt, Union):
                dt.delete(member_idx)
            else:
                dt.clearComponent(member_idx)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete member: {e}", error_type="DeleteFailed") from e

        return DeleteStructMemberResult(
            struct_name=struct_name,
            member_name=member_name,
            old_size=member_size,
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"structs"})
    @session.require_open
    def delete_structure(
        name: Annotated[
            str,
            Field(
                description="Exact name of the structure or union to delete. Example: 'config_t'"
            ),
        ],
    ) -> DeleteStructureResult:
        """Delete one structure or union type by name from the data type manager.

        Only matches structs/unions; use delete_data_type for enums, typedefs and other
        types. Returns name, old_size and old_member_count.
        """
        dt = _resolve_struct(name)
        program = session.program
        dtm = program.getDataTypeManager()

        old_size = dt.getLength()
        old_member_count = dt.getNumComponents()

        tx_id = program.startTransaction("Delete structure")
        try:
            dtm.remove(dt)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete structure: {e}", error_type="DeleteFailed") from e

        return DeleteStructureResult(
            name=name,
            old_size=old_size,
            old_member_count=old_member_count,
        )


def _parse_data_type(type_str: str):
    """Parse a C type string into a Ghidra DataType."""
    from ghidra.program.model.data import (  # noqa: PLC0415
        BooleanDataType,
        ByteDataType,
        CharDataType,
        DoubleDataType,
        FloatDataType,
        IntegerDataType,
        LongDataType,
        LongLongDataType,
        PointerDataType,
        ShortDataType,
        Undefined1DataType,
        Undefined2DataType,
        Undefined4DataType,
        Undefined8DataType,
        UnsignedIntegerDataType,
        UnsignedLongDataType,
        UnsignedLongLongDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    type_map = {
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "short": ShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "long": LongDataType.dataType,
        "long long": LongLongDataType.dataType,
        "unsigned byte": ByteDataType.dataType,  # Ghidra has no UnsignedByteDataType
        "unsigned char": ByteDataType.dataType,
        "unsigned short": UnsignedShortDataType.dataType,
        "unsigned int": UnsignedIntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "unsigned long": UnsignedLongDataType.dataType,
        "unsigned long long": UnsignedLongLongDataType.dataType,
        "float": FloatDataType.dataType,
        "double": DoubleDataType.dataType,
        "void": VoidDataType.dataType,
        "bool": BooleanDataType.dataType,
        "undefined1": Undefined1DataType.dataType,
        "undefined2": Undefined2DataType.dataType,
        "undefined4": Undefined4DataType.dataType,
        "undefined8": Undefined8DataType.dataType,
    }

    clean = type_str.strip().lower()

    # Check for pointer types
    if clean.endswith("*"):
        base = clean[:-1].strip()
        if base:
            base_dt = _parse_data_type(base)
            return PointerDataType(base_dt)
        return PointerDataType(VoidDataType.dataType)

    dt = type_map.get(clean)
    if dt is not None:
        return dt

    # Try looking up in the program's data type manager
    program = session.program
    if program:
        dtm = program.getDataTypeManager()
        for existing_dt in dtm.getAllDataTypes():
            if existing_dt.getName().lower() == clean:
                return existing_dt

    raise GhidraError(f"Unknown data type: {type_str!r}", error_type="InvalidArgument")
