# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Data type definition tools -- define bytes, words, strings, arrays at addresses."""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_MUTATE,
    Address,
    format_address,
    resolve_address,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CreateDataResult(BaseModel):
    """Result of a make-data operation (byte/word/dword/qword/float/double)."""

    address: str = Field(description="Target address (hex).")
    data_type: str = Field(description="Data type applied.")
    size: int = Field(description="Total data size in bytes.")
    count: int = Field(description="Number of elements.")
    status: str = Field(description="Operation status.")


class MakeStringResult(BaseModel):
    """Result of creating a string."""

    address: str = Field(description="String address (hex).")
    length: int = Field(description="String length in bytes.")
    string_type: str = Field(description="String encoding type.")
    status: str = Field(description="Operation status.")


class MakeArrayResult(BaseModel):
    """Result of creating an array."""

    address: str = Field(description="Array address (hex).")
    element_size: int = Field(description="Size of each element in bytes.")
    count: int = Field(description="Number of elements.")
    total_size: int = Field(description="Total array size in bytes.")
    status: str = Field(description="Operation status.")


_MAX_COUNT = 1_000_000


def _validate_count(count: int) -> None:
    if count < 1:
        raise GhidraError(f"Count must be >= 1, got {count}", error_type="InvalidArgument")
    if count > _MAX_COUNT:
        raise GhidraError(
            f"Count too large ({count}), max {_MAX_COUNT}", error_type="InvalidArgument"
        )


def _get_data_type(type_name: str):
    """Return a Ghidra DataType for the given type name."""
    from ghidra.program.model.data import (  # noqa: PLC0415
        ByteDataType,
        DoubleDataType,
        FloatDataType,
        QWordDataType,
        WordDataType,
    )
    from ghidra.program.model.data import DWordDataType as DWordDT  # noqa: PLC0415

    type_map = {
        "byte": (ByteDataType.dataType, 1),
        "word": (WordDataType.dataType, 2),
        "dword": (DWordDT.dataType, 4),
        "qword": (QWordDataType.dataType, 8),
        "float": (FloatDataType.dataType, 4),
        "double": (DoubleDataType.dataType, 8),
    }
    entry = type_map.get(type_name)
    if entry is None:
        raise GhidraError(
            f"Unknown data type: {type_name!r}. Valid: {', '.join(type_map)}",
            error_type="InvalidArgument",
        )
    return entry


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification"})
    @session.require_open
    def create_data(
        address: Address,
        data_type: Annotated[
            Literal["byte", "word", "dword", "qword", "float", "double"],
            Field(
                description="Primitive type: byte (8-bit), word (16), dword (32), qword (64), "
                "float (32-bit IEEE) or double (64-bit IEEE). Example: 'dword'"
            ),
        ],
        count: Annotated[
            int,
            Field(
                description="Number of elements; above 1 creates an array of that type. Example: 4",
                ge=1,
            ),
        ] = 1,
    ) -> CreateDataResult:
        """Define a primitive numeric data item (or array of them) at an address.

        Clears existing code units in the range first. Use create_string for text,
        create_array for integer arrays by element size, set_type for named/C types.
        Returns address, data_type, size (total bytes), count and status "ok".
        """
        from ghidra.program.model.data import ArrayDataType  # noqa: PLC0415

        _validate_count(count)
        dt, elem_size = _get_data_type(data_type)
        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        tx_id = program.startTransaction("Make data")
        try:
            # Clear existing data first
            listing.clearCodeUnits(addr, addr.add(elem_size * count - 1), False)

            if count > 1:
                arr_dt = ArrayDataType(dt, count, elem_size)
                listing.createData(addr, arr_dt)
            else:
                listing.createData(addr, dt)

            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to define {data_type} at {format_address(addr.getOffset())}: {e}",
                error_type="CreateDataFailed",
            ) from e

        return CreateDataResult(
            address=format_address(addr.getOffset()),
            data_type=data_type,
            size=elem_size * count,
            count=count,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification"})
    @session.require_open
    def create_string(
        address: Address,
        length: Annotated[
            int,
            Field(
                description="Fixed length in bytes, defined as a plain (non-terminated) "
                "string; 0 auto-detects a null-terminated string. Example: 16"
            ),
        ] = 0,
        string_type: Annotated[
            Literal["c", "utf16", "utf32"],
            Field(
                description="Encoding for auto-detected strings: c (null-terminated "
                "ASCII/UTF-8), utf16 or utf32. Ignored when length > 0. Example: 'utf16'"
            ),
        ] = "c",
    ) -> MakeStringResult:
        """Define a string data item at an address, auto-sizing to the terminator by default.

        Use list_strings to find existing strings, create_data for numeric data.
        Returns address, length (actual bytes defined), string_type and status "ok".
        """
        from ghidra.program.model.data import (  # noqa: PLC0415
            StringDataType,
            TerminatedStringDataType,
            TerminatedUnicode32DataType,
            UnicodeDataType,
        )

        type_map = {
            "c": TerminatedStringDataType.dataType,
            "utf16": UnicodeDataType.dataType,
            "utf32": TerminatedUnicode32DataType.dataType,
        }
        dt = type_map.get(string_type)
        if dt is None:
            raise GhidraError(
                f"Invalid string type: {string_type!r}. Valid: {', '.join(type_map)}",
                error_type="InvalidArgument",
            )

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)

        tx_id = program.startTransaction("Make string")
        try:
            if length > 0:
                listing.clearCodeUnits(addr, addr.add(length - 1), False)
                # For fixed-length strings, use plain StringDataType with explicit length
                listing.createData(addr, StringDataType.dataType, length)
            else:
                # Auto-detect length by clearing a reasonable area and using terminated type
                # Clear conservatively -- 1 byte at minimum for the terminated type to probe
                listing.clearCodeUnits(addr, addr, False)
                listing.createData(addr, dt)

            # Read back the actual length
            created = listing.getDataAt(addr)
            actual_length = created.getLength() if created else length

            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to define string at {format_address(addr.getOffset())}: {e}",
                error_type="CreateDataFailed",
            ) from e

        return MakeStringResult(
            address=format_address(addr.getOffset()),
            length=actual_length,
            string_type=string_type,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"modification"})
    @session.require_open
    def create_array(
        address: Address,
        element_size: Annotated[
            Literal[1, 2, 4, 8],
            Field(
                description="Element size in bytes, mapped to byte, word, dword or qword. "
                "Example: 4"
            ),
        ],
        count: Annotated[
            int, Field(description="Number of elements in the array. Example: 256", ge=1)
        ],
    ) -> MakeArrayResult:
        """Define an array of unsigned integer elements (1/2/4/8 bytes each) at an address.

        Clears existing code units in the range first. Use create_data for float/double
        arrays, set_type or apply_type_at_address for arrays of named types. Returns
        address, element_size, count, total_size and status "ok".
        """
        from ghidra.program.model.data import (  # noqa: PLC0415
            ArrayDataType,
            ByteDataType,
            QWordDataType,
            WordDataType,
        )
        from ghidra.program.model.data import DWordDataType as DWordDT  # noqa: PLC0415

        _validate_count(count)

        size_to_dt = {
            1: ByteDataType.dataType,
            2: WordDataType.dataType,
            4: DWordDT.dataType,
            8: QWordDataType.dataType,
        }
        elem_dt = size_to_dt.get(element_size)
        if elem_dt is None:
            raise GhidraError(
                f"Invalid element size: {element_size}. Must be 1, 2, 4, or 8.",
                error_type="InvalidArgument",
            )

        program = session.program
        listing = program.getListing()
        addr = resolve_address(address)
        total_size = element_size * count

        tx_id = program.startTransaction("Make array")
        try:
            listing.clearCodeUnits(addr, addr.add(total_size - 1), False)
            arr_dt = ArrayDataType(elem_dt, count, element_size)
            listing.createData(addr, arr_dt)
            program.endTransaction(tx_id, True)
        except GhidraError:
            program.endTransaction(tx_id, False)
            raise
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(
                f"Failed to create array at {format_address(addr.getOffset())}: {e}",
                error_type="CreateDataFailed",
            ) from e

        return MakeArrayResult(
            address=format_address(addr.getOffset()),
            element_size=element_size,
            count=count,
            total_size=total_size,
            status="ok",
        )
