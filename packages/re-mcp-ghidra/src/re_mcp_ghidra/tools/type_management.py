# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Data type organisation: categories, renaming, cloning, merging, finding uses."""

from __future__ import annotations

import time
from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_DESTRUCTIVE, ANNO_MUTATE, ANNO_READ_ONLY, format_address
from re_mcp_ghidra.session import session

TypePath = Annotated[
    str,
    Field(
        description=(
            'Data type path ("/category/name"), or a bare name when it is unique. '
            'Example: "/net/packet_hdr"'
        )
    ),
]
CategoryPathArg = Annotated[
    str, Field(description='Category path, "/" for the root. Example: "/net/headers"')
]
MAX_USE_TIMEOUT_S = 120


class TypeRef(BaseModel):
    name: str = Field(description="Type name.")
    path: str = Field(description="Full path including category.")
    size: int = Field(description="Size in bytes (-1 if dynamic).")


class CategoryInfo(BaseModel):
    path: str = Field(description="Category path.")
    types: int = Field(description="Data types directly in it.")
    subcategories: int = Field(description="Categories directly under it.")


class CategoryList(BaseModel):
    items: list[CategoryInfo] = Field(description="Every category, root first.")
    total: int = Field(description="Number of categories.")


class ConsolidateResult(BaseModel):
    kept: TypeRef = Field(description="The type every use now points at.")
    replaced: list[TypeRef] = Field(
        description="Duplicates whose uses moved and that were removed."
    )


class TypeUse(BaseModel):
    function: str = Field(description="Function using the type.")
    function_address: str = Field(description="Its entry point.")
    address: str = Field(description="Where in it (hex).")
    context: str = Field(description="The decompiled line using it.")


class TypeUses(BaseModel):
    type: TypeRef = Field(description="The type searched for.")
    field: str = Field(description="Field searched for, or empty for any use.")
    items: list[TypeUse] = Field(description="Uses found, up to limit.")
    total: int = Field(description="Uses found before the limit.")
    timed_out: bool = Field(description="The search stopped at timeout_s; results are partial.")
    seconds: float = Field(description="Search time.")


def _dtm():
    return session.program.getDataTypeManager()


def _ref(dt) -> TypeRef:
    return TypeRef(name=str(dt.getName()), path=str(dt.getPathName()), size=int(dt.getLength()))


def find_type(path: str):
    """A data type by path, or by bare name when exactly one type has that name."""
    dtm = _dtm()
    if path.startswith("/"):
        dt = dtm.getDataType(path)
        if dt is None:
            raise GhidraError(f"No data type {path}.", error_type="NotFound")
        return dt
    from java.util import ArrayList  # noqa: PLC0415

    found = ArrayList()
    dtm.findDataTypes(path, found)
    matches = [d for d in found if d.getDataTypeManager() == dtm]
    if not matches:
        raise GhidraError(f"No data type named {path!r}.", error_type="NotFound")
    if len(matches) > 1:
        paths = ", ".join(str(d.getPathName()) for d in matches)
        raise GhidraError(
            f"{len(matches)} types are named {path!r} ({paths}); pass the full path.",
            error_type="Ambiguous",
        )
    return matches[0]


def _category(path: str, create: bool):
    from ghidra.program.model.data import CategoryPath  # noqa: PLC0415

    cat_path = CategoryPath(path or "/")
    cat = _dtm().getCategory(cat_path)
    if cat is None and create:
        cat = _dtm().createCategory(cat_path)
    if cat is None:
        raise GhidraError(f"No category {path}.", error_type="NotFound")
    return cat


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types"})
    @session.require_open
    def list_data_type_categories() -> CategoryList:
        """List the program's data type categories (folders of types).

        Use to see how types are organised before create_data_type_category or
        move_data_type. Returns {items: [{path, types, subcategories}], total}.
        """
        items: list[CategoryInfo] = []
        pending = [_dtm().getRootCategory()]
        while pending:
            cat = pending.pop(0)
            subs = list(cat.getCategories())
            items.append(
                CategoryInfo(
                    path=str(cat.getCategoryPathName()),
                    types=len(cat.getDataTypes()),
                    subcategories=len(subs),
                )
            )
            pending.extend(sorted(subs, key=lambda c: str(c.getName())))
        return CategoryList(items=items, total=len(items))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def create_data_type_category(path: CategoryPathArg) -> CategoryInfo:
        """Create a data type category, with any missing parents.

        Use to group recovered types (one category per subsystem or library).
        Creating one that exists is not an error. Returns {path, types,
        subcategories}.
        """
        cat = _category(path, create=True)
        return CategoryInfo(
            path=str(cat.getCategoryPathName()),
            types=len(cat.getDataTypes()),
            subcategories=len(cat.getCategories()),
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def move_data_type(type_path: TypePath, category: CategoryPathArg) -> TypeRef:
        """Move a data type into a category (created if missing).

        Uses keep pointing at the type. Fails with AlreadyExists when the category
        already holds a type of that name. Returns the type's new {name, path,
        size}.
        """
        from ghidra.program.model.data import CategoryPath  # noqa: PLC0415

        dt = find_type(type_path)
        _category(category, create=True)
        try:
            dt.setCategoryPath(CategoryPath(category))
        except Exception as exc:
            raise GhidraError(
                f"Cannot move {dt.getPathName()} to {category}: {exc}",
                error_type="AlreadyExists",
            ) from exc
        return _ref(dt)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def rename_data_type(
        type_path: TypePath,
        new_name: Annotated[str, Field(description='New name. Example: "packet_hdr_t"')],
    ) -> TypeRef:
        """Rename a struct, union, enum, typedef or function definition.

        Uses keep pointing at it. Built-in types cannot be renamed; a clash with a
        type already in the same category fails with AlreadyExists. Returns the
        type's new {name, path, size}.
        """
        from ghidra.program.model.data import BuiltInDataType  # noqa: PLC0415

        dt = find_type(type_path)
        if isinstance(dt, BuiltInDataType):
            raise GhidraError(f"{dt.getName()} is built in.", error_type="InvalidArgument")
        try:
            dt.setName(new_name)
        except Exception as exc:
            raise GhidraError(
                f"Cannot rename {dt.getPathName()} to {new_name}: {exc}",
                error_type="AlreadyExists",
            ) from exc
        return _ref(dt)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"types"})
    @session.require_open
    def clone_data_type(
        type_path: TypePath,
        new_name: Annotated[str, Field(description='Name of the copy. Example: "packet_hdr_v2"')],
        category: Annotated[
            str,
            Field(description='Category for the copy; empty keeps the original\'s. Example: "/v2"'),
        ] = "",
    ) -> TypeRef:
        """Make an independent copy of a data type under a new name.

        Use to start a variant (e.g. a struct's next version) without touching the
        original. Fails with AlreadyExists if the name is taken there. Returns the
        copy's {name, path, size}.
        """
        from ghidra.program.model.data import CategoryPath  # noqa: PLC0415

        src = find_type(type_path)
        target_cat = CategoryPath(category) if category else src.getCategoryPath()
        if _dtm().getDataType(target_cat, new_name) is not None:
            raise GhidraError(
                f"{target_cat}/{new_name} already exists.", error_type="AlreadyExists"
            )
        copy = src.copy(_dtm())
        copy.setName(new_name)
        copy.setCategoryPath(target_cat)
        return _ref(_dtm().addDataType(copy, None))

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"types"})
    @session.require_open
    def consolidate_data_types(
        keep: Annotated[
            str,
            Field(description='Full path of the type to keep. Example: "/net/packet_hdr"'),
        ],
        replace: Annotated[
            list[str],
            Field(
                min_length=1,
                description=(
                    "Full paths of duplicates to fold into keep. Example: "
                    '["/Demangler/packet_hdr", "/packet_hdr"]'
                ),
            ),
        ],
        allow_size_change: Annotated[
            bool,
            Field(
                description=(
                    "Allow duplicates of a different size (their uses change layout). "
                    "Example: false"
                )
            ),
        ] = False,
    ) -> ConsolidateResult:
        """Merge duplicate data types into one: every use moves to keep, duplicates go.

        Use when importing or demangling left several copies of one type. Each
        duplicate is replaced everywhere it is used, then removed. Refuses a
        duplicate whose size differs unless allow_size_change. Returns {kept,
        replaced}.
        """
        kept = find_type(keep)
        replaced = []
        for path in replace:
            dup = find_type(path)
            if dup.getPathName() == kept.getPathName():
                continue
            if dup.getLength() != kept.getLength() and not allow_size_change:
                raise GhidraError(
                    f"{path} is {dup.getLength()} bytes, {keep} is {kept.getLength()}; pass "
                    "allow_size_change to merge anyway.",
                    error_type="SizeMismatch",
                )
            replaced.append(_ref(dup))
            _dtm().replaceDataType(dup, kept, True)
        return ConsolidateResult(kept=_ref(kept), replaced=replaced)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"types"})
    @session.require_open
    def find_data_type_uses(
        type_path: TypePath,
        field: Annotated[
            str,
            Field(description='Only uses of this field (structs); empty for any. Example: "len"'),
        ] = "",
        timeout_s: Annotated[
            int,
            Field(ge=1, le=MAX_USE_TIMEOUT_S, description="Search time limit. Example: 30"),
        ] = 20,
        limit: Annotated[int, Field(ge=1, le=2000, description="Most uses. Example: 200")] = 200,
    ) -> TypeUses:
        """Find where a data type (or one of its fields) is used in decompiled code.

        Use to learn what a struct field means from the code that reads and
        writes it, or before changing a type. Runs Ghidra's decompiler-based type
        reference finder over the program; stops at timeout_s with timed_out true
        and partial results. Returns {type, field, items: [{function,
        function_address, address, context}], total, timed_out, seconds}.
        """
        from ghidra.app.extension.datatype.finder import (  # noqa: PLC0415
            DecompilerDataTypeReferenceFinder,
        )
        from ghidra.util.task import TimeoutTaskMonitor  # noqa: PLC0415
        from java.util.concurrent import TimeUnit  # noqa: PLC0415
        from java.util.function import Consumer  # noqa: PLC0415
        from jpype import JImplements, JOverride  # noqa: PLC0415

        dt = find_type(type_path)
        found: list[TypeUse] = []

        @JImplements(Consumer)
        class Collect:
            @JOverride
            def accept(self, ref):
                func = ref.getFunction()
                ctx = ref.getContext()
                found.append(
                    TypeUse(
                        function=str(func.getName()) if func else "",
                        function_address=format_address(func.getEntryPoint().getOffset())
                        if func
                        else "",
                        address=format_address(ref.getAddress().getOffset())
                        if ref.getAddress()
                        else "",
                        context=str(ctx.getPlainText()) if ctx else "",
                    )
                )

        monitor = TimeoutTaskMonitor.timeoutIn(timeout_s, TimeUnit.SECONDS)
        start = time.monotonic()
        timed_out = False
        try:
            finder = DecompilerDataTypeReferenceFinder()
            if field:
                finder.findReferences(session.program, dt, field, Collect(), monitor)
            else:
                finder.findReferences(session.program, dt, Collect(), monitor)
        except Exception as exc:
            if "Cancelled" not in type(exc).__name__ and "cancel" not in str(exc).lower():
                raise GhidraError(f"Type search failed: {exc}", error_type="Failed") from exc
            timed_out = True
        timed_out = timed_out or bool(monitor.didTimeout())
        return TypeUses(
            type=_ref(dt),
            field=field,
            items=found[:limit],
            total=len(found),
            timed_out=timed_out,
            seconds=round(time.monotonic() - start, 2),
        )
