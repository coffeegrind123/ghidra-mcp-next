# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Bookmark management tools."""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    Address,
    FilterPattern,
    Limit,
    Offset,
    compile_filter,
    format_address,
    paginate_iter,
    resolve_address,
)
from re_mcp_ghidra.session import session

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SetBookmarkResult(BaseModel):
    """Result of setting a bookmark."""

    address: str = Field(description="Bookmark address (hex).")
    type: str = Field(default="Note", description="Bookmark type.")
    category: str = Field(description="Bookmark category.")
    description: str = Field(description="Bookmark description.")
    status: str = Field(description="Operation status.")


BookmarkType = Literal["Note", "Info", "Warning", "Error", "Analysis"]


class BookmarkItem(BaseModel):
    """A bookmark entry."""

    address: str = Field(description="Bookmark address (hex).")
    category: str = Field(description="Bookmark category.")
    description: str = Field(description="Bookmark description.")
    type: str = Field(description="Bookmark type.")


class DeleteBookmarkResult(BaseModel):
    """Result of deleting a bookmark."""

    address: str = Field(description="Bookmark address (hex).")
    category: str = Field(description="Category filter used.")
    removed_count: int = Field(description="Number of bookmarks removed.")


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_MUTATE, tags={"navigation"})
    @session.require_open
    def set_bookmark(
        address: Address,
        description: Annotated[
            str,
            Field(description="Free-text note stored on the bookmark. Example: 'C2 beacon loop'"),
        ] = "",
        category: Annotated[
            str,
            Field(description="Free-form category used to group bookmarks. Example: 'Suspicious'"),
        ] = "Analysis",
        type: Annotated[
            BookmarkType,
            Field(
                description=(
                    "Bookmark type, which Ghidra's bookmark view filters and colours by. "
                    'Example: "Warning"'
                )
            ),
        ] = "Note",
    ) -> SetBookmarkResult:
        """Add a bookmark at an address: a type, a category and a description.

        Use list_bookmarks to enumerate and delete_bookmark to remove them. Returns
        address, type, category, description and status "ok".
        """
        program = session.program
        addr = resolve_address(address)
        bm_mgr = program.getBookmarkManager()

        tx_id = program.startTransaction("Set bookmark")
        try:
            bm_mgr.setBookmark(addr, type, category, description)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to set bookmark: {e}", error_type="BookmarkFailed") from e

        return SetBookmarkResult(
            address=format_address(addr.getOffset()),
            type=type,
            category=category,
            description=description,
            status="ok",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"navigation"})
    @session.require_open
    def list_bookmarks(
        offset: Offset = 0,
        limit: Limit = 100,
        type: Annotated[
            str,
            Field(
                description=(
                    "Only this type (Note, Info, Warning, Error, Analysis); empty for "
                    'all. Example: "Error"'
                )
            ),
        ] = "",
        category: Annotated[
            str, Field(description='Only this exact category. Example: "Suspicious"')
        ] = "",
        filter_pattern: FilterPattern = "",
        start_address: Annotated[
            str, Field(description='Only at or after this address. Example: "0x401000"')
        ] = "",
        end_address: Annotated[
            str, Field(description='Only at or before this address. Example: "0x402000"')
        ] = "",
    ) -> dict:
        """List bookmarks, filtered by type, category, text or address range.

        Ghidra's analyzers leave Error and Analysis bookmarks (bad
        instructions, failed disassembly); set_bookmark adds your own.
        filter_pattern is a regex over the description and category. Returns
        {items: [{address, category, description, type}], total, offset,
        limit, has_more, categories: {type: [categories]}}.
        """
        program = session.program
        bm_mgr = program.getBookmarkManager()
        filt = compile_filter(filter_pattern)
        start = resolve_address(start_address) if start_address else None
        end = resolve_address(end_address) if end_address else None

        def _gen():
            if start is not None:
                bm_iter = bm_mgr.getBookmarksIterator(start, True)
            elif type:
                bm_iter = bm_mgr.getBookmarksIterator(type)
            else:
                bm_iter = bm_mgr.getBookmarksIterator()
            while bm_iter.hasNext():
                bm = bm_iter.next()
                if end is not None and bm.getAddress().compareTo(end) > 0:
                    if start is not None:
                        break
                    continue
                if type and bm.getTypeString() != type:
                    continue
                if category and bm.getCategory() != category:
                    continue
                fields = (bm.getComment() or "", bm.getCategory() or "")
                if filt and not any(filt.search(f) for f in fields):
                    continue
                yield BookmarkItem(
                    address=format_address(bm.getAddress().getOffset()),
                    category=bm.getCategory() or "",
                    description=bm.getComment() or "",
                    type=bm.getTypeString() or "Note",
                ).model_dump()

        page = paginate_iter(_gen(), offset, limit)
        page["categories"] = {
            str(t.getTypeString()): sorted(str(c) for c in bm_mgr.getCategories(t.getTypeString()))
            for t in bm_mgr.getBookmarkTypes()
            if bm_mgr.getCategories(t.getTypeString())
        }
        return page

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"navigation"})
    @session.require_open
    def delete_bookmark(
        address: Address,
        category: Annotated[
            str,
            Field(
                description="Only delete bookmarks in this exact category; empty string "
                "deletes every bookmark at the address. Example: 'Suspicious'"
            ),
        ] = "",
    ) -> DeleteBookmarkResult:
        """Delete the bookmarks at an address, optionally only those in one category.

        Fails with NotFound when nothing matches. Returns address, the category filter
        used and removed_count.
        """
        program = session.program
        addr = resolve_address(address)
        bm_mgr = program.getBookmarkManager()

        # Collect bookmarks to remove
        bookmarks = list(bm_mgr.getBookmarks(addr))
        if category:
            bookmarks = [bm for bm in bookmarks if bm.getCategory() == category]

        if not bookmarks:
            raise GhidraError(
                f"No bookmarks at {format_address(addr.getOffset())}"
                + (f" in category {category!r}" if category else ""),
                error_type="NotFound",
            )

        tx_id = program.startTransaction("Delete bookmark")
        try:
            for bm in bookmarks:
                bm_mgr.removeBookmark(bm)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete bookmark: {e}", error_type="BookmarkFailed") from e

        return DeleteBookmarkResult(
            address=format_address(addr.getOffset()),
            category=category,
            removed_count=len(bookmarks),
        )
