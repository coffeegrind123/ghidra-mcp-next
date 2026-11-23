# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Program tree / folder management tools.

Ghidra organizes code into a Program Tree with modules (folders) and
fragments.
"""

from __future__ import annotations

from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
)
from re_mcp_ghidra.session import session


class DirEntry(BaseModel):
    """A program tree entry."""

    name: str = Field(description="Entry name.")
    is_folder: bool = Field(description="Whether this is a module (folder).")
    path: str = Field(description="Full path.")


class ListFoldersResult(BaseModel):
    """Program tree listing."""

    tree: str = Field(description="Tree name.")
    path: str = Field(description="Listed path.")
    count: int = Field(description="Number of entries.")
    entries: list[DirEntry] = Field(description="Directory entries.")


class FolderActionResult(BaseModel):
    """Result of a folder create/rename/delete operation."""

    tree: str = Field(description="Tree name.")
    path: str = Field(description="Folder path.")
    old_path: str | None = Field(default=None, description="Previous path (for rename).")
    new_path: str | None = Field(default=None, description="New path (for rename).")


def _get_tree_root(tree_name: str):
    """Get the root module for the named program tree."""
    program = session.program
    listing = program.getListing()

    tree_names = listing.getTreeNames()
    if tree_name not in list(tree_names):
        available = list(tree_names)
        raise GhidraError(
            f"Tree {tree_name!r} not found. Available: {available}",
            error_type="NotFound",
        )

    root = listing.getRootModule(tree_name)
    if root is None:
        raise GhidraError(
            f"Cannot get root module for tree {tree_name!r}",
            error_type="NotFound",
        )
    return root


def _get_children(module):
    """Get all children (modules + fragments) of a ProgramModule."""
    return list(module.getChildren())


def _resolve_module(root, path: str):
    """Walk the path from root to find a ProgramModule."""
    from ghidra.program.model.listing import ProgramModule  # noqa: PLC0415

    parts = [p for p in path.strip("/").split("/") if p]
    current = root
    for part in parts:
        found = False
        for child in _get_children(current):
            if child.getName() == part:
                if isinstance(child, ProgramModule):
                    current = child
                    found = True
                    break
                raise GhidraError(
                    f"{part!r} is a fragment, not a folder",
                    error_type="InvalidArgument",
                )
        if not found:
            raise GhidraError(
                f"Path component {part!r} not found in {path!r}",
                error_type="NotFound",
            )
    return current


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"metadata"})
    @session.require_open
    def list_program_tree(tree: str = "Program Tree", path: str = "/") -> ListFoldersResult:
        """List folders and fragments in Ghidra's program tree.

        Args:
            tree: Program tree name (use default "Program Tree" or check
                the listing for available trees).
            path: Directory path to list (default "/" for root).
        """
        from ghidra.program.model.listing import ProgramModule  # noqa: PLC0415

        root = _get_tree_root(tree)

        # Navigate to the requested path
        module = root if path in ("/", "") else _resolve_module(root, path)

        entries = []
        for child in _get_children(module):
            child_name = child.getName()
            is_module = isinstance(child, ProgramModule)
            child_path = f"{path.rstrip('/')}/{child_name}"
            entries.append(
                DirEntry(
                    name=child_name,
                    is_folder=is_module,
                    path=child_path,
                )
            )

        return ListFoldersResult(
            tree=tree,
            path=path,
            count=len(entries),
            entries=entries,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"metadata"})
    @session.require_open
    def create_program_tree_folder(
        tree: Annotated[
            str,
            Field(
                description="Program tree name; Ghidra's default tree is 'Program Tree'. "
                "Example: 'Program Tree'"
            ),
        ],
        path: Annotated[
            str,
            Field(
                description="Slash-separated path of the folder to create; every parent "
                "must already exist. Example: '/crypto/aes'"
            ),
        ],
    ) -> FolderActionResult:
        """Create one folder (module) in a program tree under an existing parent folder.

        Use list_program_tree to see the current layout. Returns tree and path.
        """
        root = _get_tree_root(tree)
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            raise GhidraError("Empty path", error_type="InvalidArgument")

        parent_path = "/".join(parts[:-1])
        new_name = parts[-1]

        parent = _resolve_module(root, parent_path) if parent_path else root

        program = session.program
        tx_id = program.startTransaction("Create folder")
        try:
            parent.createModule(new_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to create folder: {e}", error_type="CreateFailed") from e

        return FolderActionResult(tree=tree, path=path)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"metadata"})
    @session.require_open
    def rename_program_tree_folder(
        tree: Annotated[
            str,
            Field(
                description="Program tree name; Ghidra's default tree is 'Program Tree'. "
                "Example: 'Program Tree'"
            ),
        ],
        old_path: Annotated[
            str,
            Field(description="Current slash-separated folder path. Example: '/crypto/aes'"),
        ],
        new_path: Annotated[
            str,
            Field(
                description="Path whose last component becomes the new name; its parent "
                "part is ignored, so the folder never moves. Example: '/crypto/aes256'"
            ),
        ],
    ) -> FolderActionResult:
        """Rename a program-tree folder in place; it is not moved to another parent.

        Returns tree, path (= new_path), old_path and new_path.
        """
        root = _get_tree_root(tree)
        module = _resolve_module(root, old_path)

        new_parts = [p for p in new_path.strip("/").split("/") if p]
        if not new_parts:
            raise GhidraError("Empty new path", error_type="InvalidArgument")
        new_name = new_parts[-1]

        program = session.program
        tx_id = program.startTransaction("Rename folder")
        try:
            module.setName(new_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to rename folder: {e}", error_type="RenameFailed") from e

        return FolderActionResult(tree=tree, old_path=old_path, new_path=new_path, path=new_path)

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"metadata"})
    @session.require_open
    def delete_program_tree_folder(
        tree: Annotated[
            str,
            Field(
                description="Program tree name; Ghidra's default tree is 'Program Tree'. "
                "Example: 'Program Tree'"
            ),
        ],
        path: Annotated[
            str,
            Field(
                description="Slash-separated path of the folder to delete; the root "
                "cannot be deleted. Example: '/crypto/aes'"
            ),
        ],
    ) -> FolderActionResult:
        """Delete an empty folder (module) from a program tree.

        Code is not deleted; only the tree grouping is. Fails with NotFound when the
        folder does not exist. Returns tree and path.
        """
        root = _get_tree_root(tree)

        parts = [p for p in path.strip("/").split("/") if p]
        if not parts:
            raise GhidraError("Cannot delete root", error_type="InvalidArgument")

        folder_name = parts[-1]
        parent = _resolve_module(root, "/".join(parts[:-1])) if len(parts) > 1 else root

        # Verify the child exists
        if not any(c.getName() == folder_name for c in _get_children(parent)):
            raise GhidraError(
                f"Folder {folder_name!r} not found at path {path!r}",
                error_type="NotFound",
            )

        program = session.program
        tx_id = program.startTransaction("Delete folder")
        try:
            parent.removeChild(folder_name)
            program.endTransaction(tx_id, True)
        except Exception as e:
            program.endTransaction(tx_id, False)
            raise GhidraError(f"Failed to delete folder: {e}", error_type="DeleteFailed") from e

        return FolderActionResult(tree=tree, path=path)
