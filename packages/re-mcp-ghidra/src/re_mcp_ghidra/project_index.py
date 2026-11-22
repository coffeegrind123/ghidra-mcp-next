# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Read a Ghidra project's file list without a JVM.

Bootstrap-safe: the supervisor uses this to answer ``list_project_files``
before any worker exists.  A project ``X.gpr`` keeps its local file index in
``X.rep/idata/~index.dat``::

    VERSION=1
    /                                    <- folder (no indent)
      00000000:server.dll:ac1103a3ed...  <- file in that folder: id:name:file-id
    /drivers
      00000001:usb.sys:ac11...
    NEXT-ID:2
    MD5:...

Only files stored in the project itself are listed.  For a shared (Ghidra
Server) project, versioned files that were never checked out live on the
server and are not in this index.
"""

from __future__ import annotations

import os

from re_mcp_ghidra.exceptions import GhidraError

_INDEX = os.path.join("idata", "~index.dat")
_TRAILER_PREFIXES = ("VERSION=", "NEXT-ID:", "MD5:")


def list_project_files(gpr_path: str) -> dict:
    """Return ``{"project", "folders", "files"}`` for the project at *gpr_path*."""
    path = os.path.realpath(os.path.expanduser(gpr_path))
    if not path.endswith(".gpr"):
        raise GhidraError(f"Not a Ghidra project file (.gpr): {path}", error_type="InvalidArgument")

    rep = path[: -len(".gpr")] + ".rep"
    index = os.path.join(rep, _INDEX)
    if not os.path.isfile(index):
        raise GhidraError(
            f"No project index at {index}: not a Ghidra project, or it has never been opened.",
            error_type="NotFound",
        )

    folders: list[str] = []
    files: list[str] = []
    folder = "/"
    with open(index, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip() or line.startswith(_TRAILER_PREFIXES):
                continue
            if not line.startswith(" "):
                folder = line
                folders.append(folder)
                continue

            # "  <id>:<name>:<file-id>" -- the name itself may contain ':'
            entry = line.strip()
            parts = entry.split(":")
            if len(parts) < 3:
                continue
            name = ":".join(parts[1:-1])
            files.append(folder.rstrip("/") + "/" + name)

    return {"project": path, "folders": folders, "files": files}
