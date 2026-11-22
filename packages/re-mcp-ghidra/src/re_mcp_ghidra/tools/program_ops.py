# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Worker side of the batch and execute meta tools.

The supervisor's ``batch`` / ``execute`` (re_mcp.transforms) forward here.
The leading underscore keeps these out of search_tools and get_schema: the
documented interface is the supervisor's meta tools.
"""

from __future__ import annotations

import os
from typing import Any

from fastmcp import FastMCP

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import ANNO_MUTATE_NON_IDEMPOTENT
from re_mcp_ghidra.programmable import run_batch, run_python
from re_mcp_ghidra.session import session

_EXECUTE_DISABLED = os.environ.get("GHIDRA_MCP_DISABLE_EXECUTE", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)


def register(mcp: FastMCP) -> None:
    @mcp.tool(name="_batch", annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"internal"})
    @session.require_open
    def batch_ops(
        ops: list[dict[str, Any]],
        label: str = "",
        if_revision: int | None = None,
        operation_id: str | None = None,
        dry_run: bool = False,
    ) -> dict:
        """Internal: run ops in one transaction. Use the batch meta tool."""
        return run_batch(ops, label, if_revision, operation_id, dry_run)

    @mcp.tool(name="_execute", annotations=ANNO_MUTATE_NON_IDEMPOTENT, tags={"internal"})
    @session.require_open
    def execute_python(
        code: str,
        read_only: bool = False,
        label: str = "",
        timeout_s: int = 30,
        if_revision: int | None = None,
        operation_id: str | None = None,
    ) -> dict:
        """Internal: run Python against the program. Use the execute meta tool."""
        if _EXECUTE_DISABLED:
            raise GhidraError(
                "execute is disabled on this server (GHIDRA_MCP_DISABLE_EXECUTE).",
                error_type="Disabled",
            )
        return run_python(code, read_only, label, timeout_s, if_revision, operation_id)
