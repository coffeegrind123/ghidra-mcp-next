# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ghidra-specific tool visibility constants."""

from re_mcp.transforms import MANAGEMENT_TOOLS, META_TOOLS

# Listed tools: lifecycle, meta tools, and the read loop. Everything else is
# found with search_tools and called through call / batch / execute; keeping
# the listed set small keeps the catalog in every request small.
PINNED_TOOLS = frozenset(
    {
        *MANAGEMENT_TOOLS,
        *META_TOOLS,
        "list_project_files",
        "get_database_info",
        "list_functions",
        "get_function",
        "decompile_function",
        "disassemble_function",
        "get_xrefs_to",
        "get_xrefs_from",
        "list_strings",
        "find_code_by_string",
        "undo",
    }
)
