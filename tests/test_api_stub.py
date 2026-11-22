# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""The ghidra://api/tools.pyi stub and the server instructions."""

from __future__ import annotations

import ast
from typing import Annotated

from fastmcp.tools.tool import Tool
from pydantic import BaseModel, Field
from re_mcp.transforms import ToolTransform, render_api_stub
from re_mcp_ghidra.backend import API_STUB_HEADER, INSTRUCTIONS, GhidraBackend
from re_mcp_ghidra.transforms import PINNED_TOOLS

# Claude Code keeps only the first 4,096 characters of server instructions.
CLAUDE_CODE_INSTRUCTIONS_LIMIT = 4096


class Renamed(BaseModel):
    address: str = Field(description="Function entry.")
    old_name: str
    new_name: str


def _rename(
    address: Annotated[str, Field(description='Function address. Example: "0x401000"')],
    new_name: Annotated[str, Field(description='New name. Example: "parse_packet"')],
    database: str = "",
) -> Renamed:
    """Rename a function. Ends with a "quote\""""
    raise NotImplementedError


def _internal(ops: list[dict]) -> dict:
    """Internal."""
    raise NotImplementedError


def _tools() -> list[Tool]:
    return [
        Tool.from_function(_rename, name="rename_function", tags={"functions"}),
        Tool.from_function(_internal, name="_batch"),
        Tool.from_function(_internal, name="batch"),
    ]


def test_stub_is_valid_python():
    ast.parse(render_api_stub(_tools(), API_STUB_HEADER))


def test_stub_lists_public_tools_only():
    stub = render_api_stub(_tools(), API_STUB_HEADER)
    assert "def rename_function(address: str, new_name: str) -> dict:" in stub
    assert "def _batch" not in stub
    assert "def batch" not in stub


def test_stub_documents_params_and_returns_without_database():
    stub = render_api_stub(_tools(), API_STUB_HEADER)
    assert 'new_name: New name. Example: "parse_packet"' in stub
    assert "Returns: {address: str, old_name: str, new_name: str}" in stub
    assert "database" not in stub.split("def rename_function", 1)[1]


def test_instructions_fit_claude_code():
    assert len(INSTRUCTIONS) < CLAUDE_CODE_INSTRUCTIONS_LIMIT


def test_instructions_point_at_the_api():
    for needle in ("search_tools", "ghidra://api/tools.pyi", "batch", "execute", "if_revision"):
        assert needle in INSTRUCTIONS


def test_instructions_name_disabled_meta_tools():
    on = GhidraBackend.build_instructions(ToolTransform(pinned=PINNED_TOOLS))
    off = GhidraBackend.build_instructions(ToolTransform(pinned=PINNED_TOOLS, enable_execute=False))
    assert on == INSTRUCTIONS
    assert off.endswith("Disabled on this server: execute.\n")


def _has_any_of(schema: object) -> bool:
    if isinstance(schema, dict):
        return "anyOf" in schema or any(_has_any_of(v) for v in schema.values())
    if isinstance(schema, list):
        return any(_has_any_of(v) for v in schema)
    return False


def test_meta_tool_inputs_avoid_any_of():
    # Several MCP clients reject anyOf in input schemas; optional params use
    # plain types with documented "unset" defaults instead.
    transform = ToolTransform(pinned=PINNED_TOOLS)
    for tool in (transform._get_batch_tool(), transform._get_execute_tool()):
        props = tool.parameters["properties"]
        assert not _has_any_of(props["if_revision"]), tool.name
        assert not _has_any_of(props["operation_id"]), tool.name
