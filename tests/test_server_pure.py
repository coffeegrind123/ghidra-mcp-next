# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for server.py pure functions (auto_title, ensure_title)
and Pydantic output-schema validation against representative tool outputs.

These tests run without the Ghidra JVM — the pure helpers in re_mcp.server
and the bootstrap-safe backend modules import without starting pyghidra.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from re_mcp.server import auto_title as _auto_title
from re_mcp.server import ensure_title as _ensure_title
from re_mcp.transforms import (
    BatchOperation,
)
from re_mcp_ghidra.models import RenameResult
from re_mcp_ghidra.server import _UPPERCASE_WORDS

# ---------------------------------------------------------------------------
# _auto_title
# ---------------------------------------------------------------------------


def test_auto_title_basic():
    assert _auto_title("get_function") == "Get Function"


def test_auto_title_uppercase_words():
    assert _auto_title("get_cfg_edges") == "Get CFG Edges"
    assert _auto_title("open_ghidra_project", _UPPERCASE_WORDS) == "Open GHIDRA Project"
    assert _auto_title("get_elf_debug_file_directory") == "Get ELF Debug File Directory"


def test_auto_title_single_word():
    assert _auto_title("undo") == "Undo"


def test_auto_title_single_uppercase_word():
    assert _auto_title("ghidra", _UPPERCASE_WORDS) == "GHIDRA"


def test_auto_title_leading_underscore():
    """Leading underscores should not produce leading spaces."""
    result = _auto_title("_private_func")
    assert not result.startswith(" ")
    assert result == "Private Func"


def test_auto_title_double_underscore():
    """Double underscores should not produce double spaces."""
    result = _auto_title("get__thing")
    assert "  " not in result
    assert result == "Get Thing"


# ---------------------------------------------------------------------------
# _ensure_title
# ---------------------------------------------------------------------------


def test_ensure_title_adds_title():
    kwargs: dict = {"annotations": {"readOnlyHint": True}}
    _ensure_title(kwargs, "get_function", None)
    assert kwargs["title"] == "Get Function"


def test_ensure_title_does_not_overwrite():
    kwargs: dict = {"title": "Custom Title"}
    _ensure_title(kwargs, "get_function", None)
    assert kwargs["title"] == "Custom Title"


def test_ensure_title_creates_if_missing():
    kwargs: dict = {}
    _ensure_title(kwargs, "get_function", None)
    assert kwargs["title"] == "Get Function"


def test_ensure_title_from_fn():
    def my_tool():
        pass

    kwargs: dict = {}
    _ensure_title(kwargs, None, my_tool)
    assert kwargs["title"] == "My Tool"


def test_ensure_title_name_takes_precedence_over_fn():
    def fallback():
        pass

    kwargs: dict = {}
    _ensure_title(kwargs, "get_xrefs_to", fallback)
    assert kwargs["title"] == "Get Xrefs To"


# ---------------------------------------------------------------------------
# Output schema validation — representative tool output dicts
# ---------------------------------------------------------------------------


class TestRenameResultSchema:
    def test_valid(self):
        data = {
            "address": "0x401000",
            "old_name": "sub_401000",
            "new_name": "main",
        }
        obj = RenameResult.model_validate(data)
        assert obj.old_name == "sub_401000"


# ---------------------------------------------------------------------------
# Batch model schema validation
# ---------------------------------------------------------------------------


class TestBatchOperationSchema:
    def test_valid(self):
        op = BatchOperation(tool="get_comment", params={"address": "0x401000"})
        assert op.tool == "get_comment"
        assert op.params["address"] == "0x401000"

    def test_default_params(self):
        op = BatchOperation(tool="get_database_info")
        assert op.params == {}

    def test_missing_tool(self):
        with pytest.raises(ValidationError):
            BatchOperation.model_validate({"params": {}})
