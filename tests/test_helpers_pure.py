# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for pure helper functions that don't require a backend engine.

These tests cover format_address, paginate, paginate_iter, compile_filter,
async_paginate_iter, and structured error serialization — all functions
that can run without the Ghidra JVM.
"""

from __future__ import annotations

import json

import pytest
from re_mcp.context import try_get_context
from re_mcp.exceptions import BackendError
from re_mcp.helpers import (
    async_paginate_iter,
    compile_filter,
    format_address,
    paginate,
    paginate_iter,
)
from re_mcp_ghidra.exceptions import GhidraError

# ---------------------------------------------------------------------------
# format_address
# ---------------------------------------------------------------------------


def test_format_address_zero():
    assert format_address(0) == "0x0"


def test_format_address_typical():
    assert format_address(0x401000) == "0x401000"


def test_format_address_large():
    assert format_address(0x7FFFF7DD1000) == "0x7FFFF7DD1000"


# ---------------------------------------------------------------------------
# paginate
# ---------------------------------------------------------------------------


def test_paginate_basic():
    items = list(range(10))
    result = paginate(items, offset=0, limit=5)
    assert result["items"] == [0, 1, 2, 3, 4]
    assert result["total"] == 10
    assert result["offset"] == 0
    assert result["limit"] == 5
    assert result["has_more"] is True


def test_paginate_offset():
    items = list(range(10))
    result = paginate(items, offset=8, limit=5)
    assert result["items"] == [8, 9]
    assert result["total"] == 10
    assert result["has_more"] is False


def test_paginate_empty():
    result = paginate([], offset=0, limit=10)
    assert result["items"] == []
    assert result["total"] == 0
    assert result["has_more"] is False


def test_paginate_limit_honored():
    items = list(range(1000))
    result = paginate(items, offset=0, limit=9999)
    assert result["limit"] == 9999
    assert len(result["items"]) == 1000  # all items returned


def test_paginate_negative_offset():
    items = list(range(5))
    result = paginate(items, offset=-10, limit=3)
    assert result["offset"] == 0
    assert result["items"] == [0, 1, 2]


def test_paginate_zero_limit():
    items = list(range(5))
    result = paginate(items, offset=0, limit=0)
    assert result["limit"] == 1  # min cap
    assert result["items"] == [0]


# ---------------------------------------------------------------------------
# paginate_iter
# ---------------------------------------------------------------------------


def test_paginate_iter_basic():
    result = paginate_iter(iter(range(10)), offset=0, limit=5)
    assert result["items"] == [0, 1, 2, 3, 4]
    assert result["total"] == 10
    assert result["offset"] == 0
    assert result["limit"] == 5
    assert result["has_more"] is True


def test_paginate_iter_offset():
    result = paginate_iter(iter(range(10)), offset=8, limit=5)
    assert result["items"] == [8, 9]
    assert result["total"] == 10
    assert result["has_more"] is False


def test_paginate_iter_empty():
    result = paginate_iter(iter([]), offset=0, limit=10)
    assert result["items"] == []
    assert result["total"] == 0
    assert result["has_more"] is False


def test_paginate_iter_limit_honored():
    result = paginate_iter(iter(range(1000)), offset=0, limit=9999)
    assert result["limit"] == 9999
    assert len(result["items"]) == 1000


def test_paginate_iter_generator():
    """Verify paginate_iter works with a true generator (not just list iterator)."""

    def gen():
        for i in range(5):
            yield {"value": i}

    result = paginate_iter(gen(), offset=1, limit=2)
    assert result["items"] == [{"value": 1}, {"value": 2}]
    assert result["total"] == 5
    assert result["has_more"] is True


def test_paginate_iter_matches_paginate():
    """paginate_iter should produce the same result as paginate for the same data."""
    data = list(range(20))
    for offset, limit in [(0, 5), (3, 10), (18, 5), (0, 100)]:
        expected = paginate(data, offset, limit)
        actual = paginate_iter(iter(data), offset, limit)
        assert actual == expected, f"Mismatch at offset={offset}, limit={limit}"


# ---------------------------------------------------------------------------
# compile_filter
# ---------------------------------------------------------------------------


def test_compile_filter_empty():
    pattern = compile_filter("")
    assert pattern is None


def test_compile_filter_valid():
    pattern = compile_filter("foo.*bar")
    assert pattern is not None
    assert pattern.search("foo123bar")
    assert not pattern.search("baz")


def test_compile_filter_case_insensitive():
    pattern = compile_filter("hello")
    assert pattern.search("HELLO")


def test_compile_filter_invalid():
    with pytest.raises(BackendError) as exc_info:
        compile_filter("[invalid")
    assert exc_info.value.error_type == "InvalidArgument"
    assert "Invalid regex" in str(exc_info.value)


# ---------------------------------------------------------------------------
# paginate_iter — bounded count-ahead
# ---------------------------------------------------------------------------


def test_paginate_iter_large_stops_counting():
    """For very large iterators the count-ahead cap kicks in."""
    result = paginate_iter(iter(range(100_000)), offset=0, limit=5)
    assert result["items"] == [0, 1, 2, 3, 4]
    assert result["has_more"] is True
    # total is bounded — won't be the full 100_000
    assert result["total"] <= 10_005 + 5


# ---------------------------------------------------------------------------
# GhidraError structured serialization
# ---------------------------------------------------------------------------


def test_ghidra_error_str_is_json():
    err = GhidraError("something failed", error_type="NotFound")
    parsed = json.loads(str(err))
    assert parsed == {"error": "something failed", "error_type": "NotFound"}


def test_ghidra_error_str_with_details():
    err = GhidraError("bad value", error_type="InvalidArgument", valid_values=["a", "b"])
    parsed = json.loads(str(err))
    assert parsed["error"] == "bad value"
    assert parsed["error_type"] == "InvalidArgument"
    assert parsed["valid_values"] == ["a", "b"]


def test_ghidra_error_str_no_details():
    err = GhidraError("oops")
    parsed = json.loads(str(err))
    assert parsed == {"error": "oops", "error_type": "Error"}
    assert len(parsed) == 2  # no extra keys


# ---------------------------------------------------------------------------
# async_paginate_iter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_paginate_iter_basic():
    result = await async_paginate_iter(iter(range(10)), offset=0, limit=5)
    assert result["items"] == [0, 1, 2, 3, 4]
    assert result["total"] == 10
    assert result["offset"] == 0
    assert result["limit"] == 5
    assert result["has_more"] is True


@pytest.mark.asyncio
async def test_async_paginate_iter_offset():
    result = await async_paginate_iter(iter(range(10)), offset=8, limit=5)
    assert result["items"] == [8, 9]
    assert result["total"] == 10
    assert result["has_more"] is False


@pytest.mark.asyncio
async def test_async_paginate_iter_empty():
    result = await async_paginate_iter(iter([]), offset=0, limit=10)
    assert result["items"] == []
    assert result["total"] == 0
    assert result["has_more"] is False


@pytest.mark.asyncio
async def test_async_paginate_iter_generator():
    """Verify async_paginate_iter works with a true generator."""

    def gen():
        for i in range(5):
            yield {"value": i}

    result = await async_paginate_iter(gen(), offset=1, limit=2)
    assert result["items"] == [{"value": 1}, {"value": 2}]
    assert result["total"] == 5
    assert result["has_more"] is True


@pytest.mark.asyncio
async def test_async_paginate_iter_matches_paginate_iter():
    """async_paginate_iter should produce the same result as paginate_iter."""
    data = list(range(20))
    for offset, limit in [(0, 5), (3, 10), (18, 5), (0, 100)]:
        expected = paginate_iter(iter(data), offset, limit)
        actual = await async_paginate_iter(iter(data), offset, limit)
        assert actual == expected, f"Mismatch at offset={offset}, limit={limit}"


@pytest.mark.asyncio
async def test_async_paginate_iter_large_stops_counting():
    """For very large iterators the count-ahead cap kicks in."""
    result = await async_paginate_iter(iter(range(100_000)), offset=0, limit=5)
    assert result["items"] == [0, 1, 2, 3, 4]
    assert result["has_more"] is True
    assert result["total"] <= 10_005 + 5


# ---------------------------------------------------------------------------
# try_get_context
# ---------------------------------------------------------------------------


def test_try_get_context_no_active_request():
    """Returns None when no FastMCP request context is active."""
    assert try_get_context() is None


def test_try_get_context_returns_context(monkeypatch):
    """Returns the context object when a request context is active."""
    sentinel = object()
    # try_get_context uses a lazy import, so we patch the module it imports from
    import fastmcp.server.dependencies as deps  # noqa: PLC0415

    monkeypatch.setattr(deps, "get_context", lambda: sentinel)
    result = try_get_context()
    assert result is not None, "try_get_context() returned None — monkeypatch may not be hitting"
    assert result is sentinel
