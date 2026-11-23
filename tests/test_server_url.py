# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""ghidra:// URL and server address parsing (no JVM)."""

from __future__ import annotations

import pytest
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.server_url import parse_server_address, parse_server_url


def test_program_url():
    t = parse_server_url("ghidra://srv:13200/repo/dir/prog.bin")
    assert (t.host, t.port, t.repository, t.path) == ("srv", 13200, "repo", "/dir/prog.bin")


def test_default_port():
    assert parse_server_url("ghidra://srv/repo/prog").port == 13100


def test_program_url_needs_a_path():
    with pytest.raises(GhidraError):
        parse_server_url("ghidra://srv/repo")


def test_repository_url_without_path():
    t = parse_server_url("ghidra://srv/repo", require_path=False)
    assert (t.repository, t.path) == ("repo", "/")


@pytest.mark.parametrize("bad", ["http://srv/repo/x", "ghidra:///repo/x", "ghidra://srv"])
def test_rejects_non_ghidra_urls(bad):
    with pytest.raises(GhidraError):
        parse_server_url(bad, require_path=False)


@pytest.mark.parametrize(
    ("text", "expected"),
    [("srv", ("srv", 13100)), ("srv:13200", ("srv", 13200)), ("ghidra://srv:1", ("srv", 1))],
)
def test_server_address(text, expected):
    assert parse_server_address(text) == expected
