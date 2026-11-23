# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""The unique-hash matching rule (no JVM)."""

from __future__ import annotations

from re_mcp_ghidra.matching import match_unique


def _h(address: str, value: str | None, name: str = "", default: bool = True) -> dict:
    return {
        "address": address,
        "name": name or f"FUN_{address[2:]}",
        "is_default_name": default,
        "hash": value,
    }


def test_unique_on_both_sides_matches():
    matches, ambiguous, too_small = match_unique(
        [_h("0x10", "aa", "parse", False)], [_h("0x20", "aa")]
    )
    assert [(m["source"]["address"], m["target"]["address"]) for m in matches] == [("0x10", "0x20")]
    assert (ambiguous, too_small) == (0, 0)


def test_repeated_hash_on_either_side_is_ambiguous():
    src = [_h("0x10", "aa"), _h("0x11", "aa"), _h("0x12", "bb")]
    tgt = [_h("0x20", "aa"), _h("0x21", "bb"), _h("0x22", "bb")]
    matches, ambiguous, _ = match_unique(src, tgt)
    assert matches == []
    assert ambiguous == 2


def test_too_small_and_unmatched_are_ignored():
    matches, ambiguous, too_small = match_unique(
        [_h("0x10", None), _h("0x11", "cc")], [_h("0x20", "dd")]
    )
    assert matches == []
    assert (ambiguous, too_small) == (0, 1)
