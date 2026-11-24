# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Version Tracking helpers that need no JVM: best-view merging, undo step names."""

from __future__ import annotations

from re_mcp_ghidra.programmable import step_name
from re_mcp_ghidra.tools.version_tracking import best


def _row(src, dst, sim, corr="exact_bytes", status="available"):
    return {
        "source": src,
        "destination": dst,
        "similarity": sim,
        "confidence": 1.0,
        "correlator": corr,
        "status": status,
    }


def test_best_merges_correlators_per_pair():
    out = best([_row("a", "x", 1.0), _row("a", "x", 0.9, "combined_reference")])
    assert len(out) == 1
    assert out[0]["correlators"] == ["exact_bytes", "combined_reference"]
    assert out[0]["similarity"] == 1.0


def test_best_drops_ties_on_either_side():
    # Two destinations equally good for one source: neither is kept.
    assert best([_row("a", "x", 1.0), _row("a", "y", 1.0)]) == []
    # Two sources equally good for one destination: neither is kept.
    assert best([_row("a", "x", 1.0), _row("b", "x", 1.0)]) == []


def test_best_needs_a_margin():
    assert best([_row("a", "x", 0.90), _row("a", "y", 0.88)]) == []
    kept = best([_row("a", "x", 0.95), _row("a", "y", 0.80)])
    assert [(p["source"], p["destination"]) for p in kept] == [("a", "x")]


def test_accepted_wins_and_blocks_rivals():
    rows = [_row("a", "x", 0.5, status="accepted"), _row("a", "y", 1.0), _row("b", "x", 1.0)]
    kept = best(rows)
    assert [(p["source"], p["destination"]) for p in kept] == [("a", "x")]


def test_best_is_one_to_one():
    rows = [_row(s, d, 1.0 if s == d else 0.3) for s in "abc" for d in "abc"]
    kept = best(rows)
    assert len({p["source"] for p in kept}) == len(kept) == 3
    assert len({p["destination"] for p in kept}) == 3


class _File:
    def getName(self):
        return "sample"


class _Program:
    def getDomainFile(self):
        return _File()


def test_step_name_strips_synchronized_prefixes():
    program = _Program()
    assert step_name(program, "MCP: rename") == "MCP: rename"
    assert (
        step_name(program, "sample: MCP: apply_version_tracking") == "MCP: apply_version_tracking"
    )
    assert step_name(program, "Untitled: corr\nsample: MCP: x") == "MCP: x"
    assert step_name(program, "Untitled: corr") == "Untitled: corr"
    assert step_name(program, "") == ""
