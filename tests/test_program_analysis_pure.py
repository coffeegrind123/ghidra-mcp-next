# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Graph algorithms behind get_function_metrics and analyze_call_graph (no JVM)."""

from __future__ import annotations

from re_mcp_ghidra.tools.program_analysis import _count_loops, _tarjan


def test_straight_line_has_no_loops():
    assert _count_loops([[1], [2], []], 0) == 0


def test_simple_loop():
    # 0 -> 1 -> 2 -> 1 (back edge), 2 -> 3
    assert _count_loops([[1], [2], [1, 3], []], 0) == 1


def test_backward_jump_that_is_not_a_loop():
    # 0 -> 2 and 0 -> 1 -> 2: block 2 jumps "back" to 1 only if 1 dominated 2; it does not.
    # 2 -> 1 is a backward jump into a block that does not dominate 2: not a loop.
    succ = [[1, 2], [3], [1], []]
    assert _count_loops(succ, 0) == 0


def test_nested_loops():
    # outer 1..4, inner 2..3
    succ = [[1], [2], [3], [2, 4], [1, 5], []]
    assert _count_loops(succ, 0) == 2


def test_tarjan_finds_recursion_groups():
    adj = {1: {2}, 2: {3}, 3: {1}, 4: {4}, 5: {1}}
    comps = sorted(sorted(c) for c in _tarjan(adj))
    assert [1, 2, 3] in comps
    assert [4] in comps
    assert [5] in comps


def test_tarjan_deep_chain_does_not_recurse():
    adj = {i: {i + 1} for i in range(20000)}
    adj[20000] = set()
    assert len(_tarjan(adj)) == 20001
