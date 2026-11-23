# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""The unique-hash matching rule (no JVM)."""

from __future__ import annotations

from re_mcp_ghidra.matching import (
    classify_changes,
    match_fuzzy,
    match_unique,
    similarity,
    unmatched,
)


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


def _sig(address: str, **over) -> dict:
    base = {
        "address": address,
        "name": f"FUN_{address[2:]}",
        "is_default_name": True,
        "instructions": 40,
        "blocks": 6,
        "edges": 7,
        "calls": 2,
        "callees": ["name:malloc", "name:memcpy"],
        "strings": ["bad header"],
        "constants": [16, 255],
        "block_hashes": ["a", "b", "c", "d", "e", "f"],
    }
    return {**base, **over}


def test_identical_signatures_score_one():
    assert similarity(_sig("0x1"), _sig("0x2")) == 1.0


def test_changed_constant_still_scores_high():
    changed = _sig("0x2", constants=[16, 254], block_hashes=["a", "b", "c", "d", "e", "x"])
    assert 0.8 < similarity(_sig("0x1"), changed) < 1.0


def test_unrelated_function_scores_low():
    other = _sig(
        "0x2",
        instructions=200,
        blocks=30,
        edges=45,
        calls=9,
        callees=["name:printf"],
        strings=["usage"],
        constants=[1000],
        block_hashes=["q", "r"],
    )
    assert similarity(_sig("0x1"), other) < 0.4


def test_fuzzy_is_one_to_one_and_skips_close_calls():
    src = [_sig("0x10", name="parse", is_default_name=False)]
    twin_a = _sig("0x20")
    twin_b = _sig("0x21")
    assert match_fuzzy(src, [twin_a, twin_b], threshold=0.75) == []  # tie: left unmatched
    near = _sig("0x30", constants=[16, 254], block_hashes=["a", "b", "c", "d", "e", "x"])
    far = _sig("0x31", callees=["name:free"], strings=[], constants=[], block_hashes=["z"])
    matches = match_fuzzy(src, [near, far], threshold=0.75)
    assert [(m["source"]["address"], m["target"]["address"]) for m in matches] == [("0x10", "0x30")]
    assert matches[0]["second_best"] < matches[0]["score"]


def _pair(src: str, dst: str, method: str = "exact", score: float | None = None) -> dict:
    m = {"source": {"address": src, "name": src}, "target": {"address": dst, "name": dst}}
    m["method"] = method
    if score is not None:
        m["score"] = score
    return m


def test_classify_changes_kinds_and_order():
    matches = [
        _pair("0x10", "0x20"),  # identical
        _pair("0x11", "0x21"),  # same code, swapped call target
        _pair("0x12", "0x22", "fuzzy", 0.8),  # changed code and grew
        _pair("0x13", "0x23"),  # same hash, bytes differ (relocation)
    ]
    same = {"size": 10, "callees": ["name:a"], "body": "x"}
    src = {"0x10": same, "0x11": same, "0x12": same, "0x13": same}
    dst = {
        "0x20": same,
        "0x21": {**same, "callees": ["name:b"]},
        "0x22": {**same, "size": 14},
        "0x23": {**same, "body": "y"},
    }
    changed, identical = classify_changes(matches, src, dst)
    assert identical == 1
    assert [c["target"]["address"] for c in changed] == ["0x22", "0x21", "0x23"]
    assert changed[0]["change_types"] == ["code", "size"] and changed[0]["size_delta"] == 4
    assert changed[0]["similarity"] == 0.8
    assert changed[1]["change_types"] == ["callees"]
    assert changed[1]["callees_added"] == ["name:b"] and changed[1]["callees_removed"] == ["name:a"]
    assert changed[2]["change_types"] == ["bytes"]


def test_unreadable_body_counts_as_changed_and_digests_are_optional():
    a = {"size": 4, "callees": []}
    changed, identical = classify_changes(
        [_pair("0x1", "0x2")], {"0x1": {**a, "body": None}}, {"0x2": {**a, "body": None}}
    )
    assert identical == 0 and changed[0]["change_types"] == ["bytes"]
    changed, identical = classify_changes([_pair("0x1", "0x2")], {"0x1": a}, {"0x2": a})
    assert identical == 1 and changed == []


def test_unmatched_counts_small_functions():
    items = [
        {"address": "0x1", "name": "a"},
        {"address": "0x2", "name": "b", "too_small": True},
        {"address": "0x3", "name": "c"},
    ]
    out = unmatched(items, {"0x1"})
    assert out["total"] == 2 and out["too_small"] == 1
    assert [i["name"] for i in out["items"]] == ["b", "c"]
