# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Line diff of decompiled C that separates real edits from decompiler artifacts.

Bootstrap-safe (no Ghidra imports): diff_functions runs it in a worker,
diff_functions_across at the supervisor.

Two builds of one function decompile with different load addresses in default
names (FUN_00101230 vs FUN_00202340), renumbered auto variables (uVar9 vs
uVar7) and per-build string labels. Lines are compared with addresses masked;
each remaining hunk is then classified:

    code          a real change (also any hunk that adds or removes lines)
    var-renumber  equal once auto variables become V1, V2, ... per line
    string-label  equal once string labels (s_..., u_...) are masked
    artifact      equal only with both masks

Masks decide equality only; hunks always show the original text. Rules from
cyberkaida/reverse-engineering-assistant (ReVa) DecompilationDiffUtil.
"""

from __future__ import annotations

import difflib
import re

# Default names carrying a load address; 4+ hex digits so frame names
# (local_18, auStack_28) are never touched.
_ADDRESS_LABEL = re.compile(r"\b(FUN|LAB|SUB|DAT|EXT|PTR|ARRAY|UNK)_[0-9a-fA-F]{4,}")
# s_<text>_<hex> / u_<text>_<hex>: keep the text, mask the address suffix.
_STRING_LABEL = re.compile(r"\b([su]_[0-9A-Za-z_]+?)_[0-9a-fA-F]{4,}\b")
# Bare hex, masked only inside decompiler WARNING comments (never in code,
# where it can be a real bound, mask or offset).
_BARE_HEX = re.compile(r"0x[0-9a-fA-F]+")
_AUTO_VAR = re.compile(r"\b(?:[a-z]{1,5}Var\d+|local_[0-9a-fA-F]+|[a-z]+Stack_[0-9a-fA-F]+)\b")
_STRING_LABEL_FULL = re.compile(r"\b(?:PTR_)?[su]_[0-9A-Za-z_]+")

MAX_HUNKS = 500


def normalize_addresses(line: str) -> str:
    """Mask load addresses in default names, string labels and WARNING comments."""
    out = _ADDRESS_LABEL.sub(r"\1_@", line)
    out = _STRING_LABEL.sub(r"\1_@", out)
    if "/* WARNING:" in out:
        out = _BARE_HEX.sub("0x@", out)
    return out


def canonical_auto_vars(line: str) -> str:
    """Auto variables as V1, V2, ... in first-appearance order within the line."""
    order: dict[str, str] = {}

    def repl(m: re.Match) -> str:
        return order.setdefault(m.group(0), f"V{len(order) + 1}")

    return _AUTO_VAR.sub(repl, line)


def mask_string_labels(line: str) -> str:
    return _STRING_LABEL_FULL.sub("STRLABEL", line)


def classify(a: list[str], b: list[str]) -> str:
    """Kind of one hunk of replaced lines (see module docstring)."""
    if len(a) != len(b) or not a:
        return "code"
    var = string = both = True
    for raw_x, raw_y in zip(a, b, strict=True):
        x, y = normalize_addresses(raw_x), normalize_addresses(raw_y)
        if x == y:
            continue
        cx, cy = canonical_auto_vars(x), canonical_auto_vars(y)
        var &= cx == cy
        string &= mask_string_labels(x) == mask_string_labels(y)
        both &= mask_string_labels(cx) == mask_string_labels(cy)
    if var:
        return "var-renumber"
    if string:
        return "string-label"
    if both:
        return "artifact"
    return "code"


def code_lines(text: str) -> list[str]:
    """Decompiled C as lines, without leading/trailing blank lines."""
    lines = text.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def diff_c(a: list[str], b: list[str], include_artifacts: bool = False) -> dict:
    """Diff two decompiled functions given as lines.

    Returns {similarity, a_lines, b_lines, hunks: [{kind, a_start, b_start, a,
    b}], suppressed: {kind: count}, truncated}. Starts are 1-based line numbers.
    similarity counts lines equal after masking addresses; artifact hunks count
    as equal.
    """
    na = [normalize_addresses(x) for x in a]
    nb = [normalize_addresses(x) for x in b]
    matcher = difflib.SequenceMatcher(a=na, b=nb, autojunk=False)
    hunks: list[dict] = []
    suppressed: dict[str, int] = {}
    same = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            same += i2 - i1
            continue
        kind = classify(a[i1:i2], b[j1:j2])
        if kind != "code":
            same += i2 - i1
            suppressed[kind] = suppressed.get(kind, 0) + 1
            if not include_artifacts:
                continue
        hunks.append(
            {"kind": kind, "a_start": i1 + 1, "b_start": j1 + 1, "a": a[i1:i2], "b": b[j1:j2]}
        )
    total = len(a) + len(b)
    return {
        "similarity": round(2 * same / total, 4) if total else 1.0,
        "a_lines": len(a),
        "b_lines": len(b),
        "hunks": hunks[:MAX_HUNKS],
        "suppressed": suppressed,
        "truncated": len(hunks) > MAX_HUNKS,
    }
