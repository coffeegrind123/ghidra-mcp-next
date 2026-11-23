# SPDX-FileCopyrightText: © 2026 ghidra-mcp-next contributors
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Decompiled-C diff normalisers (no JVM). Cases follow ReVa's DecompilationDiffUtilTest."""

from __future__ import annotations

from re_mcp_ghidra.cdiff import (
    canonical_auto_vars,
    classify,
    code_lines,
    diff_c,
    normalize_addresses,
)


def _same(a: str, b: str) -> bool:
    return normalize_addresses(a) == normalize_addresses(b)


def test_label_addresses_masked():
    assert _same("  if (param_1 == 0) goto LAB_00104a3c;", "  if (param_1 == 0) goto LAB_00205b7d;")
    assert _same("  iVar1 = FUN_00101230(DAT_00104000);", "  iVar1 = FUN_00202340(DAT_00205000);")


def test_string_label_keeps_text():
    assert _same("  puts(s_failed_00104abc);", "  puts(s_failed_00205def);")
    assert not _same("  puts(s_failed_00104abc);", "  puts(s_passed_00104abc);")


def test_real_edit_survives_masking():
    assert not _same(
        "  iVar1 = FUN_00101230(DAT_00104000);", "  iVar1 = FUN_00101230(DAT_00104000) + 1;"
    )


def test_warning_comment_hex_masked_but_code_hex_kept():
    assert _same(
        "  /* WARNING: Removing unreachable block (ram,0x00113988) */",
        "  /* WARNING: Removing unreachable block (ram,0x001139a8) */",
    )
    line = "  if ((uVar1 < 0x801) && (uVar2 < 0x801)) {"
    assert normalize_addresses(line) == line
    assert not _same("  if (uVar1 < 0x801) {", "  if (uVar1 < 0x802) {")


def test_frame_names_untouched():
    line = "  local_18 = auStack_28 + 4;"
    assert normalize_addresses(line) == line


def test_auto_vars_keep_identity():
    assert canonical_auto_vars("  uVar9 = uVar9 >> 0x18;") == canonical_auto_vars(
        "  uVar7 = uVar7 >> 0x18;"
    )
    # uVar8 = uVar9 + ... reads a different variable than uVar7 = uVar7 + ...
    assert canonical_auto_vars("  uVar8 = uVar9 + uVar5;") != canonical_auto_vars(
        "  uVar7 = uVar7 + uVar5;"
    )
    assert canonical_auto_vars("  param_1 = in_GS_OFFSET + 0x28;") == (
        "  param_1 = in_GS_OFFSET + 0x28;"
    )


def test_classify_kinds():
    assert classify(["  uVar9 = 1;"], ["  uVar7 = 1;"]) == "var-renumber"
    assert classify(["  puts(s_a_b_00104abc);"], ["  puts(s_a_c_00104abc);"]) == "string-label"
    assert classify(["  uVar9 = s_x_1;"], ["  uVar2 = s_y_1;"]) == "artifact"
    assert classify(["  a = 1;"], ["  a = 2;"]) == "code"
    assert classify(["  a = 1;"], ["  a = 1;", "  b = 2;"]) == "code"


def test_relocation_only_diff_has_no_hunks():
    before = code_lines("\n/* WARNING: x (ram,0x00113988) */\nvoid f(void)\n{\n  return;\n}\n")
    after = code_lines("/* WARNING: x (ram,0x001139a8) */\nvoid f(void)\n{\n  return;\n}")
    d = diff_c(before, after)
    assert d["hunks"] == [] and d["similarity"] == 1.0


def test_only_the_real_edit_remains():
    before = [
        "void caller(void)",
        "{",
        "  if (cond == 0) goto LAB_00104a3c;",
        "  log(DAT_00104100);",
        "  result = compute(x);",
        "  return;",
        "}",
    ]
    after = [*before[:2], "  if (cond == 0) goto LAB_00205b7d;", "  log(DAT_00205200);"]
    after += ["  result = compute(x, y);", *before[5:]]
    d = diff_c(before, after)
    assert len(d["hunks"]) == 1
    hunk = d["hunks"][0]
    assert hunk["kind"] == "code" and hunk["b"] == ["  result = compute(x, y);"]
    assert hunk["a_start"] == 5 and hunk["b_start"] == 5


def test_mid_body_insertion_does_not_cascade():
    before = ["void f(void)", "{", "  a();", "  b();", "  c();", "  d();", "  return;", "}"]
    after = [*before[:4], "  guard();", *before[4:]]
    d = diff_c(before, after)
    assert [(h["a"], h["b"]) for h in d["hunks"]] == [([], ["  guard();"])]


def test_artifacts_suppressed_unless_asked():
    before = ["  uVar9 = f();", "  g(uVar9);"]
    after = ["  uVar3 = f();", "  g(uVar3);"]
    d = diff_c(before, after)
    assert d["hunks"] == [] and d["suppressed"] == {"var-renumber": 1}
    assert d["similarity"] == 1.0
    shown = diff_c(before, after, include_artifacts=True)
    assert [h["kind"] for h in shown["hunks"]] == ["var-renumber"]
